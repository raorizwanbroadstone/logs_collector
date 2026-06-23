import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

import mmh3
from bitarray import bitarray

SCRIPT_DIR = Path(__file__).parent
LOGS_DIR = SCRIPT_DIR / "logs"
REPORT_DIR = SCRIPT_DIR / "report"

BLOOM_CAPACITY = 500_000
BLOOM_FPR = 0.0001

# Bloom filter and deduplication layer
class BloomFilter:
    """
    Probabilistic membership structure using MurmurHash3 double-hashing over a
    bitarray. Sized at init for a given capacity and false positive rate.
    Guarantees no false negatives; callers must resolve false positives externally.
    """

    def __init__(self, capacity: int, fpr: float):
        bit_array_size = math.ceil(-(capacity * math.log(fpr)) / (math.log(2) ** 2))
        hash_count = max(1, round((bit_array_size / capacity) * math.log(2)))
        self.bit_array_size = bit_array_size
        self.hash_count = hash_count
        self.bits = bitarray(bit_array_size)
        self.bits.setall(0)

    def compute_positions(self, key: str) -> list[int]:
        primary_hash = mmh3.hash(key, seed=0, signed=False)
        secondary_hash = mmh3.hash(key, seed=1, signed=False)
        return [(primary_hash + i * secondary_hash) % self.bit_array_size for i in range(self.hash_count)]

    def add(self, key: str) -> None:
        for position in self.compute_positions(key):
            self.bits[position] = 1

    def might_contain(self, key: str) -> bool:
        return all(self.bits[position] for position in self.compute_positions(key))


class DeduplicatingSet:
    """
    Combines BloomFilter (fast definite-miss path) with an exact backing set to
    guarantee zero duplicate insertions regardless of false positive rate.
    The Bloom filter avoids a hash-set lookup for every key the set has never seen.
    """

    def __init__(self, capacity: int = BLOOM_CAPACITY, fpr: float = BLOOM_FPR):
        self.bloom_filter = BloomFilter(capacity, fpr)
        self.seen_keys: set[str] = set()

    def add_if_new(self, key: str) -> bool:
        """Returns True and records the key if it has never been seen; False otherwise."""
        if self.bloom_filter.might_contain(key) and key in self.seen_keys:
            return False
        self.bloom_filter.add(key)
        self.seen_keys.add(key)
        return True

    def __len__(self) -> int:
        return len(self.seen_keys)


# File loading
def load_log_file(log_file: Path) -> dict:
    """
    Loads the entire JSON file. Azure OpenAI diagnostic files are small (~11KB),
    and their structure requires reading from multiple top-level keys (workspaceId,
    results.AzureDiagnostics_Sample, results.Table_Counts) in one pass.
    """
    with log_file.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


# Entity extractors
def extract_cognitive_services_resources(data: dict) -> list[dict]:
    """
    Extracts Cognitive Services / Azure OpenAI resource components from
    AzureDiagnostics_Sample records. _ResourceId (lowercase ARM path) is the
    unique key; it is stable across runs for the same resource.
    """
    results = []
    for record in data.get("results", {}).get("AzureDiagnostics_Sample", []):
        if not isinstance(record, dict):
            continue
        resource_id = record.get("_ResourceId") or record.get("ResourceId", "")
        if not resource_id:
            continue
        resource_id = resource_id.lower()
        results.append({
            "kind":              "cognitive_services_resource",
            "key":               resource_id,
            "name":              record.get("Resource", resource_id.split("/")[-1]),
            "resource_id":       resource_id,
            "resource_provider": record.get("ResourceProvider", ""),
            "resource_type":     record.get("ResourceType", ""),
            "resource_group":    record.get("ResourceGroup", ""),
            "subscription_id":   record.get("SubscriptionId", ""),
            "operation_name":    record.get("OperationName", ""),
            "category":          record.get("Category", ""),
            "workload":          record.get("ResourceProvider", ""),
        })
    return results


def extract_resource_providers(data: dict) -> list[dict]:
    """
    Extracts unique resource providers (e.g., MICROSOFT.COGNITIVESERVICES) from
    AzureDiagnostics_Sample records. Normalised to uppercase for consistency.
    """
    return [
        {"kind": "resource_provider", "key": provider, "name": provider}
        for record in data.get("results", {}).get("AzureDiagnostics_Sample", [])
        if isinstance(record, dict) and (provider := record.get("ResourceProvider", "").upper())
    ]


def extract_log_tables(data: dict) -> list[dict]:
    """
    Extracts Log Analytics table names from Table_Counts query results.
    Each table is a service that stores diagnostic telemetry in the workspace.
    """
    return [
        {"kind": "log_table", "key": table_name, "name": table_name, "record_count": str(record.get("Count", 0))}
        for record in data.get("results", {}).get("Table_Counts", [])
        if isinstance(record, dict) and (table_name := record.get("$table", ""))
    ]


def extract_workspace(data: dict) -> dict | None:
    """
    Extracts the Log Analytics workspace as a service from the top-level
    workspaceId field. Returns None if the field is absent.
    """
    ws_id = data.get("workspaceId", "")
    if not ws_id:
        return None
    return {
        "kind":  "log_analytics_workspace",
        "key":   ws_id,
        "name":  f"Log Analytics Workspace ({ws_id[:8]}...)",
        "ws_id": ws_id,
    }


# CycloneDX 1.6 serializers
def to_cyclonedx_component(entity: dict) -> dict:
    """
    Maps a raw cognitive_services_resource dict to a CycloneDX 1.6 component
    (type: application). Azure-specific fields are stored as azure: properties.
    """
    bom_ref = f"{entity['kind']}-{entity['key']}"
    field_map = [
        ("resource_id",       "azure:ResourceId"),
        ("resource_provider", "azure:ResourceProvider"),
        ("resource_type",     "azure:ResourceType"),
        ("resource_group",    "azure:ResourceGroup"),
        ("subscription_id",   "azure:SubscriptionId"),
        ("operation_name",    "azure:OperationName"),
        ("category",          "azure:Category"),
    ]
    properties = [{"name": cdx_name, "value": value} for field, cdx_name in field_map if (value := entity.get(field, ""))]

    component: dict = {
        "type":    "application",
        "bom-ref": bom_ref,
        "name":    entity["name"],
    }
    if properties:
        component["properties"] = properties
    return component


def to_cyclonedx_service(entity: dict) -> dict:
    """
    Maps a raw resource_provider, log_table, or log_analytics_workspace dict
    to a CycloneDX 1.6 service object. authenticated is True for all Azure services.
    """
    bom_ref = f"{entity['kind']}-{entity['key']}"
    service_entry: dict = {
        "bom-ref":       bom_ref,
        "name":          entity["name"],
        "authenticated": True,
    }

    properties = []
    if entity["kind"] == "log_analytics_workspace" and entity.get("ws_id"):
        properties.append({"name": "azure:WorkspaceId", "value": entity["ws_id"]})
    elif entity["kind"] == "log_table" and entity.get("record_count"):
        properties.append({"name": "azure:RecordCount", "value": entity["record_count"]})

    if properties:
        service_entry["properties"] = properties
    return service_entry


def build_dependency_graph(
    raw_components: list[dict],
    raw_services: list[dict],
) -> list[dict]:
    """
    Builds the CycloneDX dependencies section.
    Root Azure tenant depends on all services (providers, tables, workspace).
    Cognitive Services resources depend on their resource provider.
    Log tables depend on the Log Analytics workspace.
    """
    service_refs = {entity["key"]: f"{entity['kind']}-{entity['key']}" for entity in raw_services}
    workspace_refs = [
        f"{entity['kind']}-{entity['key']}"
        for entity in raw_services
        if entity["kind"] == "log_analytics_workspace"
    ]

    dependencies: list[dict] = [
        {
            "ref":       "root-azure-tenant",
            "dependsOn": list(service_refs.values()),
        }
    ]

    for entity in raw_components:
        workload_ref = service_refs.get(entity.get("workload", "").upper())
        if workload_ref:
            dependencies.append({
                "ref":       f"{entity['kind']}-{entity['key']}",
                "dependsOn": [workload_ref],
            })

    for entity in raw_services:
        if entity["kind"] == "log_table" and workspace_refs:
            dependencies.append({
                "ref":       f"{entity['kind']}-{entity['key']}",
                "dependsOn": workspace_refs,
            })

    return dependencies


def build_cyclonedx_bom(
    raw_components: list[dict],
    raw_services: list[dict],
    workspace_id: str,
    source_files: str,
) -> dict:
    """
    Assembles the full CycloneDX 1.6 BOM document from extracted entities.
    Includes metadata (tool provenance, root tenant), components, services,
    and a full dependency graph.
    """
    return {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type":    "application",
                        "name":    "azure-openai-bom-generator",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type":    "platform",
                "bom-ref": "root-azure-tenant",
                "name":    "Azure Tenant",
                "properties": [
                    {"name": "azure:WorkspaceId", "value": workspace_id},
                    {"name": "azure:SourceFiles", "value": source_files},
                ],
            },
        },
        "components":   [to_cyclonedx_component(entity) for entity in raw_components],
        "services":     [to_cyclonedx_service(entity) for entity in raw_services],
        "dependencies": build_dependency_graph(raw_components, raw_services),
    }


# Per-file processor
def process_log_file(
    log_file: Path,
    cognitive_resource_dedup: DeduplicatingSet,
    resource_provider_dedup: DeduplicatingSet,
    log_table_dedup: DeduplicatingSet,
    workspace_dedup: DeduplicatingSet,
) -> tuple[list[dict], list[dict], str]:
    """
    Loads one log file and extracts all new components and services.
    All dedup sets are shared across calls to catch cross-file duplicates.
    Returns (raw_components, raw_services, workspace_id).
    """
    data = load_log_file(log_file)
    raw_components: list[dict] = []
    raw_services: list[dict] = []

    raw_components.extend(
        entity for entity in extract_cognitive_services_resources(data)
        if cognitive_resource_dedup.add_if_new(entity["key"])
    )
    raw_services.extend(
        entity for entity in extract_resource_providers(data)
        if resource_provider_dedup.add_if_new(entity["key"])
    )
    raw_services.extend(
        entity for entity in extract_log_tables(data)
        if log_table_dedup.add_if_new(entity["key"])
    )

    workspace_entity = extract_workspace(data)
    workspace_id = workspace_entity["ws_id"] if workspace_entity else ""
    if workspace_entity and workspace_dedup.add_if_new(workspace_entity["key"]):
        raw_services.append(workspace_entity)

    return raw_components, raw_services, workspace_id


# Entry point
def main(target_file: Path | None = None) -> None:
    """
    Entry point. Processes target_file if given (called from fetch_azure_diagnostic_logs.py),
    otherwise processes all JSON files in logs/. Builds a CycloneDX 1.6 BOM and writes it
    to report/.
    """
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    log_files = [target_file] if target_file else sorted(LOGS_DIR.glob("*.json"))
    if not log_files:
        print(f"No JSON files found in {LOGS_DIR}")
        return

    cognitive_resource_dedup = DeduplicatingSet()
    resource_provider_dedup = DeduplicatingSet()
    log_table_dedup = DeduplicatingSet()
    workspace_dedup = DeduplicatingSet()

    all_components: list[dict] = []
    all_services: list[dict] = []
    workspace_id = ""

    for log_file in log_files:
        print(f"Processing {log_file.name} ...")
        components, services, first_workspace_id = process_log_file(
            log_file, cognitive_resource_dedup, resource_provider_dedup, log_table_dedup, workspace_dedup
        )
        all_components.extend(components)
        all_services.extend(services)
        if not workspace_id:
            workspace_id = first_workspace_id
        print(f"  {len(components)} new components, {len(services)} new services")

    source_files = ", ".join(file.name for file in log_files)
    bom = build_cyclonedx_bom(all_components, all_services, workspace_id, source_files)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORT_DIR / f"bom_{timestamp}.json"
    output_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    print(f"\nBOM report saved to: {output_path}")
    print(f"Total: {len(all_components)} components, {len(all_services)} services")


if __name__ == "__main__":
    main()
