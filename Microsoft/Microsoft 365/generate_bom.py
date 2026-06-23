import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

import ijson
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



# Log streaming

def stream_events(log_file: Path):
    """Yields each top-level JSON object from a large array file using ijson."""
    with log_file.open("rb") as file_handle:
        yield from ijson.items(file_handle, "item")



# Field parsers for embedded JSON strings

def parse_embedded_json_list(raw: str) -> list[str]:
    """
    ModifiedProperties stores values as JSON-encoded strings like '["Azure Managed HSM RP"]'.
    Parses them and returns a flat list of strings, falling back to a single-element list.
    """
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(x) for x in parsed if x is not None]
        return [str(parsed)]
    except (json.JSONDecodeError, TypeError):
        return [raw.strip()] if raw and raw.strip() else []


def read_extended_properties(event: dict) -> tuple[str, dict]:
    """
    Reads ExtendedProperties to return (extendedAuditEventCategory, additionalDetails dict).
    Both values are empty if the fields are absent or malformed.
    """
    category = ""
    details: dict = {}
    for prop in event.get("ExtendedProperties", []):
        name = prop.get("Name", "")
        if name == "extendedAuditEventCategory":
            category = prop.get("Value", "")
        elif name == "additionalDetails":
            try:
                details = json.loads(prop.get("Value", "{}"))
            except (json.JSONDecodeError, TypeError):
                pass
    return category, details



# Entity extractors — each returns a typed dict or None

def extract_service_principal(event: dict) -> dict | None:
    """
    Identifies AAD service principal provisioning events by checking for category
    'ServicePrincipal' in ExtendedProperties. Pulls AppId from additionalDetails
    and DisplayName from ModifiedProperties. Returns None for non-SP events.
    """
    category, details = read_extended_properties(event)
    if category != "ServicePrincipal":
        return None

    app_id = details.get("AppId") or event.get("ObjectId", "")
    if not app_id:
        return None

    modified = {prop["Name"]: prop.get("NewValue", "") for prop in event.get("ModifiedProperties", [])}
    names = parse_embedded_json_list(modified.get("DisplayName", ""))
    display_name = names[0] if names else app_id

    return {
        "kind":             "service_principal",
        "key":              app_id,
        "name":             display_name,
        "app_id":           app_id,
        "owner_org_id":     details.get("AppOwnerOrganizationId", ""),
        "provisioning":     details.get("ServicePrincipalProvisioningType", ""),
        "operation":        event.get("Operation", ""),
        "result_status":    event.get("ResultStatus", ""),
        "workload":         event.get("Workload", ""),
    }


def extract_client_app(event: dict) -> dict | None:
    """
    Extracts a consuming application from AppAccessContext if present.
    ClientAppId is used as the unique key; ClientAppName as the display name.
    Returns None for events without AppAccessContext.
    """
    context = event.get("AppAccessContext")
    if not isinstance(context, dict):
        return None
    client_id = context.get("ClientAppId", "")
    if not client_id:
        return None

    return {
        "kind":          "client_app",
        "key":           client_id,
        "name":          context.get("ClientAppName") or client_id,
        "client_app_id": client_id,
        "api_id":        context.get("APIId", ""),
        "workload":      event.get("Workload", ""),
    }


def extract_workload(event: dict) -> dict | None:
    """
    Captures each unique M365 workload (AzureActiveDirectory, MicrosoftTeams, etc.)
    as a CycloneDX service entry. RecordType is retained for the first encounter.
    Returns None when the Workload field is absent.
    """
    workload = event.get("Workload", "")
    if not workload:
        return None

    return {
        "kind":        "workload",
        "key":         workload,
        "name":        workload,
        "record_type": str(event.get("RecordType", "")),
    }



# CycloneDX 1.6 serializers

def to_cyclonedx_component(entity: dict) -> dict:
    """
    Converts a raw service_principal or client_app dict to a CycloneDX 1.6
    component object (type: application). All source fields are stored as
    namespaced properties under m365:.
    """
    bom_ref = f"{entity['kind']}-{entity['key']}"
    properties: list[dict] = []

    field_map: dict[str, dict[str, str]] = {
        "service_principal": {
            "app_id":        "m365:AppId",
            "owner_org_id":  "m365:AppOwnerOrganizationId",
            "provisioning":  "m365:ServicePrincipalProvisioningType",
            "operation":     "m365:Operation",
            "result_status": "m365:ResultStatus",
            "workload":      "m365:Workload",
        },
        "client_app": {
            "client_app_id": "m365:ClientAppId",
            "api_id":        "m365:APIId",
            "workload":      "m365:Workload",
        },
    }

    for field, cdx_name in field_map.get(entity["kind"], {}).items():
        value = entity.get(field, "")
        if value:
            properties.append({"name": cdx_name, "value": value})

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
    Converts a raw workload dict to a CycloneDX 1.6 service object.
    authenticated is set True because all M365 workloads require OAuth2.
    """
    service_entry: dict = {
        "bom-ref":       f"workload-{entity['name']}",
        "name":          entity["name"],
        "authenticated": True,
    }
    if entity.get("record_type"):
        service_entry["properties"] = [{"name": "m365:RecordType", "value": entity["record_type"]}]
    return service_entry


def build_dependency_graph(
    raw_components: list[dict],
    raw_services: list[dict],
) -> list[dict]:
    """
    Builds the CycloneDX dependencies section.
    The root tenant node depends on every workload.
    Each component depends on the workload it was observed in.
    """
    workload_refs = {entity["name"]: f"workload-{entity['name']}" for entity in raw_services}

    dependencies: list[dict] = [
        {
            "ref":       "root-m365-tenant",
            "dependsOn": list(workload_refs.values()),
        }
    ]

    for entity in raw_components:
        workload_ref = workload_refs.get(entity.get("workload", ""))
        if workload_ref:
            dependencies.append({
                "ref":       f"{entity['kind']}-{entity['key']}",
                "dependsOn": [workload_ref],
            })

    return dependencies


def build_cyclonedx_bom(
    raw_components: list[dict],
    raw_services: list[dict],
    org_id: str,
    source_files: str,
) -> dict:
    """
    Assembles the complete CycloneDX 1.6 BOM document from extracted data.
    Includes metadata (tool provenance, root component, org ID), components,
    services, and a full dependency graph.
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
                        "name":    "m365-bom-generator",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type":    "application",
                "bom-ref": "root-m365-tenant",
                "name":    "Microsoft 365 Tenant",
                "properties": [
                    {"name": "m365:OrganizationId", "value": org_id},
                    {"name": "m365:SourceFiles",    "value": source_files},
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
    service_principal_dedup: DeduplicatingSet,
    client_app_dedup: DeduplicatingSet,
    workload_dedup: DeduplicatingSet,
) -> tuple[list[dict], list[dict], str]:
    """
    Streams one log file and appends newly seen components and workloads.
    The three dedup sets are shared across files so cross-file duplicates are
    caught. Returns (raw_components, raw_services, first_seen_org_id).
    """
    raw_components: list[dict] = []
    raw_services: list[dict] = []
    org_id = ""

    for event in stream_events(log_file):
        if not org_id:
            org_id = event.get("OrganizationId", "")

        service_principal_entity = extract_service_principal(event)
        if service_principal_entity and service_principal_dedup.add_if_new(service_principal_entity["key"]):
            raw_components.append(service_principal_entity)

        client_app_entity = extract_client_app(event)
        if client_app_entity and client_app_dedup.add_if_new(client_app_entity["key"]):
            raw_components.append(client_app_entity)

        workload_entity = extract_workload(event)
        if workload_entity and workload_dedup.add_if_new(workload_entity["key"]):
            raw_services.append(workload_entity)

    return raw_components, raw_services, org_id



# Entry point

def main(target_file: Path | None = None) -> None:
    """
    Processes log files and writes a CycloneDX 1.6 BOM to report/.
    When target_file is given, only that file is processed — used when called
    directly from fetch_m365_logs.py to scope the BOM to the freshly fetched log.
    When called standalone (no argument), all JSON files in logs/ are processed.
    """
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    log_files = [target_file] if target_file else sorted(LOGS_DIR.glob("*.json"))
    if not log_files:
        print(f"No JSON files found in {LOGS_DIR}")
        return

    service_principal_dedup = DeduplicatingSet()
    client_app_dedup = DeduplicatingSet()
    workload_dedup = DeduplicatingSet()

    all_components: list[dict] = []
    all_services: list[dict] = []
    org_id = ""

    for log_file in log_files:
        print(f"Processing {log_file.name} ...")
        components, services, first_org_id = process_log_file(
            log_file, service_principal_dedup, client_app_dedup, workload_dedup
        )
        all_components.extend(components)
        all_services.extend(services)
        if not org_id:
            org_id = first_org_id
        print(f"  {len(components)} new components, {len(services)} new workloads")

    source_files = ", ".join(file.name for file in log_files)
    bom = build_cyclonedx_bom(all_components, all_services, org_id, source_files)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORT_DIR / f"bom_{timestamp}.json"
    output_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    print(f"\nBOM report saved to: {output_path}")
    print(f"Total: {len(all_components)} components, {len(all_services)} services")


if __name__ == "__main__":
    main()
