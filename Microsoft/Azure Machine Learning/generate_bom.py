import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

import ijson
import mmh3
from bitarray import bitarray

SCRIPT_DIR = Path(__file__).parent
LOGS_DIR   = SCRIPT_DIR / "logs"
REPORT_DIR = SCRIPT_DIR / "report"

BLOOM_CAPACITY = 500_000
BLOOM_FPR      = 0.0001


# Bloom filter + deduplication layer
class BloomFilter:
    """MurmurHash3 double-hashing Bloom filter. No false negatives; callers must resolve false positives."""

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
    """Bloom filter + exact backing set combination that guarantees zero duplicate insertions."""

    def __init__(self, capacity: int = BLOOM_CAPACITY, fpr: float = BLOOM_FPR):
        self.bloom_filter = BloomFilter(capacity, fpr)
        self.seen_keys: set[str] = set()

    def add_if_new(self, key: str) -> bool:
        """Returns True and records key if it has never been seen; False otherwise."""
        if self.bloom_filter.might_contain(key) and key in self.seen_keys:
            return False
        self.bloom_filter.add(key)
        self.seen_keys.add(key)
        return True

    def __len__(self) -> int:
        return len(self.seen_keys)


def stream_workspaces(log_file: Path):
    """Streams each workspace object from the log file's top-level workspaces array."""
    with log_file.open("rb") as file_handle:
        yield from ijson.items(file_handle, "workspaces.item")


# Entity extractors

def extract_workspace(ws: dict) -> dict | None:
    """Returns a workspace component dict keyed on the lowercase ARM resource ID, or None if absent."""
    resource_id = ws.get("workspace_resource_id", "")
    if not resource_id:
        return None
    return {
        "kind":            "aml_workspace",
        "key":             resource_id.lower(),
        "name":            ws.get("workspace_name") or resource_id.split("/")[-1],
        "resource_id":     resource_id.lower(),
        "subscription_id": ws.get("subscription_id", ""),
        "resource_group":  ws.get("resource_group", ""),
        "location":        ws.get("location", ""),
        "workload":        "Microsoft.MachineLearningServices",
    }


def extract_models(ws: dict) -> list[dict]:
    """Returns registered ML model dicts from assets.models; empty list if the SDK was unavailable."""
    models = ws.get("assets", {}).get("models", [])
    if not isinstance(models, list):
        return []
    ws_id = ws.get("workspace_resource_id", "").lower()
    results = []
    for model_record in models:
        if not isinstance(model_record, dict):
            continue
        name = model_record.get("name", "")
        version = str(model_record.get("version", "")) if model_record.get("version") is not None else ""
        if not name:
            continue
        results.append({
            "kind":        "ml_model",
            "key":         f"{ws_id}/models/{name}/{version}",
            "name":        name,
            "version":     version,
            "model_type":  str(model_record.get("type", "")),
            "description": str(model_record.get("description", "")),
            "resource_id": ws_id,
            "workload":    "Microsoft.MachineLearningServices",
        })
    return results


def extract_compute(ws: dict) -> list[dict]:
    """Returns compute cluster and instance dicts from assets.compute."""
    compute_list = ws.get("assets", {}).get("compute", [])
    if not isinstance(compute_list, list):
        return []
    ws_id = ws.get("workspace_resource_id", "").lower()
    results = []
    for compute_record in compute_list:
        if not isinstance(compute_record, dict):
            continue
        name = compute_record.get("name", "")
        if not name:
            continue
        results.append({
            "kind":               "compute",
            "key":                f"{ws_id}/compute/{name}",
            "name":               name,
            "compute_type":       str(compute_record.get("type", "")),
            "provisioning_state": str(compute_record.get("provisioning_state", "")),
            "location":           str(compute_record.get("location", "")),
            "resource_id":        ws_id,
        })
    return results


def extract_data_assets(ws: dict) -> list[dict]:
    """Returns versioned data asset dicts from assets.data_assets."""
    data_list = ws.get("assets", {}).get("data_assets", [])
    if not isinstance(data_list, list):
        return []
    ws_id = ws.get("workspace_resource_id", "").lower()
    results = []
    for data_record in data_list:
        if not isinstance(data_record, dict):
            continue
        name = data_record.get("name", "")
        version = str(data_record.get("version", "")) if data_record.get("version") is not None else ""
        if not name:
            continue
        results.append({
            "kind":        "data_asset",
            "key":         f"{ws_id}/data/{name}/{version}",
            "name":        name,
            "version":     version,
            "data_type":   str(data_record.get("type", "")),
            "path":        str(data_record.get("path", "")),
            "resource_id": ws_id,
        })
    return results


def extract_online_endpoints(ws: dict) -> list[dict]:
    """Returns deployed online inference endpoint dicts from assets.online_endpoints."""
    endpoint_list = ws.get("assets", {}).get("online_endpoints", [])
    if not isinstance(endpoint_list, list):
        return []
    ws_id = ws.get("workspace_resource_id", "").lower()
    results = []
    for endpoint_record in endpoint_list:
        if not isinstance(endpoint_record, dict):
            continue
        name = endpoint_record.get("name", "")
        if not name:
            continue
        results.append({
            "kind":               "online_endpoint",
            "key":                f"{ws_id}/endpoints/{name}",
            "name":               name,
            "scoring_uri":        str(endpoint_record.get("scoring_uri", "")),
            "provisioning_state": str(endpoint_record.get("provisioning_state", "")),
            "auth_mode":          str(endpoint_record.get("auth_mode", "")),
            "resource_id":        ws_id,
        })
    return results


def extract_client_apps(ws: dict) -> list[dict]:
    """Extracts OAuth2 client app IDs from JWT claims.appid in activity_logs."""
    results = []
    for event in ws.get("activity_logs", []):
        if not isinstance(event, dict):
            continue
        app_id = event.get("claims", {}).get("appid", "")
        if app_id:
            provider = event.get("resource_provider_name", {})
            results.append({
                "kind":            "client_app",
                "key":             app_id,
                "name":            app_id,
                "app_id":          app_id,
                "subscription_id": event.get("subscription_id", ""),
                "workload":        provider.get("value", "") if isinstance(provider, dict) else "",
            })
    return results


def extract_resource_providers(ws: dict) -> list[dict]:
    """Extracts Azure resource provider names from activity_logs."""
    return [
        {"kind": "resource_provider", "key": provider_name.lower(), "name": provider_name}
        for event in ws.get("activity_logs", [])
        if isinstance(event, dict)
        and isinstance(event.get("resource_provider_name"), dict)
        and (provider_name := event["resource_provider_name"].get("value", ""))
    ]


def extract_log_analytics_workspaces(ws: dict) -> list[dict]:
    """Extracts Log Analytics workspace IDs from aml_log_tables keys."""
    log_tables = ws.get("aml_log_tables", {})
    if not isinstance(log_tables, dict):
        return []
    return [
        {"kind": "log_analytics_workspace", "key": la_ws_id, "name": f"Log Analytics Workspace ({la_ws_id[:8]}...)", "ws_id": la_ws_id}
        for la_ws_id, tables in log_tables.items()
        if isinstance(tables, dict) and la_ws_id not in ("status", "error")
    ]


def capture_tenant_id(ws: dict) -> str:
    """Reads tenant_id from the first valid activity log event in the workspace."""
    for event in ws.get("activity_logs", []):
        if isinstance(event, dict):
            tid = event.get("tenant_id", "")
            if tid:
                return tid
    return ""


# CycloneDX 1.6 serializers

def to_cyclonedx_component(entity: dict) -> dict:
    """Serializes a raw component entity to a CycloneDX 1.6 component object."""
    bom_ref = f"{entity['kind']}-{entity['key']}"

    type_map = {
        "aml_workspace": "application",
        "ml_model":      "library",
        "compute":       "machine",
        "data_asset":    "file",
        "client_app":    "application",
    }

    field_map: dict[str, dict[str, str]] = {
        "aml_workspace": {
            "resource_id":     "azure:WorkspaceResourceId",
            "subscription_id": "azure:SubscriptionId",
            "resource_group":  "azure:ResourceGroup",
            "location":        "azure:Location",
        },
        "ml_model": {
            "model_type":  "aml:ModelType",
            "description": "aml:Description",
            "resource_id": "azure:WorkspaceResourceId",
        },
        "compute": {
            "compute_type":       "aml:ComputeType",
            "provisioning_state": "aml:ProvisioningState",
            "location":           "azure:Location",
            "resource_id":        "azure:WorkspaceResourceId",
        },
        "data_asset": {
            "data_type":   "aml:DataType",
            "path":        "aml:Path",
            "resource_id": "azure:WorkspaceResourceId",
        },
        "client_app": {
            "app_id":          "azure:AppId",
            "subscription_id": "azure:SubscriptionId",
            "workload":        "azure:ResourceProvider",
        },
    }

    properties = [
        {"name": cdx_name, "value": value}
        for field, cdx_name in field_map.get(entity["kind"], {}).items()
        if (value := entity.get(field, ""))
    ]

    component: dict = {
        "type":    type_map.get(entity["kind"], "application"),
        "bom-ref": bom_ref,
        "name":    entity["name"],
    }
    if entity.get("version"):
        component["version"] = entity["version"]
    if properties:
        component["properties"] = properties
    return component


def to_cyclonedx_service(entity: dict) -> dict:
    """Serializes a raw service entity to a CycloneDX 1.6 service object."""
    bom_ref = f"{entity['kind']}-{entity['key']}"
    service_entry: dict = {
        "bom-ref":       bom_ref,
        "name":          entity["name"],
        "authenticated": True,
    }

    properties = []
    if entity["kind"] == "log_analytics_workspace" and entity.get("ws_id"):
        properties.append({"name": "azure:WorkspaceId", "value": entity["ws_id"]})
    elif entity["kind"] == "online_endpoint":
        if entity.get("scoring_uri"):
            properties.append({"name": "aml:ScoringUri", "value": entity["scoring_uri"]})
        if entity.get("auth_mode"):
            properties.append({"name": "aml:AuthMode", "value": entity["auth_mode"]})
        if entity.get("provisioning_state"):
            properties.append({"name": "aml:ProvisioningState", "value": entity["provisioning_state"]})

    if properties:
        service_entry["properties"] = properties
    return service_entry


def build_dependency_graph(raw_components: list[dict], raw_services: list[dict]) -> list[dict]:
    """Builds the CycloneDX dependency graph linking workspaces, assets, providers, and endpoints."""
    service_refs = {entity["key"]: f"{entity['kind']}-{entity['key']}" for entity in raw_services}
    workspace_refs = {
        entity["key"]: f"{entity['kind']}-{entity['key']}"
        for entity in raw_components
        if entity["kind"] == "aml_workspace"
    }

    dependencies: list[dict] = [
        {
            "ref":       "root-azure-tenant",
            "dependsOn": list(service_refs.values()),
        }
    ]

    workspace_provider_key = "microsoft.machinelearningservices"

    for entity in raw_components:
        kind = entity["kind"]

        if kind == "aml_workspace":
            ref = service_refs.get(workspace_provider_key)
            if ref:
                dependencies.append({"ref": f"{kind}-{entity['key']}", "dependsOn": [ref]})

        elif kind == "client_app":
            ref = service_refs.get(entity.get("workload", "").lower())
            if ref:
                dependencies.append({"ref": f"{kind}-{entity['key']}", "dependsOn": [ref]})

        elif kind in ("ml_model", "compute", "data_asset"):
            parent_ws = entity.get("resource_id", "")
            ref = workspace_refs.get(parent_ws)
            if ref:
                dependencies.append({"ref": f"{kind}-{entity['key']}", "dependsOn": [ref]})

    for entity in raw_services:
        if entity["kind"] == "online_endpoint":
            parent_ws = entity.get("resource_id", "")
            ref = workspace_refs.get(parent_ws)
            if ref:
                dependencies.append({"ref": f"{entity['kind']}-{entity['key']}", "dependsOn": [ref]})

    return dependencies


def build_cyclonedx_bom(
    raw_components: list[dict],
    raw_services: list[dict],
    tenant_id: str,
    source_files: str,
) -> dict:
    """Assembles and returns a complete CycloneDX 1.6 BOM document."""
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
                        "name":    "azure-aml-bom-generator",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type":    "platform",
                "bom-ref": "root-azure-tenant",
                "name":    "Azure Tenant",
                "properties": [
                    {"name": "azure:TenantId",    "value": tenant_id},
                    {"name": "azure:SourceFiles", "value": source_files},
                ],
            },
        },
        "components":   [to_cyclonedx_component(entity) for entity in raw_components],
        "services":     [to_cyclonedx_service(entity) for entity in raw_services],
        "dependencies": build_dependency_graph(raw_components, raw_services),
    }


def process_log_file(
    log_file: Path,
    workspace_dedup: DeduplicatingSet,
    model_dedup: DeduplicatingSet,
    compute_dedup: DeduplicatingSet,
    data_dedup: DeduplicatingSet,
    client_dedup: DeduplicatingSet,
    provider_dedup: DeduplicatingSet,
    la_workspace_dedup: DeduplicatingSet,
    endpoint_dedup: DeduplicatingSet,
) -> tuple[list[dict], list[dict], str]:
    """Streams one log file and returns new deduplicated (components, services, tenant_id)."""
    raw_components: list[dict] = []
    raw_services: list[dict] = []
    tenant_id = ""

    for workspace_record in stream_workspaces(log_file):
        if not tenant_id:
            tenant_id = capture_tenant_id(workspace_record)

        workspace_entity = extract_workspace(workspace_record)
        if workspace_entity and workspace_dedup.add_if_new(workspace_entity["key"]):
            raw_components.append(workspace_entity)

        raw_components.extend(
            entity for entity in extract_models(workspace_record)
            if model_dedup.add_if_new(entity["key"])
        )
        raw_components.extend(
            entity for entity in extract_compute(workspace_record)
            if compute_dedup.add_if_new(entity["key"])
        )
        raw_components.extend(
            entity for entity in extract_data_assets(workspace_record)
            if data_dedup.add_if_new(entity["key"])
        )
        raw_components.extend(
            entity for entity in extract_client_apps(workspace_record)
            if client_dedup.add_if_new(entity["key"])
        )
        raw_services.extend(
            entity for entity in extract_resource_providers(workspace_record)
            if provider_dedup.add_if_new(entity["key"])
        )
        raw_services.extend(
            entity for entity in extract_log_analytics_workspaces(workspace_record)
            if la_workspace_dedup.add_if_new(entity["key"])
        )
        raw_services.extend(
            entity for entity in extract_online_endpoints(workspace_record)
            if endpoint_dedup.add_if_new(entity["key"])
        )

    return raw_components, raw_services, tenant_id


def main(target_file: Path | None = None) -> None:
    """Processes log files and writes a CycloneDX 1.6 BOM to report/."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    log_files = [target_file] if target_file else sorted(LOGS_DIR.glob("*.json"))
    if not log_files:
        print(f"No JSON files found in {LOGS_DIR}")
        return

    workspace_dedup    = DeduplicatingSet()
    model_dedup        = DeduplicatingSet()
    compute_dedup      = DeduplicatingSet()
    data_dedup         = DeduplicatingSet()
    client_dedup       = DeduplicatingSet()
    provider_dedup     = DeduplicatingSet()
    la_workspace_dedup = DeduplicatingSet()
    endpoint_dedup     = DeduplicatingSet()

    all_components: list[dict] = []
    all_services:   list[dict] = []
    tenant_id = ""

    for log_file in log_files:
        print(f"Processing {log_file.name} ...")
        components, services, first_tenant_id = process_log_file(
            log_file,
            workspace_dedup, model_dedup, compute_dedup, data_dedup,
            client_dedup, provider_dedup, la_workspace_dedup, endpoint_dedup,
        )
        all_components.extend(components)
        all_services.extend(services)
        if not tenant_id:
            tenant_id = first_tenant_id
        print(f"  {len(components)} new components, {len(services)} new services")

    source_files = ", ".join(log_file.name for log_file in log_files)
    bom = build_cyclonedx_bom(all_components, all_services, tenant_id, source_files)

    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORT_DIR / f"bom_{timestamp}.json"
    output_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    print(f"\nBOM report saved to: {output_path}")
    print(f"Total: {len(all_components)} components, {len(all_services)} services")


if __name__ == "__main__":
    main()
