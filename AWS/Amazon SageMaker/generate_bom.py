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

RESOURCE_PARAM_KEYS = {
    "trainingJobName":      "TrainingJob",
    "modelName":            "Model",
    "endpointName":         "Endpoint",
    "endpointConfigName":   "EndpointConfig",
    "pipelineName":         "Pipeline",
    "notebookInstanceName": "NotebookInstance",
    "featureGroupName":     "FeatureGroup",
    "domainId":             "Domain",
}


class BloomFilter:

    def __init__(self, capacity: int, fpr: float):
        m = math.ceil(-(capacity * math.log(fpr)) / (math.log(2) ** 2))
        k = max(1, round((m / capacity) * math.log(2)))
        self._m    = m
        self._k    = k
        self._bits = bitarray(m)
        self._bits.setall(0)

    def _positions(self, key: str) -> list[int]:
        h1 = mmh3.hash(key, seed=0, signed=False)
        h2 = mmh3.hash(key, seed=1, signed=False)
        return [(h1 + i * h2) % self._m for i in range(self._k)]

    def add(self, key: str) -> None:
        for p in self._positions(key):
            self._bits[p] = 1

    def might_contain(self, key: str) -> bool:
        return all(self._bits[p] for p in self._positions(key))


class DeduplicatingSet:

    def __init__(self, capacity: int = BLOOM_CAPACITY, fpr: float = BLOOM_FPR):
        self._bloom = BloomFilter(capacity, fpr)
        self._seen: set[str] = set()

    def add_if_new(self, key: str) -> bool:
        if self._bloom.might_contain(key) and key in self._seen:
            return False
        self._bloom.add(key)
        self._seen.add(key)
        return True

    def __len__(self) -> int:
        return len(self._seen)


def stream_events(log_file: Path):
    with log_file.open("rb") as fh:
        yield from ijson.items(fh, "item")


def extract_resource_inventory(event: dict) -> dict | None:
    if event.get("EventSource") != "sagemaker-local-enumeration":
        return None
    params        = event.get("requestParameters") or {}
    resource_type = params.get("resourceType", "")
    resource_name = params.get("resourceName", "")
    if not resource_name:
        return None
    inv = event.get("inventory") or {}
    return {
        "resource_key":         f"{resource_type}:{resource_name}",
        "resource_type":        resource_type,
        "resource_name":        resource_name,
        "arn":                  inv.get("arn", ""),
        "status":               inv.get("status", ""),
        "creation_time":        inv.get("creation_time", ""),
        "instance_type":        inv.get("instance_type", ""),
        "algorithm":            inv.get("algorithm", ""),
        "containers":           inv.get("containers", []),
        "endpoint_config_name": inv.get("endpoint_config_name", ""),
        "access_denied":        inv.get("access_denied", False),
        "not_found":            inv.get("not_found", False),
    }


def extract_sagemaker_resource(event: dict) -> dict | None:
    if event.get("EventSource") == "sagemaker-local-enumeration":
        return None
    params = event.get("requestParameters") or {}
    if not isinstance(params, dict):
        return None

    resource_type = ""
    resource_name = ""
    for param_key, rtype in RESOURCE_PARAM_KEYS.items():
        name = params.get(param_key)
        if name:
            resource_type = rtype
            resource_name = name
            break

    if not resource_name:
        for res in (event.get("Resources") or []):
            if isinstance(res, dict) and "SageMaker" in res.get("type", ""):
                arn           = res.get("ARN", "")
                resource_name = arn.split("/")[-1]
                rtype         = res.get("type", "")
                resource_type = rtype.split("::")[-1] if "::" in rtype else rtype
                break

    if not resource_name:
        return None

    key = f"{resource_type}:{resource_name}"
    return {
        "kind":          "sagemaker_resource",
        "key":           key,
        "name":          resource_name,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "region":        event.get("awsRegion", ""),
        "event_name":    event.get("EventName", ""),
        "event_source":  event.get("EventSource", ""),
    }


def extract_iam_principal(event: dict) -> dict | None:
    identity = event.get("userIdentity") or {}
    if not isinstance(identity, dict):
        return None

    identity_type = identity.get("type", "")
    account_id    = identity.get("accountId", "")
    session_arn   = identity.get("arn", "")

    if identity_type == "IAMUser":
        key  = session_arn
        name = identity.get("userName", "") or session_arn
    elif identity_type == "AssumedRole":
        issuer   = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
        role_arn = issuer.get("arn", session_arn)
        key      = role_arn
        name     = issuer.get("userName", "") or role_arn.split("/")[-1]
    elif identity_type == "Root":
        key  = f"arn:aws:iam::{account_id}:root"
        name = f"Root ({account_id})"
    else:
        key  = session_arn or identity.get("principalId", "")
        name = identity.get("userName", "") or key

    if not key:
        return None

    return {
        "kind":          "iam_principal",
        "key":           key,
        "name":          name,
        "arn":           session_arn,
        "identity_type": identity_type,
        "account_id":    account_id,
        "event_source":  event.get("EventSource", ""),
    }


def _make_bom_ref(kind: str, key: str) -> str:
    safe = key.replace(":", "-").replace("/", "-").replace(".", "-")
    return f"{kind}-{safe}"


def to_cyclonedx_service(raw: dict, inventory: dict | None = None) -> dict:
    svc: dict = {
        "bom-ref":       _make_bom_ref("sagemaker_resource", raw["key"]),
        "name":          raw["name"],
        "authenticated": True,
    }
    props = [
        {"name": "aws:SageMakerResourceType", "value": raw.get("resource_type", "")},
        {"name": "aws:SageMakerResourceName", "value": raw.get("resource_name", "")},
        {"name": "aws:Region",                "value": raw.get("region", "")},
        {"name": "aws:EventSource",           "value": raw.get("event_source", "")},
    ]
    if inventory:
        if inventory.get("access_denied"):
            props.append({"name": "aws:InventoryStatus", "value": "AccessDenied"})
        elif inventory.get("not_found"):
            props.append({"name": "aws:InventoryStatus", "value": "NotFound"})
        else:
            if inventory.get("arn"):
                props.append({"name": "aws:SageMakerResourceArn", "value": inventory["arn"]})
            if inventory.get("status"):
                props.append({"name": "aws:ResourceStatus", "value": inventory["status"]})
            if inventory.get("creation_time"):
                props.append({"name": "aws:CreationTime", "value": inventory["creation_time"]})
            if inventory.get("instance_type"):
                props.append({"name": "aws:InstanceType", "value": inventory["instance_type"]})
            if inventory.get("algorithm"):
                props.append({"name": "aws:Algorithm", "value": inventory["algorithm"]})
            for i, image in enumerate(inventory.get("containers", [])):
                if image:
                    props.append({"name": f"aws:Container:{i}", "value": image})
            if inventory.get("endpoint_config_name"):
                props.append({"name": "aws:EndpointConfigName", "value": inventory["endpoint_config_name"]})

    svc["properties"] = [p for p in props if p.get("value")]
    return svc


def to_cyclonedx_component(raw: dict) -> dict:
    props = [
        {"name": "aws:IAMPrincipalARN", "value": raw.get("arn", "")},
        {"name": "aws:IdentityType",    "value": raw.get("identity_type", "")},
        {"name": "aws:AccountId",       "value": raw.get("account_id", "")},
        {"name": "aws:EventSource",     "value": raw.get("event_source", "")},
    ]
    return {
        "type":       "application",
        "bom-ref":    _make_bom_ref(raw["kind"], raw["key"]),
        "name":       raw["name"],
        "properties": [p for p in props if p.get("value")],
    }


def build_dependency_graph(
    raw_components:      list[dict],
    raw_services:        list[dict],
    principal_resources: dict[str, set[str]],
) -> list[dict]:
    resource_ref_map = {r["key"]: _make_bom_ref("sagemaker_resource", r["key"]) for r in raw_services}

    deps: list[dict] = [
        {
            "ref":       "root-aws-account",
            "dependsOn": list(resource_ref_map.values()),
        }
    ]

    for raw in raw_components:
        accessed   = principal_resources.get(raw["key"], set())
        depends_on = [resource_ref_map[r] for r in accessed if r in resource_ref_map]
        if not depends_on:
            depends_on = ["root-aws-account"]
        deps.append({
            "ref":       _make_bom_ref(raw["kind"], raw["key"]),
            "dependsOn": depends_on,
        })

    return deps


def build_cyclonedx_bom(
    raw_components:      list[dict],
    raw_services:        list[dict],
    account_id:          str,
    source_files:        str,
    principal_resources: dict[str, set[str]],
    resource_inventory:  dict[str, dict],
) -> dict:
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
                        "name":    "aws-sagemaker-bom-generator",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type":    "application",
                "bom-ref": "root-aws-account",
                "name":    "AWS Account",
                "properties": [
                    {"name": "aws:AccountId",   "value": account_id},
                    {"name": "aws:SourceFiles", "value": source_files},
                ],
            },
        },
        "components":   [to_cyclonedx_component(r) for r in raw_components],
        "services":     [to_cyclonedx_service(r, resource_inventory.get(r["key"])) for r in raw_services],
        "dependencies": build_dependency_graph(raw_components, raw_services, principal_resources),
    }


def process_log_file(
    log_file:            Path,
    resource_dedup:      DeduplicatingSet,
    principal_dedup:     DeduplicatingSet,
    principal_resources: dict[str, set[str]],
    resource_inventory:  dict[str, dict],
) -> tuple[list[dict], list[dict], str]:
    raw_components: list[dict] = []
    raw_services:   list[dict] = []
    account_id = ""

    for event in stream_events(log_file):
        inv = extract_resource_inventory(event)
        if inv is not None:
            resource_inventory[inv["resource_key"]] = inv
            continue

        if not account_id:
            account_id = (event.get("userIdentity") or {}).get("accountId", "")

        resource = extract_sagemaker_resource(event)
        if resource and resource_dedup.add_if_new(resource["key"]):
            raw_services.append(resource)

        principal = extract_iam_principal(event)
        if principal:
            if resource:
                principal_resources.setdefault(principal["key"], set()).add(resource["key"])
            if principal_dedup.add_if_new(principal["key"]):
                raw_components.append(principal)

    return raw_components, raw_services, account_id


def main(target_file: Path | None = None) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    log_files = [target_file] if target_file else sorted(LOGS_DIR.glob("*.json"))
    if not log_files:
        print(f"No JSON files found in {LOGS_DIR}")
        return

    resource_dedup      = DeduplicatingSet()
    principal_dedup     = DeduplicatingSet()
    principal_resources: dict[str, set[str]] = {}
    resource_inventory:  dict[str, dict]     = {}

    all_components: list[dict] = []
    all_services:   list[dict] = []
    account_id = ""

    for log_file in log_files:
        print(f"Processing {log_file.name} ...")
        comps, svcs, aid = process_log_file(
            log_file, resource_dedup, principal_dedup, principal_resources, resource_inventory
        )
        all_components.extend(comps)
        all_services.extend(svcs)
        if not account_id and aid:
            account_id = aid
        print(f"  {len(comps)} new principals, {len(svcs)} new resources")

    source_files = ", ".join(f.name for f in log_files)
    bom = build_cyclonedx_bom(
        all_components, all_services, account_id, source_files,
        principal_resources, resource_inventory
    )

    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORT_DIR / f"bom_{timestamp}.json"
    output_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    print(f"\nBOM report saved to: {output_path}")
    print(f"Total: {len(all_components)} principals, {len(all_services)} resources")


if __name__ == "__main__":
    main()
