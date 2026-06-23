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


# Bloom filter and deduplication layer

class BloomFilter:
    """Probabilistic bit-array with MurmurHash3 double-hashing. No false negatives; callers handle false positives."""

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
    """Bloom filter plus exact backing set — fast miss path with zero-duplicate guarantee."""

    def __init__(self, capacity: int = BLOOM_CAPACITY, fpr: float = BLOOM_FPR):
        self._bloom = BloomFilter(capacity, fpr)
        self._seen: set[str] = set()

    def add_if_new(self, key: str) -> bool:
        """Returns True and records key if it has never been seen; False otherwise."""
        if self._bloom.might_contain(key) and key in self._seen:
            return False
        self._bloom.add(key)
        self._seen.add(key)
        return True

    def __len__(self) -> int:
        return len(self._seen)


# Log streaming

def stream_events(log_file: Path):
    """Yields each top-level JSON object from a large array file using ijson."""
    with log_file.open("rb") as fh:
        yield from ijson.items(fh, "item")


# Entity extractors — each returns a typed dict or None

def extract_bucket_inventory(event: dict) -> dict | None:
    """Returns the inventory payload for synthetic BucketContentsInventory events; None for real CloudTrail events."""
    if event.get("EventSource") != "s3-local-enumeration":
        return None
    bucket_name = (event.get("requestParameters") or {}).get("bucketName", "")
    if not bucket_name:
        return None
    inventory = event.get("inventory") or {}
    return {
        "bucket_name":       bucket_name,
        "prefixes":          inventory.get("prefixes", []),
        "top_level_objects": inventory.get("top_level_objects", []),
        "total_listed":      inventory.get("total_listed", 0),
        "is_truncated":      inventory.get("is_truncated", False),
        "access_denied":     inventory.get("access_denied", False),
    }


def extract_s3_bucket(event: dict) -> dict | None:
    """Extracts bucket name from requestParameters (three casing variants) or the Resources array; None for inventory events."""
    if event.get("EventSource") == "s3-local-enumeration":
        return None
    params = event.get("requestParameters") or {}
    if not isinstance(params, dict):
        return None

    bucket_name = (
        params.get("bucketName")
        or params.get("Bucket")
        or params.get("bucket")
    )

    if not bucket_name:
        for res in (event.get("Resources") or []):
            if isinstance(res, dict) and res.get("type") == "AWS::S3::Bucket":
                bucket_name = res.get("ARN", "").split(":")[-1]
                break

    if not bucket_name:
        return None

    return {
        "kind":         "s3_bucket",
        "key":          bucket_name,
        "name":         bucket_name,
        "bucket_name":  bucket_name,
        "region":       event.get("awsRegion", ""),
        "event_name":   event.get("EventName", ""),
        "event_source": event.get("EventSource", ""),
    }


def extract_iam_principal(event: dict) -> dict | None:
    """Extracts the caller from userIdentity. AssumedRole collapses to role ARN; returns None when no key is resolvable."""
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


# CycloneDX 1.6 serialisers

def _make_bom_ref(kind: str, key: str) -> str:
    """Sanitises key characters that may confuse BOM parsers."""
    safe = key.replace(":", "-").replace("/", "-").replace(".", "-")
    return f"{kind}-{safe}"


def to_cyclonedx_service(raw: dict, inventory: dict | None = None) -> dict:
    """Converts an S3 bucket to a CycloneDX 1.6 service entry; appends inventory properties when available."""
    svc: dict = {
        "bom-ref":       _make_bom_ref("s3_bucket", raw["key"]),
        "name":          raw["name"],
        "authenticated": True,
    }
    props = [
        {"name": "aws:S3BucketName", "value": raw["bucket_name"]},
        {"name": "aws:Region",       "value": raw.get("region", "")},
        {"name": "aws:EventSource",  "value": raw.get("event_source", "")},
    ]
    if inventory:
        if inventory.get("access_denied"):
            props.append({"name": "aws:InventoryStatus", "value": "AccessDenied"})
        else:
            props.append({"name": "aws:ObjectCount", "value": str(inventory.get("total_listed", 0))})
            if inventory.get("is_truncated"):
                props.append({"name": "aws:InventoryTruncated", "value": "true"})
            for i, prefix in enumerate(inventory.get("prefixes", [])):
                props.append({"name": f"aws:Prefix:{i}", "value": prefix})
            for i, obj in enumerate(inventory.get("top_level_objects", [])):
                props.append({"name": f"aws:RootObject:{i}",
                              "value": f"{obj['key']} ({obj['size_bytes']} bytes, {obj['storage_class']})"})

    svc["properties"] = [p for p in props if p.get("value")]
    return svc


def to_cyclonedx_component(raw: dict) -> dict:
    """Converts an IAM principal to a CycloneDX 1.6 component with aws:-namespaced properties."""
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
    raw_components:    list[dict],
    raw_services:      list[dict],
    principal_buckets: dict[str, set[str]],
) -> list[dict]:
    """Root account depends on all buckets; each principal depends on its accessed buckets (or root if none)."""
    bucket_ref_map = {r["key"]: _make_bom_ref("s3_bucket", r["key"]) for r in raw_services}

    deps: list[dict] = [
        {
            "ref":       "root-aws-account",
            "dependsOn": list(bucket_ref_map.values()),
        }
    ]

    for raw in raw_components:
        accessed = principal_buckets.get(raw["key"], set())
        depends_on = [bucket_ref_map[b] for b in accessed if b in bucket_ref_map]
        if not depends_on:
            depends_on = ["root-aws-account"]
        deps.append({
            "ref":       _make_bom_ref(raw["kind"], raw["key"]),
            "dependsOn": depends_on,
        })

    return deps


def build_cyclonedx_bom(
    raw_components:    list[dict],
    raw_services:      list[dict],
    account_id:        str,
    source_files:      str,
    principal_buckets: dict[str, set[str]],
    bucket_inventory:  dict[str, dict],
) -> dict:
    """Assembles the CycloneDX 1.6 BOM: root=AWS account, services=S3 buckets (with inventory), components=IAM principals."""
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
                        "name":    "aws-s3-bom-generator",
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
        "services":     [to_cyclonedx_service(r, bucket_inventory.get(r["key"])) for r in raw_services],
        "dependencies": build_dependency_graph(raw_components, raw_services, principal_buckets),
    }


# Per-file processor

def process_log_file(
    log_file:          Path,
    bucket_dedup:      DeduplicatingSet,
    principal_dedup:   DeduplicatingSet,
    principal_buckets: dict[str, set[str]],
    bucket_inventory:  dict[str, dict],
) -> tuple[list[dict], list[dict], str]:
    """Streams one log file; returns (new_components, new_services, account_id). principal_buckets updated even for deduplicated principals."""
    raw_components: list[dict] = []
    raw_services:   list[dict] = []
    account_id = ""

    for event in stream_events(log_file):
        inv = extract_bucket_inventory(event)
        if inv:
            bucket_inventory[inv["bucket_name"]] = inv
            continue

        if not account_id:
            account_id = (event.get("userIdentity") or {}).get("accountId", "")

        bucket = extract_s3_bucket(event)
        if bucket and bucket_dedup.add_if_new(bucket["key"]):
            raw_services.append(bucket)

        principal = extract_iam_principal(event)
        if principal:
            if bucket:
                principal_buckets.setdefault(principal["key"], set()).add(bucket["key"])
            if principal_dedup.add_if_new(principal["key"]):
                raw_components.append(principal)

    return raw_components, raw_services, account_id


# Entry point

def main(target_file: Path | None = None) -> None:
    """Processes target_file or all logs/*.json files and writes a CycloneDX 1.6 BOM to report/."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    log_files = [target_file] if target_file else sorted(LOGS_DIR.glob("*.json"))
    if not log_files:
        print(f"No JSON files found in {LOGS_DIR}")
        return

    bucket_dedup      = DeduplicatingSet()
    principal_dedup   = DeduplicatingSet()
    principal_buckets: dict[str, set[str]] = {}
    bucket_inventory:  dict[str, dict]     = {}

    all_components: list[dict] = []
    all_services:   list[dict] = []
    account_id = ""

    for log_file in log_files:
        print(f"Processing {log_file.name} ...")
        comps, svcs, aid = process_log_file(
            log_file, bucket_dedup, principal_dedup, principal_buckets, bucket_inventory
        )
        all_components.extend(comps)
        all_services.extend(svcs)
        if not account_id and aid:
            account_id = aid
        print(f"  {len(comps)} new principals, {len(svcs)} new buckets")

    source_files = ", ".join(f.name for f in log_files)
    bom = build_cyclonedx_bom(
        all_components, all_services, account_id, source_files,
        principal_buckets, bucket_inventory
    )

    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = REPORT_DIR / f"bom_{timestamp}.json"
    output_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    print(f"\nBOM report saved to: {output_path}")
    print(f"Total: {len(all_components)} principals, {len(all_services)} buckets")


if __name__ == "__main__":
    main()
