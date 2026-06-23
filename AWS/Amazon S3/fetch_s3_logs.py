import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from dotenv import load_dotenv
import generate_bom

load_dotenv(Path(__file__).parent.parent.parent / ".env")

AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
AWS_KEY_ID     = os.getenv("AWS_S3_ACCESS_KEY_ID", "") 
AWS_SECRET_KEY = os.getenv("AWS_S3_SECRET_ACCESS_KEY", "")

LOOKBACK_HOURS       = 24
BUCKET_ENUM_MAX_KEYS = 1000
OUTPUT_DIR = Path(__file__).parent / "logs"

S3_EVENT_SOURCES = [
    "s3.amazonaws.com",         # GetBucketLocation, ListBuckets, CreateBucket, PutBucketPolicy, etc.
    "s3control.amazonaws.com",  # Batch operations, access points, multi-region access points
]


def _s3_client(region: str = "us-east-1"):
    """Returns a boto3 S3 client authenticated with module-level credentials."""
    return boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


def check_s3_availability() -> bool:
    """Calls ListBuckets as a connectivity probe. Auth errors are treated as reachable."""
    try:
        _s3_client().list_buckets()
        print("  S3 is reachable")
        return True
    except Exception as exc:
        msg = str(exc)
        if any(kw in msg.lower() for kw in ("endpoint", "could not connect")):
            print(f"  S3 connectivity issue: {type(exc).__name__}")
            return False
        print(f"  S3 endpoint reachable ({type(exc).__name__}: {msg[:120]})")
        return True


def fetch_events_for_source(source: str, start_time: datetime, end_time: datetime) -> list[dict]:
    """Pages through CloudTrail lookup_events for the given source across the lookback window; handles pagination via NextToken."""
    client = boto3.client(
        "cloudtrail",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    events: list[dict] = []
    kwargs: dict = dict(
        LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": source}],
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50,
    )
    page = 0
    while True:
        resp  = client.lookup_events(**kwargs)
        batch = resp.get("Events", [])
        events.extend(batch)
        page += 1
        print(f"    Page {page}: {len(batch)} events")
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return events


def normalize_event(raw: dict) -> dict:
    """Flattens a CloudTrail boto3 event dict into a JSON-serialisable form."""
    event_time = raw.get("EventTime", datetime.now(timezone.utc))
    out: dict = {
        "EventId":     raw.get("EventId", ""),
        "EventName":   raw.get("EventName", ""),
        "EventTime":   event_time.isoformat() if isinstance(event_time, datetime) else str(event_time),
        "EventSource": raw.get("EventSource", ""),
        "Username":    raw.get("Username", ""),
        "Resources":   raw.get("Resources", []),
    }
    try:
        ct: dict = json.loads(raw.get("CloudTrailEvent", "{}"))
        out["userIdentity"]      = ct.get("userIdentity") or {}
        out["requestParameters"] = ct.get("requestParameters") or {}
        out["responseElements"]  = ct.get("responseElements") or {}
        out["awsRegion"]         = ct.get("awsRegion", "")
        out["sourceIPAddress"]   = ct.get("sourceIPAddress", "")
        out["errorCode"]         = ct.get("errorCode", "")
        out["errorMessage"]      = ct.get("errorMessage", "")
    except (json.JSONDecodeError, TypeError):
        pass
    return out


def get_bucket_region(bucket_name: str) -> str:
    """Returns the AWS region a bucket resides in via GetBucketLocation."""
    try:
        resp = _s3_client().get_bucket_location(Bucket=bucket_name)
        # us-east-1 returns None from GetBucketLocation
        return resp.get("LocationConstraint") or "us-east-1"
    except Exception:
        return ""


def enumerate_bucket_contents(bucket_name: str, region: str) -> dict:
    """Lists top-level prefixes and objects up to BUCKET_ENUM_MAX_KEYS; sets access_denied=True on permission errors."""
    result = {
        "prefixes":          [],
        "top_level_objects": [],
        "total_listed":      0,
        "is_truncated":      False,
        "access_denied":     False,
    }
    try:
        client = _s3_client(region or "us-east-1")
        resp   = client.list_objects_v2(
            Bucket=bucket_name,
            Delimiter="/",
            MaxKeys=BUCKET_ENUM_MAX_KEYS,
        )
        result["prefixes"] = [p["Prefix"] for p in resp.get("CommonPrefixes") or []]
        result["top_level_objects"] = [
            {
                "key":           obj["Key"],
                "size_bytes":    obj.get("Size", 0),
                "storage_class": obj.get("StorageClass", ""),
                "last_modified": obj["LastModified"].isoformat() if isinstance(obj.get("LastModified"), datetime) else str(obj.get("LastModified", "")),
            }
            for obj in resp.get("Contents") or []
        ]
        result["total_listed"] = resp.get("KeyCount", 0)
        result["is_truncated"] = resp.get("IsTruncated", False)
    except Exception as exc:
        msg = str(exc)
        if "AccessDenied" in msg or "NoSuchBucket" in msg or "AllAccessDisabled" in msg:
            result["access_denied"] = True
            print(f"    Cannot enumerate {bucket_name}: {type(exc).__name__}")
        else:
            print(f"    Error enumerating {bucket_name}: {exc}")
    return result


def extract_unique_buckets(events: list[dict]) -> list[str]:
    """Collects every distinct bucket name seen across all normalised events."""
    seen: set[str] = set()
    for event in events:
        params = event.get("requestParameters") or {}
        name = (
            params.get("bucketName")
            or params.get("Bucket")
            or params.get("bucket")
        )
        if name and name not in seen:
            seen.add(name)
    return sorted(seen)


def build_inventory_event(bucket_name: str, region: str, inventory: dict, event_time: datetime) -> dict:
    """Wraps bucket enumeration results as a synthetic CloudTrail-shaped event; s3-local-enumeration source discriminates it from real events."""
    return {
        "EventId":     f"inventory-{bucket_name}",
        "EventName":   "BucketContentsInventory",
        "EventSource": "s3-local-enumeration",
        "EventTime":   event_time.isoformat(),
        "Username":    "",
        "Resources":   [],
        "userIdentity":      {},
        "requestParameters": {"bucketName": bucket_name},
        "responseElements":  {},
        "awsRegion":         region,
        "sourceIPAddress":   "",
        "errorCode":         "AccessDenied" if inventory["access_denied"] else "",
        "errorMessage":      "",
        "inventory":         inventory,
    }


def main() -> None:
    """Fetches CloudTrail S3 events, enumerates bucket contents, writes logs/, then calls generate_bom.main()."""
    if not all([AWS_KEY_ID, AWS_SECRET_KEY]):
        print("Missing required credentials. Set AWS_S3_ACCESS_KEY_ID / AWS_S3_SECRET_ACCESS_KEY "
              "or AWS_BEDROCK_ACCESS_KEY_ID / AWS_BEDROCK_SECRET_ACCESS_KEY in .env")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"s3_logs_{timestamp}.json"

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    print(f"Region : {AWS_REGION}")
    print(f"Window : {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} -> {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    print("Checking S3 availability...")
    check_s3_availability()
    print()

    # stage 1 — cloudtrail events
    all_events: list[dict] = []
    for source in S3_EVENT_SOURCES:
        print(f"Fetching CloudTrail events: {source}")
        try:
            raw_events = fetch_events_for_source(source, start_time, end_time)
            normalised = [normalize_event(e) for e in raw_events]
            all_events.extend(normalised)
            print(f"  {len(normalised)} events from {source}\n")
        except Exception as exc:
            print(f"  Error fetching {source}: {exc}\n")

    # stage 2 — bucket content enumeration
    unique_buckets = extract_unique_buckets(all_events)
    print(f"Enumerating contents of {len(unique_buckets)} unique buckets...")

    for bucket_name in unique_buckets:
        print(f"  -> {bucket_name}")
        region    = get_bucket_region(bucket_name)
        inventory = enumerate_bucket_contents(bucket_name, region)
        if not inventory["access_denied"]:
            print(f"    {len(inventory['prefixes'])} prefixes, "
                  f"{len(inventory['top_level_objects'])} root objects"
                  + (" (truncated)" if inventory["is_truncated"] else ""))
        all_events.append(build_inventory_event(bucket_name, region, inventory, end_time))

    # write log file
    with output_file.open("w", encoding="utf-8") as output_file_handle:
        json.dump(all_events, output_file_handle, indent=2, ensure_ascii=False)

    print(f"\nCompleted.")
    print(f"  Total events collected: {len(all_events)}")
    print(f"  Output saved to:        {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()
