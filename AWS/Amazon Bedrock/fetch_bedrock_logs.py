import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from dotenv import load_dotenv
import generate_bom

load_dotenv(Path(__file__).parent.parent.parent / ".env")

AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
AWS_KEY_ID     = os.getenv("AWS_BEDROCK_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("AWS_BEDROCK_SECRET_ACCESS_KEY", "")

LOOKBACK_HOURS = 24
OUTPUT_DIR = Path(__file__).parent / "logs"

# CloudTrail event sources that cover all Bedrock activity
BEDROCK_EVENT_SOURCES = [
    "bedrock.amazonaws.com",                # InvokeModel, ListFoundationModels, etc.
    "bedrock-agent.amazonaws.com",          # CreateAgent, CreateKnowledgeBase, etc.
    "bedrock-agent-runtime.amazonaws.com",  # InvokeAgent, Retrieve, etc.
]


def check_bedrock_availability() -> bool:
    """
    Calls ListFoundationModels to verify that Bedrock is reachable in the
    configured region. Returns True even on auth errors — only endpoint
    resolution failures indicate the region is unsupported.
    """
    try:
        boto3.client(
            "bedrock",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_KEY,
        ).list_foundation_models()
        print(f"  Bedrock is available in {AWS_REGION}")
        return True
    except Exception as exc:
        msg = str(exc)
        if any(kw in msg for kw in ("EndpointResolutionError", "UnknownEndpoint", "Could not connect")):
            print(f"  Bedrock is NOT available in {AWS_REGION}.")
            print("  Confirmed Bedrock regions: us-east-1, us-west-2, eu-central-1, eu-west-1")
            return False
        print(f"  Bedrock endpoint reachable ({type(exc).__name__}: {msg[:120]})")
        return True


def fetch_events_for_source(source: str, start_time: datetime, end_time: datetime) -> list[dict]:
    """
    Pages through CloudTrail lookup_events for the given event source across
    the lookback window. Free CloudTrail event history covers the last 90 days
    of management events; data events (InvokeModel payloads) require a paid trail.
    """
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
    """
    Flattens a CloudTrail event dict returned by boto3.
    EventTime is a datetime object from boto3 — serialised to ISO-8601 string.
    CloudTrailEvent is a JSON string — parsed and merged into the top level.
    """
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


def main() -> None:
    if not all([AWS_KEY_ID, AWS_SECRET_KEY]):
        print("Missing required environment variables: AWS_BEDROCK_ACCESS_KEY_ID, AWS_BEDROCK_SECRET_ACCESS_KEY")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"bedrock_logs_{timestamp}.json"

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    print(f"Region : {AWS_REGION}")
    print(f"Window : {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} → {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    print("Checking Bedrock availability...")
    check_bedrock_availability()
    print()

    all_events: list[dict] = []

    for source in BEDROCK_EVENT_SOURCES:
        print(f"Fetching CloudTrail events: {source}")
        try:
            raw_events = fetch_events_for_source(source, start_time, end_time)
            normalised = [normalize_event(e) for e in raw_events]
            all_events.extend(normalised)
            print(f"  {len(normalised)} events from {source}\n")
        except Exception as exc:
            print(f"  Error fetching {source}: {exc}\n")

    with output_file.open("w", encoding="utf-8") as output_file_handle:
        json.dump(all_events, output_file_handle, indent=2, ensure_ascii=False)

    print(f"Completed.")
    print(f"  Total events collected: {len(all_events)}")
    print(f"  Output saved to:        {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()
