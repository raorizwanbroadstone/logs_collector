import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from dotenv import load_dotenv
import generate_bom

load_dotenv(Path(__file__).parent.parent.parent / ".env")

AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
AWS_KEY_ID     = os.getenv("AWS_SAGEMAKER_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("AWS_SAGEMAKER_SECRET_ACCESS_KEY", "")

LOOKBACK_HOURS = 24
OUTPUT_DIR     = Path(__file__).parent / "logs"

SAGEMAKER_EVENT_SOURCES = [
    "sagemaker.amazonaws.com",
]

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


def _sagemaker_client():
    return boto3.client(
        "sagemaker",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


def check_sagemaker_availability() -> bool:
    try:
        _sagemaker_client().list_endpoints(MaxResults=1)
        print("  SageMaker is reachable")
        return True
    except Exception as exc:
        msg = str(exc)
        if any(kw in msg.lower() for kw in ("could not connect", "connection refused", "nodename nor servname")):
            print(f"  SageMaker connectivity issue: {type(exc).__name__}")
            return False
        print(f"  SageMaker endpoint reachable ({type(exc).__name__}: {msg[:120]})")
        return True


def fetch_events_for_source(source: str, start_time: datetime, end_time: datetime) -> list[dict]:
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


def extract_unique_resources(events: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    resources: list[dict] = []
    for event in events:
        params = event.get("requestParameters") or {}
        if not isinstance(params, dict):
            continue
        for param_key, resource_type in RESOURCE_PARAM_KEYS.items():
            name = params.get(param_key)
            if name and (resource_type, name) not in seen:
                seen.add((resource_type, name))
                resources.append({"resource_type": resource_type, "resource_name": name})
    return resources


def describe_resource(resource_type: str, resource_name: str) -> dict:
    client = _sagemaker_client()
    result = {
        "resource_type":        resource_type,
        "resource_name":        resource_name,
        "arn":                  "",
        "status":               "",
        "creation_time":        "",
        "instance_type":        "",
        "algorithm":            "",
        "containers":           [],
        "endpoint_config_name": "",
        "access_denied":        False,
        "not_found":            False,
    }
    try:
        if resource_type == "TrainingJob":
            resp = client.describe_training_job(TrainingJobName=resource_name)
            result["arn"]    = resp.get("TrainingJobArn", "")
            result["status"] = resp.get("TrainingJobStatus", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""
            rc   = resp.get("ResourceConfig") or {}
            algo = resp.get("AlgorithmSpecification") or {}
            result["instance_type"] = rc.get("InstanceType", "")
            result["algorithm"]     = algo.get("TrainingImage", "") or algo.get("AlgorithmName", "")

        elif resource_type == "Model":
            resp = client.describe_model(ModelName=resource_name)
            result["arn"] = resp.get("ModelArn", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""
            primary    = resp.get("PrimaryContainer") or {}
            containers = resp.get("Containers") or ([primary] if primary else [])
            result["containers"] = [c.get("Image", "") for c in containers if isinstance(c, dict)]

        elif resource_type == "Endpoint":
            resp = client.describe_endpoint(EndpointName=resource_name)
            result["arn"]    = resp.get("EndpointArn", "")
            result["status"] = resp.get("EndpointStatus", "")
            ct = resp.get("CreationTime")
            result["creation_time"]        = ct.isoformat() if ct else ""
            result["endpoint_config_name"] = resp.get("EndpointConfigName", "")

        elif resource_type == "EndpointConfig":
            resp = client.describe_endpoint_config(EndpointConfigName=resource_name)
            result["arn"] = resp.get("EndpointConfigArn", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""
            variants = resp.get("ProductionVariants") or []
            result["instance_type"] = variants[0].get("InstanceType", "") if variants else ""

        elif resource_type == "Pipeline":
            resp = client.describe_pipeline(PipelineName=resource_name)
            result["arn"]    = resp.get("PipelineArn", "")
            result["status"] = resp.get("PipelineStatus", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""

        elif resource_type == "NotebookInstance":
            resp = client.describe_notebook_instance(NotebookInstanceName=resource_name)
            result["arn"]           = resp.get("NotebookInstanceArn", "")
            result["status"]        = resp.get("NotebookInstanceStatus", "")
            result["instance_type"] = resp.get("InstanceType", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""

        elif resource_type == "FeatureGroup":
            resp = client.describe_feature_group(FeatureGroupName=resource_name)
            result["arn"]    = resp.get("FeatureGroupArn", "")
            result["status"] = resp.get("FeatureGroupStatus", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""

        elif resource_type == "Domain":
            resp = client.describe_domain(DomainId=resource_name)
            result["arn"]    = resp.get("DomainArn", "")
            result["status"] = resp.get("Status", "")
            ct = resp.get("CreationTime")
            result["creation_time"] = ct.isoformat() if ct else ""

    except Exception as exc:
        msg = str(exc)
        if "AccessDenied" in msg or "AccessDeniedException" in msg:
            result["access_denied"] = True
            print(f"    Cannot describe {resource_type} {resource_name}: {type(exc).__name__}")
        elif "ResourceNotFound" in msg or "ValidationException" in msg or "does not exist" in msg.lower():
            result["not_found"] = True
            print(f"    Not found: {resource_type}/{resource_name}")
        else:
            print(f"    Error describing {resource_type}/{resource_name}: {exc}")
    return result


def build_resource_inventory_event(resource: dict, event_time: datetime) -> dict:
    resource_type = resource["resource_type"]
    resource_name = resource["resource_name"]
    return {
        "EventId":           f"inventory-{resource_type}-{resource_name}",
        "EventName":         "SageMakerResourceInventory",
        "EventSource":       "sagemaker-local-enumeration",
        "EventTime":         event_time.isoformat(),
        "Username":          "",
        "Resources":         [],
        "userIdentity":      {},
        "requestParameters": {"resourceType": resource_type, "resourceName": resource_name},
        "responseElements":  {},
        "awsRegion":         AWS_REGION,
        "sourceIPAddress":   "",
        "errorCode":         "AccessDenied" if resource.get("access_denied") else "",
        "errorMessage":      "",
        "inventory":         resource,
    }


def main() -> None:
    if not all([AWS_KEY_ID, AWS_SECRET_KEY]):
        print("Missing required credentials. Set AWS_SAGEMAKER_ACCESS_KEY_ID / AWS_SAGEMAKER_SECRET_ACCESS_KEY in .env")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"sagemaker_logs_{timestamp}.json"

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    print(f"Region : {AWS_REGION}")
    print(f"Window : {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} -> {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    print("Checking SageMaker availability...")
    check_sagemaker_availability()
    print()

    all_events: list[dict] = []
    for source in SAGEMAKER_EVENT_SOURCES:
        print(f"Fetching CloudTrail events: {source}")
        try:
            raw_events = fetch_events_for_source(source, start_time, end_time)
            normalised = [normalize_event(e) for e in raw_events]
            all_events.extend(normalised)
            print(f"  {len(normalised)} events from {source}\n")
        except Exception as exc:
            print(f"  Error fetching {source}: {exc}\n")

    unique_resources = extract_unique_resources(all_events)
    print(f"Describing {len(unique_resources)} unique SageMaker resources...")

    for resource_ref in unique_resources:
        rtype = resource_ref["resource_type"]
        rname = resource_ref["resource_name"]
        print(f"  -> {rtype}/{rname}")
        details = describe_resource(rtype, rname)
        if not details["access_denied"] and not details["not_found"]:
            status = details.get("status", "")
            itype  = details.get("instance_type", "")
            print(f"    status={status}" + (f", instance={itype}" if itype else ""))
        all_events.append(build_resource_inventory_event(details, end_time))

    with output_file.open("w", encoding="utf-8") as fh:
        json.dump(all_events, fh, indent=2, ensure_ascii=False)

    print(f"\nCompleted.")
    print(f"  Total events collected: {len(all_events)}")
    print(f"  Output saved to:        {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()
