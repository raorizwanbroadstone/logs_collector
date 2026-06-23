import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from dotenv import load_dotenv
import generate_bom

load_dotenv(Path(__file__).parent.parent.parent / ".env")

AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_KEY_ID     = os.getenv("AWS_IAM_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("AWS_IAM_SECRET_ACCESS_KEY", "")

LOOKBACK_HOURS = 24
OUTPUT_DIR     = Path(__file__).parent / "logs"

IAM_EVENT_SOURCES = ["iam.amazonaws.com"]

RESOURCE_PARAM_KEYS = {
    "userName":   "User",
    "roleName":   "Role",
    "groupName":  "Group",
    "policyName": "Policy",
}


def _iam_client():
    return boto3.client(
        "iam",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


def _cloudtrail_client():
    return boto3.client(
        "cloudtrail",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_KEY,
    )


def check_iam_availability() -> bool:
    try:
        _iam_client().get_account_summary()
        print("  IAM is reachable")
        return True
    except Exception as exc:
        msg = str(exc)
        if any(kw in msg.lower() for kw in ("could not connect", "connection refused", "nodename")):
            print(f"  IAM connectivity issue: {type(exc).__name__}")
            return False
        print(f"  IAM endpoint reachable ({type(exc).__name__}: {msg[:120]})")
        return True


def fetch_events_for_source(source: str, start_time: datetime, end_time: datetime) -> list[dict]:
    client = _cloudtrail_client()
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


def describe_user(client, user_name: str) -> dict:
    result = {
        "resource_type":         "User",
        "resource_name":         user_name,
        "arn":                   "",
        "user_id":               "",
        "create_date":           "",
        "password_last_used":    "",
        "mfa_count":             0,
        "active_key_count":      0,
        "inactive_key_count":    0,
        "attached_policy_count": 0,
        "group_count":           0,
        "access_denied":         False,
        "not_found":             False,
    }
    try:
        resp = client.get_user(UserName=user_name)
        user = resp.get("User") or {}
        result["arn"]     = user.get("Arn", "")
        result["user_id"] = user.get("UserId", "")
        cd  = user.get("CreateDate")
        plu = user.get("PasswordLastUsed")
        result["create_date"]        = cd.isoformat() if cd else ""
        result["password_last_used"] = plu.isoformat() if plu else ""

        try:
            mfa_resp = client.list_mfa_devices(UserName=user_name)
            result["mfa_count"] = len(mfa_resp.get("MFADevices") or [])
        except Exception:
            pass

        try:
            keys = (client.list_access_keys(UserName=user_name).get("AccessKeyMetadata") or [])
            result["active_key_count"]   = sum(1 for k in keys if k.get("Status") == "Active")
            result["inactive_key_count"] = sum(1 for k in keys if k.get("Status") == "Inactive")
        except Exception:
            pass

        try:
            pols = (client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies") or [])
            result["attached_policy_count"] = len(pols)
        except Exception:
            pass

        try:
            grps = (client.list_groups_for_user(UserName=user_name).get("Groups") or [])
            result["group_count"] = len(grps)
        except Exception:
            pass

    except Exception as exc:
        msg = str(exc)
        if "AccessDenied" in msg or "AccessDeniedException" in msg:
            result["access_denied"] = True
            print(f"    Cannot describe User {user_name}: {type(exc).__name__}")
        elif "NoSuchEntityException" in msg:
            result["not_found"] = True
            print(f"    Not found: User/{user_name}")
        else:
            print(f"    Error describing User/{user_name}: {exc}")
    return result


def describe_role(client, role_name: str) -> dict:
    result = {
        "resource_type":         "Role",
        "resource_name":         role_name,
        "arn":                   "",
        "role_id":               "",
        "create_date":           "",
        "description":           "",
        "max_session_duration":  0,
        "attached_policy_count": 0,
        "access_denied":         False,
        "not_found":             False,
    }
    try:
        resp = client.get_role(RoleName=role_name)
        role = resp.get("Role") or {}
        result["arn"]                  = role.get("Arn", "")
        result["role_id"]              = role.get("RoleId", "")
        result["description"]          = role.get("Description", "")
        result["max_session_duration"] = role.get("MaxSessionDuration", 0)
        cd = role.get("CreateDate")
        result["create_date"] = cd.isoformat() if cd else ""

        try:
            pols = (client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies") or [])
            result["attached_policy_count"] = len(pols)
        except Exception:
            pass

    except Exception as exc:
        msg = str(exc)
        if "AccessDenied" in msg or "AccessDeniedException" in msg:
            result["access_denied"] = True
            print(f"    Cannot describe Role {role_name}: {type(exc).__name__}")
        elif "NoSuchEntityException" in msg:
            result["not_found"] = True
            print(f"    Not found: Role/{role_name}")
        else:
            print(f"    Error describing Role/{role_name}: {exc}")
    return result


def describe_group(client, group_name: str) -> dict:
    result = {
        "resource_type":         "Group",
        "resource_name":         group_name,
        "arn":                   "",
        "group_id":              "",
        "create_date":           "",
        "member_count":          0,
        "attached_policy_count": 0,
        "access_denied":         False,
        "not_found":             False,
    }
    try:
        resp  = client.get_group(GroupName=group_name)
        group = resp.get("Group") or {}
        result["arn"]          = group.get("Arn", "")
        result["group_id"]     = group.get("GroupId", "")
        result["member_count"] = len(resp.get("Users") or [])
        cd = group.get("CreateDate")
        result["create_date"] = cd.isoformat() if cd else ""

        try:
            pols = (client.list_attached_group_policies(GroupName=group_name).get("AttachedPolicies") or [])
            result["attached_policy_count"] = len(pols)
        except Exception:
            pass

    except Exception as exc:
        msg = str(exc)
        if "AccessDenied" in msg or "AccessDeniedException" in msg:
            result["access_denied"] = True
            print(f"    Cannot describe Group {group_name}: {type(exc).__name__}")
        elif "NoSuchEntityException" in msg:
            result["not_found"] = True
            print(f"    Not found: Group/{group_name}")
        else:
            print(f"    Error describing Group/{group_name}: {exc}")
    return result


def describe_policy(client, policy_name: str, account_id: str) -> dict:
    result = {
        "resource_type":    "Policy",
        "resource_name":    policy_name,
        "arn":              "",
        "policy_id":        "",
        "create_date":      "",
        "update_date":      "",
        "default_version":  "",
        "attachment_count": 0,
        "access_denied":    False,
        "not_found":        False,
    }
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    try:
        resp   = client.get_policy(PolicyArn=policy_arn)
        policy = resp.get("Policy") or {}
        result["arn"]              = policy.get("Arn", "")
        result["policy_id"]        = policy.get("PolicyId", "")
        result["default_version"]  = policy.get("DefaultVersionId", "")
        result["attachment_count"] = policy.get("AttachmentCount", 0)
        cd = policy.get("CreateDate")
        ud = policy.get("UpdateDate")
        result["create_date"] = cd.isoformat() if cd else ""
        result["update_date"] = ud.isoformat() if ud else ""
    except Exception as exc:
        msg = str(exc)
        if "AccessDenied" in msg or "AccessDeniedException" in msg:
            result["access_denied"] = True
            print(f"    Cannot describe Policy {policy_name}: {type(exc).__name__}")
        elif "NoSuchEntityException" in msg:
            result["not_found"] = True
            print(f"    Not found: Policy/{policy_name}")
        else:
            print(f"    Error describing Policy/{policy_name}: {exc}")
    return result


def describe_resource(resource_type: str, resource_name: str, account_id: str = "") -> dict:
    client = _iam_client()
    if resource_type == "User":
        return describe_user(client, resource_name)
    if resource_type == "Role":
        return describe_role(client, resource_name)
    if resource_type == "Group":
        return describe_group(client, resource_name)
    if resource_type == "Policy":
        return describe_policy(client, resource_name, account_id)
    return {"resource_type": resource_type, "resource_name": resource_name,
            "access_denied": False, "not_found": False}


def enumerate_all_resources() -> tuple[list[dict], str]:
    client    = _iam_client()
    resources: list[dict] = []
    account_id = ""

    try:
        summary    = client.get_account_summary().get("SummaryMap") or {}
        account_id = ""
    except Exception:
        pass

    try:
        paginator = client.get_paginator("list_users")
        count = 0
        for page in paginator.paginate():
            for user in (page.get("Users") or []):
                name = user.get("UserName", "")
                if name:
                    resources.append({"resource_type": "User", "resource_name": name})
                    count += 1
                if not account_id:
                    arn = user.get("Arn", "")
                    if arn:
                        account_id = arn.split(":")[4]
        print(f"  {count} users")
    except Exception as exc:
        print(f"  Error enumerating users: {exc}")

    try:
        paginator = client.get_paginator("list_roles")
        count = 0
        for page in paginator.paginate():
            for role in (page.get("Roles") or []):
                name = role.get("RoleName", "")
                if name:
                    resources.append({"resource_type": "Role", "resource_name": name})
                    count += 1
        print(f"  {count} roles")
    except Exception as exc:
        print(f"  Error enumerating roles: {exc}")

    try:
        paginator = client.get_paginator("list_groups")
        count = 0
        for page in paginator.paginate():
            for group in (page.get("Groups") or []):
                name = group.get("GroupName", "")
                if name:
                    resources.append({"resource_type": "Group", "resource_name": name})
                    count += 1
        print(f"  {count} groups")
    except Exception as exc:
        print(f"  Error enumerating groups: {exc}")

    try:
        paginator = client.get_paginator("list_policies")
        count = 0
        for page in paginator.paginate(Scope="Local"):
            for policy in (page.get("Policies") or []):
                name = policy.get("PolicyName", "")
                if name:
                    resources.append({"resource_type": "Policy", "resource_name": name})
                    count += 1
        print(f"  {count} customer-managed policies")
    except Exception as exc:
        print(f"  Error enumerating policies: {exc}")

    return resources, account_id


def build_inventory_event(resource: dict, event_time: datetime) -> dict:
    resource_type = resource["resource_type"]
    resource_name = resource["resource_name"]
    return {
        "EventId":           f"inventory-{resource_type}-{resource_name}",
        "EventName":         "IAMResourceInventory",
        "EventSource":       "iam-local-enumeration",
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
        print("Missing credentials. Set AWS_IAM_ACCESS_KEY_ID / AWS_IAM_SECRET_ACCESS_KEY in .env")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"iam_logs_{timestamp}.json"

    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    print(f"Region : {AWS_REGION}")
    print(f"Window : {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} -> {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    print("Checking IAM availability...")
    if not check_iam_availability():
        return
    print()

    all_events: list[dict] = []
    for source in IAM_EVENT_SOURCES:
        print(f"Fetching CloudTrail events: {source}")
        try:
            raw_events = fetch_events_for_source(source, start_time, end_time)
            normalised = [normalize_event(e) for e in raw_events]
            all_events.extend(normalised)
            print(f"  {len(normalised)} events from {source}\n")
        except Exception as exc:
            print(f"  Error fetching {source}: {exc}\n")

    print("Enumerating current IAM resources...")
    enumerated, account_id = enumerate_all_resources()

    ct_resources = extract_unique_resources(all_events)
    seen: set[tuple[str, str]] = {(r["resource_type"], r["resource_name"]) for r in enumerated}
    for r in ct_resources:
        key = (r["resource_type"], r["resource_name"])
        if key not in seen:
            seen.add(key)
            enumerated.append(r)

    print(f"\nDescribing {len(enumerated)} unique IAM resources...")
    for resource_ref in enumerated:
        rtype = resource_ref["resource_type"]
        rname = resource_ref["resource_name"]
        print(f"  -> {rtype}/{rname}")
        details = describe_resource(rtype, rname, account_id)
        if not details.get("access_denied") and not details.get("not_found"):
            if rtype == "User":
                mfa  = details.get("mfa_count", 0)
                keys = details.get("active_key_count", 0)
                print(f"    mfa={mfa}, active_keys={keys}")
            elif rtype == "Role":
                desc = details.get("description", "")[:60]
                print(f"    {desc}" if desc else "    no description")
            elif rtype == "Group":
                members = details.get("member_count", 0)
                print(f"    members={members}")
            elif rtype == "Policy":
                attached = details.get("attachment_count", 0)
                print(f"    attachments={attached}")
        all_events.append(build_inventory_event(details, end_time))

    with output_file.open("w", encoding="utf-8") as fh:
        json.dump(all_events, fh, indent=2, ensure_ascii=False)

    print(f"\nCompleted.")
    print(f"  Total events collected: {len(all_events)}")
    print(f"  Output saved to:        {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()