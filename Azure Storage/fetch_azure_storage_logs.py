import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from azure.core.exceptions import HttpResponseError
from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("AZURE_STORAGE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_STORAGE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_STORAGE_CLIENT_SECRET")
FALLBACK_WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")
# Comma-separated subscription IDs used when the SP cannot list subscriptions automatically
SUBSCRIPTION_IDS_ENV = os.getenv("AZURE_STORAGE_SUBSCRIPTION_ID")

HOURS_BACK = 24

OUTPUT_DIR = Path(__file__).parent / "logs"

# Sub-resource paths that hold data-plane diagnostic settings for storage
STORAGE_SUB_RESOURCES = [
    "blobServices/default",
    "fileServices/default",
    "queueServices/default",
    "tableServices/default",
]

# Log Analytics tables for each storage sub-resource type
STORAGE_LOG_TABLES = [
    "StorageBlobLogs",
    "StorageFileLogs",
    "StorageQueueLogs",
    "StorageTableLogs",
]


def get_credential():
    return ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


def get_subscriptions(credential):
    print("  🔍 Listing subscriptions...")
    try:
        client = SubscriptionClient(credential)
        subs = [
            {"id": s.subscription_id, "name": s.display_name}
            for s in client.subscriptions.list()
        ]
        print(f"  ✅ Found {len(subs)} subscription(s)")
        return subs
    except Exception as e:
        print(f"  ❌ Error listing subscriptions: {e}")
        return []


def get_storage_accounts(credential, subscription_id):
    try:
        client = ResourceManagementClient(credential, subscription_id)
        accounts = []
        for resource in client.resources.list(
            filter="resourceType eq 'Microsoft.Storage/storageAccounts'"
        ):
            parts = resource.id.split("/")
            rg = parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts else "unknown"
            accounts.append({
                "id": resource.id,
                "name": resource.name,
                "location": resource.location,
                "resource_group": rg,
            })
        return accounts
    except HttpResponseError as e:
        print(f"    ⚠️  Cannot list storage accounts (HTTP {e.status_code}): {e.message}")
        return []
    except Exception as e:
        print(f"    ⚠️  Cannot list storage accounts: {e}")
        return []


def get_diagnostic_settings(monitor_client, resource_uri):
    try:
        settings = list(monitor_client.diagnostic_settings.list(resource_uri=resource_uri))
        return [s.as_dict() for s in settings]
    except HttpResponseError as e:
        if e.status_code in (401, 403):
            return {"error": "insufficient_permissions", "detail": str(e.message)}
        return {"error": str(e.message or e)}
    except Exception as e:
        return {"error": str(e)}


def collect_all_diagnostic_settings(monitor_client, account_id):
    """Collect diagnostic settings from the account and all sub-resources."""
    all_settings = {
        "account": get_diagnostic_settings(monitor_client, account_id),
    }
    for sub in STORAGE_SUB_RESOURCES:
        uri = f"{account_id}/{sub}"
        all_settings[sub] = get_diagnostic_settings(monitor_client, uri)
    return all_settings


def extract_workspace_ids(all_diag_settings):
    """Pull unique Log Analytics workspace IDs out of all diagnostic settings."""
    workspace_ids = []
    for _level, settings in all_diag_settings.items():
        if not isinstance(settings, list):
            continue
        for setting in settings:
            ws_id = setting.get("workspace_id")
            if ws_id and ws_id not in workspace_ids:
                workspace_ids.append(ws_id)
    return workspace_ids


def get_activity_logs(monitor_client, account_id):
    """Fetch Azure Activity (management-plane) logs for a storage account."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=HOURS_BACK)
    filter_str = (
        f"eventTimestamp ge '{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
        f"and resourceId eq '{account_id}'"
    )
    try:
        events = list(monitor_client.activity_logs.list(filter=filter_str))
        return [e.as_dict() for e in events]
    except HttpResponseError as e:
        if e.status_code in (401, 403):
            return {"error": "insufficient_permissions", "detail": str(e.message)}
        return {"error": str(e.message or e)}
    except Exception as e:
        return {"error": str(e)}


def query_log_analytics(logs_client, workspace_id, account_name):
    """Query Log Analytics storage tables for a given storage account name."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=HOURS_BACK)
    results = {}

    for table in STORAGE_LOG_TABLES:
        query = (
            f"{table}\n"
            f"| where TimeGenerated >= ago({HOURS_BACK}h)\n"
            f"| where AccountName == '{account_name}'\n"
            f"| order by TimeGenerated desc\n"
            f"| limit 1000"
        )
        try:
            response = logs_client.query_workspace(
                workspace_id=workspace_id,
                query=query,
                timespan=(start_time, end_time),
            )
            if response.status == LogsQueryStatus.SUCCESS and response.tables:
                tbl = response.tables[0]
                col_names = [c.name if hasattr(c, "name") else str(c) for c in tbl.columns]
                results[table] = [dict(zip(col_names, row)) for row in tbl.rows]
            else:
                results[table] = []
        except HttpResponseError as e:
            error_code = getattr(e, "error", None)
            code_str = str(error_code.code if error_code else "")
            if "TableNotFound" in code_str or e.status_code == 404:
                results[table] = {"status": "table_not_found"}
            elif e.status_code in (401, 403):
                results[table] = {"status": "insufficient_permissions"}
            else:
                results[table] = {"error": str(e.message or e)}
        except Exception as e:
            results[table] = {"error": str(e)}

    return results


def process_storage_account(monitor_client, logs_client, sub_id, sub_name, account):
    account_id = account["id"]
    account_name = account["name"]
    rg = account["resource_group"]

    print(f"    📦 {account_name} ({rg})")

    result = {
        "subscription_id": sub_id,
        "subscription_name": sub_name,
        "storage_account_id": account_id,
        "storage_account_name": account_name,
        "resource_group": rg,
        "location": account.get("location"),
        "diagnostic_logging_enabled": False,
        "diagnostic_settings": {},
        "activity_logs": [],
        "storage_diagnostic_logs": {},
        "error": None,
    }

    try:
        # Diagnostic settings (account + sub-resources)
        print(f"      🔍 Checking diagnostic settings...")
        diag = collect_all_diagnostic_settings(monitor_client, account_id)
        result["diagnostic_settings"] = diag

        enabled_count = sum(
            len(v) for v in diag.values() if isinstance(v, list)
        )
        result["diagnostic_logging_enabled"] = enabled_count > 0
        if enabled_count:
            print(f"      ✅ {enabled_count} diagnostic setting(s) found")
        else:
            print(f"      ℹ️  Diagnostic logging not enabled")

        # Activity logs
        print(f"      🔍 Fetching activity logs...")
        activity = get_activity_logs(monitor_client, account_id)
        result["activity_logs"] = activity
        if isinstance(activity, list):
            print(f"      ✅ {len(activity)} activity log event(s)")
        else:
            print(f"      ⚠️  Activity logs: {activity.get('error', 'unknown error')}")

        # Log Analytics queries
        workspace_ids = extract_workspace_ids(diag)
        if not workspace_ids and FALLBACK_WORKSPACE_ID:
            workspace_ids = [FALLBACK_WORKSPACE_ID]

        if workspace_ids:
            print(f"      🔍 Querying {len(workspace_ids)} Log Analytics workspace(s)...")
            per_workspace = {}
            for ws_id in workspace_ids:
                per_workspace[ws_id] = query_log_analytics(logs_client, ws_id, account_name)
            result["storage_diagnostic_logs"] = per_workspace

            total = sum(
                len(rows)
                for ws in per_workspace.values()
                for rows in ws.values()
                if isinstance(rows, list)
            )
            print(f"      ✅ {total} storage diagnostic log event(s)")
        else:
            result["storage_diagnostic_logs"] = {
                "status": "no_log_analytics_workspace_configured"
            }

    except Exception as e:
        print(f"      ❌ Unexpected error: {e}")
        result["error"] = str(e)

    return result


def main():
    print("🚀 Azure Storage Logs Collector")
    print("=" * 50)

    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("❌ Missing required env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"azure_storage_{timestamp}.json"

    credential = get_credential()
    logs_client = LogsQueryClient(credential)

    subscriptions = get_subscriptions(credential)
    if not subscriptions:
        print("⚠️  No accessible subscriptions found.")

    all_results = []
    total_accounts = 0
    total_log_events = 0
    total_errors = 0

    for sub in subscriptions:
        sub_id = sub["id"]
        sub_name = sub["name"]
        print(f"\n📋 Subscription: {sub_name} ({sub_id})")

        monitor_client = MonitorManagementClient(credential, sub_id)

        accounts = get_storage_accounts(credential, sub_id)
        print(f"  ✅ Found {len(accounts)} storage account(s)")

        if not accounts:
            all_results.append({
                "subscription_id": sub_id,
                "subscription_name": sub_name,
                "status": "no_storage_accounts_found",
            })
            continue

        for account in accounts:
            total_accounts += 1
            account_result = process_storage_account(
                monitor_client, logs_client, sub_id, sub_name, account
            )
            all_results.append(account_result)

            if account_result.get("error"):
                total_errors += 1

            if isinstance(account_result.get("activity_logs"), list):
                total_log_events += len(account_result["activity_logs"])

            for ws_logs in account_result.get("storage_diagnostic_logs", {}).values():
                if isinstance(ws_logs, dict):
                    for rows in ws_logs.values():
                        if isinstance(rows, list):
                            total_log_events += len(rows)

    output_data = {
        "collectionTime": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "subscriptions_processed": len(subscriptions),
            "storage_accounts_processed": total_accounts,
            "total_log_events_collected": total_log_events,
            "errors": total_errors,
        },
        "storage_accounts": all_results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"\n🎉 Done!")
    print(f"  📊 Subscriptions processed: {len(subscriptions)}")
    print(f"  📦 Storage accounts processed: {total_accounts}")
    print(f"  📄 Total log events collected: {total_log_events}")
    print(f"  ❌ Errors: {total_errors}")
    print(f"  💾 Output saved to: {output_file}")


if __name__ == "__main__":
    main()
