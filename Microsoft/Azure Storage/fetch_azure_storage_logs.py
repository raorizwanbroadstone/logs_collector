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
import generate_bom

load_dotenv()

TENANT_ID = os.getenv("AZURE_STORAGE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_STORAGE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_STORAGE_CLIENT_SECRET")
SUBSCRIPTION_IDS_ENV = os.getenv("AZURE_STORAGE_SUBSCRIPTION_ID")

LOOKBACK_HOURS = 24

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
    print("Listing subscriptions...")
    try:
        client = SubscriptionClient(credential)
        subscription_list = [
            {"id": subscription.subscription_id, "name": subscription.display_name}
            for subscription in client.subscriptions.list()
        ]
        print(f"  Found {len(subscription_list)} subscription(s).")
        return subscription_list
    except Exception as error:
        print(f"  Error listing subscriptions: {error}")
        return []


def get_storage_accounts(credential, subscription_id):
    try:
        client = ResourceManagementClient(credential, subscription_id)
        accounts = []
        for resource in client.resources.list(
            filter="resourceType eq 'Microsoft.Storage/storageAccounts'"
        ):
            parts = resource.id.split("/")
            resource_group = (
                parts[parts.index("resourceGroups") + 1]
                if "resourceGroups" in parts
                else "unknown"
            )
            accounts.append({
                "id": resource.id,
                "name": resource.name,
                "location": resource.location,
                "resource_group": resource_group,
            })
        return accounts
    except HttpResponseError as error:
        print(f"    Cannot list storage accounts (HTTP {error.status_code}): {error.message}")
        return []
    except Exception as error:
        print(f"    Cannot list storage accounts: {error}")
        return []


def get_diagnostic_settings(monitor_client, resource_uri):
    try:
        settings = list(monitor_client.diagnostic_settings.list(resource_uri=resource_uri))
        return [setting.as_dict() for setting in settings]
    except HttpResponseError as error:
        if error.status_code in (401, 403):
            return {"error": "insufficient_permissions", "detail": str(error.message)}
        return {"error": str(error.message or error)}
    except Exception as error:
        return {"error": str(error)}


def collect_all_diagnostic_settings(monitor_client, account_id):
    """Collect diagnostic settings from the account level and all four sub-resources."""
    all_settings = {
        "account": get_diagnostic_settings(monitor_client, account_id),
    }
    for sub_resource in STORAGE_SUB_RESOURCES:
        uri = f"{account_id}/{sub_resource}"
        all_settings[sub_resource] = get_diagnostic_settings(monitor_client, uri)
    return all_settings


def extract_workspace_ids(all_diag_settings):
    """Pull unique Log Analytics workspace IDs from all diagnostic settings."""
    workspace_ids = []
    for diagnostic_level, settings in all_diag_settings.items():
        if not isinstance(settings, list):
            continue
        for setting in settings:
            workspace_id = setting.get("workspace_id")
            if workspace_id and workspace_id not in workspace_ids:
                workspace_ids.append(workspace_id)
    return workspace_ids


def get_activity_logs(monitor_client, account_id):
    """Fetch Azure Activity (management-plane) logs for a storage account."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    filter_str = (
        f"eventTimestamp ge '{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
        f"and resourceId eq '{account_id}'"
    )
    try:
        events = list(monitor_client.activity_logs.list(filter=filter_str))
        return [event.as_dict() for event in events]
    except HttpResponseError as error:
        if error.status_code in (401, 403):
            return {"error": "insufficient_permissions", "detail": str(error.message)}
        return {"error": str(error.message or error)}
    except Exception as error:
        return {"error": str(error)}


def query_log_analytics(logs_client, workspace_id, account_name):
    """Query Log Analytics storage tables for the given storage account name."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)
    results = {}

    for table in STORAGE_LOG_TABLES:
        query = (
            f"{table}\n"
            f"| where TimeGenerated >= ago({LOOKBACK_HOURS}h)\n"
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
                result_table = response.tables[0]
                column_names = [
                    column.name if hasattr(column, "name") else str(column)
                    for column in result_table.columns
                ]
                results[table] = [dict(zip(column_names, row)) for row in result_table.rows]
            else:
                results[table] = []
        except HttpResponseError as error:
            error_code = getattr(error, "error", None)
            code_str = str(error_code.code if error_code else "")
            if "TableNotFound" in code_str or error.status_code == 404:
                results[table] = {"status": "table_not_found"}
            elif error.status_code in (401, 403):
                results[table] = {"status": "insufficient_permissions"}
            else:
                results[table] = {"error": str(error.message or error)}
        except Exception as error:
            results[table] = {"error": str(error)}

    return results


def process_storage_account(monitor_client, logs_client, subscription_id, subscription_name, account):
    account_id = account["id"]
    account_name = account["name"]
    resource_group = account["resource_group"]

    print(f"    {account_name} ({resource_group})")

    result = {
        "subscription_id": subscription_id,
        "subscription_name": subscription_name,
        "storage_account_id": account_id,
        "storage_account_name": account_name,
        "resource_group": resource_group,
        "location": account.get("location"),
        "diagnostic_logging_enabled": False,
        "diagnostic_settings": {},
        "activity_logs": [],
        "storage_diagnostic_logs": {},
        "error": None,
    }

    try:
        print("      Checking diagnostic settings...")
        diagnostic_settings_data = collect_all_diagnostic_settings(monitor_client, account_id)
        result["diagnostic_settings"] = diagnostic_settings_data

        enabled_count = sum(
            len(v) for v in diagnostic_settings_data.values() if isinstance(v, list)
        )
        result["diagnostic_logging_enabled"] = enabled_count > 0
        if enabled_count:
            print(f"      {enabled_count} diagnostic setting(s) found.")
        else:
            print("      Diagnostic logging not enabled.")

        print("      Fetching activity logs...")
        activity_log_events = get_activity_logs(monitor_client, account_id)
        result["activity_logs"] = activity_log_events
        if isinstance(activity_log_events, list):
            print(f"      {len(activity_log_events)} activity log event(s).")
        else:
            print(f"      Activity logs error: {activity_log_events.get('error', 'unknown error')}")

        workspace_ids = extract_workspace_ids(diagnostic_settings_data)

        if workspace_ids:
            print(f"      Querying {len(workspace_ids)} Log Analytics workspace(s)...")
            workspace_query_results = {}
            for workspace_id in workspace_ids:
                workspace_query_results[workspace_id] = query_log_analytics(
                    logs_client, workspace_id, account_name
                )
            result["storage_diagnostic_logs"] = workspace_query_results

            total_diagnostic_log_events = sum(
                len(rows)
                for workspace_logs in workspace_query_results.values()
                for rows in workspace_logs.values()
                if isinstance(rows, list)
            )
            print(f"      {total_diagnostic_log_events} storage diagnostic log event(s).")
        else:
            result["storage_diagnostic_logs"] = {
                "status": "no_log_analytics_workspace_configured"
            }

    except Exception as error:
        print(f"      Unexpected error: {error}")
        result["error"] = str(error)

    return result


def main():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("Missing required environment variables: AZURE_STORAGE_TENANT_ID, AZURE_STORAGE_CLIENT_ID, AZURE_STORAGE_CLIENT_SECRET")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"azure_storage_{timestamp}.json"

    credential = get_credential()
    logs_client = LogsQueryClient(credential)

    subscriptions = get_subscriptions(credential)
    if not subscriptions:
        print("No accessible subscriptions found.")

    all_results = []
    total_accounts = 0
    total_log_events = 0
    total_errors = 0

    for subscription in subscriptions:
        subscription_id = subscription["id"]
        subscription_name = subscription["name"]
        print(f"\nSubscription: {subscription_name} ({subscription_id})")

        monitor_client = MonitorManagementClient(credential, subscription_id)
        accounts = get_storage_accounts(credential, subscription_id)
        print(f"  Found {len(accounts)} storage account(s).")

        if not accounts:
            all_results.append({
                "subscription_id": subscription_id,
                "subscription_name": subscription_name,
                "status": "no_storage_accounts_found",
            })
            continue

        for account in accounts:
            total_accounts += 1
            account_result = process_storage_account(
                monitor_client, logs_client, subscription_id, subscription_name, account
            )
            all_results.append(account_result)

            if account_result.get("error"):
                total_errors += 1

            if isinstance(account_result.get("activity_logs"), list):
                total_log_events += len(account_result["activity_logs"])

            for workspace_logs in account_result.get("storage_diagnostic_logs", {}).values():
                if isinstance(workspace_logs, dict):
                    for rows in workspace_logs.values():
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

    with open(output_file, "w", encoding="utf-8") as output_file_handle:
        json.dump(output_data, output_file_handle, indent=2, default=str)

    print(f"\nCompleted.")
    print(f"  Subscriptions processed:    {len(subscriptions)}")
    print(f"  Storage accounts processed: {total_accounts}")
    print(f"  Total log events collected: {total_log_events}")
    print(f"  Errors:                     {total_errors}")
    print(f"  Output saved to:            {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()
