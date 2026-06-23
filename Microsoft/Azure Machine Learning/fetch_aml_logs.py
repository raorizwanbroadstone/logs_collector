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

TENANT_ID = os.getenv("AZURE_AML_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_AML_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_AML_CLIENT_SECRET")
LOOKBACK_HOURS = 24
OUTPUT_DIR = Path(__file__).parent / "logs"

# Log Analytics tables produced by AML diagnostic settings
AML_LOG_TABLES = [
    "AmlComputeJobEvents",
    "AmlComputeClusterEvents",
    "AmlComputeInstanceEvents",
    "AmlRunStatusChangedEvent",
    "AmlDataSetEvent",
    "AmlModelEvent",
    "AmlDeploymentEvent",
    "AmlInferencingEvent",
]

# Try to import azure-ai-ml for richer asset inventory (models, jobs, endpoints)
try:
    from azure.ai.ml import MLClient
    AML_SDK_AVAILABLE = True
except ImportError:
    AML_SDK_AVAILABLE = False


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


def get_aml_workspaces(credential, subscription_id):
    try:
        client = ResourceManagementClient(credential, subscription_id)
        workspaces = []
        for resource in client.resources.list(
            filter="resourceType eq 'Microsoft.MachineLearningServices/workspaces'"
        ):
            parts = resource.id.split("/")
            resource_group = (
                parts[parts.index("resourceGroups") + 1]
                if "resourceGroups" in parts
                else "unknown"
            )
            workspaces.append({
                "id": resource.id,
                "name": resource.name,
                "location": resource.location,
                "resource_group": resource_group,
                "subscription_id": subscription_id,
            })
        return workspaces
    except HttpResponseError as error:
        print(f"    Cannot list AML workspaces (HTTP {error.status_code}): {error.message}")
        return []
    except Exception as error:
        print(f"    Cannot list AML workspaces: {error}")
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


def extract_workspace_ids(diagnostic_settings):
    workspace_ids = []
    if not isinstance(diagnostic_settings, list):
        return workspace_ids
    for setting in diagnostic_settings:
        workspace_id = setting.get("workspace_id")
        if workspace_id and workspace_id not in workspace_ids:
            workspace_ids.append(workspace_id)
    return workspace_ids


def get_activity_logs(monitor_client, resource_id):
    start_time = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    filter_str = (
        f"eventTimestamp ge '{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
        f"and resourceId eq '{resource_id}'"
    )
    try:
        events = list(monitor_client.activity_logs.list(filter=filter_str))
        return [event_record.as_dict() for event_record in events]
    except HttpResponseError as error:
        if error.status_code in (401, 403):
            return {"error": "insufficient_permissions", "detail": str(error.message)}
        return {"error": str(error.message or error)}
    except Exception as error:
        return {"error": str(error)}


def query_aml_log_tables(logs_client, workspace_id):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)
    results = {}

    for table in AML_LOG_TABLES:
        query = (
            f"{table}\n"
            f"| where TimeGenerated >= ago({LOOKBACK_HOURS}h)\n"
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


def get_aml_assets(credential, subscription_id, resource_group, workspace_name):
    """Use azure-ai-ml SDK to enumerate models, jobs, endpoints, compute, and data assets."""
    if not AML_SDK_AVAILABLE:
        return {"status": "azure-ai-ml package not installed — run: pip install azure-ai-ml"}

    try:
        ml_client = MLClient(credential, subscription_id, resource_group, workspace_name)
        assets = {}

        try:
            model_list = list(ml_client.models.list())
            assets["models"] = [
                {
                    "name": model.name,
                    "version": model.version,
                    "type": str(model.type) if hasattr(model, "type") else None,
                    "description": getattr(model, "description", None),
                    "tags": getattr(model, "tags", {}),
                    "creation_context": (
                        model.creation_context.as_dict()
                        if hasattr(model, "creation_context") and model.creation_context
                        else None
                    ),
                }
                for model in model_list
            ]
            print(f"        {len(assets['models'])} model(s)")
        except Exception as error:
            assets["models"] = {"error": str(error)}

        try:
            job_list = list(ml_client.jobs.list())
            assets["jobs"] = [
                {
                    "name": job.name,
                    "display_name": getattr(job, "display_name", None),
                    "status": str(job.status) if hasattr(job, "status") else None,
                    "type": str(job.type) if hasattr(job, "type") else None,
                    "tags": getattr(job, "tags", {}),
                    "creation_context": (
                        job.creation_context.as_dict()
                        if hasattr(job, "creation_context") and job.creation_context
                        else None
                    ),
                }
                for job in job_list
            ]
            print(f"        {len(assets['jobs'])} job(s)")
        except Exception as error:
            assets["jobs"] = {"error": str(error)}

        try:
            endpoint_list = list(ml_client.online_endpoints.list())
            assets["online_endpoints"] = [
                {
                    "name": endpoint.name,
                    "provisioning_state": str(endpoint.provisioning_state) if hasattr(endpoint, "provisioning_state") else None,
                    "scoring_uri": getattr(endpoint, "scoring_uri", None),
                    "auth_mode": str(endpoint.auth_mode) if hasattr(endpoint, "auth_mode") else None,
                    "tags": getattr(endpoint, "tags", {}),
                }
                for endpoint in endpoint_list
            ]
            print(f"        {len(assets['online_endpoints'])} online endpoint(s)")
        except Exception as error:
            assets["online_endpoints"] = {"error": str(error)}

        try:
            compute_list = list(ml_client.compute.list())
            assets["compute"] = [
                {
                    "name": compute_resource.name,
                    "type": str(compute_resource.type) if hasattr(compute_resource, "type") else None,
                    "provisioning_state": str(compute_resource.provisioning_state) if hasattr(compute_resource, "provisioning_state") else None,
                    "location": getattr(compute_resource, "location", None),
                }
                for compute_resource in compute_list
            ]
            print(f"        {len(assets['compute'])} compute resource(s)")
        except Exception as error:
            assets["compute"] = {"error": str(error)}

        try:
            data_asset_list = list(ml_client.data.list())
            assets["data_assets"] = [
                {
                    "name": data_asset.name,
                    "version": data_asset.version,
                    "type": str(data_asset.type) if hasattr(data_asset, "type") else None,
                    "path": getattr(data_asset, "path", None),
                    "tags": getattr(data_asset, "tags", {}),
                }
                for data_asset in data_asset_list
            ]
            print(f"        {len(assets['data_assets'])} data asset(s)")
        except Exception as error:
            assets["data_assets"] = {"error": str(error)}

        return assets

    except Exception as error:
        return {"error": str(error)}


def process_workspace(monitor_client, logs_client, credential, workspace):
    subscription_id = workspace["subscription_id"]
    workspace_resource_id = workspace["id"]
    workspace_name = workspace["name"]
    resource_group = workspace["resource_group"]

    print(f"    {workspace_name} ({resource_group})")

    result = {
        "subscription_id": subscription_id,
        "workspace_resource_id": workspace_resource_id,
        "workspace_name": workspace_name,
        "resource_group": resource_group,
        "location": workspace.get("location"),
        "diagnostic_settings": {},
        "activity_logs": [],
        "aml_log_tables": {},
        "assets": {},
        "error": None,
    }

    try:
        print("      Checking diagnostic settings...")
        diagnostic_settings_data = get_diagnostic_settings(monitor_client, workspace_resource_id)
        result["diagnostic_settings"] = diagnostic_settings_data

        print("      Fetching activity logs...")
        activity_log_events = get_activity_logs(monitor_client, workspace_resource_id)
        result["activity_logs"] = activity_log_events
        if isinstance(activity_log_events, list):
            print(f"      {len(activity_log_events)} activity log event(s).")
        else:
            print(f"      Activity logs error: {activity_log_events.get('error', 'unknown')}")

        workspace_ids = (
            extract_workspace_ids(diagnostic_settings_data)
            if isinstance(diagnostic_settings_data, list)
            else []
        )

        if workspace_ids:
            print(f"      Querying AML log tables in {len(workspace_ids)} workspace(s)...")
            workspace_query_results = {}
            for log_analytics_workspace_id in workspace_ids:
                workspace_query_results[log_analytics_workspace_id] = query_aml_log_tables(
                    logs_client, log_analytics_workspace_id
                )
            result["aml_log_tables"] = workspace_query_results

            total_log_events = sum(
                len(rows)
                for workspace_logs in workspace_query_results.values()
                for rows in workspace_logs.values()
                if isinstance(rows, list)
            )
            print(f"      {total_log_events} AML log event(s).")
        else:
            result["aml_log_tables"] = {"status": "no_log_analytics_workspace_configured"}

        print("      Listing AML assets (models, jobs, endpoints, compute, data)...")
        result["assets"] = get_aml_assets(
            credential, subscription_id, resource_group, workspace_name
        )

    except Exception as error:
        print(f"      Unexpected error: {error}")
        result["error"] = str(error)

    return result


def main():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("Missing required environment variables: AZURE_AML_TENANT_ID, AZURE_AML_CLIENT_ID, AZURE_AML_CLIENT_SECRET")
        return

    if not AML_SDK_AVAILABLE:
        print("azure-ai-ml not installed — asset inventory will be skipped.")
        print("Install with: pip install azure-ai-ml")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"azure_ml_{timestamp}.json"

    credential = get_credential()
    logs_client = LogsQueryClient(credential)

    subscriptions = get_subscriptions(credential)
    if not subscriptions:
        print("No accessible subscriptions found.")

    all_results = []
    total_workspaces = 0
    total_errors = 0

    for subscription in subscriptions:
        subscription_id = subscription["id"]
        subscription_name = subscription["name"]
        print(f"\nSubscription: {subscription_name} ({subscription_id})")

        monitor_client = MonitorManagementClient(credential, subscription_id)
        workspaces = get_aml_workspaces(credential, subscription_id)
        print(f"  Found {len(workspaces)} AML workspace(s).")

        if not workspaces:
            all_results.append({
                "subscription_id": subscription_id,
                "subscription_name": subscription_name,
                "status": "no_aml_workspaces_found",
            })
            continue

        for workspace in workspaces:
            total_workspaces += 1
            workspace_result = process_workspace(monitor_client, logs_client, credential, workspace)
            workspace_result["subscription_name"] = subscription_name
            all_results.append(workspace_result)
            if workspace_result.get("error"):
                total_errors += 1

    output_data = {
        "collectionTime": datetime.now(timezone.utc).isoformat(),
        "aml_sdk_available": AML_SDK_AVAILABLE,
        "summary": {
            "subscriptions_processed": len(subscriptions),
            "workspaces_processed": total_workspaces,
            "errors": total_errors,
        },
        "workspaces": all_results,
    }

    with open(output_file, "w", encoding="utf-8") as output_file_handle:
        json.dump(output_data, output_file_handle, indent=2, default=str)

    print(f"\nCompleted.")
    print(f"  Subscriptions processed:  {len(subscriptions)}")
    print(f"  AML workspaces processed: {total_workspaces}")
    print(f"  Errors:                   {total_errors}")
    print(f"  Output saved to:          {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()
