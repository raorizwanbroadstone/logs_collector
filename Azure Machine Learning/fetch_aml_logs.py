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

TENANT_ID = os.getenv("AZURE_AML_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_AML_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_AML_CLIENT_SECRET")
FALLBACK_WORKSPACE_ID = os.getenv("AZURE_AML_WORKSPACE_ID")

HOURS_BACK = 24
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


def get_aml_workspaces(credential, subscription_id):
    try:
        client = ResourceManagementClient(credential, subscription_id)
        workspaces = []
        for resource in client.resources.list(
            filter="resourceType eq 'Microsoft.MachineLearningServices/workspaces'"
        ):
            parts = resource.id.split("/")
            rg = parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts else "unknown"
            workspaces.append({
                "id": resource.id,
                "name": resource.name,
                "location": resource.location,
                "resource_group": rg,
                "subscription_id": subscription_id,
            })
        return workspaces
    except HttpResponseError as e:
        print(f"    ⚠️  Cannot list AML workspaces (HTTP {e.status_code}): {e.message}")
        return []
    except Exception as e:
        print(f"    ⚠️  Cannot list AML workspaces: {e}")
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


def extract_workspace_ids(diag_settings):
    workspace_ids = []
    if not isinstance(diag_settings, list):
        return workspace_ids
    for setting in diag_settings:
        ws_id = setting.get("workspace_id")
        if ws_id and ws_id not in workspace_ids:
            workspace_ids.append(ws_id)
    return workspace_ids


def get_activity_logs(monitor_client, resource_id):
    start_time = datetime.now(timezone.utc) - timedelta(hours=HOURS_BACK)
    filter_str = (
        f"eventTimestamp ge '{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
        f"and resourceId eq '{resource_id}'"
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


def query_aml_log_tables(logs_client, workspace_id):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=HOURS_BACK)
    results = {}

    for table in AML_LOG_TABLES:
        query = (
            f"{table}\n"
            f"| where TimeGenerated >= ago({HOURS_BACK}h)\n"
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


def get_aml_assets(credential, subscription_id, resource_group, workspace_name):
    """Use azure-ai-ml SDK to enumerate models, jobs, endpoints, compute, and data assets."""
    if not AML_SDK_AVAILABLE:
        return {"status": "azure-ai-ml package not installed — run: pip install azure-ai-ml"}

    try:
        ml_client = MLClient(credential, subscription_id, resource_group, workspace_name)
        assets = {}

        # Registered models — core AIBom artifact
        try:
            models = list(ml_client.models.list())
            assets["models"] = [
                {
                    "name": m.name,
                    "version": m.version,
                    "type": str(m.type) if hasattr(m, "type") else None,
                    "description": getattr(m, "description", None),
                    "tags": getattr(m, "tags", {}),
                    "creation_context": (
                        m.creation_context.as_dict()
                        if hasattr(m, "creation_context") and m.creation_context
                        else None
                    ),
                }
                for m in models
            ]
            print(f"        ✅ {len(assets['models'])} model(s)")
        except Exception as e:
            assets["models"] = {"error": str(e)}

        # Training / pipeline jobs
        try:
            jobs = list(ml_client.jobs.list())
            assets["jobs"] = [
                {
                    "name": j.name,
                    "display_name": getattr(j, "display_name", None),
                    "status": str(j.status) if hasattr(j, "status") else None,
                    "type": str(j.type) if hasattr(j, "type") else None,
                    "tags": getattr(j, "tags", {}),
                    "creation_context": (
                        j.creation_context.as_dict()
                        if hasattr(j, "creation_context") and j.creation_context
                        else None
                    ),
                }
                for j in jobs
            ]
            print(f"        ✅ {len(assets['jobs'])} job(s)")
        except Exception as e:
            assets["jobs"] = {"error": str(e)}

        # Online inference endpoints
        try:
            endpoints = list(ml_client.online_endpoints.list())
            assets["online_endpoints"] = [
                {
                    "name": ep.name,
                    "provisioning_state": str(ep.provisioning_state) if hasattr(ep, "provisioning_state") else None,
                    "scoring_uri": getattr(ep, "scoring_uri", None),
                    "auth_mode": str(ep.auth_mode) if hasattr(ep, "auth_mode") else None,
                    "tags": getattr(ep, "tags", {}),
                }
                for ep in endpoints
            ]
            print(f"        ✅ {len(assets['online_endpoints'])} online endpoint(s)")
        except Exception as e:
            assets["online_endpoints"] = {"error": str(e)}

        # Compute clusters / instances
        try:
            computes = list(ml_client.compute.list())
            assets["compute"] = [
                {
                    "name": c.name,
                    "type": str(c.type) if hasattr(c, "type") else None,
                    "provisioning_state": str(c.provisioning_state) if hasattr(c, "provisioning_state") else None,
                    "location": getattr(c, "location", None),
                }
                for c in computes
            ]
            print(f"        ✅ {len(assets['compute'])} compute resource(s)")
        except Exception as e:
            assets["compute"] = {"error": str(e)}

        # Data assets
        try:
            data_assets = list(ml_client.data.list())
            assets["data_assets"] = [
                {
                    "name": d.name,
                    "version": d.version,
                    "type": str(d.type) if hasattr(d, "type") else None,
                    "path": getattr(d, "path", None),
                    "tags": getattr(d, "tags", {}),
                }
                for d in data_assets
            ]
            print(f"        ✅ {len(assets['data_assets'])} data asset(s)")
        except Exception as e:
            assets["data_assets"] = {"error": str(e)}

        return assets

    except Exception as e:
        return {"error": str(e)}


def process_workspace(monitor_client, logs_client, credential, workspace):
    sub_id = workspace["subscription_id"]
    ws_resource_id = workspace["id"]
    ws_name = workspace["name"]
    rg = workspace["resource_group"]

    print(f"    🧠 {ws_name} ({rg})")

    result = {
        "subscription_id": sub_id,
        "workspace_resource_id": ws_resource_id,
        "workspace_name": ws_name,
        "resource_group": rg,
        "location": workspace.get("location"),
        "diagnostic_settings": {},
        "activity_logs": [],
        "aml_log_tables": {},
        "assets": {},
        "error": None,
    }

    try:
        print(f"      🔍 Checking diagnostic settings...")
        diag = get_diagnostic_settings(monitor_client, ws_resource_id)
        result["diagnostic_settings"] = diag

        print(f"      🔍 Fetching activity logs...")
        activity = get_activity_logs(monitor_client, ws_resource_id)
        result["activity_logs"] = activity
        if isinstance(activity, list):
            print(f"      ✅ {len(activity)} activity log event(s)")
        else:
            print(f"      ⚠️  Activity logs: {activity.get('error', 'unknown')}")

        workspace_ids = extract_workspace_ids(diag) if isinstance(diag, list) else []
        if not workspace_ids and FALLBACK_WORKSPACE_ID:
            workspace_ids = [FALLBACK_WORKSPACE_ID]

        if workspace_ids:
            print(f"      🔍 Querying AML log tables in {len(workspace_ids)} workspace(s)...")
            per_workspace = {}
            for la_ws_id in workspace_ids:
                per_workspace[la_ws_id] = query_aml_log_tables(logs_client, la_ws_id)
            result["aml_log_tables"] = per_workspace

            total = sum(
                len(rows)
                for ws_logs in per_workspace.values()
                for rows in ws_logs.values()
                if isinstance(rows, list)
            )
            print(f"      ✅ {total} AML log event(s)")
        else:
            result["aml_log_tables"] = {"status": "no_log_analytics_workspace_configured"}

        print(f"      🔍 Listing AML assets (models, jobs, endpoints, compute, data)...")
        result["assets"] = get_aml_assets(credential, sub_id, rg, ws_name)

    except Exception as e:
        print(f"      ❌ Unexpected error: {e}")
        result["error"] = str(e)

    return result


def main():
    print("🚀 Azure Machine Learning Logs Collector")
    print("=" * 50)

    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("❌ Missing required env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
        return

    if not AML_SDK_AVAILABLE:
        print("⚠️  azure-ai-ml not installed — asset inventory will be skipped.")
        print("    Install with: pip install azure-ai-ml")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"azure_ml_{timestamp}.json"

    credential = get_credential()
    logs_client = LogsQueryClient(credential)

    subscriptions = get_subscriptions(credential)
    if not subscriptions:
        print("⚠️  No accessible subscriptions found.")

    all_results = []
    total_workspaces = 0
    total_errors = 0

    for sub in subscriptions:
        sub_id = sub["id"]
        sub_name = sub["name"]
        print(f"\n📋 Subscription: {sub_name} ({sub_id})")

        monitor_client = MonitorManagementClient(credential, sub_id)
        workspaces = get_aml_workspaces(credential, sub_id)
        print(f"  ✅ Found {len(workspaces)} AML workspace(s)")

        if not workspaces:
            all_results.append({
                "subscription_id": sub_id,
                "subscription_name": sub_name,
                "status": "no_aml_workspaces_found",
            })
            continue

        for ws in workspaces:
            total_workspaces += 1
            ws_result = process_workspace(monitor_client, logs_client, credential, ws)
            ws_result["subscription_name"] = sub_name
            all_results.append(ws_result)
            if ws_result.get("error"):
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

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"\n🎉 Done!")
    print(f"  📊 Subscriptions processed: {len(subscriptions)}")
    print(f"  🧠 AML workspaces processed: {total_workspaces}")
    print(f"  ❌ Errors: {total_errors}")
    print(f"  💾 Output saved to: {output_file}")


if __name__ == "__main__":
    main()
