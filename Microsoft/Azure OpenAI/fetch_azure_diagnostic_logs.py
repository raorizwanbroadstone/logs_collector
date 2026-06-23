import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from dotenv import load_dotenv
import generate_bom

load_dotenv()

TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")

LOOKBACK_HOURS = 24
OUTPUT_DIR = Path(__file__).parent / "logs"


def get_credential():
    return ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )


def run_query(client, query: str, query_name: str):
    print(f"Running query: {query_name}...")

    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

        response = client.query_workspace(
            workspace_id=WORKSPACE_ID,
            query=query,
            timespan=(start_time, end_time),
        )

        if response.status == LogsQueryStatus.SUCCESS:
            if not response.tables:
                print(f"  {query_name}: No tables returned.")
                return []
            table = response.tables[0]
            columns = [col.name if hasattr(col, "name") else str(col) for col in table.columns]
            results = [dict(zip(columns, row)) for row in table.rows]
            print(f"  {query_name}: {len(results)} record(s) found.")
            return results

        print(f"  {query_name}: Query failed.")
        return []

    except Exception as error:
        print(f"  Error in {query_name}: {error}")
        return []


def main():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID]):
        print("Missing required environment variables: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_WORKSPACE_ID")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    credential = get_credential()
    client = LogsQueryClient(credential)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

    queries = {
        "Connection_Test": """
            print Message="Connected to Log Analytics Workspace"
        """,
        "Workspace_Time": """
            print CurrentTime=now()
        """,
        "Table_Counts": """
            search *
            | summarize Count=count() by $table
            | order by Count desc
        """,
        "AzureDiagnostics_Sample": """
            AzureDiagnostics
            | take 10
        """,
    }

    all_results = {name: run_query(client, query, name) for name, query in queries.items()}

    output_data = {
        "collectionTime": datetime.now(timezone.utc).isoformat(),
        "workspaceId": WORKSPACE_ID,
        "message": (
            "If Connection_Test and Workspace_Time return data but "
            "Table_Counts is empty, the workspace is accessible but "
            "currently has no ingested logs."
        ),
        "results": all_results,
    }

    output_file = OUTPUT_DIR / f"azure_openai_{timestamp}.json"

    with open(output_file, "w", encoding="utf-8") as output_file_handle:
        json.dump(output_data, output_file_handle, indent=2, default=str)

    print(f"\nCompleted. Output saved to: {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)

    if not all_results.get("Table_Counts"):
        print("\nWorkspace is reachable but currently contains no data.")


if __name__ == "__main__":
    main()
