# Azure OpenAI and ML — Diagnostic Log Collector

This module connects to an **Azure Log Analytics Workspace** and runs KQL (Kusto Query Language) queries to retrieve diagnostic logs from Azure Cognitive Services and Azure OpenAI resources. Results are saved as timestamped JSON files for analysis and retention.

---

## Folder Structure

```
Azure OpenAI/
├── fetch_azure_diagnostic_logs.py    # Main script — queries Log Analytics and writes output
└── azure_diagnostic_logs/            # Output directory for JSON result files
    ├── workspace_test_2026-06-17_09-05-02.json
    ├── workspace_test_2026-06-17_09-52-29.json
    └── workspace_test_2026-06-17_10-04-24.json
```

---

## Script: `fetch_azure_diagnostic_logs.py`

### Purpose
Authenticates with Azure using a Service Principal, connects to a Log Analytics Workspace, executes a suite of diagnostic KQL queries, and saves the results to a JSON file.

### Configuration

These values are read from environment variables (set in the root `.env` file):

| Variable | Description |
|---|---|
| `AZURE_TENANT_ID` | Azure Active Directory tenant ID |
| `AZURE_CLIENT_ID` | Service principal application (client) ID |
| `AZURE_CLIENT_SECRET` | Service principal client secret |
| `AZURE_WORKSPACE_ID` | Log Analytics Workspace resource ID |

Two constants control runtime behavior:

```python
HOURS_BACK = 24          # How far back (in hours) to query logs
OUTPUT_DIR = "azure_diagnostic_logs"   # Directory for output JSON files
```

### Authentication

Uses `azure-identity`'s `ClientSecretCredential`:

```python
credential = ClientSecretCredential(
    tenant_id=AZURE_TENANT_ID,
    client_id=AZURE_CLIENT_ID,
    client_secret=AZURE_CLIENT_SECRET
)
```

The credential is passed to `LogsQueryClient` from `azure-monitor-query` to execute workspace queries.

### Functions

#### `get_credential()`
Instantiates and returns a `ClientSecretCredential` using environment variables. Raises `ValueError` if any required variable is missing.

#### `run_query(client, query, query_name)`
Executes a single KQL query against the workspace and returns a list of row dictionaries.

- Converts all row values to JSON-serializable Python types (handles `datetime`, `timedelta`, `UUID`, etc.)
- Returns `[]` on query error, printing the exception
- Time range is `timedelta(hours=HOURS_BACK)` relative to now

#### `main()`
Orchestrates the full workflow:
1. Loads environment variables from `.env`
2. Creates the Azure credential and `LogsQueryClient`
3. Runs all four queries (see below)
4. Writes aggregated results to a timestamped JSON file in `azure_diagnostic_logs/`

### KQL Queries Executed

| Query Name | KQL | Purpose |
|---|---|---|
| `Connection_Test` | `print "Connected"` | Confirms workspace connectivity |
| `Workspace_Time` | `print now()` | Returns current server time from the workspace |
| `Table_Counts` | `union withsource=TableName *  \| summarize count() by TableName` | Lists all tables and their record counts |
| `AzureDiagnostics_Sample` | `AzureDiagnostics \| take 10` | Returns up to 10 sample diagnostic records |

### Output Format

Results are written to `azure_diagnostic_logs/workspace_test_YYYY-MM-DD_HH-MM-SS.json`:

```json
{
  "timestamp": "2026-06-17T10:04:24.123456",
  "workspace_id": "<workspace-id>",
  "hours_back": 24,
  "queries": {
    "Connection_Test": [...],
    "Workspace_Time": [...],
    "Table_Counts": [...],
    "AzureDiagnostics_Sample": [...]
  }
}
```

### Running the Script

```bash
# From the project root, with venv activated
cd "Azure OpenAI and ML"
python fetch_azure_diagnostic_logs.py
```

A new timestamped JSON file will appear in `azure_diagnostic_logs/` upon success.

---

## Output Directory: `azure_diagnostic_logs/`

See the [azure_diagnostic_logs/README.md](azure_diagnostic_logs/README.md) for details on output file schema and sample data.

---

## Azure Resource Context

This module targets **Azure Cognitive Services / Azure OpenAI** resources. Diagnostic logs are ingested into the Log Analytics Workspace from resources like:

```
/subscriptions/<sub-id>/resourceGroups/<rg>/providers/
  Microsoft.CognitiveServices/accounts/AOAI-MYCOMPANY-001
```

### AzureDiagnostics Record Fields

Key fields present in `AzureDiagnostics` records from Cognitive Services:

| Field | Description |
|---|---|
| `TenantId` | Log Analytics workspace tenant |
| `TimeGenerated` | UTC timestamp of the log event |
| `ResourceId` | Full Azure resource identifier |
| `Category` | Log category (e.g., `Audit`) |
| `OperationName` | Operation performed (e.g., `CreateResource`) |
| `ResultType` | Outcome of the operation |
| `SubscriptionId` | Azure subscription |
| `ResourceGroup` | Resource group name |
| `ResourceProvider` | `MICROSOFT.COGNITIVESERVICES` |
| `ResourceType` | Resource type within the provider |
| `ResourceGroup` | Resource group for the resource |

---

## Required Azure Permissions

The service principal used must have the following role on the Log Analytics Workspace:

- **Log Analytics Reader** — allows querying workspace data via the API

To assign via Azure CLI:
```bash
az role assignment create \
  --assignee <client-id> \
  --role "Log Analytics Reader" \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>
```

---

## Troubleshooting

| Issue | Likely Cause | Resolution |
|---|---|---|
| `ValueError: Missing environment variable` | `.env` not loaded or variable not set | Check `.env` file exists and contains all 4 Azure variables |
| `AuthenticationError` | Wrong client ID, secret, or tenant | Verify service principal credentials in Azure Portal |
| Empty `AzureDiagnostics_Sample` results | No logs ingested yet | Enable diagnostic settings on the target Azure resource |
| `WorkspaceNotFound` | Wrong `AZURE_WORKSPACE_ID` | Confirm the workspace ID in Azure Portal under Log Analytics Workspace > Overview |
