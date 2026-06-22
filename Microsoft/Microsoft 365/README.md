# Microsoft 365 — Audit Log Collector

Collects audit logs from the Microsoft 365 Management Activity API across all major workloads for a rolling 24-hour window, and automatically generates a CycloneDX 1.6 Bill of Materials report on each run.

---

## Structure

```
Microsoft 365/
├── fetch_m365_logs.py    # Main script — fetches and aggregates M365 audit logs
├── generate_bom.py       # Streams collected logs and produces a CycloneDX 1.6 BOM
├── logs/                 # Output: timestamped audit log JSON files
└── report/               # Output: timestamped CycloneDX BOM reports
```

---

## Setup

Add the following to the root `.env` file:

```env
M365_TENANT_ID=<your-azure-ad-tenant-id>
M365_CLIENT_ID=<your-app-client-id>
M365_CLIENT_SECRET=<your-app-client-secret>
```

The registered Azure AD application requires the following **application permission** (not delegated) with admin consent granted:

| API | Permission |
| --- | --- |
| Office 365 Management APIs | `ActivityFeed.Read` |

---

## Usage

```bash
# Run from the Microsoft 365 directory with the project venv activated
python fetch_m365_logs.py
```

Output files are written to `logs/` and `report/` with timestamps in their filenames. `generate_bom.py` can also be run standalone to reprocess all existing files in `logs/`.

---

## How It Works

`fetch_m365_logs.py` executes the following pipeline on each run:

1. Acquires an OAuth2 bearer token via MSAL Client Credentials flow
2. Enables subscriptions for all five content types — this is idempotent and safe to re-run
3. Lists all available content blobs within the last 24 hours for each content type
4. Downloads each blob and accumulates the records
5. Writes all records to `logs/m365_audit_logs_<timestamp>.json`
6. Invokes `generate_bom.py` to produce `report/bom_<timestamp>.json` from the new file

`generate_bom.py` streams log events using `ijson`, deduplicates entities via a Bloom filter backed by an exact set, and serialises the results into a CycloneDX 1.6 document containing components (service principals, client apps) and services (workloads).

**Content types collected:**

| Content Type | Coverage |
| --- | --- |
| `Audit.AzureActiveDirectory` | Sign-ins, role assignments, app registrations |
| `Audit.Exchange` | Mailbox logins, message operations, folder changes |
| `Audit.SharePoint` | File access, sharing events, page views |
| `Audit.General` | Microsoft Teams, Planner, Stream |
| `DLP.All` | Policy matches, sensitive data detections |

