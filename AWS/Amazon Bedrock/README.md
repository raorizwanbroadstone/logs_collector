# Amazon Bedrock — CloudTrail Log Collector

Connects to **AWS CloudTrail** via boto3, fetches the last 24 hours of API activity across all Amazon Bedrock event sources, deduplicates entities using a Bloom filter, and generates a **CycloneDX 1.6 Bill of Materials** report on each run.

---

## Structure

```
Amazon Bedrock/
├── fetch_bedrock_logs.py   # Main script — queries CloudTrail and writes logs/
├── generate_bom.py         # Streams collected logs and produces a CycloneDX 1.6 BOM
├── logs/                   # Output: timestamped raw CloudTrail JSON files
└── report/                 # Output: timestamped CycloneDX BOM reports
```

---

## Setup

Add the following to the root `.env` file:

```env
AWS_DEFAULT_REGION=eu-north-1
AWS_BEDROCK_ACCESS_KEY_ID=<your-key-id>
AWS_BEDROCK_SECRET_ACCESS_KEY=<your-secret>
```

The IAM user (`amazon_bedrock_log`) requires the following permissions attached as a custom inline policy:

| Service | Permissions |
| --- | --- |
| AWS CloudTrail | `cloudtrail:LookupEvents`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| Amazon Bedrock | `bedrock:ListFoundationModels`, `bedrock:ListAgents`, `bedrock:ListKnowledgeBases` |

---

## Usage

```bash
# Run from the Amazon Bedrock directory with the project venv activated
python fetch_bedrock_logs.py
```

Output files are written to `logs/` and `report/` with timestamps in their filenames. `generate_bom.py` can also be run standalone to reprocess all existing files in `logs/`.

---

## How It Works

`fetch_bedrock_logs.py` executes the following pipeline on each run:

1. Verifies Bedrock is available in the configured region via `ListFoundationModels`
2. Pages through `cloudtrail:LookupEvents` for each event source across a 24-hour window
3. Normalises each event — converts `EventTime` to ISO-8601 and unpacks the embedded `CloudTrailEvent` JSON string
4. Writes all events to `logs/bedrock_logs_<timestamp>.json`
5. Invokes `generate_bom.py` to produce `report/bom_<timestamp>.json` from the new file

`generate_bom.py` streams log events using `ijson`, deduplicates entities via a Bloom filter backed by an exact set, and serialises the results into a CycloneDX 1.6 document containing components (IAM principals, Bedrock agents) and services (foundation models).

**Event sources collected:**

| Event Source | Coverage |
| --- | --- |
| `bedrock.amazonaws.com` | Foundation model invocations, model listing, guardrails, customisation jobs |
| `bedrock-agent.amazonaws.com` | Agents control plane — creating, updating, and deleting agents and knowledge bases |
| `bedrock-agent-runtime.amazonaws.com` | Agents data plane — invoking agents and querying knowledge bases |
