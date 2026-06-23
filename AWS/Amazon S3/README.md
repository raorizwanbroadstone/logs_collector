# Amazon S3 — CloudTrail Log Collector

Connects to **AWS CloudTrail** via boto3, fetches the last 24 hours of S3 API activity, enumerates top-level bucket contents, and generates a **CycloneDX 1.6 Bill of Materials** report. Reuses the same IAM user and CloudTrail credentials as the Bedrock collector.

---

## Structure

```
Amazon S3/
├── fetch_s3_logs.py    # Queries CloudTrail for S3 events and enumerates bucket contents, writes logs/
├── generate_bom.py     # Streams logs, deduplicates entities, produces CycloneDX 1.6 BOM
├── logs/               # Output: timestamped raw CloudTrail JSON
└── report/             # Output: timestamped CycloneDX BOM reports
```

---

## Setup

Add the following to the root `.env` file:

```env
AWS_DEFAULT_REGION=eu-north-1
AWS_S3_ACCESS_KEY_ID=<your-key-id>
AWS_S3_SECRET_ACCESS_KEY=<your-secret>
```

If `AWS_S3_ACCESS_KEY_ID` is absent, the script falls back to `AWS_BEDROCK_ACCESS_KEY_ID` automatically — both collectors use the same IAM user (`amazon_bedrock_log`) and the `cloudtrail:LookupEvents` permission already covers all AWS event sources.

The IAM user requires:

| Permission | Why Needed |
| --- | --- |
| `cloudtrail:LookupEvents` | Fetches CloudTrail event history for S3 API activity |
| `cloudtrail:DescribeTrails` | Checks whether a Trail is configured for S3 data events |
| `s3:ListAllMyBuckets` | Connectivity probe in `check_s3_availability()` |
| `s3:GetBucketLocation` | Determines which region each bucket resides in |
| `s3:ListBucket` | Enumerates top-level prefixes and objects per bucket |

---

## Usage

```bash
# Run from the Amazon S3 directory with the project venv activated
python fetch_s3_logs.py
```

Output files are written to `logs/` and `report/` with timestamps in their filenames. `generate_bom.py` can also be run standalone to reprocess all existing files in `logs/`.

---

## How It Works

`fetch_s3_logs.py` executes the following pipeline on each run:

1. Verifies S3 is reachable via `ListBuckets`
2. Pages through `cloudtrail:LookupEvents` for both S3 event sources across a 24-hour window
3. Normalises each event: converts `EventTime` to ISO-8601 and unpacks the embedded `CloudTrailEvent` JSON string
4. Enumerates top-level contents (prefixes and objects) for every unique bucket observed in the events
5. Appends a synthetic `BucketContentsInventory` event per bucket so the BOM generator can include inventory data without a separate read pass
6. Writes all events to `logs/s3_logs_<timestamp>.json`
7. Invokes `generate_bom.py` to produce `report/bom_<timestamp>.json`

`generate_bom.py` streams log events using `ijson`, deduplicates entities via a Bloom filter backed by an exact set, tracks every bucket each IAM principal accessed across all events (not just first occurrence), and serialises the results into a CycloneDX 1.6 document.

**Event sources collected:**

| Event Source | Coverage |
| --- | --- |
| `s3.amazonaws.com` | Bucket-level and object-level S3 operations |
| `s3control.amazonaws.com` | S3 Batch Operations, Access Points, Multi-Region Access Points |

> **Note:** Free CloudTrail event history captures management events only (`ListBuckets`, `CreateBucket`, `PutBucketPolicy`). Object-level operations (`GetObject`, `PutObject`) are data events and require a paid CloudTrail Trail with S3 data event logging enabled.

---

## Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `NoCredentialsError` | Neither S3 nor Bedrock credentials set in `.env` | Add `AWS_S3_ACCESS_KEY_ID` or `AWS_BEDROCK_ACCESS_KEY_ID` to `MS_logs_collector/.env` |
| `AccessDenied: cloudtrail:LookupEvents` | IAM user missing CloudTrail permission | Add `cloudtrail:LookupEvents` to the user's inline policy |
| 0 events from `s3control.amazonaws.com` | No S3 Batch or Access Point operations in the last 24 hours | Normal — only fires when S3 Control APIs are used |
| Object-level events missing | Data events not enabled on a Trail | Configure a Trail in AWS Console → CloudTrail → enable S3 data events |
| Empty BOM | No S3 activity in the last 24 hours | Expected — logs populate once S3 APIs are called |
