# Amazon SageMaker — CloudTrail Log Collector

Connects to **AWS CloudTrail** via boto3, fetches the last 24 hours of SageMaker API activity, describes each discovered resource (training jobs, models, endpoints, pipelines, notebooks, feature groups, domains), and generates a **CycloneDX 1.6 Bill of Materials** report.

---

## Structure

```
Amazon SageMaker/
├── fetch_sagemaker_logs.py    # Queries CloudTrail for SageMaker events and describes each resource, writes logs/
├── generate_bom.py            # Streams logs, deduplicates entities, produces CycloneDX 1.6 BOM
├── logs/                      # Output: timestamped raw CloudTrail JSON
└── report/                    # Output: timestamped CycloneDX BOM reports
```

---

## Setup

Add the following to the root `.env` file:

```env
AWS_DEFAULT_REGION=eu-north-1
AWS_SAGEMAKER_ACCESS_KEY_ID=<your-key-id>
AWS_SAGEMAKER_SECRET_ACCESS_KEY=<your-secret>
```

### How to create the IAM user and generate credentials

**Step 1 — Create the IAM user**

1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/)
2. Go to **Users** → **Create user**
3. Enter a username (e.g. `sagemaker-bom-collector`) → **Next**
4. Select **Attach policies directly**
5. Search for and attach both managed policies:
   - `AmazonSageMakerReadOnly`
   - `AWSCloudTrail_ReadOnlyAccess`
6. **Next** → **Create user**

**Step 2 — Generate access keys**

1. In IAM, open the user you just created
2. Go to **Security credentials** → **Create access key**
3. Select **Application running outside AWS** → **Next** → **Create access key**
4. Copy the **Access key ID** → set as `AWS_SAGEMAKER_ACCESS_KEY_ID`
5. Copy the **Secret access key** → set as `AWS_SAGEMAKER_SECRET_ACCESS_KEY`

> The secret key is shown only once. Store it immediately.

**Step 3 — Set your region**

Your SageMaker region code is shown in the top-right of the AWS Console (e.g. `eu-north-1`, `us-east-1`, `ap-southeast-1`). Set it as `AWS_DEFAULT_REGION`.

---

## Required IAM permissions

Attach these two AWS managed policies to the IAM user:

| Managed Policy | Why Needed |
| --- | --- |
| `AmazonSageMakerReadOnly` | Grants `sagemaker:List*` and `sagemaker:Describe*` — covers the availability probe and all resource describe calls |
| `AWSCloudTrail_ReadOnlyAccess` | Grants `cloudtrail:LookupEvents` — fetches SageMaker API activity from CloudTrail event history |

---

## Usage

```bash
# Run from the Amazon SageMaker directory with the project venv activated
python fetch_sagemaker_logs.py
```

Output files are written to `logs/` and `report/` with timestamps in their filenames. `generate_bom.py` can also be run standalone to reprocess all existing files in `logs/`.

---

## How It Works

`fetch_sagemaker_logs.py` executes the following pipeline on each run:

1. Verifies SageMaker is reachable via `ListEndpoints`
2. Pages through `cloudtrail:LookupEvents` for `sagemaker.amazonaws.com` across a 24-hour window
3. Normalises each event: converts `EventTime` to ISO-8601 and unpacks the embedded `CloudTrailEvent` JSON string
4. Extracts every unique resource reference (training job, model, endpoint, etc.) from `requestParameters`
5. Calls the appropriate SageMaker `Describe*` API for each resource to capture status, ARN, instance type, and other metadata
6. Appends a synthetic `SageMakerResourceInventory` event per resource so the BOM generator can include describe output without a separate read pass
7. Writes all events to `logs/sagemaker_logs_<timestamp>.json`
8. Invokes `generate_bom.py` to produce `report/bom_<timestamp>.json`

`generate_bom.py` streams log events using `ijson`, deduplicates entities via a Bloom filter backed by an exact set, tracks every resource each IAM principal accessed across all events (not just first occurrence), and serialises the results into a CycloneDX 1.6 document.

**Resource types collected:**

| Resource Type | requestParameters key | Describe API |
| --- | --- | --- |
| TrainingJob | `trainingJobName` | `DescribeTrainingJob` |
| Model | `modelName` | `DescribeModel` |
| Endpoint | `endpointName` | `DescribeEndpoint` |
| EndpointConfig | `endpointConfigName` | `DescribeEndpointConfig` |
| Pipeline | `pipelineName` | `DescribePipeline` |
| NotebookInstance | `notebookInstanceName` | `DescribeNotebookInstance` |
| FeatureGroup | `featureGroupName` | `DescribeFeatureGroup` |
| Domain | `domainId` | `DescribeDomain` |

---

## Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `NoCredentialsError` | Credentials not set in `.env` | Add `AWS_SAGEMAKER_ACCESS_KEY_ID` and `AWS_SAGEMAKER_SECRET_ACCESS_KEY` to `MS_logs_collector/.env` |
| `AccessDenied: cloudtrail:LookupEvents` | IAM user missing CloudTrail permission | Add `cloudtrail:LookupEvents` to the inline policy |
| `AccessDenied: sagemaker:Describe*` | IAM user missing SageMaker describe permissions | Add the missing `sagemaker:Describe*` action to the inline policy |
| 0 events from `sagemaker.amazonaws.com` | No SageMaker API calls in the last 24 hours | Normal — events appear once SageMaker APIs are used |
| Resource listed as `NotFound` | Resource was deleted between the CloudTrail event and the describe call | Expected — the event is still recorded in the BOM with `InventoryStatus: NotFound` |
| Empty BOM | No SageMaker activity in the last 24 hours | Expected — logs populate once SageMaker APIs are called |
