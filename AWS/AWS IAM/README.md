# AWS IAM — Log Collector

Connects to **AWS IAM** via boto3, fetches the last 24 hours of IAM management events from CloudTrail, enumerates all current users, roles, groups, and customer-managed policies, describes each with its full configuration, and generates a **CycloneDX 1.6 Bill of Materials** report.

IAM is a global AWS service — its resources exist account-wide and are not scoped to a region. The region setting is used only to route CloudTrail `LookupEvents` calls.

---

## Structure

```
AWS IAM/
├── fetch_iam_logs.py    # Queries CloudTrail for IAM events and enumerates all principals
├── generate_bom.py      # Streams logs, deduplicates entities, produces CycloneDX BOM
├── logs/                # Output: timestamped raw CloudTrail JSON
└── report/              # Output: timestamped CycloneDX BOM reports
```

---

## Setup

Add the following to the root `.env` file:

```env
AWS_DEFAULT_REGION=us-west-2
AWS_IAM_ACCESS_KEY_ID=<your-key-id>
AWS_IAM_SECRET_ACCESS_KEY=<your-secret>
```

### How to create the IAM user and generate credentials

**Step 1 — Create the IAM user**

1. Open the [AWS IAM Console](https://console.aws.amazon.com/iam/)
2. Go to **Users** → **Create user**
3. Enter a username (e.g. `iam-bom-collector`) → **Next**
4. Select **Attach policies directly**
5. Search for and attach these two managed policies:
   - `IAMReadOnlyAccess`
   - `AWSCloudTrail_ReadOnlyAccess`
6. **Next** → **Create user**

**Step 2 — Generate access keys**

1. In IAM, open the user you just created
2. Go to **Security credentials** → **Create access key**
3. Select **Application running outside AWS** → **Next** → **Create access key**
4. Copy the **Access key ID** → set as `AWS_IAM_ACCESS_KEY_ID`
5. Copy the **Secret access key** → set as `AWS_IAM_SECRET_ACCESS_KEY`

> The secret key is shown only once. Store it immediately.

**Step 3 — Set your region**

Your region code is shown in the top-right of the AWS Console (e.g. `us-west-2`, `eu-north-1`). Set it as `AWS_DEFAULT_REGION`. IAM API calls work regardless of region; this setting only affects the CloudTrail endpoint used for event lookup.

---

## Required IAM permissions

| Managed Policy | Why Needed |
| --- | --- |
| `IAMReadOnlyAccess` | Grants `iam:ListUsers`, `iam:ListRoles`, `iam:ListGroups`, `iam:ListPolicies`, `iam:GetUser`, `iam:GetRole`, `iam:GetGroup`, `iam:GetPolicy`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListAttachedRolePolicies`, `iam:ListAttachedGroupPolicies`, `iam:ListGroupsForUser`, `iam:GetAccountSummary` — covers full enumeration and describe |
| `AWSCloudTrail_ReadOnlyAccess` | Grants `cloudtrail:LookupEvents` — fetches IAM management event history |

---

## Usage

```bash
# Run from the AWS IAM directory with the project venv activated
python fetch_iam_logs.py
```

Output files are written to `logs/` and `report/` with timestamps in their filenames. `generate_bom.py` can also be run standalone to reprocess all existing files in `logs/`.

---

## How It Works

`fetch_iam_logs.py` executes the following pipeline on each run:

1. Verifies IAM is reachable via `GetAccountSummary`
2. Pages through `cloudtrail:LookupEvents` for `iam.amazonaws.com` across a 24-hour window
3. Normalises each event: converts `EventTime` to ISO-8601 and unpacks the embedded `CloudTrailEvent` JSON string
4. Enumerates **all current IAM principals and policies** via paginated List calls
5. Merges CloudTrail-referenced entities with enumerated entities, deduplicating by type and name
6. Calls the appropriate Get/Describe API for each entity to capture its current configuration
7. Appends a synthetic `IAMResourceInventory` event per entity so the BOM generator can include describe output without a separate read pass
8. Writes all events to `logs/iam_logs_<timestamp>.json`
9. Invokes `generate_bom.py` to produce `report/bom_<timestamp>.json`

**Resource types collected:**

| Resource Type | Enumerate API | Describe APIs | BOM Properties |
| --- | --- | --- | --- |
| User | `ListUsers` (paginated) | `GetUser`, `ListMFADevices`, `ListAccessKeys`, `ListAttachedUserPolicies`, `ListGroupsForUser` | ARN, user ID, creation date, password last used, MFA count, active/inactive key count, attached policy count, group membership count |
| Role | `ListRoles` (paginated) | `GetRole`, `ListAttachedRolePolicies` | ARN, role ID, creation date, description, max session duration, attached policy count |
| Group | `ListGroups` (paginated) | `GetGroup`, `ListAttachedGroupPolicies` | ARN, group ID, creation date, member count, attached policy count |
| Policy | `ListPolicies(Scope=Local)` (paginated) | `GetPolicy` | ARN, policy ID, creation date, update date, default version ID, attachment count |

> Only **customer-managed policies** are enumerated (`Scope=Local`). AWS-managed policies (hundreds of built-in policies) are excluded as they are not part of the account's resource inventory.

**CloudTrail events captured (examples):**

| Event Name | What Changed |
| --- | --- |
| `CreateUser` | New IAM user created |
| `DeleteUser` | IAM user deleted |
| `CreateRole` | New IAM role created |
| `DeleteRole` | IAM role deleted |
| `CreateGroup` | New IAM group created |
| `DeleteGroup` | IAM group deleted |
| `CreatePolicy` | New customer-managed policy created |
| `DeletePolicy` | Customer-managed policy deleted |
| `AttachUserPolicy` | Managed policy attached to user |
| `DetachUserPolicy` | Managed policy detached from user |
| `AttachRolePolicy` | Managed policy attached to role |
| `DetachRolePolicy` | Managed policy detached from role |
| `PutRolePolicy` | Inline policy added or updated on a role |
| `DeleteRolePolicy` | Inline policy removed from a role |
| `CreateAccessKey` | Access key created for a user |
| `DeleteAccessKey` | Access key deleted |
| `UpdateAccessKey` | Access key activated or deactivated |
| `CreateLoginProfile` | Console password set for a user |
| `UpdateLoginProfile` | Console password changed |
| `EnableMFADevice` | MFA device registered |
| `DeactivateMFADevice` | MFA device deactivated |
| `AddUserToGroup` | User added to group |
| `RemoveUserFromGroup` | User removed from group |
| `UpdateAssumeRolePolicy` | Role trust policy modified |

> **Security note:** `CreateAccessKey`, `DeleteAccessKey`, `AttachUserPolicy`, and `UpdateAssumeRolePolicy` are high-value security signals. Any unexpected modification to IAM principals or their permissions should be investigated.

---

## Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `NoCredentialsError` | Credentials not set in `.env` | Add `AWS_IAM_ACCESS_KEY_ID` and `AWS_IAM_SECRET_ACCESS_KEY` to `MS_logs_collector/.env` |
| `AccessDenied: iam:ListUsers` | IAM user missing the managed policy | Attach `IAMReadOnlyAccess` to the IAM user |
| `AccessDenied: cloudtrail:LookupEvents` | IAM user missing CloudTrail policy | Attach `AWSCloudTrail_ReadOnlyAccess` to the IAM user |
| `NoSuchEntityException` on a Policy | Policy was referenced in a CloudTrail event but deleted before the describe call | Recorded in BOM with `InventoryStatus: NotFound` |
| Many AWS service roles enumerated | `ListRoles` returns all roles including AWS-managed service roles | Expected — service roles are part of the identity BOM. They are described normally |