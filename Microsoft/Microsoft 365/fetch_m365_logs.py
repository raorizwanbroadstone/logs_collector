import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import msal
import requests
from dotenv import load_dotenv
import generate_bom

load_dotenv()

TENANT_ID = os.getenv("M365_TENANT_ID")
CLIENT_ID = os.getenv("M365_CLIENT_ID")
CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET")

LOOKBACK_HOURS = 24
OUTPUT_DIR = Path(__file__).parent / "logs"

CONTENT_TYPES = [
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All",
]


def get_access_token():
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=["https://manage.office.com/.default"])

    if "access_token" in result:
        print("Token acquired successfully.")
        return result["access_token"]
    else:
        raise Exception(f"Token acquisition failed: {result.get('error_description')}")


def start_subscription(token, content_type):
    """Enable a subscription for the given content type. Idempotent — AF20024 means already active."""
    url = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed/subscriptions/start"
    params = {
        "contentType": content_type,
        "PublisherIdentifier": TENANT_ID,
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(url, headers=headers, params=params)

    if response.status_code in [200, 201]:
        print(f"Subscription started: {content_type}")
    elif response.status_code == 400 and "AF20024" in response.text:
        print(f"Subscription already active: {content_type}")
    else:
        print(f"Subscription start returned {response.status_code} for {content_type}: {response.text[:400]}")

    return response.status_code in [200, 201, 400]


def list_content(token, content_type, start_time, end_time):
    url = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed/subscriptions/content"
    params = {
        "contentType": content_type,
        "startTime": start_time,
        "endTime": end_time,
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


def fetch_content_blob(token, content_uri):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(content_uri, headers=headers)
    response.raise_for_status()
    return response.json()


def main():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("Missing required environment variables: M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_file = OUTPUT_DIR / f"m365_audit_logs_{timestamp}.json"

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    token = get_access_token()
    audit_log_records = []

    print("Enabling subscriptions...")
    for content_type in CONTENT_TYPES:
        start_subscription(token, content_type)
        time.sleep(1)

    print("\nFetching content blobs...")
    for content_type in CONTENT_TYPES:
        print(f"\nFetching {content_type} logs...")
        try:
            content_list = list_content(token, content_type, start_time_str, end_time_str)
            print(f"  Found {len(content_list)} content blobs.")

            for content_blob in content_list:
                print(f"    Downloading blob: {content_blob.get('contentId')}")
                try:
                    blob_records = fetch_content_blob(token, content_blob["contentUri"])
                    audit_log_records.extend(blob_records)
                except Exception as error:
                    print(f"      Failed to download blob: {error}")
                time.sleep(0.3)
        except Exception as error:
            print(f"  Error fetching {content_type}: {error}")

    with open(output_file, "w", encoding="utf-8") as output_file_handle:
        json.dump(audit_log_records, output_file_handle, indent=2, ensure_ascii=False)

    print(f"\nCompleted.")
    print(f"  Total events fetched: {len(audit_log_records)}")
    print(f"  Output saved to:      {output_file}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=output_file)


if __name__ == "__main__":
    main()
