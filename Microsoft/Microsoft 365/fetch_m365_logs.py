import msal
import requests
import json
from datetime import datetime, timedelta, UTC
from pathlib import Path
import time
import os
from dotenv import load_dotenv
import generate_bom
load_dotenv()

TENANT_ID = os.getenv("M365_TENANT_ID")
CLIENT_ID = os.getenv("M365_CLIENT_ID")
CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET")

CONTENT_TYPES = [
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
    "DLP.All",
]

collection_timestamp = datetime.now(UTC)
START_TIME = (collection_timestamp - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
END_TIME = collection_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(
    LOG_DIR, f"m365_audit_logs_{collection_timestamp.strftime('%Y%m%d_%H%M%S')}.json"
)


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


def list_content(token, content_type):
    url = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed/subscriptions/content"
    params = {
        "contentType": content_type,
        "startTime": START_TIME,
        "endTime": END_TIME,
    }
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()


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


def fetch_content_blob(token, content_uri):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(content_uri, headers=headers)
    response.raise_for_status()
    return response.json()


def main():
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
            content_list = list_content(token, content_type)
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

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output_file:
        json.dump(audit_log_records, output_file, indent=2, ensure_ascii=False)

    print(f"\nCompleted. Total events fetched: {len(audit_log_records)}")
    print(f"Saved to: {OUTPUT_FILE}")

    print("\nGenerating BOM report...")
    generate_bom.main(target_file=Path(OUTPUT_FILE))


if __name__ == "__main__":
    main()