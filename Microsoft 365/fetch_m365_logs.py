import msal
import requests
import json
from datetime import datetime, timedelta, UTC
import time
import os
from dotenv import load_dotenv
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

now = datetime.now(UTC)
START_TIME = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
END_TIME = now.strftime("%Y-%m-%dT%H:%M:%SZ")

OUTPUT_FILE = "m365_audit_logs.json"

def get_access_token():
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=["https://manage.office.com/.default"])
    
    if "access_token" in result:
        print("✅ Token acquired successfully")
        return result["access_token"]
    else:
        raise Exception(f"Token error: {result.get('error_description')}")

def list_content(token, content_type):
    url = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed/subscriptions/content"
    params = {
        "contentType": content_type,
        "startTime": START_TIME,
        "endTime": END_TIME
    }
    headers = {"Authorization": f"Bearer {token}"}
    
    resp = requests.get(url, headers=headers, params=params)
    
    print(f"Status for {content_type}: {resp.status_code}")
    if resp.status_code != 200:
        print("Response:", resp.text[:500])  # Show error details
    
    resp.raise_for_status()
    return resp.json()

def start_subscription(token, content_type):
    """Start (or enable) subscription for a content type - one time only"""
    url = f"https://manage.office.com/api/v1.0/{TENANT_ID}/activity/feed/subscriptions/start"
    params = {
        "contentType": content_type,
        "PublisherIdentifier": TENANT_ID   # Important for some tenants
    }
    headers = {"Authorization": f"Bearer {token}"}
    
    resp = requests.post(url, headers=headers, params=params)
    
    print(f"Start subscription for {content_type}: {resp.status_code}")
    if resp.status_code in [200, 201]:
        print(f"  ✅ Subscription started/enabled for {content_type}")
    elif resp.status_code == 400 and "AF20024" in resp.text:  # Already enabled
        print(f"  ✅ Subscription already enabled for {content_type}")
    else:
        print("  Response:", resp.text[:400])
    
    # We don't raise error here - continue anyway
    return resp.status_code in [200, 201, 400]


def main():
    token = get_access_token()
    all_logs = []

    print("Starting/enabling subscriptions...")
    for ct in CONTENT_TYPES:
        start_subscription(token, ct)
        time.sleep(1)

    print("\nFetching content blobs...")
    for ct in CONTENT_TYPES:
        print(f"\nFetching {ct} logs...")
        try:
            content_list = list_content(token, ct)
            print(f"  Found {len(content_list)} content blobs for {ct}")
            
            for item in content_list:
                print(f"    Downloading blob: {item.get('contentId')}")
                try:
                    logs = fetch_content_blob(token, item["contentUri"])
                    all_logs.extend(logs)
                except Exception as e:
                    print(f"      Failed to download blob: {e}")
                time.sleep(0.3)
        except Exception as e:
            print(f"  Error fetching {ct}: {e}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_logs, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Done! Total events fetched: {len(all_logs)}")
    print(f"Saved to {OUTPUT_FILE}")

def fetch_content_blob(token, content_uri):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(content_uri, headers=headers)
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    main()