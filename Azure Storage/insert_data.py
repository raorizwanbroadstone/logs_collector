from azure.storage.blob import BlobServiceClient
import os
from dotenv import load_dotenv
load_dotenv()

conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

client = BlobServiceClient.from_connection_string(conn_str)

container = client.get_container_client("rag-documents")

# Create the container if it doesn't exist yet
try:
    container.create_container()
    print("Container created.")
except Exception:
    pass  # already exists

container.upload_blob("test.txt", b"hello", overwrite=True)

blob = container.get_blob_client("test.txt")
blob.download_blob().readall()

blob.delete_blob()