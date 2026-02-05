
from __future__ import annotations

from typing import Any, Iterable, Optional
import json, re

# from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContainerClient, BlobClient

def main():
    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")
    for b in rag_container.list_blobs(name_starts_with="clause"):
        name = b.name
        bc = rag_container.get_blob_client(name)
        raw = bc.download_blob().readall()
        clause = json.loads(raw)
        # number = int(re.search(r'-(\d+)\.json', name).group(1))
        print(name)

    
main()
