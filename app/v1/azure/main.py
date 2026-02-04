
from __future__ import annotations

from typing import Any, Iterable, Optional
import json, re

# from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContainerClient, BlobClient

class AzureBlobClient:
    """
    Thin wrapper around Azure Blob Storage SDK with sensible auth defaults.

    Auth options:
      1) AAD (recommended): supply storage_account_name (or account_url)
         - locally: `az login`
         - in Azure: Managed Identity
      2) Connection string (quick/dev): supply connection_string
    """

    # --- Auth inputs ---
    storage_account_name: Optional[str] = None
    account_url: Optional[str] = None
    connection_string: Optional[str] = None

    # --- Credential behavior ---
    allow_interactive_browser: bool = False

    # def __init__(
    #     *,
    #     storage_account_name: Optional[str] = None,
    #     account_url: Optional[str] = None,
    #     connection_string: Optional[str] = None,
    #     allow_interactive_browser: bool = False,
    # ) -> None:
    #     self.storage_account_name = storage_account_name
    #     self.account_url = account_url
    #     self.connection_string = connection_string
    #     self.allow_interactive_browser = allow_interactive_browser
    #     if self.allow_interactive_browser:
    #         return DefaultAzureCredential(exclude_interactive_browser_credential=False)
    #     return DefaultAzureCredential()

    def service(self) -> BlobServiceClient:
        """Create a BlobServiceClient using either connection string or AAD."""
        if self.connection_string:
            return BlobServiceClient.from_connection_string(self.connection_string)

        return BlobServiceClient(
            account_url=self._build_account_url(),
            credential=self._build_credential(),
        )

    def container(self, container_name: str) -> ContainerClient:
        """Create a ContainerClient for a given container."""
        return self.service().get_container_client(container_name)

    def blob_client(self, container_name: str, blob_name: str) -> BlobClient:
        """Create a BlobClient for a given container + blob."""
        return self.service().get_blob_client(container=container_name, blob=blob_name)

    def ensure_container(self, container_name: str) -> None:
        """Create the container if it doesn't exist (idempotent)."""
        c = self.container(container_name)
        try:
            c.create_container()
        except Exception as e:
            # If it already exists, ignore; otherwise raise.
            # The SDK raises ResourceExistsError, but we avoid importing extra types.
            msg = str(e).lower()
            if "already exists" not in msg and "resourceexists" not in msg:
                raise

    def upload_json(
        self,
        container_name: str,
        blob_name: str,
        obj: Any,
        *,
        overwrite: bool = True,
        content_type: str = "application/json",
    ) -> None:
        bc = self.blob_client(container_name, blob_name)
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        bc.upload_blob(
            payload,
            overwrite=overwrite,
            content_type=content_type,
        )

    def download_json(self, container_name: str, blob_name: str) -> Any:
        bc = self.blob_client(container_name, blob_name)
        raw = bc.download_blob().readall()
        return json.loads(raw)

    def list_json(  
        self,
        container_name: str,
        *,
        prefix: str = "",
    ) -> Iterable[str]:
        c = self.container(container_name)
        for b in c.list_blobs(name_starts_with=prefix):
            if b.name.endswith(".json"):
                yield b.name

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
