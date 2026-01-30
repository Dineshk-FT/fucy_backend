from __future__ import annotations

from typing import Any, Iterable, Optional
import json

from azure.identity import DefaultAzureCredential
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

    def __post_init__(self) -> None:
        if not (self.connection_string or self.storage_account_name or self.account_url):
            raise ValueError(
                "Provide one of: connection_string, storage_account_name, or account_url."
            )

        if self.connection_string and (self.storage_account_name or self.account_url):
            raise ValueError(
                "Provide either connection_string OR (storage_account_name/account_url), not both."
            )

    def _build_account_url(self) -> str:
        if self.account_url:
            return self.account_url
        # Default public cloud endpoint; adjust for gov/stack if needed.
        return f"https://{self.storage_account_name}.blob.core.windows.net"

    def _build_credential(self):
        if self.allow_interactive_browser:
            return DefaultAzureCredential(exclude_interactive_browser_credential=False)
        return DefaultAzureCredential()

    def service(self) -> BlobServiceClient:
        """Create a BlobServiceClient using either connection string or AAD."""
        if self.connection_string:
            return BlobServiceClient.from_connection_string(self.connection_string)

        return BlobServiceClient(
            account_url=self._build_account_url(),
            credential=self._build_credential(),
        )

    # ---------- Convenience helpers ----------

    def container(self, container_name: str) -> ContainerClient:
        return self.service().get_container_client(container_name)

    def blob_client(self, container_name: str, blob_name: str) -> BlobClient:
        return self.container(container_name).get_blob_client(blob_name)

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
