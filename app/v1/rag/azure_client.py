# =============================================================================
# azure_client.py — Azure Blob Storage client utilities
# =============================================================================

import json
import xml.etree.ElementTree as ET
from io import BytesIO
from typing import Optional, List, Tuple, Any

from azure.storage.blob import BlobServiceClient, ContainerClient

from app.v1.rag.config import AZURE_CONNECTION_STRING, AZURE_CONTAINER_NAME, AZURE_PATHS


class AzureBlobClient:
    """Client for Azure Blob Storage operations."""
    
    def __init__(self):
        self.connection_string = AZURE_CONNECTION_STRING
        self.container_name = AZURE_CONTAINER_NAME
        self._service_client: Optional[BlobServiceClient] = None
        self._container_client: Optional[ContainerClient] = None
    
    @property
    def service_client(self) -> BlobServiceClient:
        if self._service_client is None:
            self._service_client = BlobServiceClient.from_connection_string(
                self.connection_string
            )
        return self._service_client
    
    @property
    def container_client(self) -> ContainerClient:
        if self._container_client is None:
            self._container_client = self.service_client.get_container_client(
                self.container_name
            )
        return self._container_client
    
    def download_blob(self, blob_path: str) -> Optional[bytes]:
        """Download blob content as bytes."""
        try:
            blob_client = self.container_client.get_blob_client(blob_path)
            return blob_client.download_blob().readall()
        except Exception as e:
            print(f"  ⚠️ Failed to download {blob_path}: {e}")
            return None
    
    def download_json(self, blob_path: str) -> Optional[dict]:
        """Download and parse JSON blob."""
        data = self.download_blob(blob_path)
        if data:
            try:
                return json.loads(data.decode('utf-8'))
            except json.JSONDecodeError as e:
                print(f"  ⚠️ JSON parse error for {blob_path}: {e}")
        return None
    
    def download_xml(self, blob_path: str) -> Optional[ET.Element]:
        """Download and parse XML blob."""
        data = self.download_blob(blob_path)
        if data:
            try:
                return ET.parse(BytesIO(data)).getroot()
            except Exception as e:
                print(f"  ⚠️ XML parse error for {blob_path}: {e}")
        return None
    
    def download_text(self, blob_path: str) -> Optional[str]:
        """Download blob as text."""
        data = self.download_blob(blob_path)
        return data.decode('utf-8') if data else None
    
    def list_blobs(self, prefix: str) -> List[str]:
        """List all blobs with given prefix."""
        try:
            blobs = self.container_client.list_blobs(name_starts_with=prefix)
            return [blob.name for blob in blobs]
        except Exception as e:
            print(f"  ⚠️ Failed to list blobs with prefix {prefix}: {e}")
            return []
    
    def upload_json(self, blob_path: str, data: dict, overwrite: bool = True) -> bool:
        """Upload JSON data to blob."""
        try:
            blob_client = self.container_client.get_blob_client(blob_path)
            json_str = json.dumps(data, indent=2, ensure_ascii=False)
            blob_client.upload_blob(json_str, overwrite=overwrite)
            return True
        except Exception as e:
            print(f"  ❌ Failed to upload to {blob_path}: {e}")
            return False
    
    def blob_exists(self, blob_path: str) -> bool:
        """Check if blob exists."""
        try:
            blob_client = self.container_client.get_blob_client(blob_path)
            return blob_client.exists()
        except Exception:
            return False


# Singleton instance
_azure_client: Optional[AzureBlobClient] = None


def get_azure_client() -> AzureBlobClient:
    """Get or create the Azure Blob client singleton."""
    global _azure_client
    if _azure_client is None:
        _azure_client = AzureBlobClient()
    return _azure_client