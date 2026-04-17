# =============================================================================
# config.py — Central configuration for TARA RAG pipeline
# =============================================================================

from pathlib import Path

# ---------------------------------------------------------------------------
# Base dataset directory (relative to this file's location)
# ---------------------------------------------------------------------------
BASE_PATH    = Path(__file__).parent / "datasets"

MITRE_MOBILE = BASE_PATH / "mobileattack.json"
MITRE_ICS    = BASE_PATH / "icsattack.json"
ATM_PATH     = BASE_PATH / "atm.json"
CAPEC_PATH   = BASE_PATH / "capec.xml"
CWE_PATH     = BASE_PATH / "cwec.xml"
ECU_PATH     = BASE_PATH / "dataecu.json"
ANNEX_PATH   = BASE_PATH / "annex.json"
CLAUSE_PATH  = BASE_PATH / "clauses"
REPORTS_PATH = BASE_PATH / "reports_db"
PDF_PATH     = BASE_PATH

# ---------------------------------------------------------------------------
# Azure Blob Storage Configuration
# ---------------------------------------------------------------------------
AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net"
AZURE_CONTAINER_NAME = "rag"

# ---------------------------------------------------------------------------
# Azure Blob Paths (virtual folders in container)
# ---------------------------------------------------------------------------
AZURE_PATHS = {
    "MITRE_MOBILE": "mobileattack.json",
    "MITRE_ICS": "icsattack.json",
    "ATM_PATH": "atm.json",
    "CAPEC_PATH": "capec.xml",
    "CWE_PATH": "cwec.xml",
    "ECU_PATH": "dataecu.json",
    "ANNEX_PATH": "annex.json",
    "CLAUSE_PATH": "clauses/",
    "REPORTS_PATH": "REPORTS_DB/",
    "PDF_PATH": "pdfs/",
    "CACHE_PREFIX": "cache/"
}

# ---------------------------------------------------------------------------
# Embedding model
# BGE-small beats MiniLM on BEIR benchmarks at same size
# ---------------------------------------------------------------------------
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
# Fallback: "sentence-transformers/all-MiniLM-L6-v2"

# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------
MAX_CHARS = 1500   # max chars per chunk for threat-framework entries

# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------
GEMINI_MODEL = "gemini-2.5-flash-lite" 

# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
RETRIEVER_TOP_K = 50  # Raised to 50 for maximum technical coverage

# ---------------------------------------------------------------------------
# Vector DB (Weaviate) - Keep for backward compatibility
# ---------------------------------------------------------------------------
WEAVIATE_URL = "https://5uc6g0vjt8ax2yyl1kcdvq.c0.asia-southeast1.gcp.weaviate.cloud"
WEAVIATE_API_KEY = "dHR1b0U3dW81WmQ4eU01N18xZXlyWkRTSXUvdHdWaTlQWExoVUtuWEJqWUFYdUhjWVRLRzAxbGVtcks0PV92MjAw"
WEAVIATE_COLLECTION = "HaystackDocument"