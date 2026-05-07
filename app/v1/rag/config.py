import os

# ---------------------------------------------------------------------------
# Azure Blob Storage Configuration
# ---------------------------------------------------------------------------
AZURE_CONNECTION_STRING = os.environ.get(
    "AZURE_CONNECTION_STRING", 
    "DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net"
)
AZURE_CONTAINER_NAME = os.environ.get("AZURE_CONTAINER_NAME", "rag")

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
# ---------------------------------------------------------------------------
EMBED_MODEL = "BAAI/bge-small-en-v1.5"

# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------
MAX_CHARS = 1500   

# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------
GEMINI_MODEL = "gemini-2.5-flash-lite" 

# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
RETRIEVER_TOP_K = 50