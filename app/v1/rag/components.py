# =============================================================================
# components.py — Config, ECU resolution, UUID post-processing, component setup
# =============================================================================

import json
import os
import re
import uuid as _uuid
from pathlib import Path

from azure.storage.blob import BlobServiceClient
from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack_integrations.components.generators.google_ai import GoogleAIGeminiGenerator


# ─────────────────────────────────────────────────────────────────────────────
# AZURE BLOB STORAGE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net"
blob = BlobServiceClient.from_connection_string(CONNECTION_STRING)
rag_container = blob.get_container_client("rag")


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

EMBED_MODEL      = "BAAI/bge-small-en-v1.5"
MAX_CHARS        = 1500
GEMINI_MODEL     = "gemini-2.5-flash-lite"
RETRIEVER_TOP_K  = 20


# ─────────────────────────────────────────────────────────────────────────────
# ECU RESOLUTION (from Azure)
# ─────────────────────────────────────────────────────────────────────────────

_SUFFIX_WORDS = {
    "ecu", "system", "module", "interface", "controller", "unit",
    "network", "port", "server", "bus", "head", "vehicle", "automotive"
}

_ALIASES = {
    "obd":               "obd",
    "obd-ii":            "obd",
    "obd2":              "obd",
    "tcu":               "tcu",
    "telematics control":"tcu",
    "bcm":               "bcm",
    "ecm":               "ecm",
    "ivi":               "ivi",
    "eps":               "eps",
    "abs":               "abs",
    "bms":               "bms",
    "adas":              "adas",
}


def _acronym(text: str) -> str:
    skip      = {"the", "and", "for", "of", "a", "an", "or", "in", "on", "to", "/"}
    words     = [w.strip("()/-").lower() for w in text.replace("/", " ").split()]
    sig_words = [w for w in words if w and w not in skip]
    core      = [w for w in sig_words if w not in _SUFFIX_WORDS]
    chosen    = core if core else sig_words
    return "".join(w[0] for w in chosen if w)


def resolve_ecu(query: str) -> dict | None:
    """5-pass fuzzy-match query to dataecu.json from Azure. Returns entry dict or None."""
    try:
        bc = rag_container.get_blob_client("REPORTS_DB/data.json")
        raw = bc.download_blob().readall()
        ecu_db = json.loads(raw)
    except Exception as e:
        print(f"⚠️  Failed to load ECU data from Azure: {e}")
        return None
    
    q = query.lower().strip()

    # Pass 0: alias table
    for phrase, key in _ALIASES.items():
        if phrase in q and key in ecu_db:
            return ecu_db[key]
    # Pass 1: exact key or standalone word
    for key, entry in ecu_db.items():
        if key == q or f" {key} " in f" {q} ":
            return entry
    # Pass 2: full name substring
    for key, entry in ecu_db.items():
        if entry["name"].lower() in q:
            return entry
    # Pass 3a: exact acronym
    qa = _acronym(q)
    for key, entry in ecu_db.items():
        if qa and qa == key:
            return entry
    # Pass 3b: acronym prefix
    if len(qa) >= 2:
        for key, entry in ecu_db.items():
            if key.startswith(qa) and len(key) - len(qa) <= 1:
                return entry
    # Pass 4: word overlap
    for key, entry in ecu_db.items():
        name_words = [w.strip("()/-").lower() for w in entry["name"].replace("/", " ").split()]
        core       = [w for w in name_words if len(w) > 2 and w not in _SUFFIX_WORDS]
        if sum(1 for w in core if w in q) >= 2:
            return entry
    # Pass 5: key word in query
    for key, entry in ecu_db.items():
        if any(w in q for w in key.replace("_", " ").split() if len(w) > 3):
            return entry
    return None


def list_ecus() -> None:
    """Print all ECU keys and names from dataecu.json in Azure."""
    try:
        bc = rag_container.get_blob_client("REPORTS_DB/data.json")
        raw = bc.download_blob().readall()
        ecu_db = json.loads(raw)
    except Exception as e:
        print(f"⚠️  Failed to load ECU data from Azure: {e}")
        return
    
    print(f"\n{'Key':<20} {'Name'}")
    print("-" * 60)
    for key, entry in ecu_db.items():
        print(f"  {key:<18} {entry.get('name', '')}")
    print(f"\nTotal: {len(ecu_db)} ECU entries")


def build_enriched_query(user_query: str, ecu_entry: dict | None) -> str:
    if ecu_entry:
        return (
            f"{ecu_entry['name']}\n\n"
            f"AUTHORITATIVE ASSET LIST (from system dataecu specification) — "
            f"generate ONLY these assets, no others:\n"
            f"{ecu_entry['hint']}\n\n"
            f"All threat analysis, damage scenarios, and edges must reference "
            f"ONLY the assets listed above. Do NOT add any other components."
        )
    return user_query


# ─────────────────────────────────────────────────────────────────────────────
# POST-PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

def stamp_uuids(obj: dict) -> dict:
    """Replace empty/placeholder id/_id/model_id fields with fresh uuid4 values."""
    ID_KEYS = {"id", "_id", "model_id"}

    def _bad(val):
        if not val:
            return True
        if isinstance(val, str) and (
            "PLACEHOLDER" in val or val.strip() == "" or val.startswith("<")
        ):
            return True
        return False

    def _walk(o):
        if isinstance(o, dict):
            for k, v in list(o.items()):
                if k in ID_KEYS and _bad(v):
                    o[k] = str(_uuid.uuid4())
                else:
                    _walk(v)
        elif isinstance(o, list):
            for item in o:
                _walk(item)

    _walk(obj)
    return obj


def crosslink_node_ids(obj: dict) -> dict:
    """Propagate stamped nodeIds into Derivations and cyberLosses by label-matching."""
    nodes = obj.get("assets", {}).get("template", {}).get("nodes", [])
    label_to_id = {
        n.get("data", {}).get("label", "").lower(): n.get("id")
        for n in nodes if n.get("id")
    }
    for d in obj.get("damage_scenarios", {}).get("Derivations", []):
        nid = d.get("nodeId", "")
        if not nid or str(nid).startswith("<") or "PLACEHOLDER" in str(nid):
            d["nodeId"] = label_to_id.get(d.get("asset", "").lower()) or str(_uuid.uuid4())
    for det in obj.get("damage_scenarios", {}).get("Details", []):
        for cl in det.get("cyberLosses", []):
            nid = cl.get("nodeId", "")
            if not nid or str(nid).startswith("<") or "PLACEHOLDER" in str(nid):
                cl["nodeId"] = label_to_id.get(cl.get("node", "").lower()) or str(_uuid.uuid4())
            if not cl.get("id") or str(cl.get("id", "")).startswith("<"):
                cl["id"] = str(_uuid.uuid4())
    return obj


def parse_and_fix(raw_text: str) -> dict | None:
    """Strip markdown fences, parse JSON, stamp UUIDs, crosslink nodeIds."""
    cleaned = re.sub(r"^```[a-z]*\n?", "", raw_text.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"```$", "", cleaned.strip())
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON parse error: {e}")
        print(f"Raw output (first 500 chars):\n{cleaned[:500]}")
        return None
    return crosslink_node_ids(stamp_uuids(obj))


def print_summary(tara_json: dict) -> None:
    node_count  = len(tara_json.get("assets", {}).get("template", {}).get("nodes", []))
    edge_count  = len(tara_json.get("assets", {}).get("template", {}).get("edges", []))
    deriv_count = len(tara_json.get("damage_scenarios", {}).get("Derivations", []))
    ds_count    = len(tara_json.get("damage_scenarios", {}).get("Details", []))
    print(f"   Nodes          : {node_count}")
    print(f"   Edges          : {edge_count}")
    print(f"   Derivations    : {deriv_count}")
    print(f"   Damage details : {ds_count}")
    print("   IDs            : all stamped as uuid4")


# ─────────────────────────────────────────────────────────────────────────────
# HAYSTACK COMPONENT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def build_store(all_docs):
    """Embed all_docs, load into InMemoryDocumentStore. Returns (store, text_embedder)."""
    store         = InMemoryDocumentStore()
    doc_embedder  = SentenceTransformersDocumentEmbedder(model=EMBED_MODEL)
    text_embedder = SentenceTransformersTextEmbedder(model=EMBED_MODEL)
    doc_embedder.warm_up()
    text_embedder.warm_up()
    print(f"✅ Embedders ready  [{EMBED_MODEL}]")

    print(f"🔄 Embedding {len(all_docs)} documents...")
    embedded_docs = doc_embedder.run(documents=all_docs)["documents"]
    store.write_documents(embedded_docs)
    print(f"✅ {store.count_documents()} documents embedded and stored.")
    return store, text_embedder


def build_retriever(store):
    return InMemoryEmbeddingRetriever(document_store=store, top_k=RETRIEVER_TOP_K)


def build_generator():
    if "GOOGLE_API_KEY" not in os.environ:
        raise EnvironmentError(
            "❌ GOOGLE_API_KEY not set.\n"
            "   Windows : set GOOGLE_API_KEY=your-key-here\n"
            "   Linux   : export GOOGLE_API_KEY=your-key-here"
        )
    return GoogleAIGeminiGenerator(model=GEMINI_MODEL)