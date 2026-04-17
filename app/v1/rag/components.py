# =============================================================================
# components.py — Config, ECU resolution, UUID post-processing, component setup
# =============================================================================

import json
import os
import re
import uuid as _uuid
from typing import Optional

from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack_integrations.components.generators.google_ai import GoogleAIGeminiGenerator

from app.v1.rag.azure_client import get_azure_client
from app.v1.rag.config import (
    EMBED_MODEL, GEMINI_MODEL, RETRIEVER_TOP_K,
    AZURE_PATHS
)


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
    "telematics control": "tcu",
    "bcm":               "bcm",
    "ecm":               "ecm",
    "ivi":               "ivi",
    "eps":               "eps",
    "abs":               "abs",
    "bms":               "bms",
    "adas":              "adas",
}


def _acronym(text: str) -> str:
    skip = {"the", "and", "for", "of", "a", "an", "or", "in", "on", "to", "/"}
    words = [w.strip("()/-").lower() for w in text.replace("/", " ").split()]
    sig_words = [w for w in words if w and w not in skip]
    core = [w for w in sig_words if w not in _SUFFIX_WORDS]
    chosen = core if core else sig_words
    return "".join(w[0] for w in chosen if w)


def resolve_ecu(query: str) -> Optional[dict]:
    """5-pass fuzzy-match query to dataecu.json from Azure. Returns entry dict or None."""
    client = get_azure_client()
    ecu_db = client.download_json(AZURE_PATHS["ECU_PATH"])
    
    if not ecu_db:
        print("⚠️  Failed to load ECU data from Azure")
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
        if entry.get("name", "").lower() in q:
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
        name_words = [w.strip("()/-").lower() for w in entry.get("name", "").replace("/", " ").split()]
        core = [w for w in name_words if len(w) > 2 and w not in _SUFFIX_WORDS]
        if sum(1 for w in core if w in q) >= 2:
            return entry
    
    # Pass 5: key word in query
    for key, entry in ecu_db.items():
        if any(w in q for w in key.replace("_", " ").split() if len(w) > 3):
            return entry
    
    return None


def list_ecus() -> None:
    """Print all ECU keys and names from dataecu.json in Azure."""
    client = get_azure_client()
    ecu_db = client.download_json(AZURE_PATHS["ECU_PATH"])
    
    if not ecu_db:
        print("⚠️  Failed to load ECU data from Azure")
        return
    
    print(f"\n{'Key':<20} {'Name'}")
    print("-" * 60)
    for key, entry in ecu_db.items():
        print(f"  {key:<18} {entry.get('name', '')}")
    print(f"\nTotal: {len(ecu_db)} ECU entries")


def build_enriched_query(user_query: str, ecu_entry: Optional[dict]) -> str:
    if ecu_entry:
        return (
            f"{ecu_entry.get('name', '')}\n\n"
            f"AUTHORITATIVE ASSET LIST (from system dataecu specification) — "
            f"generate ONLY these assets, no others:\n"
            f"{ecu_entry.get('hint', '')}\n\n"
            f"All threat analysis, damage scenarios, and edges must reference "
            f"ONLY the assets listed above. Do NOT add any other components."
        )
    return user_query


# ─────────────────────────────────────────────────────────────────────────────
# POST-PROCESSING
# ─────────────────────────────────────────────────────────────────────────────

def _hex_id(base=None, inc=0):
    """Generates a 24-char hex ID. If base is provided, increments it."""
    if base and len(base) >= 24:
        prefix = base[:-2]
        val = int(base[-2:], 16) + inc
        return f"{prefix}{val:02x}"
    return _uuid.uuid4().hex[:24]


def stamp_uuids(obj: dict) -> dict:
    """Replace placeholder IDs with BMS-compliant hex IDs."""
    
    models = obj.get("Models", [])
    assets = obj.get("Assets", [])
    attacks = obj.get("Attacks", [])
    ds_list = obj.get("Damage_scenarios", [])
    ts_list = obj.get("Threat_scenarios", [])
    
    mid = None
    uid = None

    if models and isinstance(models, list):
        model0 = models[0]
        if not model0.get("_id") or "uuid" in str(model0.get("_id")):
            model0["_id"] = _hex_id()
        if not model0.get("user_id") or "uuid" in str(model0.get("user_id")):
            model0["user_id"] = _hex_id()
            
        mid = model0["_id"]
        uid = model0["user_id"]
        
        for asset in assets:
            if not asset.get("_id") or "uuid" in str(asset.get("_id")):
                asset["_id"] = _hex_id(mid, 1)
            asset["model_id"] = mid
            asset["user_id"] = uid
            
        for attack in attacks:
            if not attack.get("_id") or "uuid" in str(attack.get("_id")):
                attack["_id"] = _hex_id(mid, 2)
            attack["model_id"] = mid

        for ds in ds_list:
            if not ds.get("_id") or "uuid" in str(ds.get("_id")):
                ds["_id"] = _hex_id(mid, 8)
            ds["model_id"] = mid
            if "user_id" not in ds:
                ds["user_id"] = uid

        for ts in ts_list:
            if not ts.get("_id") or "uuid" in str(ts.get("_id")):
                ts["_id"] = _hex_id(mid, 11)
            ts["model_id"] = mid

    ID_KEYS = {"id", "_id", "parentId", "source", "target", "nodeId", "rowId", "propId", "threat_id", "ID"}
    
    def _bad(val):
        if not val:
            return True
        if isinstance(val, str) and ("PLACEHOLDER" in val or val.strip() == "" or val.startswith("<")):
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
    """Links node labels to IDs across template and Details for all Assets."""
    assets_list = obj.get("Assets", [])
    if not isinstance(assets_list, list):
        return obj

    for asset in assets_list:
        template = asset.get("template", {})
        nodes = template.get("nodes", [])
        edges = template.get("edges", [])
        details = asset.get("Details", asset.get("details", []))
        
        label_to_id = {
            n.get("data", {}).get("label", "").lower(): n.get("id")
            for n in nodes if n.get("id")
        }

        for edge in edges:
            src_label = str(edge.get("source", "")).lower()
            tgt_label = str(edge.get("target", "")).lower()
            if src_label in label_to_id:
                edge["source"] = label_to_id[src_label]
            if tgt_label in label_to_id:
                edge["target"] = label_to_id[tgt_label]

        if details:
            asset["Details"] = details
            if "details" in asset:
                del asset["details"]
            
            for d in details:
                name_key = str(d.get("name", "")).lower()
                nid = d.get("nodeId", "")
                if not nid or str(nid).startswith("<") or "PLACEHOLDER" in str(nid):
                    d["nodeId"] = label_to_id.get(name_key) or str(_uuid.uuid4())
                
                for p in d.get("props", []):
                    if not p.get("id") or str(p.get("id")).startswith("<"):
                        p["id"] = str(_uuid.uuid4())
    
    return obj


def parse_and_fix(raw_text: str) -> Optional[dict]:
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
    assets = tara_json.get("Assets", [])
    ds_list = tara_json.get("Damage_scenarios", [])
    
    if not assets or not isinstance(assets, list):
        print("   [Warning] No Assets found in TARA output.")
        return

    asset = assets[0]
    template = asset.get("template", {})
    nodes = template.get("nodes", [])
    edges = template.get("edges", [])
    details = asset.get("Details", [])
    
    ds_root = ds_list[0] if ds_list else {}

    print(f"   Nodes          : {len(nodes)}")
    print(f"   Edges          : {len(edges)}")
    print(f"   Architecture Details : {len(details)}")
    print(f"   Damage Scenarios : {len(ds_root.get('Details', []))}")
    print("   IDs            : stamped as BMS-compliant hex IDs")


# ─────────────────────────────────────────────────────────────────────────────
# HAYSTACK COMPONENT BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def build_store(all_docs=None):
    """Embed all_docs, load into InMemoryDocumentStore."""
    store = InMemoryDocumentStore()
    
    text_embedder = SentenceTransformersTextEmbedder(model=EMBED_MODEL)
    text_embedder.warm_up()

    if not all_docs:
        print("⚠️ No documents provided. Store is empty.")
        return store, text_embedder

    print(f"✅ Embedders ready  [{EMBED_MODEL}]")
    doc_embedder = SentenceTransformersDocumentEmbedder(model=EMBED_MODEL)
    doc_embedder.warm_up()

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