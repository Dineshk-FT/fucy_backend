from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable
import xml.etree.ElementTree as ET
from lxml import etree

from azure.storage.blob import BlobServiceClient
from haystack import Document

# Azure Blob Storage configuration
CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net"
blob = BlobServiceClient.from_connection_string(CONNECTION_STRING)
rag_container = blob.get_container_client("rag")

# Constants
MAX_CHARS = 1500  # max chars per chunk for threat-framework entries

# Relationships between CAPEC and CWE
relationships = {
    "CAPEC-66": ["CWE-89"],
    "CAPEC-100": ["CWE-79"],
    "CAPEC-115": ["CWE-119"],
}


def _truncate(text: str, max_chars: int = MAX_CHARS) -> str:
    """Trim long descriptions to avoid embedding token waste."""
    if len(text) <= max_chars:
        return text
    # Cut at last sentence boundary within limit
    cut = text[:max_chars]
    last_period = cut.rfind(". ")
    return cut[:last_period + 1] if last_period > 0 else cut + "..."


def _flatten_list(lst):
    """Recursively flatten nested lists to a single list of strings."""
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(_flatten_list(item))
        elif isinstance(item, str):
            result.append(item)
    return result


def chunk_text(text, chunk_size=400, overlap=50):
    """Legacy chunking function - kept for compatibility."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - overlap
    return chunks


def load_ecu_data(data_blob_name: str = "data.json") -> list[Document]:
    """Load ECU/system data JSON — one Document per ECU entry."""
    bc = rag_container.get_blob_client(data_blob_name)
    raw = bc.download_blob().readall()
    ecu_data = json.loads(raw)

    ecu_docs = []
    for k, v in ecu_data.items():
        ecu_docs.append(
            Document(
                content=json.dumps(v, indent=2),
                meta={
                    "source": "ECU",
                    "title": k,
                    "type": "ecu_data"
                }
            )
        )
    print(f"✅ ECU Loaded: {len(ecu_docs)} entries")
    return ecu_docs


def _section_to_text(section, clause_id=""):
    """Convert a clause section dict to a readable text block."""
    parts = []
    sid = section.get("section_id", "")
    title = section.get("section_title", "")
    parts.append(f"ISO 21434 Clause {clause_id} — Section {sid}: {title}")

    # Content bullets
    for item in _flatten_list(section.get("content", [])):
        parts.append(f"  - {item}")

    # Requirements
    for req in section.get("requirements", []):
        rid = req.get("id", "")
        rdesc = " ".join(_flatten_list(req.get("description", [])))
        parts.append(f"  [{rid}] {rdesc}")

    # Recommendations
    for rec in section.get("recommendations", []):
        rid = rec.get("id", "")
        rdesc = " ".join(_flatten_list(rec.get("description", [])))
        parts.append(f"  [{rid}] (Recommendation) {rdesc}")

    # Nested subsections
    for sub in section.get("subsections", []):
        parts.append(_section_to_text(sub, clause_id))

    return "\n".join(parts)


def load_clause_jsons() -> list[Document]:
    """Load ISO 21434 clause JSON files with section-level chunking."""
    records = []
    
    for b in rag_container.list_blobs(name_starts_with="clause"):
        name = b.name
        bc = rag_container.get_blob_client(name)
        raw = bc.download_blob().readall()
        clause = json.loads(raw)

        clause_id = clause.get("clause_id", re.search(r'-(\d+)', name).group(1) if re.search(r'-(\d+)', name) else "")
        clause_title = clause.get("clause_title", f"Clause {clause_id}")

        # Section-level chunking
        for section in clause.get("sections", []):
            text = _section_to_text(section, clause_id)
            if len(text.strip()) < 20:
                continue

            records.append(
                Document(
                    content=text,
                    meta={
                        "source": "ISO_21434",
                        "clause": clause_id,
                        "clause_title": clause_title,
                        "section_id": section.get("section_id", ""),
                        "title": section.get("section_title", ""),
                        "type": "clause_section"
                    }
                )
            )

    print(f"✅ ISO Clauses Loaded: {len(records)} sections")
    return records


def load_annex(annex_blob_name: str = "annex.json") -> list[Document]:
    """Load Annex F JSON with section-level chunking."""
    try:
        bc = rag_container.get_blob_client(annex_blob_name)
        raw = bc.download_blob().readall()
        annex_json = json.loads(raw)
    except Exception as e:
        print(f"⚠️  Annex file not found — skipping. Error: {e}")
        return []

    annex_docs = []
    annex_id = annex_json.get("annex_id", "F")
    annex_title = annex_json.get("annex_title", "Guidelines for Impact Rating")

    for section in annex_json.get("sections", []):
        parts = []
        sid = section.get("section_id", "")
        stitle = section.get("section_title", "")
        parts.append(f"Annex {annex_id}: {annex_title} — Section {sid}: {stitle}")

        for c in section.get("content", []):
            parts.append(f"  - {c}")

        for t in section.get("tables", []):
            cols = t.get("columns", [])
            rows = t.get("rows", [])
            parts.append(f"\nTable {t.get('table_id')}: {t.get('table_title')}")
            if cols and rows:
                parts.append(" | ".join(cols))
                parts.append("-" * 40)
                for r in rows:
                    parts.append(" | ".join(str(r.get(col, "")) for col in cols))

        for note in section.get("notes", []):
            parts.append(f"Note: {note}")

        text = "\n".join(parts)
        if len(text.strip()) < 20:
            continue

        annex_docs.append(
            Document(
                content=text,
                meta={
                    "source": "ANNEX_F",
                    "annex": annex_id,
                    "section_id": sid,
                    "title": stitle,
                    "type": "annex_section"
                }
            )
        )

    print(f"✅ Annex Loaded: {len(annex_docs)} sections")
    return annex_docs


def ingest_mitre(mitre_blob_name: str, source: str = "MITRE_MOBILE") -> list[Document]:
    """Load MITRE ATT&CK JSON — one Document per attack-pattern."""
    try:
        bc = rag_container.get_blob_client(mitre_blob_name)
        raw = bc.download_blob().readall()
        data = json.loads(raw)
    except Exception as e:
        print(f"⚠️  MITRE file {mitre_blob_name} not found — skipping. Error: {e}")
        return []

    docs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        desc = _truncate(obj.get("description", ""))
        if not desc:
            continue
        docs.append(
            Document(
                content=f"MITRE Technique: {name}\nDescription: {desc}",
                meta={
                    "source": source,
                    "stix_id": obj.get("id"),
                    "technique": name,
                    "type": "attack_pattern"
                }
            )
        )
    print(f"✅ MITRE {source} Loaded: {len(docs)} techniques")
    return docs


def ingest_atm(atm_blob_name: str = "atm.json") -> list[Document]:
    """Load Automotive Threat Matrix JSON — one Document per attack-pattern."""
    try:
        bc = rag_container.get_blob_client(atm_blob_name)
        raw = bc.download_blob().readall()
        data = json.loads(raw)
    except Exception as e:
        print(f"⚠️  ATM file not found — skipping. Error: {e}")
        return []

    docs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        # Strip HTML tags from ATM descriptions
        raw_desc = obj.get("description", "")
        desc = _truncate(re.sub(r"<[^>]+>", " ", raw_desc).strip())
        if not desc:
            continue
        docs.append(
            Document(
                content=f"ATM Technique: {name}\nDescription: {desc}",
                meta={
                    "source": "ATM",
                    "stix_id": obj.get("id"),
                    "technique": name,
                    "type": "attack_pattern"
                }
            )
        )
    print(f"✅ ATM Loaded: {len(docs)} techniques")
    return docs


def ingest_capec(capec_blob_name: str = "capec_v3.9.xml") -> list[Document]:
    """Load CAPEC XML — one Document per Attack_Pattern."""
    try:
        bc = rag_container.get_blob_client(capec_blob_name)
        raw = bc.download_blob().readall()
        root = ET.fromstring(raw)
    except Exception as e:
        print(f"⚠️  CAPEC file not found — skipping. Error: {e}")
        return []

    ns = {"capec": "http://capec.mitre.org/capec-3"}
    docs = []

    patterns = root.findall(".//capec:Attack_Pattern", ns)
    if not patterns:
        patterns = root.findall(".//{*}Attack_Pattern")

    for ap in patterns:
        capec_id = ap.get("ID")
        name = ap.findtext("capec:Name", default="", namespaces=ns)
        desc = _truncate(ap.findtext("capec:Description", default="", namespaces=ns))
        if not desc:
            continue

        related_cwe = relationships.get(f"CAPEC-{capec_id}", [])
        docs.append(
            Document(
                content=f"CAPEC-{capec_id}: {name}\nDescription: {desc}",
                meta={
                    "source": "CAPEC",
                    "capec_id": f"CAPEC-{capec_id}",
                    "attack_pattern": name,
                    "related_cwe": related_cwe,
                    "type": "attack_pattern"
                }
            )
        )
    print(f"✅ CAPEC Loaded: {len(docs)} patterns")
    return docs


def ingest_cwe(cwe_blob_name: str = "cwec_v4.19.1.xml") -> list[Document]:
    """Load CWE XML — one Document per Weakness."""
    try:
        bc = rag_container.get_blob_client(cwe_blob_name)
        raw = bc.download_blob().readall()
        parser = etree.XMLParser(recover=True, huge_tree=True)
        root = etree.fromstring(raw, parser)
    except Exception as e:
        print(f"⚠️  CWE file not found — skipping. Error: {e}")
        return []

    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
    docs = []

    for w in root.findall(".//cwe:Weakness", namespaces=ns):
        cwe_id = w.get("ID")
        name = w.get("Name", "")
        desc_el = w.find("cwe:Description", namespaces=ns)
        desc = _truncate((desc_el.text or "").strip()) if desc_el is not None else ""
        if not desc:
            continue
        docs.append(
            Document(
                content=f"CWE-{cwe_id}: {name}\nDescription: {desc}",
                meta={
                    "source": "CWE",
                    "cwe_id": f"CWE-{cwe_id}",
                    "weakness": name,
                    "type": "weakness"
                }
            )
        )
    print(f"✅ CWE Loaded: {len(docs)} weaknesses")
    return docs


def _clean_node_for_text(node):
    """Extract readable label+description from a node dict."""
    data = node.get("data", {})
    label = data.get("label", node.get("id", ""))
    desc = data.get("description", "")
    props = node.get("properties", [])
    ntype = node.get("type", "component")
    return label, desc, props, ntype


def ingest_reports_db() -> list[Document]:
    """Ingest TARA reference reports with fine-grained chunking."""
    docs = []
    
    # List all JSON files in the reports_db virtual folder
    for b in rag_container.list_blobs(name_starts_with="REPORTS_DB/"):
        if not b.name.endswith('.json'):
            continue
        
        fname = b.name.split('/')[-1]
        bc = rag_container.get_blob_client(b.name)
        raw = bc.download_blob().readall()
        report = json.loads(raw)

        # Format A: direct {assets, damage_scenarios}
        if "assets" in report and "damage_scenarios" in report:
            assets_block = report["assets"]
            damage_block = report["damage_scenarios"]
            model_name = assets_block.get("model_id", fname.replace(".json", ""))
            nodes_list = assets_block.get("template", {}).get("nodes", [])
            derivation_list = damage_block.get("Derivations") or damage_block.get("derivation") or []
            details_list = damage_block.get("Details") or damage_block.get("details") or []

        # Format B: wrapped (bms_1.json)
        elif "Assets" in report:
            a_block = report["Assets"][0] if report.get("Assets") else {}
            model_name = report["Models"][0]["name"] if report.get("Models") else fname
            nodes_list = a_block.get("template", {}).get("nodes", [])
            ds_list = (report.get("Damage_scenarios") or report.get("DamageScenarios") or [])
            d_block = ds_list[0] if ds_list else {}
            derivation_list = d_block.get("Derivations") or d_block.get("derivation") or []
            details_list = d_block.get("Details") or d_block.get("details") or []
        else:
            print(f"  Unrecognised format in {fname} — skipping.")
            continue

        # Chunk 1: All named nodes
        node_count = 0
        for node in nodes_list:
            label, desc, props, ntype = _clean_node_for_text(node)
            if not label or label.strip() == "":
                continue
            is_asset = node.get("isAsset", False)
            content = (
                f"Reference Component [{model_name}]: {label}\n"
                f"Type: {ntype}  IsAsset: {is_asset}\n"
                f"Description: {desc}\n"
                f"Security Properties: {', '.join(props) if props else 'N/A'}"
            )
            docs.append(
                Document(
                    content=content,
                    meta={
                        "source": "REPORTS_DB",
                        "file": fname,
                        "model": model_name,
                        "type": "asset",
                        "is_asset": is_asset,
                        "node_id": node.get("id", ""),
                        "component_type": "reference"
                    }
                )
            )
            node_count += 1

        # Chunk 2: Damage derivation entries
        deriv_count = 0
        for d in derivation_list:
            name = d.get("name", "")
            asset = d.get("asset", "")
            loss = d.get("loss", "")
            scene = d.get("damage_scene", "")
            if not name:
                continue
            content = (
                f"Reference Damage Derivation [{model_name}]:\n"
                f"Threat/Weakness: {name}\n"
                f"Affected Asset: {asset}\n"
                f"Cyber Loss: {loss}\n"
                f"Damage Scene: {scene}"
            )
            docs.append(
                Document(
                    content=content,
                    meta={
                        "source": "REPORTS_DB",
                        "file": fname,
                        "model": model_name,
                        "type": "damage_derivation",
                        "component_type": "reference"
                    }
                )
            )
            deriv_count += 1

        # Chunk 3: Damage detail entries
        detail_count = 0
        for det in details_list:
            dname = det.get("Name", "")
            ddesc = _truncate(det.get("Description", ""), 800)
            impacts = det.get("impacts", {})
            losses = [(cl.get("name", ""), cl.get("node", ""))
                     for cl in det.get("cyberLosses", [])]
            if not dname:
                continue
            impact_str = "  ".join(f"{k}: {v}" for k, v in impacts.items() if v)
            loss_str = ", ".join(f"{n} ({nd})" for n, nd in losses if n)
            content = (
                f"Reference Damage Scenario [{model_name}]: {dname}\n"
                f"Description: {ddesc}\n"
                f"Cyber Losses: {loss_str}\n"
                f"Impact Ratings: {impact_str}"
            )
            docs.append(
                Document(
                    content=content,
                    meta={
                        "source": "REPORTS_DB",
                        "file": fname,
                        "model": model_name,
                        "type": "damage_detail",
                        "component_type": "reference"
                    }
                )
            )
            detail_count += 1

        print(f"  {fname}: {node_count} components | {deriv_count} derivations | {detail_count} details")

    print(f"✅ REPORTS_DB total chunks: {len(docs)}")
    return docs


def load_all_records() -> list[Document]:
    """Load all documents from all sources."""
    records = (
        load_ecu_data("data.json")
        + load_clause_jsons()
        + load_annex("annex.json")
        + ingest_mitre("mobile-attack (1).json", "MITRE_MOBILE")
        + ingest_mitre("ics-attack (1).json", "MITRE_ICS")
        + ingest_atm("atm.json")
        + ingest_capec("capec_v3.9.xml")
        + ingest_cwe("cwec_v4.19.1.xml")
        + ingest_reports_db()
    )
    print(f"\n{'='*50}")
    print(f"Total documents loaded: {len(records)}")
    return records


def to_haystack_documents(records: Iterable[Document | dict]) -> list[Document]:
    """Convert records to Haystack Documents with deduplication."""
    docs: list[Document] = []
    seen_ids: set[str] = set()
    duplicate_count = 0

    for item in records:
        if isinstance(item, Document):
            doc = item
        else:
            # Handle dict format
            meta = {k: v for k, v in item.items() if k not in {"content"}}
            doc = Document(content=item.get("content", ""), meta=meta)

        if doc.id in seen_ids:
            duplicate_count += 1
            continue

        seen_ids.add(doc.id)
        docs.append(doc)

    if duplicate_count:
        print(f"⚠️  Skipped {duplicate_count} duplicate document(s) during ingest.")

    return docs


def index_documents(document_store, doc_embedder, docs: list[Document]) -> list[Document]:
    """Write and embed documents in the document store."""
    # Guard: skip if already embedded
    existing = document_store.count_documents()
    if existing > 0:
        print(f"ℹ️  Document store already has {existing} documents — skipping re-embedding.")
        return document_store.filter_documents()

    print(f"🔄 Embedding {len(docs)} documents...")
    
    # Write initial documents
    document_store.write_documents(docs)
    
    # Embed documents
    result = doc_embedder.run(documents=docs)
    embedded_docs = result["documents"]
    
    # Update with embeddings
    document_store.write_documents(embedded_docs, policy="overwrite")
    
    print(f"✅ {document_store.count_documents()} documents embedded and stored.")
    return embedded_docs


def summarize_by_source(docs: list[Document]) -> dict[str, int]:
    """Summarize document count by source."""
    out = {}
    for d in docs:
        src = (d.meta or {}).get("source", "Unknown")
        out[src] = out.get(src, 0) + 1
    return out