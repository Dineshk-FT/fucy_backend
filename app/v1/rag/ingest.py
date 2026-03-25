# =============================================================================
# ingest.py — All dataset ingestion functions from Azure Blob Storage
# =============================================================================

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Iterable

from azure.storage.blob import BlobServiceClient
from haystack import Document
from lxml import etree


# ── Azure Blob Storage configuration ─────────────────────────────────────────
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


# ── Private helpers ───────────────────────────────────────────────────────────

def _truncate_framework(text: str, max_chars: int = MAX_CHARS) -> str:
    """Trim long threat-framework descriptions; cut at last sentence boundary."""
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars]
    last_period = cut.rfind(". ")
    return cut[:last_period + 1] if last_period > 0 else cut + "..."


def _truncate(text, max_len: int = 800) -> str:
    """Generic truncator used for reports/ECU content."""
    if not text:
        return ""
    text = str(text)
    return text if len(text) <= max_len else text[:max_len] + "..."


def _flatten_list(lst):
    """Recursively flatten nested lists to a single list of strings."""
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(_flatten_list(item))
        elif isinstance(item, str):
            result.append(item)
    return result


def _section_to_text(section, clause_id: str = "") -> str:
    """Convert a clause section dict to a readable text block."""
    parts = []
    sid = section.get("section_id", "")
    title = section.get("section_title", "")
    parts.append(f"ISO 21434 Clause {clause_id} - Section {sid}: {title}")

    for item in _flatten_list(section.get("content", [])):
        parts.append(f"  - {item}")

    for req in section.get("requirements", []):
        rid = req.get("id", "")
        rdesc = " ".join(_flatten_list(req.get("description", [])))
        parts.append(f"  [{rid}] {rdesc}")

    for rec in section.get("recommendations", []):
        rid = rec.get("id", "")
        rdesc = " ".join(_flatten_list(rec.get("description", [])))
        parts.append(f"  [{rid}] (Recommendation) {rdesc}")

    for sub in section.get("subsections", []):
        parts.append(_section_to_text(sub, clause_id))

    return "\n".join(parts)


def _clean_node_for_text(node: dict):
    """Extract readable label + description from node dict."""
    data = node.get("data", {})
    label = data.get("label", node.get("id", ""))
    desc = data.get("description", "")
    props = node.get("properties") or []
    ntype = node.get("type", "component")
    return label, desc, props, ntype


# ── Threat-framework ingestion from Azure ─────────────────────────────────────

def ingest_mitre(mitre_blob_name: str, source: str = "MITRE_MOBILE") -> list[Document]:
    """Load MITRE ATT&CK JSON from Azure - one Document per attack-pattern."""
    try:
        bc = rag_container.get_blob_client(mitre_blob_name)
        raw = bc.download_blob().readall()
        data = json.loads(raw)
    except Exception as e:
        print(f"⚠️  MITRE file {mitre_blob_name} not found: {e}")
        return []

    docs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        desc = _truncate_framework(obj.get("description", ""))
        if not desc:
            continue
        docs.append(Document(
            content=f"MITRE Technique: {name}\nDescription: {desc}",
            meta={"source": source, "stix_id": obj.get("id"), "type": "attack_pattern"}
        ))
    print(f"✅ MITRE {source} Loaded: {len(docs)} techniques")
    return docs


def ingest_atm(atm_blob_name: str = "REPORTS_DB/atm.json") -> list[Document]:
    """Load Automotive Threat Matrix JSON from Azure."""
    try:
        bc = rag_container.get_blob_client(atm_blob_name)
        raw = bc.download_blob().readall()
        data = json.loads(raw)
    except Exception as e:
        print(f"⚠️  ATM file not found: {e}")
        return []

    docs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        raw_desc = obj.get("description", "")
        desc = _truncate_framework(re.sub(r"<[^>]+>", " ", raw_desc).strip())
        if not desc:
            continue
        docs.append(Document(
            content=f"ATM Technique: {name}\nDescription: {desc}",
            meta={"source": "ATM", "stix_id": obj.get("id"), "type": "attack_pattern"}
        ))
    print(f"✅ ATM Loaded: {len(docs)} techniques")
    return docs


def ingest_capec(capec_blob_name: str = "REPORTS_DB/capec_v3.9.xml") -> list[Document]:
    """Load CAPEC XML from Azure."""
    try:
        bc = rag_container.get_blob_client(capec_blob_name)
        raw = bc.download_blob().readall()
        root = ET.fromstring(raw)
    except Exception as e:
        print(f"⚠️  CAPEC file not found: {e}")
        return []

    ns = {"capec": "http://capec.mitre.org/capec-3"}
    docs = []

    patterns = root.findall(".//capec:Attack_Pattern", ns)
    if not patterns:
        patterns = root.findall(".//{*}Attack_Pattern")

    for ap in patterns:
        capec_id = ap.get("ID")
        name = ap.findtext("capec:Name", default="", namespaces=ns)
        desc = _truncate_framework(ap.findtext("capec:Description", default="", namespaces=ns))
        if not desc:
            continue

        related_cwe = relationships.get(f"CAPEC-{capec_id}", [])
        docs.append(Document(
            content=f"CAPEC-{capec_id}: {name}\nDescription: {desc}",
            meta={
                "source": "CAPEC",
                "capec_id": f"CAPEC-{capec_id}",
                "attack_pattern": name,
                "related_cwe": related_cwe,
                "type": "attack_pattern"
            }
        ))
    print(f"✅ CAPEC Loaded: {len(docs)} patterns")
    return docs


def ingest_cwe(cwe_blob_name: str = "REPORTS_DB/cwec_v4.19.1.xml") -> list[Document]:
    """Load CWE XML from Azure."""
    try:
        bc = rag_container.get_blob_client(cwe_blob_name)
        raw = bc.download_blob().readall()
        parser = etree.XMLParser(recover=True, huge_tree=True)
        root = etree.fromstring(raw, parser)
    except Exception as e:
        print(f"⚠️  CWE file not found: {e}")
        return []

    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
    docs = []

    for w in root.findall(".//cwe:Weakness", namespaces=ns):
        cwe_id = w.get("ID")
        name = w.get("Name", "")
        desc_el = w.find("cwe:Description", namespaces=ns)
        desc = _truncate_framework((desc_el.text or "").strip()) if desc_el is not None else ""
        if not desc:
            continue
        docs.append(Document(
            content=f"CWE-{cwe_id}: {name}\nDescription: {desc}",
            meta={"source": "CWE", "cwe_id": f"CWE-{cwe_id}", "weakness": name, "type": "weakness"}
        ))
    print(f"✅ CWE Loaded: {len(docs)} weaknesses")
    return docs


# ── ISO 21434 & Annex ingestion from Azure ─────────────────────────────────────

def ingest_iso_clauses() -> list[Document]:
    """Load ISO 21434 clause JSON files from Azure with section-level chunking."""
    records = []
    
    # Look for clause files in REPORTS_DB folder
    for b in rag_container.list_blobs(name_starts_with="REPORTS_DB/clause"):
        name = b.name
        try:
            bc = rag_container.get_blob_client(name)
            raw = bc.download_blob().readall()
            clause = json.loads(raw)
        except Exception as e:
            print(f"⚠️  Failed to load clause file {name}: {e}")
            continue

        # Extract clause ID from filename or from the JSON
        clause_id = clause.get("clause_id", "")
        if not clause_id:
            match = re.search(r'clause[_-]?(\d+)', name, re.IGNORECASE)
            if match:
                clause_id = match.group(1)
            else:
                clause_id = "unknown"
        
        clause_title = clause.get("clause_title", f"Clause {clause_id}")

        # Section-level chunking
        for section in clause.get("sections", []):
            text = _section_to_text(section, clause_id)
            if len(text.strip()) < 20:
                continue

            records.append(Document(
                content=text,
                meta={
                    "source": "ISO_21434",
                    "clause": clause_id,
                    "clause_title": clause_title,
                    "section_id": section.get("section_id", ""),
                    "title": section.get("section_title", ""),
                    "type": "clause_section"
                }
            ))

    print(f"✅ ISO Clauses Loaded: {len(records)} sections")
    return records


def ingest_annex(annex_blob_name: str = "REPORTS_DB/annex.json") -> list[Document]:
    """Load Annex F JSON from Azure with section-level chunking."""
    try:
        bc = rag_container.get_blob_client(annex_blob_name)
        raw = bc.download_blob().readall()
        annex_json = json.loads(raw)
    except Exception as e:
        print(f"⚠️  Annex file not found: {e}")
        return []

    annex_docs = []
    annex_id = annex_json.get("annex_id", "F")
    annex_title = annex_json.get("annex_title", "Guidelines for Impact Rating")

    for section in annex_json.get("sections", []):
        parts = []
        sid = section.get("section_id", "")
        stitle = section.get("section_title", "")
        parts.append(f"Annex {annex_id}: {annex_title} - Section {sid}: {stitle}")

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

        annex_docs.append(Document(
            content=text,
            meta={
                "source": "ANNEX_F",
                "annex": annex_id,
                "section_id": sid,
                "title": stitle,
                "type": "annex_section"
            }
        ))

    print(f"✅ Annex Loaded: {len(annex_docs)} sections")
    return annex_docs


# ── ECU data ingestion from Azure ──────────────────────────────────────────────

def ingest_ecu(ecu_blob_name: str = "REPORTS_DB/data.json") -> list[Document]:
    """Load ECU/system data JSON from Azure - one Document per ECU entry."""
    try:
        bc = rag_container.get_blob_client(ecu_blob_name)
        raw = bc.download_blob().readall()
        ecu_data = json.loads(raw)
    except Exception as e:
        print(f"⚠️  ECU data file not found: {e}")
        return []

    ecu_docs = []
    for k, v in ecu_data.items():
        ecu_docs.append(Document(
            content=json.dumps(v, indent=2),
            meta={"source": "ECU", "title": k, "type": "ecu_data"}
        ))
    print(f"✅ ECU Loaded: {len(ecu_docs)} entries")
    return ecu_docs


# ── Reports DB ingestion from Azure ────────────────────────────────────────────

def ingest_reports_db() -> list[Document]:
    """Ingest TARA reference reports from Azure with fine-grained chunking."""
    docs = []
    
    # List all JSON files in the REPORTS_DB folder
    for b in rag_container.list_blobs(name_starts_with="REPORTS_DB/"):
        if not b.name.endswith('.json'):
            continue
        
        # Skip configuration files
        skip_files = [
            "REPORTS_DB/data.json", 
            "REPORTS_DB/annex.json", 
            "REPORTS_DB/mobile-attack (1).json", 
            "REPORTS_DB/ics-attack (1).json",
            "REPORTS_DB/atm.json"
        ]
        if b.name in skip_files:
            continue
        
        # Skip clause files
        if "clause" in b.name.lower():
            continue
            
        fname = b.name.split('/')[-1]
        
        try:
            bc = rag_container.get_blob_client(b.name)
            raw = bc.download_blob().readall()
            report = json.loads(raw)
        except Exception as e:
            print(f"  ⚠️ Failed to load {fname}: {e}")
            continue

        # Format A: {"assets": {...}, "damage_scenarios": {...}}
        if "assets" in report and "damage_scenarios" in report:
            assets_block = report["assets"]
            damage_block = report["damage_scenarios"]
            model_name = assets_block.get("model_id", fname.replace(".json", ""))
            nodes_list = assets_block.get("template", {}).get("nodes", [])
            edges_list = assets_block.get("template", {}).get("edges", [])
            derivation_list = damage_block.get("Derivations") or damage_block.get("derivation") or []
            details_list = damage_block.get("Details") or damage_block.get("details") or []

        # Format B: {"Assets": [...], "Models": [...], ...}
        elif "Assets" in report:
            a_block = report["Assets"][0] if report.get("Assets") else {}
            model_name = report["Models"][0]["name"] if report.get("Models") else fname
            nodes_list = a_block.get("template", {}).get("nodes", [])
            edges_list = a_block.get("template", {}).get("edges", [])
            ds_list = report.get("Damage_scenarios") or report.get("DamageScenarios") or []
            d_block = ds_list[0] if ds_list else {}
            derivation_list = d_block.get("Derivations") or d_block.get("derivation") or []
            details_list = d_block.get("Details") or d_block.get("details") or []
        else:
            print(f"  Unrecognised format in {fname} — skipping.")
            continue

        # Chunk 1: Component nodes
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
            docs.append(Document(
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
            ))
            node_count += 1

        # Chunk 2: Damage derivations
        deriv_count = 0
        for d in derivation_list:
            name = d.get("name", "")
            if not name:
                continue
            content = (
                f"Reference Damage Derivation [{model_name}]:\n"
                f"Threat/Weakness: {name}\n"
                f"Affected Asset: {d.get('asset', '')}\n"
                f"Cyber Loss: {d.get('loss', '')}\n"
                f"Damage Scene: {d.get('damage_scene', '')}"
            )
            docs.append(Document(
                content=content,
                meta={
                    "source": "REPORTS_DB",
                    "file": fname,
                    "model": model_name,
                    "type": "damage_derivation",
                    "component_type": "reference"
                }
            ))
            deriv_count += 1

        # Chunk 3: Damage details
        detail_count = 0
        for det in details_list:
            dname = det.get("Name", "")
            if not dname:
                continue
            impacts = det.get("impacts", {})
            losses = [(cl.get("name", ""), cl.get("node", "")) for cl in det.get("cyberLosses", [])]
            impact_str = "  ".join(f"{k}: {v}" for k, v in impacts.items() if v)
            loss_str = ", ".join(f"{n} ({nd})" for n, nd in losses if n)
            content = (
                f"Reference Damage Scenario [{model_name}]: {dname}\n"
                f"Description: {_truncate(det.get('Description', ''), 800)}\n"
                f"Cyber Losses: {loss_str}\n"
                f"Impact Ratings: {impact_str}"
            )
            docs.append(Document(
                content=content,
                meta={
                    "source": "REPORTS_DB",
                    "file": fname,
                    "model": model_name,
                    "type": "damage_detail",
                    "component_type": "reference"
                }
            ))
            detail_count += 1

        # Chunk 4: Hierarchy summary
        id_to_label = {}
        children_map = {}
        for node in nodes_list:
            label = node.get("data", {}).get("label", "") or node.get("id", "")
            nid = node.get("id", "")
            ntype = node.get("type", "default")
            pid = node.get("parentId")
            id_to_label[nid] = label or f"(unnamed {ntype})"
            children_map.setdefault(pid, []).append(
                f"{label} (type:{ntype})" if label else f"(unnamed {ntype})"
            )

        hierarchy_lines = [f"Architecture Hierarchy for [{model_name}]:"]
        for pid_key in [None, "null", ""]:
            for child in children_map.get(pid_key, []):
                hierarchy_lines.append(f"  TOP: {child}")
        for pid, kids in children_map.items():
            if pid in [None, "null", ""]:
                continue
            parent_label = id_to_label.get(pid, pid)
            hierarchy_lines.append(f"  {parent_label} contains: {', '.join(kids)}")

        if len(hierarchy_lines) > 1:
            docs.append(Document(
                content="\n".join(hierarchy_lines),
                meta={"source": "REPORTS_DB", "file": fname, "model": model_name, "type": "hierarchy_summary"}
            ))

        # Chunk 5: Edge summary
        if edges_list:
            edge_lines = [f"Edge connections for [{model_name}]:"]
            for edge in edges_list:
                elabel = edge.get("data", {}).get("label", "")
                src_id = edge.get("source", "")
                tgt_id = edge.get("target", "")
                src_label = id_to_label.get(src_id, src_id)
                tgt_label = id_to_label.get(tgt_id, tgt_id)
                eprops = edge.get("properties", [])
                edge_lines.append(
                    f"  {elabel}: {src_label} <-> {tgt_label} "
                    f"(properties: {', '.join(eprops) if eprops else 'none'})"
                )
            docs.append(Document(
                content="\n".join(edge_lines),
                meta={"source": "REPORTS_DB", "file": fname, "model": model_name, "type": "edge_summary"}
            ))

        if node_count > 0 or deriv_count > 0 or detail_count > 0:
            print(f"  {fname}: {node_count} components | {deriv_count} derivations | {detail_count} details")

    print(f"✅ REPORTS_DB total chunks: {len(docs)}")
    return docs


# ── Master loader for all documents from Azure ─────────────────────────────────

def load_all_documents() -> list[Document]:
    """Load all documents from Azure Blob Storage."""
    print("Loading threat frameworks from Azure...")
    mitre_docs = ingest_mitre("REPORTS_DB/mobile-attack (1).json", "MITRE_MOBILE")
    mitre_docs += ingest_mitre("REPORTS_DB/ics-attack (1).json", "MITRE_ICS")
    atm_docs = ingest_atm("REPORTS_DB/atm.json")
    capec_docs = ingest_capec("REPORTS_DB/capec_v3.9.xml")
    cwe_docs = ingest_cwe("REPORTS_DB/cwec_v4.19.1.xml")
    print(Counter(d.meta["source"] for d in mitre_docs + atm_docs + capec_docs + cwe_docs))

    print("\nLoading ISO 21434 clauses from Azure...")
    iso_docs = ingest_iso_clauses()
    annex_docs = ingest_annex("REPORTS_DB/annex.json")
    print(f"  ISO 21434: {len(iso_docs)} sections  |  Annex F: {len(annex_docs)} sections")

    print("\nLoading ECU data from Azure...")
    ecu_docs = ingest_ecu("REPORTS_DB/data.json")
    print(f"  ECU entries: {len(ecu_docs)}")

    print("\nLoading REPORTS DB from Azure...")
    reports_docs = ingest_reports_db()

    all_docs = ecu_docs + iso_docs + annex_docs
    all_docs += mitre_docs + atm_docs + capec_docs + cwe_docs + reports_docs

    print(f"\n{'='*50}")
    print(f"Total documents: {len(all_docs)}")
    dist = Counter(d.meta.get("source", "?") for d in all_docs)
    for src, cnt in sorted(dist.items()):
        print(f"  {src:<20}: {cnt}")
    return all_docs