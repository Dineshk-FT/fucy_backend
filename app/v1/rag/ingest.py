# =============================================================================
# ingest.py — All dataset ingestion functions from Azure Blob Storage
# =============================================================================

import json
import re
from collections import Counter
from typing import List, Optional

from haystack import Document
from lxml import etree

from app.v1.rag.azure_client import get_azure_client
from app.v1.rag.config import MAX_CHARS, AZURE_PATHS


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(text: str, max_chars: int = MAX_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars]
    last_period = cut.rfind(". ")
    return cut[:last_period + 1] if last_period > 0 else cut + "..."


def _flatten_list(lst) -> list:
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(_flatten_list(item))
        elif isinstance(item, str):
            result.append(item)
    return result


def _section_to_text(section: dict, clause_id: str = "") -> str:
    parts = []
    sid = section.get("section_id", "")
    title = section.get("section_title", "")
    parts.append(f"ISO 21434 Clause {clause_id} — Section {sid}: {title}")
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
    data = node.get("data", {})
    label = data.get("label", node.get("id", ""))
    desc = data.get("description", "")
    props = node.get("properties") or []
    ntype = node.get("type", "component")
    return label, desc, props, ntype


# ─────────────────────────────────────────────────────────────────────────────
# Threat frameworks
# ─────────────────────────────────────────────────────────────────────────────

def ingest_mitre(source: str) -> List[Document]:
    """Ingest MITRE ATT&CK from Azure."""
    client = get_azure_client()
    path = AZURE_PATHS["MITRE_MOBILE"] if source == "MITRE_MOBILE" else AZURE_PATHS["MITRE_ICS"]
    data = client.download_json(path)
    
    if not data:
        print(f"  ⚠️ Failed to load {source} from Azure")
        return []
    
    docs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        desc = _truncate(obj.get("description", ""))
        if not desc:
            continue
        docs.append(Document(
            content=f"MITRE Technique: {name}\nDescription: {desc}",
            meta={"source": source, "stix_id": obj.get("id")}
        ))
    return docs


def ingest_atm() -> List[Document]:
    """Ingest ATM framework from Azure."""
    client = get_azure_client()
    data = client.download_json(AZURE_PATHS["ATM_PATH"])
    
    if not data:
        print("  ⚠️ Failed to load ATM from Azure")
        return []
    
    docs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name", "")
        desc = _truncate(re.sub(r"<[^>]+>", " ", obj.get("description", "")).strip())
        if not desc:
            continue
        docs.append(Document(
            content=f"ATM Technique: {name}\nDescription: {desc}",
            meta={"source": "ATM", "stix_id": obj.get("id")}
        ))
    return docs


def ingest_capec() -> List[Document]:
    """Ingest CAPEC from Azure."""
    client = get_azure_client()
    root = client.download_xml(AZURE_PATHS["CAPEC_PATH"])
    
    if root is None:
        print("  ⚠️ Failed to load CAPEC from Azure")
        return []
    
    ns = {"capec": "http://capec.mitre.org/capec-3"}
    docs = []
    for ap in root.findall(".//capec:Attack_Pattern", ns):
        cid = ap.get("ID")
        name = ap.findtext("capec:Name", default="", namespaces=ns)
        desc = _truncate(ap.findtext("capec:Description", default="", namespaces=ns))
        if not desc:
            continue
        docs.append(Document(
            content=f"CAPEC-{cid}: {name}\nDescription: {desc}",
            meta={"source": "CAPEC", "capec_id": cid}
        ))
    return docs


def ingest_cwe() -> List[Document]:
    """Ingest CWE from Azure."""
    client = get_azure_client()
    data = client.download_blob(AZURE_PATHS["CWE_PATH"])
    
    if data is None:
        print("  ⚠️ Failed to load CWE from Azure")
        return []
    
    parser = etree.XMLParser(recover=True, huge_tree=True)
    tree = etree.parse( BytesIO(data), parser)
    root = tree.getroot()
    ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
    docs = []
    for w in root.findall(".//cwe:Weakness", namespaces=ns):
        cwe_id = w.get("ID")
        name = w.get("Name", "")
        desc_el = w.find("cwe:Description", namespaces=ns)
        desc = _truncate((desc_el.text or "").strip()) if desc_el is not None else ""
        if not desc:
            continue
        docs.append(Document(
            content=f"CWE-{cwe_id}: {name}\nDescription: {desc}",
            meta={"source": "CWE", "cwe_id": f"CWE-{cwe_id}"}
        ))
    return docs


# ─────────────────────────────────────────────────────────────────────────────
# ISO 21434 & Annex F
# ─────────────────────────────────────────────────────────────────────────────

def ingest_iso_clauses() -> List[Document]:
    """Ingest ISO 21434 clauses from Azure."""
    client = get_azure_client()
    clause_blobs = client.list_blobs(AZURE_PATHS["CLAUSE_PATH"])
    
    docs = []
    for blob_path in clause_blobs:
        if not blob_path.endswith(".json"):
            continue
        
        data = client.download_json(blob_path)
        if not data:
            continue
        
        clause_id = data.get("clause_id", "")
        clause_title = data.get("clause_title", f"Clause {clause_id}")
        
        for section in data.get("sections", []):
            text = _section_to_text(section, clause_id)
            if len(text.strip()) < 20:
                continue
            docs.append(Document(
                content=text,
                meta={
                    "source": "ISO_21434",
                    "clause": clause_id,
                    "clause_title": clause_title,
                    "section_id": section.get("section_id", ""),
                    "title": section.get("section_title", ""),
                }
            ))
    
    print(f"  ISO 21434: {len(docs)} sections")
    return docs


def ingest_annex() -> List[Document]:
    """Ingest Annex F from Azure."""
    client = get_azure_client()
    annex = client.download_json(AZURE_PATHS["ANNEX_PATH"])
    
    if not annex:
        print("  ⚠️ Annex file not found in Azure — skipping.")
        return []
    
    annex_id = annex.get("annex_id", "F")
    annex_title = annex.get("annex_title", "Guidelines for Impact Rating")
    docs = []
    
    for section in annex.get("sections", []):
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
        docs.append(Document(
            content=text,
            meta={"source": "ANNEX_F", "annex": annex_id, "section_id": sid, "title": stitle}
        ))
    
    print(f"  Annex F: {len(docs)} sections")
    return docs


# ─────────────────────────────────────────────────────────────────────────────
# ECU data & Reports DB
# ─────────────────────────────────────────────────────────────────────────────

def _truncate_short(text, max_len: int = 800) -> str:
    if not text:
        return ""
    text = str(text)
    return text if len(text) <= max_len else text[:max_len] + "..."


def ingest_ecu() -> List[Document]:
    """Ingest ECU data from Azure."""
    client = get_azure_client()
    data = client.download_json(AZURE_PATHS["ECU_PATH"])
    
    if not data:
        print("  ⚠️ ECU file not found in Azure — skipping.")
        return []
    
    docs = []
    items = data.items() if isinstance(data, dict) else enumerate(data)
    for key, val in items:
        docs.append(Document(
            content=json.dumps(val, indent=2),
            meta={"source": "ECU", "title": str(key)}
        ))
    
    print(f"  ECU entries: {len(docs)}")
    return docs


def ingest_reports_db() -> List[Document]:
    """Ingest reports database from Azure."""
    client = get_azure_client()
    report_blobs = client.list_blobs(AZURE_PATHS["REPORTS_PATH"])
    
    docs = []
    
    for blob_path in report_blobs:
        if not blob_path.endswith(".json") or blob_path == AZURE_PATHS["ECU_PATH"]:
            continue
        
        fname = blob_path.split("/")[-1]
        report = client.download_json(blob_path)
        
        if not report:
            continue

        if "assets" in report and "damage_scenarios" in report:
            assets_block = report["assets"]
            damage_block = report["damage_scenarios"]
            model_name = assets_block.get("model_id", fname.replace(".json", ""))
            nodes_list = assets_block.get("template", {}).get("nodes", [])
            derivation_list = damage_block.get("Derivations") or damage_block.get("derivation") or []
            details_list = damage_block.get("Details") or damage_block.get("details") or []
        elif "Assets" in report:
            a_block = report["Assets"][0] if report.get("Assets") else {}
            model_name = report["Models"][0]["name"] if report.get("Models") else fname
            nodes_list = a_block.get("template", {}).get("nodes", [])
            ds_list = report.get("Damage_scenarios") or report.get("DamageScenarios") or []
            d_block = ds_list[0] if ds_list else {}
            derivation_list = d_block.get("Derivations") or d_block.get("derivation") or []
            details_list = d_block.get("Details") or d_block.get("details") or []
        else:
            print(f"  Unrecognised format in {fname} — skipping.")
            continue

        node_count = 0
        for node in nodes_list:
            label, desc, props, ntype = _clean_node_for_text(node)
            if not label or label.strip() == "":
                continue
            is_asset = node.get("isAsset", False)
            docs.append(Document(
                content=(
                    f"Reference Component [{model_name}]: {label}\n"
                    f"Type: {ntype}  IsAsset: {is_asset}\n"
                    f"Description: {desc}\n"
                    f"Security Properties: {', '.join(props) if props else 'N/A'}"
                ),
                meta={"source": "REPORTS_DB", "file": fname, "model": model_name,
                      "type": "asset", "is_asset": is_asset, "node_id": node.get("id", "")}
            ))
            node_count += 1

        deriv_count = 0
        for d in derivation_list:
            name = d.get("name", "")
            if not name:
                continue
            docs.append(Document(
                content=(
                    f"Reference Damage Derivation [{model_name}]:\n"
                    f"Threat/Weakness: {name}\n"
                    f"Affected Asset: {d.get('asset', '')}\n"
                    f"Cyber Loss: {d.get('loss', '')}\n"
                    f"Damage Scene: {d.get('damage_scene', '')}"
                ),
                meta={"source": "REPORTS_DB", "file": fname,
                      "model": model_name, "type": "damage_derivation"}
            ))
            deriv_count += 1

        detail_count = 0
        for det in details_list:
            dname = det.get("Name", "")
            if not dname:
                continue
            impacts = det.get("impacts", {})
            losses = [(cl.get("name", ""), cl.get("node", "")) for cl in det.get("cyberLosses", [])]
            impact_str = "  ".join(f"{k}: {v}" for k, v in impacts.items() if v)
            loss_str = ", ".join(f"{n} ({nd})" for n, nd in losses if n)
            docs.append(Document(
                content=(
                    f"Reference Damage Scenario [{model_name}]: {dname}\n"
                    f"Description: {_truncate_short(det.get('Description', ''), 800)}\n"
                    f"Cyber Losses: {loss_str}\n"
                    f"Impact Ratings: {impact_str}"
                ),
                meta={"source": "REPORTS_DB", "file": fname,
                      "model": model_name, "type": "damage_detail"}
            ))
            detail_count += 1

        # Hierarchy summary
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
                meta={"source": "REPORTS_DB", "file": fname,
                      "model": model_name, "type": "hierarchy_summary"}
            ))

        print(f"  {fname}: {node_count} components | {deriv_count} derivations | {detail_count} details")

    print(f"\nREPORTS_DB (JSON) total chunks: {len(docs)}")
    return docs


def ingest_markdown_reports() -> List[Document]:
    """Ingest professional Markdown knowledge documents from Azure."""
    client = get_azure_client()
    md_blobs = client.list_blobs(AZURE_PATHS["REPORTS_PATH"])
    
    docs = []
    
    for blob_path in md_blobs:
        if not blob_path.endswith(".md"):
            continue
        
        fname = blob_path.split("/")[-1]
        content = client.download_text(blob_path)
        
        if not content:
            continue

        sections = re.split(r"\n(?=## )", content)
        for i, sec in enumerate(sections):
            if not sec.strip():
                continue
            
            docs.append(Document(
                content=sec.strip(),
                meta={
                    "source": "KNOWLEDGE_BASE",
                    "file": fname,
                    "section": i,
                    "type": "markdown_report"
                }
            ))
        print(f"  {fname}: Processed {len(sections)} knowledge sections.")

    print(f"KNOWLEDGE_BASE (Markdown) total chunks: {len(docs)}")
    return docs


def ingest_pdfs() -> List[Document]:
    """Ingest PDF files from Azure by extracting text and chunking."""
    client = get_azure_client()
    pdf_blobs = client.list_blobs(AZURE_PATHS["PDF_PATH"])
    
    docs = []
    
    try:
        from pypdf import PdfReader
        from io import BytesIO
    except ImportError:
        print("⚠️  pypdf not installed. Skipping PDF ingestion.")
        return []

    for blob_path in pdf_blobs:
        if not blob_path.endswith(".pdf"):
            continue
        
        fname = blob_path.split("/")[-1]
        print(f"  Ingesting PDF: {fname}...")
        
        try:
            data = client.download_blob(blob_path)
            if not data:
                continue
            
            reader = PdfReader(BytesIO(data))
            full_text = ""
            for i, page in enumerate(reader.pages):
                text = page.extract_text()
                if text:
                    full_text += f"\n--- Page {i+1} ---\n" + text
            
            chunk_size = 2000
            overlap = 200
            
            p_docs = []
            for i in range(0, len(full_text), chunk_size - overlap):
                chunk = full_text[i:i + chunk_size]
                if not chunk.strip():
                    continue
                
                p_docs.append(Document(
                    content=chunk.strip(),
                    meta={
                        "source": "REGULATION_PDF",
                        "file": fname,
                        "chunk_index": len(p_docs),
                        "type": "technical_regulation"
                    }
                ))
            docs.extend(p_docs)
            print(f"    {fname}: {len(p_docs)} chunks created.")
        except Exception as e:
            print(f"  ❌ Error processing {fname}: {e}")

    return docs


# ─────────────────────────────────────────────────────────────────────────────
# Master loader
# ─────────────────────────────────────────────────────────────────────────────

def load_all_documents() -> List[Document]:
    """Load and merge all dataset sources from Azure."""
    print("Loading threat frameworks...")
    mitre_mobile = ingest_mitre("MITRE_MOBILE")
    mitre_ics = ingest_mitre("MITRE_ICS")
    atm_docs = ingest_atm()
    capec_docs = ingest_capec()
    cwe_docs = ingest_cwe()
    
    print(f"  MITRE Mobile: {len(mitre_mobile)}, MITRE ICS: {len(mitre_ics)}")
    print(f"  ATM: {len(atm_docs)}, CAPEC: {len(capec_docs)}, CWE: {len(cwe_docs)}")

    print("\nLoading ISO 21434 clauses...")
    iso_docs = ingest_iso_clauses()
    annex_docs = ingest_annex()

    print("\nLoading ECU data...")
    ecu_docs = ingest_ecu()

    print("\nLoading REPORTS DB...")
    reports_docs = ingest_reports_db()
    kb_docs = ingest_markdown_reports()

    print("\nLoading PDF regulations...")
    pdf_docs = ingest_pdfs()

    all_docs = ecu_docs + iso_docs + annex_docs
    all_docs += mitre_mobile + mitre_ics + atm_docs + capec_docs + cwe_docs
    all_docs += reports_docs + kb_docs + pdf_docs

    print(f"\n{'='*50}")
    print(f"Total documents: {len(all_docs)}")
    dist = Counter(d.meta.get("source", "?") for d in all_docs)
    for src, cnt in sorted(dist.items()):
        print(f"  {src:<20}: {cnt}")
    
    return all_docs