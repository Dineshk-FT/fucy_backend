from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable
from azure.storage.blob import BlobServiceClient

from haystack import Document
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import SentenceTransformersDocumentEmbedder


blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
rag_container = blob.get_container_client("rag")

@dataclass(frozen=True)
class IngestPaths:
    annex_path: str = "annex.json"
    data_path: str = "data.json"


def load_ecu_data() -> list[dict[str, Any]]:
    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client("rag", IngestPaths.data_path)
    raw = bc.download_blob().readall()
    ecu_data = json.loads(raw)

    # with open(data_path, "r", encoding="utf-8") as f:
    #     ecu_data = json.load(f)

    if isinstance(ecu_data, dict):
        return list(ecu_data.values())
    if isinstance(ecu_data, list):
        return ecu_data

    return [{"type": "ECU", "content": json.dumps(ecu_data, indent=2)}]


def load_clause_jsons() -> list[dict[str, Any]]:

    records = []

    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")

    for b in rag_container.list_blobs(name_starts_with="clause"):
        name = b.name
        bc = rag_container.get_blob_client("rag", name)
        
        raw = bc.download_blob().readall()
        clause = json.loads(raw)
        number = int(re.search(r'-(\d+)\.json', name).group(1))

        records.append(
            {
                "type": "Clause",
                "clause": number,
                "title": clause.get("title", f"Clause {number}"),
                "content": clause.get("content", json.dumps(clause, indent=2)),
            }
        )


    # for file in clause_files:
    #     with open(file, "r", encoding="utf-8") as f:
    #         clause = json.load(f)

    #     clause_number = os.path.splitext(os.path.basename(file))[0].split("-")[1]

    #     records.append(
    #         {
    #             "type": "Clause",
    #             "clause": clause_number,
    #             "title": clause.get("title", f"Clause {clause_number}"),
    #             "content": clause.get("content", json.dumps(clause, indent=2)),
    #         }
    #     )

    return records


def load_annex() -> list[dict[str, Any]]:

    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client("rag", IngestPaths.annex_path)
    raw = bc.download_blob().readall()
    annex_json = json.loads(raw)

    # with open(annex_path, "r", encoding="utf-8") as f:
    #     annex_json = json.load(f)

    annex_records = []

    if isinstance(annex_json, dict) and "annex_id" in annex_json:
        parts = [
            f"Annex {annex_json.get('annex_id')} — {annex_json.get('annex_title')}"
        ]

        for section in annex_json.get("sections", []):
            parts.append(
                f"\n### {section.get('section_id')} — {section.get('section_title')}"
            )

            for c in section.get("content", []):
                parts.append(f"- {c}")

            for t in section.get("tables", []):
                parts.append(f"\nTable {t.get('table_id')}: {t.get('table_title')}")

                if "columns" in t and "rows" in t:
                    parts.append(" | ".join(t["columns"]))
                    parts.append("-" * 40)
                    for row in t["rows"]:
                        parts.append(
                            " | ".join(str(row.get(col, "")) for col in t["columns"])
                        )

            for note in section.get("notes", []):
                parts.append(f"Note: {note}")

        annex_records.append(
            {
                "type": "Annex",
                "title": annex_json.get("annex_title"),
                "content": "\n".join(parts),
            }
        )
    else:
        annex_records.append(
            {
                "type": "Annex",
                "content": json.dumps(annex_json, indent=2),
            }
        )

    return annex_records


def load_all_records(paths: IngestPaths) -> list[dict[str, Any]]:
    return (
        load_ecu_data()
        + load_clause_jsons()
        + load_annex()
    )


def to_haystack_documents(records: Iterable[dict[str, Any]]) -> list[Document]:
    docs = []
    for item in records:
        docs.append(
            Document(
                content=item.get("content", ""),
                meta={
                    "source": item.get("type"),
                    "title": item.get("title"),
                    "clause": item.get("clause"),
                },
            )
        )
    return docs


def index_documents(
    document_store: InMemoryDocumentStore,
    doc_embedder: SentenceTransformersDocumentEmbedder,
    docs: list[Document],
) -> list[Document]:
    document_store.write_documents(docs)
    result = doc_embedder.run(documents=docs)
    embedded_docs = result["documents"]
    document_store.write_documents(embedded_docs, policy="overwrite")
    return embedded_docs


def summarize_by_source(docs: list[Document]) -> dict[str, int]:
    out = {}
    for d in docs:
        src = (d.meta or {}).get("source", "Unknown")
        out[src] = out.get(src, 0) + 1
    return out


def ingest_mitre(mitre_blob_name: str, source: str = "MITRE") -> list[dict[str, Any]]:
    """
    Ingests a MITRE ATT&CK STIX-like JSON bundle from Azure blob storage.

    Returns records like:
      {"type": "MITRE_ICS", "title": "Txxxx Technique Name", "content": "...", ...}
    """
    bc = rag_container.get_blob_client("rag", mitre_blob_name)
    raw = bc.download_blob().readall()
    bundle = json.loads(raw)

    records: list[dict[str, Any]] = []

    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
    if not isinstance(objects, list):
        return records

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "attack-pattern":
            continue

        name = obj.get("name", "")
        desc = obj.get("description", "")

        technique_id = ""
        url = ""
        refs = obj.get("external_references", [])
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                ext_id = ref.get("external_id", "")
                if isinstance(ext_id, str) and ext_id.startswith("T") and not technique_id:
                    technique_id = ext_id
                if not url and ref.get("url"):
                    url = ref.get("url")

        tactics = []
        kcp = obj.get("kill_chain_phases", [])
        if isinstance(kcp, list):
            for p in kcp:
                if isinstance(p, dict) and p.get("phase_name"):
                    tactics.append(p.get("phase_name"))

        platforms = obj.get("x_mitre_platforms", [])
        if not isinstance(platforms, list):
            platforms = []

        lines = []
        header = f"{technique_id} {name}".strip() if technique_id else str(name).strip()
        if header:
            lines.append(f"Technique: {header}")
        if tactics:
            lines.append(f"Tactics: {', '.join(str(t) for t in tactics if t)}")
        if platforms:
            lines.append(f"Platforms: {', '.join(str(p) for p in platforms if p)}")
        if url:
            lines.append(f"Reference: {url}")
        if desc:
            lines.append("")
            lines.append(str(desc).strip())

        records.append(
            {
                "type": source,
                "title": header or source,
                "content": "\n".join(lines).strip(),
                "technique_id": technique_id,
                "url": url,
            }
        )

    return records


def ingest_atm(atm_blob_name: str = "atm.json") -> list[dict[str, Any]]:
    """
    Ingests an Automotive Threat Matrix JSON from Azure blob storage.
    Handles common shapes (list or dict with techniques/entries).
    """
    bc = rag_container.get_blob_client("rag", atm_blob_name)
    raw = bc.download_blob().readall()
    atm_json = json.loads(raw)

    records: list[dict[str, Any]] = []

    entries: list[Any] = []
    if isinstance(atm_json, list):
        entries = atm_json
    elif isinstance(atm_json, dict):
        for key in ("techniques", "entries", "objects", "data"):
            v = atm_json.get(key)
            if isinstance(v, list):
                entries = v
                break
        if not entries:
            vals = list(atm_json.values())
            if vals and all(isinstance(x, dict) for x in vals):
                entries = vals

    for e in entries:
        if not isinstance(e, dict):
            continue

        atm_id = e.get("id") or e.get("technique_id") or e.get("external_id") or ""
        name = e.get("name") or e.get("title") or atm_id or ""
        desc = e.get("description") or e.get("details") or ""
        domain = e.get("domain") or e.get("matrix") or ""

        header = f"{atm_id} — {name}".strip(" —")
        lines = [header] if header else [str(name)]
        if domain:
            lines.append(f"Domain: {domain}")
        if desc:
            lines.append("")
            lines.append(str(desc).strip())

        records.append(
            {
                "type": "ATM",
                "title": header or str(name) or "ATM",
                "content": "\n".join(lines).strip(),
                "atm_id": str(atm_id),
                "domain": str(domain),
            }
        )

    return records


def ingest_capec(capec_blob_name: str = "capec.xml") -> list[dict[str, Any]]:
    """
    Ingests CAPEC XML from Azure blob storage using xml.etree.ElementTree.
    Extracts Attack_Pattern/Attack_Patterns with ID, Name, and Summary/Description.
    """
    import xml.etree.ElementTree as ET

    bc = rag_container.get_blob_client("rag", capec_blob_name)
    xml_bytes = bc.download_blob().readall()

    records: list[dict[str, Any]] = []

    root = ET.fromstring(xml_bytes)

    # Prefer namespace-tolerant finds
    patterns = root.findall(".//{*}Attack_Pattern")
    if not patterns:
        # Some CAPEC dumps may use different casing
        patterns = root.findall(".//{*}attack_pattern")

    for ap in patterns:
        capec_id = ap.attrib.get("ID") or ap.attrib.get("Id") or ap.attrib.get("id") or ""
        name = ap.findtext(".//{*}Name") or ap.findtext(".//{*}name") or ""
        summary = ap.findtext(".//{*}Summary") or ap.findtext(".//{*}Description") or ""

        header = f"CAPEC-{capec_id} — {name}".strip(" —")
        content = "\n".join([header, "", str(summary).strip()]).strip()

        records.append(
            {
                "type": "CAPEC",
                "title": header or str(name) or "CAPEC",
                "content": content,
                "capec_id": f"CAPEC-{capec_id}" if capec_id else "",
            }
        )

    return records


def ingest_cwe(cwe_blob_name: str = "cwe.xml") -> list[dict[str, Any]]:
    """
    Ingests CWE XML from Azure blob storage.
    Tries lxml for robustness (huge files); falls back to ElementTree.
    Extracts Weakness entries (ID, Name, Description).
    """
    bc = rag_container.get_blob_client("rag", cwe_blob_name)
    xml_bytes = bc.download_blob().readall()

    records: list[dict[str, Any]] = []

    # Try lxml first (better for huge CWE dumps)
    try:
        from lxml import etree as LET  # type: ignore

        parser = LET.XMLParser(recover=True, huge_tree=True)
        root = LET.fromstring(xml_bytes, parser=parser)

        for w in root.findall(".//{*}Weakness"):
            cwe_id = w.get("ID") or ""
            name = w.get("Name") or ""
            desc_el = w.find(".//{*}Description")
            desc = desc_el.text if desc_el is not None and desc_el.text else ""

            header = f"CWE-{cwe_id} — {name}".strip(" —")
            content = "\n".join([header, "", str(desc).strip()]).strip()

            records.append(
                {
                    "type": "CWE",
                    "title": header or str(name) or "CWE",
                    "content": content,
                    "cwe_id": f"CWE-{cwe_id}" if cwe_id else "",
                }
            )

        return records

    except Exception:
        pass

    # Fallback: ElementTree
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_bytes)

    for w in root.findall(".//{*}Weakness"):
        cwe_id = w.attrib.get("ID") or ""
        name = w.attrib.get("Name") or ""
        desc = ""
        d = w.find(".//{*}Description")
        if d is not None and d.text:
            desc = d.text

        header = f"CWE-{cwe_id} — {name}".strip(" —")
        content = "\n".join([header, "", str(desc).strip()]).strip()

        records.append(
            {
                "type": "CWE",
                "title": header or str(name) or "CWE",
                "content": content,
                "cwe_id": f"CWE-{cwe_id}" if cwe_id else "",
            }
        )

    return records
