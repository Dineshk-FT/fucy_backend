from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable
from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import BlobServiceClient

from haystack import Document
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import SentenceTransformersDocumentEmbedder

relationships = {
    "CAPEC-66": ["CWE-89"],
    "CAPEC-100": ["CWE-79"],
    "CAPEC-115": ["CWE-119"],
}

blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
rag_container = blob.get_container_client("rag")

@dataclass(frozen=True)
class IngestPaths:
    annex_path: str = "annex.json"
    data_path: str = "data.json"
    mitre_mobile_path: str = "mobile-attack (1).json"
    mitre_ics_path: str = "ics-attack (1).json"
    atm_path: str = "atm.json"
    capec_path: str = "capec_v3.9.xml"
    cwe_path: str = "cwec_v4.19.1.xml"

def chunk_text(text, chunk_size=400, overlap=50):
    chunks = []
    start = 0

    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - overlap

    return chunks

def load_ecu_data(data_blob_name: str = "data.json") -> list[dict[str, Any]]:
    # change this
    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client(data_blob_name)
    raw = bc.download_blob().readall()
    ecu_data = json.loads(raw)

    # with open(data_path, "r", encoding="utf-8") as f:
    #     ecu_data = json.load(f)
    ecu_docs = []
    for k, v in ecu_data.items():
        ecu_docs.append(
            Document(
                content=json.dumps(v, indent=2),
                meta={
                    "source": "ECU",
                    "title": k
                }
            )
        )
    print("ECU Loaded")
    return ecu_docs

def load_clause_jsons() -> list[dict[str, Any]]:
    # add metadata here

    records = []
    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")

    for b in rag_container.list_blobs(name_starts_with="clause"):
        name = b.name
        bc = rag_container.get_blob_client(name)
        
        raw = bc.download_blob().readall()
        clause = json.loads(raw)
        number = int(re.search(r'-(\d+)\.json', name).group(1))
        
        records.append(
            Document(
                content=clause.get(
                    "content",
                    json.dumps(clause, indent=2)
                ),
                meta={
                    "source": "ISO_21434",
                    "clause": number,
                    "title": clause.get("title", f"Clause {number}")
                }
            )
        )
    

    return records

def load_annex(annex_blob_name: str = "annex.json") -> list[dict[str, Any]]:
    # annex contains impact information
    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client(annex_blob_name)
    raw = bc.download_blob().readall()
    annex_json = json.loads(raw)

    annex_docs = []

    content_parts = [
        f"Annex {annex_json.get('annex_id', '')}: {annex_json.get('annex_title', '')}"
    ]

    for section in annex_json.get("sections", []):
        content_parts.append(
            f"\n\n### {section.get('section_id')} — {section.get('section_title')}"
        )

        for c in section.get("content", []):
            content_parts.append(f"- {c}")

        for t in section.get("tables", []):
            content_parts.append(
                f"\nTable {t.get('table_id')}: {t.get('table_title')}"
            )
            cols = t.get("columns", [])
            rows = t.get("rows", [])

            if cols and rows:
                content_parts.append(" | ".join(cols))
                content_parts.append("-" * 40)
                for r in rows:
                    content_parts.append(
                        " | ".join(str(r.get(col, "")) for col in cols)
                    )

        for note in section.get("notes", []):
            content_parts.append(f"Note: {note}")

    annex_docs.append(
        Document(
            content="\n".join(content_parts),
            meta={
                "source": "ANNEX_F",
                "annex": annex_json.get("annex_id"),
                "title": annex_json.get("annex_title")
            }
        )
    )
    return annex_docs

def load_all_records(paths: IngestPaths) -> list[dict[str, Any]]:
    records = (
        load_ecu_data("data.json")
        + load_clause_jsons()
        + load_annex("annex.json")
        + ingest_mitre("mobile-attack.json", "MITRE_MOBILE")
        + ingest_mitre("ics-attack.json", "MITRE_ICS")
        + ingest_atm("atm.json")
        + ingest_capec("capec_v3.9.xml")
        + ingest_cwe("cwec_v4.19.1.xml")
    )
    print("INGESTED ALL RECORDS")

    return records

def to_haystack_documents(records: Iterable[dict[str, Any] | Document]) -> list[Document]:
    docs: list[Document] = []
    seen_ids: set[str] = set()
    duplicate_count = 0

    for item in records:
        if isinstance(item, Document):
            doc = item
        else:
            meta = {k: v for k, v in item.items() if k not in {"content", "type"}}
            meta["source"] = item.get("type") or "Unknown"
            doc = Document(
                content=item.get("content", ""),
                meta=meta,
            )

        if doc.id in seen_ids:
            duplicate_count += 1
            continue

        seen_ids.add(doc.id)
        docs.append(doc)

    if duplicate_count:
        print(f"[RAG] Skipped {duplicate_count} duplicate document(s) during ingest.")

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

def ingest_mitre(mitre_blob_name: str, source: str = "MITRE"):
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client(mitre_blob_name)
    raw = bc.download_blob().readall()
    data = json.loads(raw)

    docs = []

    for obj in data.get("objects", []):

        if obj.get("type") == "attack-pattern":

            name = obj.get("name", "")
            desc = obj.get("description", "")

            if not desc:
                continue

            text = f"MITRE Technique: {name}\nDescription: {desc}"

            chunks = chunk_text(text)

            for chunk in chunks:

                docs.append(
                    Document(
                        content=chunk,
                        meta={
                            "source": source,
                            "stix_id": obj.get("id"),
                            "technique": name
                        }
                    )
                )

    return docs

def ingest_atm(atm_blob_name: str = "atm.json"):
    """
    Ingests an Automotive Threat Matrix JSON from Azure blob storage.
    Handles common shapes (list or dict with techniques/entries).
    """
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client(atm_blob_name)
    raw = bc.download_blob().readall()
    data = json.loads(raw)

    docs = []

    for obj in data.get("objects", []):

        if obj.get("type") == "attack-pattern":

            name = obj.get("name", "")
            desc = obj.get("description", "")

            if not desc:
                continue

            text = f"ATM Technique: {name}\nDescription: {desc}"

            chunks = chunk_text(text)

            for chunk in chunks:

                docs.append(
                    Document(
                        content=chunk,
                        meta={
                            "source": "ATM",
                            "stix_id": obj.get("id"),
                            "technique": name
                        }
                    )
                )
    print("ATM DONE")
    return docs

def ingest_capec(capec_blob_name: str = "capec.xml"):
    """
    Ingests CAPEC XML from Azure blob storage using xml.etree.ElementTree.
    Extracts Attack_Pattern/Attack_Patterns with ID, Name, and Summary/Description.
    """
    import xml.etree.ElementTree as ET
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client(capec_blob_name)
    raw = bc.download_blob().readall()
    root = ET.fromstring(raw)

    ns = {"capec": "http://capec.mitre.org/capec-3"}

    docs = []
    patterns = root.findall(".//capec:Attack_Pattern", ns)
    if not patterns:
        patterns = root.findall(".//{*}Attack_Pattern")

    for ap in patterns:

        capec_id = ap.get("ID")

        name = ap.findtext("capec:Name", default="", namespaces=ns)
        desc = ap.findtext("capec:Description", default="", namespaces=ns)

        if not desc:
            continue

        text = f"CAPEC-{capec_id}: {name}\nDescription: {desc}"

        chunks = chunk_text(text)

        related_cwe = relationships.get(f"CAPEC-{capec_id}", [])

        for chunk in chunks:

            docs.append(
                Document(
                    content=chunk,
                    meta={
                        "source": "CAPEC",
                        "capec_id": f"CAPEC-{capec_id}",
                        "attack_pattern": name,
                        "related_cwe": related_cwe
                    }
                )
            )
    print("ended capec ingestion")
    return docs

def ingest_cwe(cwe_blob_name: str = "cwe.xml"):
    """
    Ingests CWE XML from Azure blob storage.
    Tries lxml for robustness (huge files); falls back to ElementTree.
    Extracts Weakness entries (ID, Name, Description).
    """
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client(cwe_blob_name)
    raw = bc.download_blob().readall()
    try:
        from lxml import etree as LET  # type: ignore
        parser = LET.XMLParser(recover=True, huge_tree=True)
        root = LET.fromstring(raw, parser=parser)
    except Exception:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(raw)

    docs = []

    for w in root.findall(".//{*}Weakness"):

        cwe_id = w.get("ID")
        name = w.get("Name")

        desc_elem = w.find(".//{*}Description")

        desc = desc_elem.text if desc_elem is not None else ""

        if not desc:
            continue

        text = f"CWE-{cwe_id}: {name}\nDescription: {desc}"

        chunks = chunk_text(text)

        for chunk in chunks:

            docs.append(
                Document(
                    content=chunk,
                    meta={
                        "source": "CWE",
                        "cwe_id": f"CWE-{cwe_id}",
                        "weakness": name
                    }
                )
            )

    return docs
