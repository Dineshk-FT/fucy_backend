from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable
from azure import BlobServiceClient

from haystack import Document
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import SentenceTransformersDocumentEmbedder


blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
rag_container = blob.get_container_client("rag")

@dataclass(frozen=True)
class IngestPaths:
    clause_dir: str = "./clauses"
    annex_path: str = "annex.json"
    data_path: str = "data.json"


def load_ecu_data() -> list[dict[str, Any]]:
    blob = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=fucytechdocs;AccountKey=+MpE5EQsABQbMW+HnS0vj1PqXbWc2AzBEeKwzMbPNz4S3lXPfkoxFv5m2rUj2y3GXpbxInJucWH7+AStJSYK5w==;EndpointSuffix=core.windows.net")
    rag_container = blob.get_container_client("rag")
    bc = rag_container.get_blob_client("rag", "data.json")
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
        bc = rag_container.get_blob_client("rag", "b.name")
        
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
    bc = rag_container.get_blob_client("rag", "annex.json")
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
