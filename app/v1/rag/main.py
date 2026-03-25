# =============================================================================
# main.py — CLI entry point and exports for TARA RAG Pipeline (Azure version)
# =============================================================================

import argparse
import json
import os
import re
import sys
from pathlib import Path
from collections import Counter
from typing import Iterable

sys.path.insert(0, str(Path(__file__).parent))

from haystack import Document
from haystack.components.builders import PromptBuilder

from components import (
    resolve_ecu, list_ecus, build_enriched_query,
    parse_and_fix, print_summary,
    stamp_uuids, crosslink_node_ids,
    EMBED_MODEL, GEMINI_MODEL, RETRIEVER_TOP_K,
    build_store, build_retriever, build_generator,
)
from ingest import load_all_documents
from pipeline import build_pipeline, run_query
from prompt import TARA_PROMPT_TEMPLATE


# ── Document retrieval functions ──────────────────────────────────────────────

def retrieve_documents(query: str, top_k: int = 70) -> list[Document]:
    """
    Retrieve documents for a given query.
    Returns a list of Haystack Document objects.
    """
    print(f"Loading documents from Azure...")
    all_docs = load_all_documents()
    
    print(f"Building pipeline...")
    pipeline, _ = build_pipeline(all_docs)
    
    print(f"Retrieving documents for: {query}")
    result = pipeline.run(
        {
            "text_embedder": {"text": query},
            "prompt_builder": {"question": query},
        },
        include_outputs_from=["retriever"],
    )
    
    return result["retriever"]["documents"]


def build_prompt_from_documents(
    query: str, 
    documents: list[Document], 
    template: str = None
) -> str:
    """
    Build a prompt from retrieved documents.
    """
    template_to_use = template or TARA_PROMPT_TEMPLATE
    
    prompt_builder = PromptBuilder(
        template=template_to_use,
        required_variables=["documents", "question"],
    )
    
    result = prompt_builder.run(documents=documents, question=query)
    return result["prompt"]


def build_rag_context(
    documents: Iterable[Document],
    joiner: str = "\n\n---\n\n",
    include_meta: bool = True,
) -> str:
    """
    Build a context string from documents for the prompt.
    
    Args:
        documents: List of Haystack Document objects
        joiner: String to join document contexts
        include_meta: Whether to include metadata in the context
    
    Returns:
        Formatted context string
    """
    parts: list[str] = []
    for doc in documents:
        content = doc.content or ""
        if include_meta and doc.meta:
            source = doc.meta.get("source", "Unknown")
            section = doc.meta.get("section_id", "") or doc.meta.get("type", "")
            if section:
                parts.append(f"[{source} § {section}]\n{content}")
            else:
                parts.append(f"[{source}]\n{content}")
        else:
            parts.append(content)
    return joiner.join(parts)


# ── Document store verification ──────────────────────────────────────────────

def verify_document_store(document_store) -> None:
    """Verify that all expected sources are present in the document store."""
    stored = document_store.filter_documents()
    sources = {d.meta.get("source") for d in stored}

    total_docs = document_store.count_documents()
    print(f"\n{'='*50}")
    print(f"Total documents in store: {total_docs}")

    if total_docs == 0:
        print("⚠️  WARNING: No documents found in store!")
        print("   Check Azure connection and blob paths.")
        print(f"{'='*50}\n")
        return

    dist = Counter(d.meta.get("source", "?") for d in stored)
    for src, cnt in sorted(dist.items()):
        print(f"  {src:<20}: {cnt}")

    if total_docs >= 1500:
        assert "REPORTS_DB" in sources, "REPORTS_DB source missing"
        assert "ISO_21434" in sources, "ISO_21434 source missing"
        assert "CWE" in sources and "CAPEC" in sources, "Threat framework sources missing"

        reports_count = sum(1 for d in stored if d.meta.get("source") == "REPORTS_DB")
        iso_count = sum(1 for d in stored if d.meta.get("source") == "ISO_21434")

        print("\n✅ All assertions passed!")
        print(f"   ISO_21434    : {iso_count} section-level chunks")
        print(f"   REPORTS_DB   : {reports_count} asset/scenario chunks")
        print(f"   All sources  : {sorted(sources)}")
    else:
        print(f"\n⚠️  Only {total_docs} documents loaded (expected >=1500)")
    
    print(f"{'='*50}\n")


# ── RAG Resources initialization ─────────────────────────────────────────────

from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class RagResources:
    """Container for RAG resources."""
    document_store: object
    text_embedder: object
    retriever: object
    doc_embedder: object


def init_rag_resources() -> RagResources:
    """Initialize all RAG resources and ingest documents."""
    print("Initializing RAG resources...")

    print("\nLoading all documents from Azure Blob Storage...")
    all_docs = load_all_documents()

    if not all_docs:
        print("❌ ERROR: No documents loaded from Azure. Check Azure connection.")
        return RagResources(
            document_store=None,
            text_embedder=None,
            retriever=None,
            doc_embedder=None,
        )

    print("\nBuilding document store and embedders...")
    store, text_embedder = build_store(all_docs)
    retriever = build_retriever(store)

    # Verify the store has documents
    verify_document_store(store)

    return RagResources(
        document_store=store,
        text_embedder=text_embedder,
        retriever=retriever,
        doc_embedder=None,  # Not needed after initial embedding
    )


@lru_cache(maxsize=1)
def get_rag_resources() -> RagResources:
    """Get cached RAG resources (singleton)."""
    return init_rag_resources()


# ── Export list for other modules ─────────────────────────────────────────────

__all__ = [
    # Component builders
    "create_document_store",
    "create_embedders",
    "create_retriever",
    
    # Pipeline functions
    "build_pipeline",
    "run_query",
    
    # Document loading
    "load_all_documents",
    
    # Retrieval functions
    "retrieve_documents",
    "build_prompt_from_documents",
    "build_rag_context",  # Added this
    
    # ECU functions
    "resolve_ecu",
    "list_ecus",
    "build_enriched_query",
    
    # Post-processing
    "parse_and_fix",
    "print_summary",
    "stamp_uuids",
    "crosslink_node_ids",
    
    # Store verification
    "verify_document_store",
    
    # RAG Resources
    "init_rag_resources",
    "get_rag_resources",
    "RagResources",
    
    # Constants
    "EMBED_MODEL",
    "GEMINI_MODEL",
    "RETRIEVER_TOP_K",
]


# ── Re-export helper functions ──────────────────────────────────────────────

def create_document_store():
    """Re-export from components"""
    from components import create_document_store as _create_document_store
    return _create_document_store()


def create_embedders(model: str = EMBED_MODEL):
    """Re-export from components"""
    from components import create_embedders as _create_embedders
    return _create_embedders(model)


def create_retriever(document_store, top_k: int = RETRIEVER_TOP_K):
    """Re-export from components"""
    from components import create_retriever as _create_retriever
    return _create_retriever(document_store, top_k)


# ── Main CLI entry point ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TARA RAG Pipeline — ISO/SAE 21434 Threat Analysis & Risk Assessment Generator (Azure)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --query "Battery Management System ECU"
  python main.py --query "Infotainment Head Unit" --output infotainment_tara.json
  python main.py --list-ecus
        """,
    )
    parser.add_argument("--query",  "-q", type=str, default=None,
                        help='Target ECU or system (e.g. "Battery Management System ECU")')
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output JSON filename (default: tara_output_<query>.json)")
    parser.add_argument("--no-save", action="store_true",
                        help="Print JSON to console only, do not save to file")
    parser.add_argument("--list-ecus", action="store_true",
                        help="List all ECU keys from dataecu.json and exit")
    args = parser.parse_args()

    # ── List ECUs and exit (no API key needed) ────────────────────────────────
    if args.list_ecus:
        list_ecus()
        return

    if not args.query:
        parser.print_help()
        sys.exit(1)

    user_query = args.query.strip()

    print("\n" + "=" * 60)
    print("  TARA RAG Pipeline v2.0 (Azure)  |  ISO/SAE 21434")
    print("=" * 60)
    print(f"  Query : {user_query}")
    print("=" * 60 + "\n")

    # ── API key check ─────────────────────────────────────────────────────────
    if "GOOGLE_API_KEY" not in os.environ:
        print("❌ GOOGLE_API_KEY is not set.")
        print("   Windows : set GOOGLE_API_KEY=your-key-here")
        print("   Linux   : export GOOGLE_API_KEY=your-key-here")
        sys.exit(1)

    # ── Step 1: Resolve ECU from Azure ────────────────────────────────────────
    print("[1/4] Resolving ECU from dataecu.json (Azure)...")
    ecu_entry = resolve_ecu(user_query)
    if ecu_entry:
        print(f"  ✅ Matched : {ecu_entry['name']}")
        print(f"     Type   : {ecu_entry['type']}")
        print(f"     Hint   : {ecu_entry['hint'][:100]}...")
    else:
        print("  ⚠️  No dataecu.json match — using open-ended generation")

    enriched_query = build_enriched_query(user_query, ecu_entry)

    # ── Step 2: Ingest from Azure ─────────────────────────────────────────────
    print("\n[2/4] Ingesting datasets from Azure...")
    all_docs = load_all_documents()

    # ── Step 3: Embed & pipeline ──────────────────────────────────────────────
    print("\n[3/4] Embedding documents & building pipeline...")
    pipeline, _ = build_pipeline(all_docs)

    # ── Step 4: Generate ──────────────────────────────────────────────────────
    print("\n[4/4] Generating TARA report...")
    print(f"  Embedding model : {EMBED_MODEL}")
    print(f"  LLM model       : {GEMINI_MODEL}")
    print(f"  Retriever top_k : {RETRIEVER_TOP_K}")
    print(f"  Enriched query  : {enriched_query[:120]}...")

    raw_output = run_query(pipeline, user_query, enriched_query)

    # ── Post-process ──────────────────────────────────────────────────────────
    print("\nPost-processing...")
    tara_json = parse_and_fix(raw_output)

    if tara_json is None:
        print("❌ Failed to generate valid JSON. Raw output:")
        print(raw_output[:1000])
        sys.exit(1)

    print("✅ Valid JSON parsed.")
    print_summary(tara_json)

    # ── Print ─────────────────────────────────────────────────────────────────
    print("\n" + "-" * 60)
    print(json.dumps(tara_json, indent=2, ensure_ascii=False))
    print("-" * 60)

    # ── Save ──────────────────────────────────────────────────────────────────
    if not args.no_save:
        out_file = args.output or (
            "tara_output_" + re.sub(r"[^a-zA-Z0-9_-]", "_", user_query.strip()) + ".json"
        )
        out_path = Path(__file__).parent / out_file
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(tara_json, f, indent=2, ensure_ascii=False)
        print(f"\n✅ Saved → {out_path}")


if __name__ == "__main__":
    main()