# =============================================================================
# main.py — CLI entry point for TARA LangGraph RAG Pipeline
# =============================================================================

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from components import (
    resolve_ecu, list_ecus, build_enriched_query,
    parse_and_fix, print_summary,
    EMBED_MODEL, GEMINI_MODEL, RETRIEVER_TOP_K,
)
from app.v1.rag.ingest import load_all_documents
from app.v1.rag.pipeline import build_graph


def main():
    parser = argparse.ArgumentParser(description="TARA Agentic RAG Pipeline")
    parser.add_argument("--query", "-q", type=str, default=None)
    parser.add_argument("--output", "-o", type=str, default=None)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--list-ecus", action="store_true")
    args = parser.parse_args()

    if args.list_ecus:
        list_ecus()
        return

    if not args.query:
        parser.print_help()
        sys.exit(1)

    user_query = args.query.strip()

    print("\n" + "=" * 60)
    print("  TARA Agentic RAG (LangGraph) with Azure")
    print("=" * 60)
    print(f"  Query : {user_query}")
    print("=" * 60 + "\n")

    if "GOOGLE_API_KEY" not in os.environ:
        print("[Error] GOOGLE_API_KEY not set")
        sys.exit(1)

    print("[1/4] Resolving ECU...")
    ecu_entry = resolve_ecu(user_query)
    if ecu_entry:
        print(f"  [Success] Matched : {ecu_entry['name']}")
    else:
        print("  [Warning] No match found")

    enriched_query = build_enriched_query(user_query, ecu_entry)

    print("\n[2/4] Loading documents from Azure...")
    all_docs = load_all_documents()

    print("\n[3/4] Building LangGraph pipeline...")
    graph = build_graph(all_docs)

    print("\n[4/4] Generating report...")
    print(f"  Embedding model : {EMBED_MODEL}")
    print(f"  LLM model       : {GEMINI_MODEL}")
    print(f"  Retriever top_k : {RETRIEVER_TOP_K}")

    result = graph.invoke({
        "user_query": user_query,
        "enriched_query": enriched_query,
        "retry_count": 0
    })

    raw_output = result["answer"]

    print("\nPost-processing...")
    tara_json = parse_and_fix(raw_output)

    if tara_json is None:
        print("[Error] Failed to parse output")
        print(raw_output[:1000])
        sys.exit(1)

    print("[Success] JSON parsed successfully")
    print_summary(tara_json)

    if not args.no_save:
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", user_query.strip())
        
        outputs_dir = Path(__file__).parent / "outputs"
        tara_dir = outputs_dir / "Results"
        tara_dir.mkdir(parents=True, exist_ok=True)

        out_file = args.output or f"tara_output_{safe_name}.json"
        out_path = tara_dir / out_file
        
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(tara_json, f, indent=2, ensure_ascii=False)
        print(f"[Success] TARA Saved -> {out_path}")
        
        print(f"  [Score] Final Score: {result.get('eval_score', 0)}%")
        print("\n" + "=" * 60)
        print("  TARA GENERATION COMPLETE")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()