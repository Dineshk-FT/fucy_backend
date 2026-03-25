# =============================================================================
# pipeline.py — Haystack RAG pipeline assembly and run
# =============================================================================

from collections import Counter

from haystack import Pipeline
from haystack.components.builders import PromptBuilder

from components import build_store, build_retriever, build_generator, EMBED_MODEL, RETRIEVER_TOP_K
from prompt import TARA_PROMPT_TEMPLATE


def build_pipeline(all_docs):
    """
    Embed documents, build and connect the full Haystack RAG pipeline.

    Returns:
        pipeline       — assembled, connected Haystack Pipeline
        text_embedder  — SentenceTransformersTextEmbedder (needed for run_query)
    """
    # Build document store and embedders
    store, text_embedder = build_store(all_docs)

    # Build components
    retriever      = build_retriever(store)
    generator      = build_generator()
    prompt_builder = PromptBuilder(
        template=TARA_PROMPT_TEMPLATE,
        required_variables=["documents", "question"],
    )

    # Assemble pipeline
    pipeline = Pipeline()
    pipeline.add_component("text_embedder",  text_embedder)
    pipeline.add_component("retriever",      retriever)
    pipeline.add_component("prompt_builder", prompt_builder)
    pipeline.add_component("llm",            generator)

    pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
    pipeline.connect("retriever",               "prompt_builder.documents")
    pipeline.connect("prompt_builder",          "llm")

    print("✅ TARA RAG pipeline built and connected.")
    return pipeline, text_embedder


def run_query(pipeline, user_query: str, enriched_query: str) -> str:
    """
    Run the pipeline for a single query.

    Args:
        pipeline:       Assembled Haystack pipeline (from build_pipeline).
        user_query:     Plain query — used for embedding (accurate retrieval).
        enriched_query: Query + authoritative asset list — used for the LLM prompt.

    Returns:
        Raw LLM reply string.
    """
    result = pipeline.run(
        {
            "text_embedder":  {"text": user_query},
            "prompt_builder": {"question": enriched_query},
        },
        include_outputs_from=["retriever"],
    )

    ret_docs = result["retriever"]["documents"]
    print(f"\nDocuments retrieved : {len(ret_docs)}")
    print(f"Sources             : {Counter(d.meta.get('source') for d in ret_docs)}\n")

    return result["llm"]["replies"][0] if result["llm"]["replies"] else ""