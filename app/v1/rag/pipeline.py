from __future__ import annotations

from haystack import Pipeline
from haystack.components.builders import PromptBuilder
from haystack.components.embedders import SentenceTransformersTextEmbedder
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever


def build_retrieval_prompt_pipeline(
    text_embedder: SentenceTransformersTextEmbedder,
    retriever: InMemoryEmbeddingRetriever,
    prompt_builder: PromptBuilder,
) -> Pipeline:
    """Build a RAG pipeline with retrieval and prompt building."""
    pipeline = Pipeline()

    pipeline.add_component("text_embedder", text_embedder)
    pipeline.add_component("retriever", retriever)
    pipeline.add_component("prompt_builder", prompt_builder)

    pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
    pipeline.connect("retriever", "prompt_builder.documents")

    print("✅ TARA RAG pipeline built and connected successfully.")
    return pipeline


def create_complete_pipeline(
    text_embedder: SentenceTransformersTextEmbedder,
    retriever: InMemoryEmbeddingRetriever,
    prompt_builder: PromptBuilder,
    llm: object,
) -> Pipeline:
    """Build a complete RAG pipeline including LLM generation."""
    pipeline = Pipeline()

    pipeline.add_component("text_embedder", text_embedder)
    pipeline.add_component("retriever", retriever)
    pipeline.add_component("prompt_builder", prompt_builder)
    pipeline.add_component("llm", llm)

    pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
    pipeline.connect("retriever", "prompt_builder.documents")
    pipeline.connect("prompt_builder", "llm")

    print("✅ Complete TARA RAG pipeline built with LLM.")
    return pipeline