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
    pipeline = Pipeline()

    pipeline.add_component("text_embedder", text_embedder)
    pipeline.add_component("retriever", retriever)
    pipeline.add_component("prompt_builder", prompt_builder)

    pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
    pipeline.connect("retriever", "prompt_builder.documents")

    return pipeline
