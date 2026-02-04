from __future__ import annotations

from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever


DEFAULT_ST_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def create_document_store() -> InMemoryDocumentStore:
    return InMemoryDocumentStore()


def create_embedders(
    model: str = DEFAULT_ST_MODEL,
) -> tuple[SentenceTransformersDocumentEmbedder, SentenceTransformersTextEmbedder]:
    doc_embedder = SentenceTransformersDocumentEmbedder(model=model)
    text_embedder = SentenceTransformersTextEmbedder(model=model)
    doc_embedder.warm_up()
    return doc_embedder, text_embedder


def create_retriever(document_store: InMemoryDocumentStore) -> InMemoryEmbeddingRetriever:
    return InMemoryEmbeddingRetriever(document_store)
