from __future__ import annotations

from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever

# BGE-small beats MiniLM on BEIR benchmarks, same size
DEFAULT_ST_MODEL = "BAAI/bge-small-en-v1.5"
# Fallback: "sentence-transformers/all-MiniLM-L6-v2"


def create_document_store() -> InMemoryDocumentStore:
    """Create an in-memory document store."""
    store = InMemoryDocumentStore()
    print("🧠 InMemoryDocumentStore initialized.")
    return store


def create_embedders(
    model: str = DEFAULT_ST_MODEL,
) -> tuple[SentenceTransformersDocumentEmbedder, SentenceTransformersTextEmbedder]:
    """Create and warm up document and text embedders."""
    doc_embedder = SentenceTransformersDocumentEmbedder(model=model)
    text_embedder = SentenceTransformersTextEmbedder(model=model)
    
    doc_embedder.warm_up()
    text_embedder.warm_up()
    
    print(f"✅ Embedders ready [{model}]")
    return doc_embedder, text_embedder


def create_retriever(
    document_store: InMemoryDocumentStore,
    top_k: int = 20
) -> InMemoryEmbeddingRetriever:
    """Create an embedding retriever with specified top_k."""
    retriever = InMemoryEmbeddingRetriever(document_store, top_k=top_k)
    print(f"🔍 Retriever created (top_k={top_k}).")
    return retriever