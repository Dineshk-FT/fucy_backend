from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable
from collections import Counter
from haystack.document_stores.in_memory import InMemoryDocumentStore  # Fixed import
from haystack.components.embedders import SentenceTransformersDocumentEmbedder, SentenceTransformersTextEmbedder
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever

from haystack import Document

from .components import create_document_store, create_embedders, create_retriever
from .prompt import ISO21434_CLAUSE15_TEMPLATE, create_prompt_builder
from .ingest import (
    load_all_records,
    index_documents,
    summarize_by_source,
)
from .pipeline import build_retrieval_prompt_pipeline

__all__ = [
    "create_document_store",
    "create_embedders",
    "create_retriever",
    "ISO21434_CLAUSE15_TEMPLATE",
    "create_prompt_builder",
    "load_all_records",
    "index_documents",
    "summarize_by_source",
    "build_retrieval_prompt_pipeline",
    "init_rag_resources",
    "get_rag_resources",
    "retrieve_documents",
    "build_rag_context",
    "build_prompt_from_documents",
    "verify_document_store",
]


@dataclass(frozen=True)
class RagResources:
    """Container for RAG resources."""
    document_store: InMemoryDocumentStore
    text_embedder: SentenceTransformersTextEmbedder
    retriever: InMemoryEmbeddingRetriever
    doc_embedder: SentenceTransformersDocumentEmbedder


def init_rag_resources() -> RagResources:
    """Initialize all RAG resources and ingest documents."""
    print("Initializing RAG resources...")
    
    # Create components
    store = create_document_store()
    doc_embedder, text_embedder = create_embedders()
    retriever = create_retriever(store)

    # Load and index documents
    print("\nLoading all documents from Azure storage...")
    docs = load_all_records()
    
    print("\nIndexing documents...")
    index_documents(store, doc_embedder, docs)
    
    # Verify ingestion
    verify_document_store(store)
    
    return RagResources(
        document_store=store,
        text_embedder=text_embedder,
        retriever=retriever,
        doc_embedder=doc_embedder
    )


@lru_cache(maxsize=1)
def get_rag_resources() -> RagResources:
    """Get cached RAG resources."""
    return init_rag_resources()


def verify_document_store(document_store) -> None:
    """Verify that all expected sources are present in the document store."""
    stored = document_store.filter_documents()
    sources = {d.meta.get("source") for d in stored}
    
    total_docs = document_store.count_documents()
    print(f"\n{'='*50}")
    print(f"Total documents in store: {total_docs}")
    
    # Distribution by source
    dist = Counter(d.meta.get("source", "?") for d in stored)
    for src, cnt in sorted(dist.items()):
        print(f"  {src:<20}: {cnt}")
    
    # Assertions
    assert total_docs >= 1500, f"Expected ≥1500 docs, got {total_docs}"
    assert "REPORTS_DB" in sources, "REPORTS_DB source missing"
    assert "ISO_21434" in sources, "ISO_21434 source missing"
    assert "CWE" in sources and "CAPEC" in sources, "Threat framework sources missing"
    
    reports_count = sum(1 for d in stored if d.meta.get("source") == "REPORTS_DB")
    iso_count = sum(1 for d in stored if d.meta.get("source") == "ISO_21434")
    
    print("\n✅ All assertions passed!")
    print(f"   ISO_21434    : {iso_count} section-level chunks")
    print(f"   REPORTS_DB   : {reports_count} asset/scenario chunks")
    print(f"   All sources  : {sorted(sources)}")
    print(f"{'='*50}\n")


def retrieve_documents(question: str, top_k: int = 20) -> list[Document]:
    """Retrieve documents relevant to the question."""
    resources = get_rag_resources()
    
    print(f"Retrieving documents for: {question[:100]}...")
    embedding = resources.text_embedder.run(text=question)["embedding"]
    result = resources.retriever.run(query_embedding=embedding, top_k=top_k)
    
    docs = result["documents"]
    print(f"Retrieved {len(docs)} documents")
    
    # Show source distribution
    sources = Counter(d.meta.get("source") for d in docs)
    print(f"Sources: {dict(sources)}")
    
    return docs


def build_prompt_from_documents(
    question: str,
    documents: list[Document],
    template: str = ISO21434_CLAUSE15_TEMPLATE,
) -> str:
    """Build a prompt from retrieved documents."""
    prompt_builder = create_prompt_builder(template=template)
    result = prompt_builder.run(documents=documents, question=question)
    return result["prompt"]


def build_rag_context(
    documents: Iterable[Document],
    joiner: str = "\n\n---\n\n",
    include_meta: bool = True,
) -> str:
    """Build a context string from documents for the prompt."""
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