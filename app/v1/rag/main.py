from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

from haystack import Document

from .components import create_document_store, create_embedders, create_retriever
from .prompt import ISO21434_CLAUSE15_TEMPLATE, create_prompt_builder
from .ingest import (
    IngestPaths,
    load_all_records,
    to_haystack_documents,
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
    "IngestPaths",
    "load_all_records",
    "to_haystack_documents",
    "index_documents",
    "summarize_by_source",
    "build_retrieval_prompt_pipeline",
    "init_rag_resources",
    "get_rag_resources",
    "retrieve_documents",
    "build_rag_context",
    "build_prompt_from_documents",
]


@dataclass(frozen=True)
class RagResources:
    text_embedder: object
    retriever: object


def init_rag_resources(paths: IngestPaths | None = None) -> RagResources:
    store = create_document_store()
    print("hi")
    doc_embedder, text_embedder = create_embedders()
    print("hi 2")
    retriever = create_retriever(store)
    print("hi 3")

    docs = load_all_records(paths or IngestPaths())
    print("hi 4")
    # docs = to_haystack_documents(records)
    index_documents(store, doc_embedder, docs)
    print("hi 6")

    return RagResources(text_embedder=text_embedder, retriever=retriever)


@lru_cache(maxsize=1)
def get_rag_resources() -> RagResources:
    return init_rag_resources()


def retrieve_documents(question: str, top_k: int = 5) -> list[Document]:
    resources = get_rag_resources()
    print('after resources')
    embedding = resources.text_embedder.run(text=question)["embedding"]
    print('after embedding')
    result = resources.retriever.run(query_embedding=embedding, top_k=top_k)
    return result["documents"]


def build_prompt_from_documents(
    question: str,
    documents: list[Document],
    template: str = ISO21434_CLAUSE15_TEMPLATE,
) -> str:
    prompt_builder = create_prompt_builder(template=template)
    result = prompt_builder.run(documents=documents, question=question)
    return result["prompt"]


def build_rag_context(
    documents: Iterable[Document],
    joiner: str = "\n\n",
    include_meta: bool = False,
) -> str:
    parts: list[str] = []
    for doc in documents:
        content = doc.content or ""
        if include_meta and doc.meta:
            title = doc.meta.get("title") or doc.meta.get("source")
            if title:
                parts.append(f"[{title}] {content}")
                continue
        parts.append(content)
    return joiner.join(parts)
