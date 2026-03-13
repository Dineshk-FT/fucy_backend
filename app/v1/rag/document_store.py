from haystack import Document
import json
from .pipeline import get_document_store

def filter_full_asset():
    """Helper to filter full_asset documents"""
    store = get_document_store()
    return store.filter_documents(
        filters={
            "operator": "AND",
            "conditions": [
                {
                    "field": "meta.type",
                    "operator": "==",
                    "value": "full_asset"
                }
            ]
        }
    )

def search_similar(query, top_k=75):
    """Search for similar documents using embeddings"""
    from .pipeline import text_embedder, retriever
    
    query_embedding = text_embedder.run(text=query)["embedding"]
    return retriever.run(query_embedding=query_embedding, top_k=top_k)["documents"]