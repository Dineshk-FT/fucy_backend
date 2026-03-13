import json
from .pipeline import get_pipeline, get_document_store
from .document_store import filter_full_asset

def process_query(query, top_k=75):
    """
    Process a natural language query and return structured JSON
    
    Special handling for "item definition" and "assets" queries
    """
    store = get_document_store()
    pipeline = get_pipeline()
    
    query_lower = query.lower()
    
    # Special case: item definition or assets query
    if "item definition" in query_lower or "assets" in query_lower:
        results = filter_full_asset()
        
        if results:
            return {
                "result": json.loads(results[0].content)
            }
        else:
            return {
                "result": {
                    "error": "No full_asset document found"
                }
            }
    
    # Normal RAG flow
    response = pipeline.run({
        "text_embedder": {"text": query},
        "retriever": {"top_k": top_k},
        "prompt_builder": {"question": query}
    })
    
    raw_output = response["llm"]["replies"][0]
    return json.loads(raw_output)

def process_query_with_history(query, history=None):
    """Process query and return result with history tracking"""
    result = process_query(query)
    
    if history is not None:
        history.append({
            "query": query,
            "result": result
        })
    
    return result