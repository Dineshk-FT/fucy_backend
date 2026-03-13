import os
from haystack import Pipeline, Document
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever
from haystack.components.builders import PromptBuilder
from haystack_integrations.components.generators.google_ai import GoogleAIGeminiGenerator
import atexit
import signal
import threading

# Global pipeline instances
rag_pipeline = None
prompt_builder = None
text_embedder = None
retriever = None
generator = None
document_store = None
doc_embedder = None

# Flag to track if cleanup is in progress
_cleaning_up = False

def cleanup_resources():
    """Clean up resources at shutdown"""
    global _cleaning_up
    if _cleaning_up:
        return
    
    _cleaning_up = True
    
    # Clear references to help garbage collection
    global rag_pipeline, prompt_builder, text_embedder, retriever, generator, document_store, doc_embedder
    
    rag_pipeline = None
    prompt_builder = None
    text_embedder = None
    retriever = None
    generator = None
    document_store = None
    doc_embedder = None
    
    # Force garbage collection
    import gc
    gc.collect()

# Register cleanup on exit
atexit.register(cleanup_resources)

def setup_pipeline(api_key, model_name="sentence-transformers/all-MiniLM-L6-v2"):
    """Initialize all RAG components and pipeline"""
    global rag_pipeline, prompt_builder, text_embedder, retriever, generator, document_store, doc_embedder
    
    try:
        # Initialize document store
        document_store = InMemoryDocumentStore()
        
        # Setup embedders with threading disabled
        doc_embedder = SentenceTransformersDocumentEmbedder(
            model=model_name,
            token={"use_auth_token": False}  # Disable auth token to avoid threads
        )
        text_embedder = SentenceTransformersTextEmbedder(
            model=model_name,
            token={"use_auth_token": False}  # Disable auth token to avoid threads
        )
        
        # Warm up with timeout
        doc_embedder.warm_up()
        
        # Setup retriever (top_k=50 for broad context)
        retriever = InMemoryEmbeddingRetriever(document_store=document_store, top_k=50)
        
        # Setup prompt template
        template = """
        You are a strict JSON extraction engine for knowledge base.
        
        You will receive:
        1. Context documents — raw JSON objects exactly as stored (nodes, edges, derivations, details)
        2. A natural language user query
        
        YOUR RESPONSIBILITY:
        - Identify what the user is asking
        - Collect ALL relevant JSON objects from the context
        - Return them EXACTLY as they appear
        - DO NOT modify structure
        - DO NOT rename keys
        - DO NOT remove fields
        - DO NOT add fields
        - DO NOT restructure nested objects
        - DO NOT change ordering inside objects
        - DO NOT hallucinate missing values
        
        ABSOLUTE RULES:
        - Copy JSON objects verbatim
        - Preserve id, type, data, position, positionAbsolute, style, height, width,
          parentId, isAsset, source, target, sourceHandle, targetHandle,
          and every nested property exactly as-is
        - If a field exists (even false, 0, "", empty array) → include it
        - If a field does not exist → do not create it
        - Return ONLY valid JSON
        - No markdown
        - No explanation
        - No extra text
        - The output must start with {"result":
        
        OUTPUT STRUCTURE (never change this structure):
        {
          "result": {
            "query_intent": "<one-line description of user intent>",
            "assets": [],
            "_id":,
            "user_id":,
            "model_id":,
            "template": {},
            "edges": [],
            "Details": [],
            "damage_scenarios": [],
            "damage_details": []
          }
        }
        
        SECTION INCLUSION LOGIC:
        
        1) If query contains "item definition"
           → Extract the full_asset object from context
           → Populate fields exactly as:
                _id        → from asset._id
                user_id    → from asset.user_id
                model_id   → from asset.model_id
                template   → from asset.template
                Details    → from asset.Details
           → Leave assets array EMPTY
           → Leave edges array EMPTY
           → Leave damage sections EMPTY
        
        2) If query contains "components"
           → Return ONLY component nodes inside assets array
        
        3) If query contains "connectors"
           → Return ONLY connector nodes inside assets array
        
        4) If query contains "edges" or "connections"
           → Return ONLY edge objects inside edges array
        
        5) If query contains "damage scenarios" or "derivations"
           → Return ONLY derivation objects inside damage_scenarios
        
        6) If query contains "details" or "damage details"
           → Return ONLY detail objects inside damage_details
        
        7) If query contains "all" or "full" or "everything" or "report"
           → Populate:
                template (nodes + edges)
                Details
                damage_scenarios
                damage_details
           → Leave assets and edges arrays EMPTY
        
        8) If query mentions a specific node name:
           → Filter every returned section strictly to that node only
        
        If a section is not requested, return it as empty array.
        
        CONTEXT DOCUMENTS:
        {% for document in documents %}
        {{ document.content }}
        {% endfor %}
        
        USER QUERY:
        {{ question }}
        
        Return ONLY valid JSON starting with {"result": and nothing else.
        """
        
        prompt_builder = PromptBuilder(template=template, required_variables=["documents", "question"])
        
        # Setup Gemini generator
        os.environ["GOOGLE_API_KEY"] = api_key
        generator = GoogleAIGeminiGenerator(model="gemini-2.5-flash-lite")
        
        # Build pipeline
        rag_pipeline = Pipeline()
        rag_pipeline.add_component("text_embedder", text_embedder)
        rag_pipeline.add_component("retriever", retriever)
        rag_pipeline.add_component("prompt_builder", prompt_builder)
        rag_pipeline.add_component("llm", generator)
        
        rag_pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
        rag_pipeline.connect("retriever.documents", "prompt_builder.documents")
        rag_pipeline.connect("prompt_builder.prompt", "llm.parts")
        
        return rag_pipeline, document_store, doc_embedder
        
    except Exception as e:
        # Clean up if initialization fails
        cleanup_resources()
        raise e

def get_pipeline():
    """Get the initialized pipeline instance"""
    if rag_pipeline is None:
        raise Exception("Pipeline not initialized. Call setup_pipeline first.")
    return rag_pipeline

def get_document_store():
    """Get the document store instance"""
    if document_store is None:
        raise Exception("Document store not initialized. Call setup_pipeline first.")
    return document_store