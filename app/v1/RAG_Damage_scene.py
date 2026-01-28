# ==============================================
# DAMAGE SCENARIO GENERATOR — ISO/SAE 21434
# (RAG-based, backend-only, deterministic)
# ==============================================

import os
import json
import glob
from flask import Blueprint
from typing import List
from haystack import Pipeline, Document, component
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.components.embedders import (
    SentenceTransformersDocumentEmbedder,
    SentenceTransformersTextEmbedder,
)
from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever
from haystack.components.builders import PromptBuilder
from haystack_integrations.components.generators.google_ai import GoogleAIGeminiGenerator

# ------------------------------------------------
# 1. DOCUMENT STORE & EMBEDDERS
# ------------------------------------------------

rag_damage_scene = Blueprint("rag_damage_scene", __name__)

# Get the correct paths - v1 and Methods are siblings in app folder
current_file_dir = os.path.dirname(os.path.abspath(__file__))  # C:\New Project\fucy_backend\Backend_details\app\v1
app_dir = os.path.dirname(current_file_dir)  # C:\New Project\fucy_backend\Backend_details\app
methods_dir = os.path.join(app_dir, "Methods")  # C:\New Project\fucy_backend\Backend_details\app\Methods

# Define paths
CLAUSE_PATH = os.path.join(methods_dir, "clauses")
DATA_PATH = os.path.join(methods_dir, "data.json")
ANNEX_PATH = os.path.join(methods_dir, "annex.json")

print(f"RAG Setup - Paths:")
print(f"  Current file: {current_file_dir}")
print(f"  App dir: {app_dir}")
print(f"  Methods dir: {methods_dir}")
print(f"  Data path: {DATA_PATH}")
print(f"  Clause path: {CLAUSE_PATH}")
print(f"  Annex path: {ANNEX_PATH}")

document_store = InMemoryDocumentStore()

doc_embedder = SentenceTransformersDocumentEmbedder(
    model="sentence-transformers/all-MiniLM-L6-v2"
)
text_embedder = SentenceTransformersTextEmbedder(
    model="sentence-transformers/all-MiniLM-L6-v2"
)

doc_embedder.warm_up()

retriever = InMemoryEmbeddingRetriever(document_store)

# ------------------------------------------------
# Custom Document Cleaner Component
# ------------------------------------------------

@component
class DocumentCleanerFilter:
    """
    Custom component to clean and filter documents before sending to LLM.
    Removes noisy content and limits document count.
    """
    
    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        """Clean and filter documents."""
        if not documents:
            return {"documents": []}
        
        # Limit number of documents
        max_docs = 3
        limited_docs = documents[:max_docs]
        
        # Clean each document
        cleaned_docs = []
        for doc in limited_docs:
            content = doc.content
            
            # Skip if content is just a JSON array without meaningful info
            if content.strip().startswith('[') and content.strip().endswith(']'):
                try:
                    data = json.loads(content)
                    # Extract meaningful information from JSON
                    if isinstance(data, list):
                        extracted_info = []
                        for item in data[:2]:  # Only first 2 items
                            if isinstance(item, dict):
                                if 'name' in item:
                                    extracted_info.append(f"Item: {item['name']}")
                                elif 'label' in item:
                                    extracted_info.append(f"Component: {item['label']}")
                                elif 'description' in item:
                                    extracted_info.append(f"Description: {item['description']}")
                                elif 'task' in item:
                                    extracted_info.append(f"Task: {item['task']}")
                                elif 'loss' in item:
                                    extracted_info.append(f"Loss: {item['loss']}")
                        
                        if extracted_info:
                            content = "\n".join(extracted_info)
                        else:
                            # If no meaningful info, skip this document
                            continue
                except json.JSONDecodeError:
                    # Not valid JSON, keep as is but truncate
                    if len(content) > 250:
                        content = content[:250] + "..."
            elif len(content) > 300:
                # Truncate very long content
                content = content[:300] + "..."
            
            # Create a new document with cleaned content
            cleaned_doc = Document(
                content=content,
                meta=doc.meta
            )
            cleaned_docs.append(cleaned_doc)
        
        return {"documents": cleaned_docs}

# ------------------------------------------------
# 2. STRICT DAMAGE-SCENARIO PROMPT (ISO CLAUSE 15)
# ------------------------------------------------

damage_template = """
You are an **automotive cybersecurity analyst** performing **Damage Scenario Identification**
strictly according to **ISO/SAE 21434 Clause 15**.

Your task is to generate **ONLY damage scenarios** for automotive components.

STRICT RULES:
- Do NOT generate threats
- Do NOT generate attack feasibility  
- Do NOT generate mitigations
- Do NOT calculate risk
- Do NOT add explanations
- Use ISO/SAE 21434 terminology ONLY
- Output Markdown ONLY

---

## ISO IMPACT LEVELS (Use EXACTLY one for each category):
- Negligible
- Minor
- Moderate
- Major
- Severe

---

## RELEVANT CONTEXT:
{% for document in documents %}
- {{ document.content }}
{% endfor %}

Item under analysis: **{{question}}**

---

# DAMAGE SCENARIOS — {{question}}

Generate **EXACTLY 3 distinct damage scenarios** in this format:

## Damage Scenario 1
**Description:** [Concise description of the damage]
**Safety Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Operational Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Financial Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Privacy Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Regulatory Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Overall Impact:** [Most severe level from above]

## Damage Scenario 2
**Description:** [Concise description of the damage]
**Safety Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Operational Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Financial Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Privacy Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Regulatory Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Overall Impact:** [Most severe level from above]

## Damage Scenario 3
**Description:** [Concise description of the damage]
**Safety Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Operational Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Financial Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Privacy Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Regulatory Impact:** [Negligible/Minor/Moderate/Major/Severe]
**Overall Impact:** [Most severe level from above]
"""

prompt_builder = PromptBuilder(
    template=damage_template,
    required_variables=["documents", "question"],
)

# ------------------------------------------------
# 3. LLM SETUP
# ------------------------------------------------

if not os.getenv("GOOGLE_API_KEY"):
    raise EnvironmentError("❌ GOOGLE_API_KEY not set")

generator = GoogleAIGeminiGenerator(
    model="gemini-2.5-flash-lite",
    generation_config={
        "temperature": 0.2,
        "max_output_tokens": 1000,
        "top_p": 0.8,
    }
)

# ------------------------------------------------
# 4. PIPELINE WITH CLEANER
# ------------------------------------------------

damage_pipeline = Pipeline()

# Add components
damage_pipeline.add_component("text_embedder", text_embedder)
damage_pipeline.add_component("retriever", retriever)
damage_pipeline.add_component("document_cleaner", DocumentCleanerFilter())
damage_pipeline.add_component("prompt_builder", prompt_builder)
damage_pipeline.add_component("llm", generator)

# Connect the pipeline
damage_pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
damage_pipeline.connect("retriever.documents", "document_cleaner.documents")
damage_pipeline.connect("document_cleaner.documents", "prompt_builder.documents")
damage_pipeline.connect("prompt_builder", "llm")

# ------------------------------------------------
# 5. LOAD ONLY RELEVANT DATA
# ------------------------------------------------

docs = []

# Create concise documents
def create_concise_document(content, source="General"):
    """Create a concise document with only essential information."""
    content_str = ""
    
    if isinstance(content, dict):
        # Extract only key fields
        summary = []
        if 'name' in content:
            summary.append(f"Name: {content['name']}")
        if 'description' in content:
            desc = content['description']
            if len(desc) > 80:
                desc = desc[:80] + "..."
            summary.append(f"Description: {desc}")
        if 'properties' in content and isinstance(content['properties'], list):
            summary.append(f"Properties: {', '.join(content['properties'][:2])}")
        if 'requirements' in content:
            summary.append("Contains security requirements")
        
        content_str = "\n".join(summary) if summary else json.dumps(content, indent=2)[:150]
    elif isinstance(content, str):
        # Clean string content
        if len(content) > 150:
            content_str = content[:150] + "..."
        else:
            content_str = content
    else:
        content_str = str(content)[:150]
    
    return Document(content=content_str, meta={"source": source})

# Load essential data
try:
    print(f"\nLoading documents...")
    
    # ECU / Item metadata from data.json
    if os.path.exists(DATA_PATH):
        print(f"✓ Loading data.json...")
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            ecu_data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(ecu_data, dict):
                # If it's a dict with items
                for key, value in ecu_data.items():
                    if isinstance(value, (dict, list)):
                        docs.append(create_concise_document(value, "ECU Data"))
            elif isinstance(ecu_data, list):
                # If it's a list of items
                for item in ecu_data[:3]:  # Only first 3 items
                    docs.append(create_concise_document(item, "ECU Item"))
    else:
        print(f"✗ data.json not found at {DATA_PATH}")
    
    # ISO Clause 15 - most relevant for damage scenarios
    clause_15_path = os.path.join(methods_dir, "clause-15.json")
    if os.path.exists(clause_15_path):
        print(f"✓ Loading clause-15.json...")
        with open(clause_15_path, "r", encoding="utf-8") as f:
            clause_15 = json.load(f)
            docs.append(create_concise_document(clause_15, "ISO 21434 Clause 15"))
    else:
        print(f"✗ clause-15.json not found at {clause_15_path}")
    
    # Check for clauses directory
    if os.path.exists(CLAUSE_PATH) and os.path.isdir(CLAUSE_PATH):
        print(f"✓ Loading other relevant clauses...")
        clause_files = glob.glob(os.path.join(CLAUSE_PATH, "clause-*.json"))
        # Load clauses related to security, risk, damage
        relevant_keywords = ['security', 'risk', 'damage', 'impact', 'safety']
        loaded = 0
        for file in clause_files:
            if loaded >= 2:  # Limit to 2 additional clauses
                break
            try:
                with open(file, "r", encoding="utf-8") as f:
                    clause = json.load(f)
                    clause_text = json.dumps(clause).lower()
                    if any(keyword in clause_text for keyword in relevant_keywords):
                        docs.append(create_concise_document(clause, "ISO Clause"))
                        loaded += 1
            except Exception as e:
                continue
    
    # Annex file
    if os.path.exists(ANNEX_PATH):
        print(f"✓ Loading annex.json...")
        with open(ANNEX_PATH, "r", encoding="utf-8") as f:
            annex = json.load(f)
            docs.append(create_concise_document(annex, "Annex"))
    else:
        print(f"✗ annex.json not found at {ANNEX_PATH}")
    
    print(f"Total documents loaded: {len(docs)}")
    
except Exception as e:
    print(f"Error loading documents: {e}")
    import traceback
    traceback.print_exc()
    
    # Add essential fallback documents
    docs.append(Document(
        content="ISO/SAE 21434: Automotive cybersecurity standard for damage scenario identification and impact assessment.",
        meta={"source": "ISO Standard"}
    ))
    docs.append(Document(
        content="Damage scenarios consider Safety, Operational, Financial, Privacy, and Regulatory impacts with levels: Negligible, Minor, Moderate, Major, Severe.",
        meta={"source": "Impact Framework"}
    ))

# Write & embed
if docs:
    try:
        print(f"\nEmbedding {len(docs)} documents...")
        document_store.write_documents(docs)
        embedded_docs = doc_embedder.run(documents=docs)["documents"]
        document_store.write_documents(embedded_docs, policy="overwrite")
        print("✓ Document store ready")
    except Exception as e:
        print(f"Error embedding documents: {e}")
        import traceback
        traceback.print_exc()
else:
    print("⚠ Warning: No documents loaded into document store")

# ------------------------------------------------
# 6. EXPORT
# ------------------------------------------------

__all__ = ["damage_pipeline"]

print("\n" + "="*50)
print("RAG Damage Scenario Generator Initialized Successfully")
print("="*50)