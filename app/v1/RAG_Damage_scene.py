import os
import json
import glob
import traceback
from flask import Blueprint, jsonify, request
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
# 1. SETUP PATHS & DOCUMENT STORE
# ------------------------------------------------

rag_damage_scene = Blueprint("rag_damage_scene", __name__)

# Paths mapping (v1 is in app/v1, Methods is in app/Methods)
current_file_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.dirname(current_file_dir)
methods_dir = os.path.join(app_dir, "Methods")

CLAUSE_PATH = os.path.join(methods_dir, "clauses")
DATA_PATH = os.path.join(methods_dir, "data.json")
ANNEX_PATH = os.path.join(methods_dir, "annex.json")
BMS_PATH = os.path.join(methods_dir, "bms.json")  # The source file

document_store = InMemoryDocumentStore()

doc_embedder = SentenceTransformersDocumentEmbedder(model="sentence-transformers/all-MiniLM-L6-v2")
text_embedder = SentenceTransformersTextEmbedder(model="sentence-transformers/all-MiniLM-L6-v2")
doc_embedder.warm_up()

retriever = InMemoryEmbeddingRetriever(document_store)

# ------------------------------------------------
# 2. CUSTOM COMPONENTS
# ------------------------------------------------

@component
class DocumentCleanerFilter:
    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        if not documents:
            return {"documents": []}
        # Limit to top 5 relevant context documents
        return {"documents": documents[:5]}

# ------------------------------------------------
# 3. PROMPT TEMPLATE (ISO/SAE 21434 Focus)
# ------------------------------------------------

damage_template = """
You are an **automotive cybersecurity expert** performing **Damage Scenario Identification** (ISO/SAE 21434 Clause 15).

## ANALYSIS CONTEXT (From BMS Design):
{% for document in documents %}
- {{ document.content }}
{% endfor %}

## TARGET COMPONENT:
Target: **{{question}}**

## TASK:
Based on the BMS architecture provided in the context, generate **3 distinct damage scenarios** for the component: **{{question}}**.
Focus on the consequences of the loss of security properties (Integrity, Confidentiality, Availability, Authenticity) as defined in the BMS model.

---

# DAMAGE SCENARIOS — {{question}}

## DAMAGE SCENARIO 1
**Description:** [Specific automotive impact, e.g., 'Malicious CAN injection causes Battery Pack relay to open during high-speed driving']
**Safety Impact:** [S0-S4 + Justification]
**Operational Impact:** [O0-O4 + Justification]
**Financial Impact:** [F0-F4 + Justification]
**Privacy Impact:** [P0-P4 + Justification]
**Overall Impact:** [Highest level identified]

## DAMAGE SCENARIO 2
**Description:** [Different attack vector]
**Safety Impact:** [Rating]
**Operational Impact:** [Rating]
**Financial Impact:** [Rating]
**Privacy Impact:** [Rating]
**Overall Impact:** [Rating]

## DAMAGE SCENARIO 3
**Description:** [Different attack vector]
**Safety Impact:** [Rating]
**Operational Impact:** [Rating]
**Financial Impact:** [Rating]
**Privacy Impact:** [Rating]
**Overall Impact:** [Rating]
"""

prompt_builder = PromptBuilder(template=damage_template, required_variables=["documents", "question"])

# ------------------------------------------------
# 4. LLM & PIPELINE
# ------------------------------------------------

if not os.getenv("GOOGLE_API_KEY"):
    raise EnvironmentError("❌ GOOGLE_API_KEY not set")

generator = GoogleAIGeminiGenerator(
    model="gemini-2.5-flash", # Optimized for speed/flash analysis
    generation_config={"temperature": 0.1, "max_output_tokens": 1200}
)

damage_pipeline = Pipeline()
damage_pipeline.add_component("text_embedder", text_embedder)
damage_pipeline.add_component("retriever", retriever)
damage_pipeline.add_component("document_cleaner", DocumentCleanerFilter())
damage_pipeline.add_component("prompt_builder", prompt_builder)
damage_pipeline.add_component("llm", generator)

damage_pipeline.connect("text_embedder.embedding", "retriever.query_embedding")
damage_pipeline.connect("retriever.documents", "document_cleaner.documents")
damage_pipeline.connect("document_cleaner.documents", "prompt_builder.documents")
damage_pipeline.connect("prompt_builder", "llm")

# ------------------------------------------------
# 5. DATA INGESTION (INCLUDING BMS.JSON)
# ------------------------------------------------

def ingest_data():
    docs = []
    
    # 1. Load BMS.json specifically
    if os.path.exists(BMS_PATH):
        try:
            with open(BMS_PATH, "r", encoding="utf-8") as f:
                bms_data = json.load(f)
                # Ingest Architecture
                assets = bms_data.get("Assets", [{}])[0]
                edges = assets.get("template", {}).get("edges", [])
                details = assets.get("Details", [])
                
                # Create context for edges/connections
                edge_context = "BMS Connectivity Map: " + ", ".join([f"{e['data']['label']} connects {e['source']} to {e['target']}" for e in edges])
                docs.append(Document(content=edge_context, meta={"source": "bms_connectivity"}))
                
                # Create context for asset properties
                for asset in details:
                    prop_list = ", ".join([p['name'] for p in asset.get('props', [])])
                    docs.append(Document(
                        content=f"Asset '{asset['name']}' (ID: {asset['nodeId']}) has security properties: {prop_list}. Type: {asset['type']}.",
                        meta={"source": "bms_asset_details"}
                    ))
        except Exception as e:
            print(f"Error parsing BMS.json: {e}")

    # 2. Load Clauses/Annexes
    for path, src in [(ANNEX_PATH, "Annex"), (DATA_PATH, "General Data")]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
                docs.append(Document(content=str(content)[:1000], meta={"source": src}))

    # 3. Write and Embed
    if docs:
        embedded_docs = doc_embedder.run(documents=docs)["documents"]
        document_store.write_documents(embedded_docs, policy="overwrite")
        print(f"✓ Ingested {len(docs)} documents for RAG context.")

ingest_data()

# ------------------------------------------------
# 6. API LOGIC (READING BMS.JSON AUTOMATICALLY)
# ------------------------------------------------

def parse_damage_scenarios(text):
    """Helper to split LLM output into blocks if needed."""
    return text.split("## DAMAGE SCENARIO")

@rag_damage_scene.route("/v1/rag-generate/bms-damage-scenarios", methods=["POST", "GET"])
def generate_bms_scenarios():
    """
    Automatically reads bms.json, iterates through assets,
    and returns generated damage scenarios.
    """
    if not os.path.exists(BMS_PATH):
        return jsonify({"error": "bms.json not found"}), 404

    try:
        with open(BMS_PATH, "r", encoding="utf-8") as f:
            bms_data = json.load(f)
        
        # Get list of assets from the "Details" section
        asset_details = bms_data.get("Assets", [{}])[0].get("Details", [])
        
        final_output = []

        # Process each asset that is not a group or empty
        for asset in asset_details:
            name = asset.get("name")
            if not name or asset.get("type") == "group":
                continue
            
            # Run pipeline for this specific component
            result = damage_pipeline.run({
                "text_embedder": {"text": f"Impact analysis for {name}"},
                "prompt_builder": {"question": name}
            })
            
            raw_reply = result["llm"]["replies"][0]
            
            final_output.append({
                "nodeId": asset.get("nodeId"),
                "asset_name": name,
                "security_properties": [p['name'] for p in asset.get('props', [])],
                "damage_scenarios_markdown": raw_reply
            })

        return jsonify({
            "model_name": bms_data["Models"][0]["name"],
            "total_assets_processed": len(final_output),
            "results": final_output
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------
# 7. EXPORT PIPELINE
# ------------------------------------------------

__all__ = ["rag_damage_scene", "damage_pipeline"]