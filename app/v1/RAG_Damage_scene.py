# ==============================================
# DAMAGE SCENARIO GENERATOR — ISO/SAE 21434
# (RAG-based, backend-only, deterministic)
# ==============================================

import os
import json
import glob
from haystack import Pipeline, Document
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
# 2. STRICT DAMAGE-SCENARIO PROMPT (ISO CLAUSE 15)
# ------------------------------------------------

damage_template = """
You are an **automotive cybersecurity analyst** performing **Damage Scenario Identification**
strictly according to **ISO/SAE 21434 Clause 15.3.3**.

Your task is to generate **ONLY damage scenarios**.

STRICT RULES:
- Do NOT generate threats
- Do NOT generate attack feasibility
- Do NOT generate mitigations
- Do NOT calculate risk
- Do NOT add explanations
- Use ISO/SAE 21434 terminology ONLY
- Output Markdown ONLY

If a category is not applicable, explicitly write **Not Applicable (N/A)**.

---

## ISO IMPACT LEVELS (LOCKED)
Use EXACTLY one of:
- Negligible
- Minor
- Moderate
- Major
- Severe

---

## ISO CONTEXT (AUTHORITATIVE)
{% for document in documents %}
- {{ document.content }}
{% endfor %}

Item under analysis: **{{question}}**

---

# DAMAGE SCENARIOS — {{question}}

Generate **AT LEAST 5 distinct damage scenarios**.

---

## Damage Scenario ID: DS_<ITEM>_00X

### Description
Describe the damage to stakeholders, vehicle, or organization.

### Impact Assessment

| Impact Category | Impact Level |
|----------------|--------------|
| Safety Impact | Negligible / Minor / Moderate / Major / Severe |
| Operational Impact | Negligible / Minor / Moderate / Major / Severe |
| Financial Impact | Negligible / Minor / Moderate / Major / Severe |
| Privacy Impact | Negligible / Minor / Moderate / Major / Severe |
| Regulatory Impact | Negligible / Minor / Moderate / Major / Severe |

### Overall Impact
Provide **ONE value**, equal to the most severe impact above.

---
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
    model="gemini-2.5-flash-lite"
)

# ------------------------------------------------
# 4. PIPELINE
# ------------------------------------------------

damage_pipeline = Pipeline()

damage_pipeline.add_component("text_embedder", text_embedder)

damage_pipeline.add_component("retriever", retriever)

damage_pipeline.add_component("prompt_builder", prompt_builder)

damage_pipeline.add_component("llm", generator)

damage_pipeline.connect("text_embedder.embedding", "retriever.query_embedding")

damage_pipeline.connect("retriever", "prompt_builder.documents")


damage_pipeline.connect("prompt_builder", "llm")

# ------------------------------------------------
# 5. LOAD ISO + ECU DATA
# ------------------------------------------------

CLAUSE_PATH = "./clauses"
DATA_PATH = "./data.json"
ANNEX_PATH = "./annex.json"

docs = []

# ECU / Item metadata
with open(DATA_PATH, "r", encoding="utf-8") as f:
    ecu_data = json.load(f)
    for v in ecu_data.values():
        docs.append(Document(content=json.dumps(v, indent=2), meta={"source": "ECU"}))

# ISO Clauses
for file in glob.glob(os.path.join(CLAUSE_PATH, "clause-*.json")):
    with open(file, "r", encoding="utf-8") as f:
        clause = json.load(f)
        docs.append(Document(content=json.dumps(clause, indent=2), meta={"source": "Clause"}))

# Annex (optional)
if os.path.exists(ANNEX_PATH):
    with open(ANNEX_PATH, "r", encoding="utf-8") as f:
        annex = json.load(f)
        docs.append(Document(content=json.dumps(annex, indent=2), meta={"source": "Annex"}))

# Write & embed
document_store.write_documents(docs)
embedded_docs = doc_embedder.run(documents=docs)["documents"]
document_store.write_documents(embedded_docs, policy="overwrite")

# ------------------------------------------------
# 6. EXPORT
# ------------------------------------------------

__all__ = ["damage_pipeline"]


