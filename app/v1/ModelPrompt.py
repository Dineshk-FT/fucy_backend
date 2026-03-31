from flask import Blueprint, request, jsonify, current_app
import ast
import json
import re
from db import db
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
from app.v1.RiskDeterminationAndTreatment import add_risk_treatment
from app.Methods.helpers import build_full_edge, build_basic_node,calculate_node_positions,structure_attack_tree_templates,AttackTableoptions,threat_type,safe_json_parse
from app.v1.gemini.main import GeminiClient
import random
import os
import uuid
import string
from collections import defaultdict
from datetime import datetime
from bson import ObjectId
import traceback
from werkzeug.datastructures import MultiDict
import time
from app.v1.rag.main import (
    retrieve_documents,
    build_rag_context,
    build_prompt_from_documents,
    stamp_uuids,
    crosslink_node_ids,
    resolve_ecu,
    build_enriched_query,
)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


modelprompt = Blueprint("modelprompt", __name__)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
gemini_client = GeminiClient(GOOGLE_API_KEY, os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))

# Path to dataecu.json — adjust to match your project layout
ECU_DB_PATH = os.getenv("ECU_DB_PATH", "datasets/dataecu.json")


#1- Prompt template for label creation (inputs for the model)
def build_prompt(system_name, user_prompt=None):
    # --- Default Instructions ---
    default_prompt = f"""
        Build the prompt for generating system inputs (TARA as per ISO 21434).
        You are an automotive System Architect following ISO/SAE 21434 standards.
        """

    # --- Data Structure Prompt ---
    data_structure_prompt = """
        Generate a JSON list of label-value pairs that represent realistic inputs required to build TARA as per ISO 21434 '{system_name}'.
        (for Data structure)
        Each entry must follow this structure:
        - "label": (input field name, such as 'systemComponents' or 'communicationInterfaces')
        - "value": (example values in a short comma-separated format, no extra explanation)

        Avoid technical explanations, no nested structures, and no long sentences.
        Only output valid JSON array.

        Example format:
        [
        { "label": "systemComponents", "value": "Engine, Transmission, Chassis" },
        { "label": "communicationInterfaces", "value": "CAN, Ethernet, LIN" },
        ...
        ]
        """

    # Final prompt uses user prompt if provided
    return (user_prompt or default_prompt) + data_structure_prompt


@modelprompt.route("/v1/generate/get_system_inputs", methods=["POST"])
def get_system_inputs():
    system_name = request.form.get("systemName")
    user_prompt = request.form.get("systemInputPrompt")  # optional override

    if not system_name:
        return jsonify({"error": "'systemName' is required in form data"}), 400

    try:
        docs = retrieve_documents(user_prompt, top_k=5)
        prompt = build_prompt_from_documents(user_prompt, documents=docs)
        response = gemini_client.generate_content(prompt)
        content = gemini_client.get_text(response).strip()

        inputs = safe_json_parse(content)
        if not inputs:
            return jsonify({
                "error": "Could not parse model response as JSON",
                "raw_response": content
            }), 500

        return jsonify({"inputs": inputs})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#2- Item definition prompt
@modelprompt.route("/v1/generate/model", methods=["POST"])
def generate_reactflow_template(standalone=False, request_data=None):
    """Generate ReactFlow template - can be called as route or function."""
    try:
        if not request_data:
            request_data = request

        # ── Parse request ──────────────────────────────────────────────────
        if request.is_json:
            data = request.get_json()
            user_id      = request.headers.get("user-id")
            created_by   = data.get("createdBy", "system")
            system_name  = data.get("systemName", "Test System")
            custom_prompt = data.get("itemDefinitionPrompt")

            static_fields = {"createdBy", "systemName", "itemDefinitionPrompt", "modelId"}
            dynamic_fields = {k: v for k, v in data.items() if k not in static_fields}
        else:
            user_id      = request.headers.get("user-id")
            created_by   = request_data.form.get("createdBy", "system")
            system_name  = request_data.form.get("systemName", "Test System")
            custom_prompt = request_data.form.get("itemDefinitionPrompt")

            static_fields = {"createdBy", "systemName", "itemDefinitionPrompt", "modelId"}
            dynamic_fields = {
                key: request_data.form.get(key)
                for key in request_data.form
                if key not in static_fields
            }

        dynamic_prompt_lines = "\n".join([
            f"{key.replace('_', ' ').title()}: {value}"
            for key, value in dynamic_fields.items()
        ])

        # ── Import RAG functions ───────────────────────────────────────────
        from app.v1.rag.components import (
            resolve_ecu as rag_resolve_ecu,
            build_enriched_query as rag_build_enriched_query,
            stamp_uuids as rag_stamp_uuids,
            crosslink_node_ids as rag_crosslink_node_ids,
            parse_and_fix as rag_parse_and_fix,
        )
        from app.v1.rag.ingest import load_all_documents
        from app.v1.rag.pipeline import build_pipeline
        from app.v1.rag.prompt import TARA_PROMPT_TEMPLATE
        from haystack.components.builders import PromptBuilder
        from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
        
        # ── ECU resolution and enrichment ───────────────────────────────────
        print(f"Resolving ECU for query: {system_name}")
        
        ecu_entry = rag_resolve_ecu(system_name)
        if ecu_entry:
            print(f"Matched ECU  : {ecu_entry['name']}")
            print(f"Type         : {ecu_entry['type']}")
            print(f"Asset hint   : {ecu_entry['hint'][:120]}...")
        else:
            print("No dataecu.json match — using open-ended generation.")

        # Build enriched LLM query with authoritative asset list
        enriched_query = rag_build_enriched_query(system_name, ecu_entry)
        
        print("\n" + "="*80)
        print("ENRICHED QUERY (for LLM):")
        print("="*80)
        print(enriched_query[:1000] + "..." if len(enriched_query) > 1000 else enriched_query)
        print("="*80 + "\n")

        # ── Load documents and build pipeline ───────────────────────────────
        print(f"Loading documents from Azure and building RAG pipeline...")
        
        # Load all documents from Azure
        all_docs = load_all_documents()
        
        # Build the pipeline (this embeds documents and creates the pipeline)
        pipeline, _ = build_pipeline(all_docs)
        
        # Retrieve documents using plain system_name for embedding
        print(f"Retrieving documents for system: {system_name}")
        
        # Run the pipeline to get retrieval
        retrieval_result = pipeline.run(
            {
                "text_embedder": {"text": system_name},
                "prompt_builder": {"question": enriched_query},
            },
            include_outputs_from=["retriever"],
        )
        
        retrieved_docs = retrieval_result["retriever"]["documents"]
        print(f"Retrieved {len(retrieved_docs)} documents")
        
        # Print retrieved document sources
        from collections import Counter
        sources = Counter(d.meta.get('source') for d in retrieved_docs)
        print(f"Retrieved document sources: {dict(sources)}")
        
        # ── Build prompt using YOUR template from prompt.py ─────────────────
        print("Building prompt using TARA_PROMPT_TEMPLATE from prompt.py...")
        
        prompt_builder = PromptBuilder(
            template=TARA_PROMPT_TEMPLATE,
            required_variables=["documents", "question"],
        )
        
        prompt_result = prompt_builder.run(
            documents=retrieved_docs,
            question=enriched_query
        )
        
        rag_prompt = prompt_result["prompt"]
        
        # print(f"RAG prompt built with {len(retrieved_docs)} retrieved documents")
        # print(f"RAG prompt length: {len(rag_prompt)} characters")
        
        # print("\n" + "="*80)
        # print("RAG PROMPT (first 2000 chars):")
        # print("="*80)
        # print(rag_prompt[:2000])
        # print("="*80 + "\n")

        # ── Combine with custom prompt if provided ──────────────────────────
        if custom_prompt:
            enhanced_prompt = f"""
System: {system_name}

Additional Requirements: {custom_prompt}

{rag_prompt}
"""
        else:
            enhanced_prompt = rag_prompt

        # Add dynamic field lines (extra form inputs)
        if dynamic_prompt_lines:
            enhanced_prompt += f"\n\nAdditional System Details:\n{dynamic_prompt_lines}"

        # ── Save the final prompt for debugging ─────────────────────────────
        # print("\n" + "="*80)
        # print("FINAL PROMPT SENT TO GEMINI:")
        # print("="*80)
        # print(enhanced_prompt[:2000] + "..." if len(enhanced_prompt) > 2000 else enhanced_prompt)
        # print("="*80)
        # print(f"FINAL PROMPT LENGTH: {len(enhanced_prompt)} characters")
        # print("="*80 + "\n")

        # Save to file for inspection
        try:
            with open("backend_prompt.txt", "w", encoding="utf-8") as f:
                f.write(enhanced_prompt)
            print("✅ Prompt saved to backend_prompt.txt")
        except Exception as e:
            print(f"Could not save prompt to file: {e}")

        # ── Call Gemini ────────────────────────────────────────────────────
        print("Calling Gemini API...")
        response = gemini_client.generate_content(enhanced_prompt)
        output = gemini_client.get_text(response).strip()

        # Print Gemini response
        # print("\n" + "="*80)
        # print("GEMINI RESPONSE (first 1000 chars):")
        # print("="*80)
        # print(output[:1000])
        # print("="*80 + "\n")

        # Clean markdown fences and JS-style comments
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")
        cleaned = re.sub(r'//.*', '', cleaned)

        # ── Parse JSON using RAG's parse_and_fix ───────────────────────────
        tara_json = rag_parse_and_fix(cleaned)

        if tara_json is None:
            # Fallback to manual parsing
            try:
                tara_json = json.loads(cleaned)
                print("✅ Successfully parsed JSON from Gemini (manual)")
            except json.JSONDecodeError as e:
                print(f"❌ JSON parse error: {e}")
                print(f"Raw output: {cleaned[:500]}...")
                raise ValueError(f"Invalid JSON from Gemini: {e}")

        # ── Ensure UUID stamping and cross-linking ─────────────────────────
        if "assets" in tara_json:
            tara_json = rag_stamp_uuids(tara_json)
            tara_json = rag_crosslink_node_ids(tara_json)

        # ── Extract template (nodes + edges) ──────────────────────────────
        template_data = None
        # print ("Extracting template data from Gemini response...", tara_json)
        if "assets" in tara_json and isinstance(tara_json["assets"], dict):
            if "template" in tara_json["assets"]:
                template_data = tara_json["assets"]["template"]
            else:
                template_data = tara_json["assets"]
        elif "nodes" in tara_json and "edges" in tara_json:
            template_data = tara_json
        elif "templates" in tara_json and isinstance(tara_json["templates"], dict):
            template_data = tara_json["templates"]
        else:
            for key, value in tara_json.items():
                if isinstance(value, dict) and "nodes" in value and "edges" in value:
                    template_data = value
                    break

        if not template_data or not isinstance(template_data, dict):
            print(f"Unexpected response structure: {json.dumps(tara_json, indent=2)[:500]}")
            raise ValueError("Invalid response format from Gemini - missing nodes/edges")

        minimal_nodes = template_data.get("nodes", [])
        minimal_edges = template_data.get("edges", [])

        if not isinstance(minimal_nodes, list) or not isinstance(minimal_edges, list):
            raise ValueError("Invalid response format from Gemini - nodes/edges must be lists")

        print(f"Generated {len(minimal_nodes)} nodes and {len(minimal_edges)} edges")

        # ── Build full ReactFlow-ready template with enhanced node data ─────
        # Process nodes to ensure they have all required fields
        # processed_nodes = []
        # for node in minimal_nodes:
        #     processed_node = {
        #         "id": node.get("id", str(uuid.uuid4())),
        #         "type": node.get("type", "default"),
        #         "parentId": node.get("parentId"),
        #         "data": {
        #             "label": node.get("data", {}).get("label", ""),
        #             "description": node.get("data", {}).get("description", ""),
        #             "style": {
        #                 "backgroundColor": node.get("data", {}).get("style", {}).get("backgroundColor", "#dadada"),
        #                 "borderColor": node.get("data", {}).get("style", {}).get("borderColor", "gray"),
        #                 "borderStyle": "solid",
        #                 "borderWidth": "2px",
        #                 "color": "black",
        #                 "fontFamily": "Inter",
        #                 "fontSize": "12px",
        #                 "fontWeight": 500,
        #                 "height": node.get("data", {}).get("style", {}).get("height", 50),
        #                 "width": node.get("data", {}).get("style", {}).get("width", 150)
        #             }
        #         },
        #         "properties": node.get("properties", []),
        #         "isAsset": node.get("isAsset", False),
        #         "width": node.get("width", 150),
        #         "height": node.get("height", 50),
        #         "position": node.get("position", {"x": 0, "y": 0}),
        #         "positionAbsolute": node.get("positionAbsolute", {"x": 0, "y": 0}),
        #         "zIndex": node.get("zIndex", 0)
        #     }
        #     processed_nodes.append(processed_node)
        
        # Calculate node positions for better layout
        # from app.Methods.helpers import calculate_node_positions
        # positioned_nodes = calculate_node_positions(processed_nodes)

        # Process edges with default values
        # normalized_edges = []
        # for e in minimal_edges:
        #     edge = dict(e)
        #     edge.setdefault("sourceHandle", "bottom")
        #     edge.setdefault("targetHandle", "top")
        #     edge.setdefault("type", "step")
        #     edge.setdefault("animated", True)
        #     edge.setdefault("markerEnd", {"type": "arrowclosed", "color": "#64B5F6", "width": 18, "height": 18})
        #     edge.setdefault("markerStart", {"type": "arrowclosed", "color": "#64B5F6", "width": 18, "height": 18, "orient": "auto-start-reverse"})
        #     edge.setdefault("style", {"stroke": "#808080", "strokeWidth": 2, "end": True, "start": True})
        #     normalized_edges.append(edge)

        # from app.Methods.helpers import build_full_edge
        # full_edges = [build_full_edge(e) for e in normalized_edges]

        final_template = {
            "nodes": minimal_nodes,
            "edges": minimal_edges,
        }

        # ── Generate Derivations and Details using helper function ───────────
        # print("Generating Derivations and Details using getDerivationsAndDetails...")
        
        # Extract existing details if any (for preserving IDs)
        existing_details = {}
        
        # Call the helper function to generate Derivations and Details
        Derivations, Details = getDerivationsAndDetails(final_template, existing_details)
        
        # print(f"Generated {len(Derivations)} derivations and {len(Details)} details")

        # ── Store model in DB ──────────────────────────────────────────────
        from datetime import datetime
        current = datetime.now()
        model_doc = {
            "name":         system_name,
            "template":     [],
            "created_by":   created_by,
            "created_at":   current,
            "last_updated": current,
            "user_id":      user_id,
            "status":       1,
            "type":         "model",
        }
        result = db.Models.insert_one(model_doc)
        model_id = str(result.inserted_id)

        # Store asset with template
        db.Assets.insert_one({
            "model_id":        model_id,
            "template":        final_template,
            "asset_name":      f"{system_name}-asset",
            "asset_properties": "",
            "Details":         Details,
        })

        # Store damage scenarios with derivations and details
        db.Damage_scenarios.update_one(
            {"model_id": model_id, "type": "Derived"},
            {
                "$set": {
                    "model_id":    model_id,
                    "type":        "Derived",
                    "Derivations": Derivations,
                    "Details":     Details,
                }
            },
            upsert=True,
        )

        # node_count = len(positioned_nodes)
        # edge_count = len(full_edges)
        # deriv_count = len(Derivations)
        # ds_count = len(Details)
        # print(f"   Nodes         : {node_count}")
        # print(f"   Edges         : {edge_count}")
        # print(f"   Derivations   : {deriv_count}")
        # print(f"   Damage details: {ds_count}")

        result_data = {
            "message":     "Template generated and stored successfully",
            "model_id":    model_id,
            "template":    final_template,
            "system_name": system_name,
            "derivations": Derivations,
            "details":     Details,
        }

        if standalone:
            return result_data
        return current_app.response_class(
            response=json.dumps(result_data, cls=JSONEncoder),
            status=201,
            mimetype="application/json",
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        if standalone:
            raise e
        return jsonify({"error in item definition": str(e)}), 500


#3 - Damage scenario creation
def generate_object_id():
    """Generate MongoDB-style ObjectId"""
    return ''.join(random.choices(string.hexdigits.lower(), k=24))

# Wrapper Flask endpoint
@modelprompt.route('/v1/generate/damage-scenarios', methods=['POST'])
def create_damage_scenarios_with_rag(standalone=False, request_data=None):
    """Generate damage scenarios using RAG-enhanced prompts - stores as User-defined type"""
    try:
        # Match item definition's request handling exactly
        if not request_data:
            request_data = request

        # Parse request like item definition
        if request.is_json:
            data = request.get_json()
            model_id = data.get("modelId")
            system_name = data.get("systemName", "")
            template_raw = data.get("template", "{}")
            user_prompt = data.get("damageScenarioPrompt", "")
            custom_prompt = data.get("itemDefinitionPrompt", "")
            
            # Handle dynamic fields
            static_fields = {"modelId", "systemName", "template", "damageScenarioPrompt", "itemDefinitionPrompt"}
            dynamic_fields = {k: v for k, v in data.items() if k not in static_fields}
        else:
            # Handle form data
            model_id = request_data.form.get("modelId")
            system_name = request_data.form.get("systemName", "")
            template_raw = request_data.form.get("template", "{}")
            user_prompt = request_data.form.get("damageScenarioPrompt", "")
            custom_prompt = request_data.form.get("itemDefinitionPrompt", "")
            
            # Handle dynamic fields
            static_fields = {"modelId", "systemName", "template", "damageScenarioPrompt", "itemDefinitionPrompt"}
            dynamic_fields = {
                key: request_data.form.get(key)
                for key in request_data.form
                if key not in static_fields
            }

        # Build dynamic prompt lines
        dynamic_prompt_lines = "\n".join([
            f"{key.replace('_', ' ').title()}: {value}"
            for key, value in dynamic_fields.items()
        ])

        if not model_id:
            if standalone:
                raise ValueError("modelId is required")
            return jsonify({"error": "modelId is required"}), 400

        # Parse template safely
        try:
            template = json.loads(template_raw) if template_raw else {}
        except json.JSONDecodeError as e:
            return jsonify({"error": "Invalid template JSON", "details": str(e)}), 400

        print(f"DEBUG: model_id = {model_id}")
        print(f"DEBUG: system_name = {system_name}")
        print(f"DEBUG: template nodes = {len(template.get('nodes', []))}")

        # ── RAG Setup (same as item definition) ───────────────────────────────
        from app.v1.rag.components import (
            resolve_ecu as rag_resolve_ecu,
            build_enriched_query as rag_build_enriched_query,
            stamp_uuids as rag_stamp_uuids,
            crosslink_node_ids as rag_crosslink_node_ids,
            parse_and_fix as rag_parse_and_fix,
        )
        from app.v1.rag.ingest import load_all_documents
        from app.v1.rag.pipeline import build_pipeline
        from app.v1.rag.prompt import TARA_PROMPT_TEMPLATE
        from haystack.components.builders import PromptBuilder

        # ── ECU resolution (same as item definition) ─────────────────────────
        print(f"Resolving ECU for damage scenarios: {system_name}")
        
        ecu_entry = rag_resolve_ecu(system_name)
        if ecu_entry:
            print(f"Matched ECU  : {ecu_entry['name']}")
            print(f"Type         : {ecu_entry['type']}")

        # Build enriched query (same as item definition)
        enriched_query = rag_build_enriched_query(system_name, ecu_entry)
        
        # Add architecture context to the question
        architecture_context = f"""
        IMPORTANT: The following system architecture has already been defined.
        You MUST reference ONLY these existing components when generating damage scenarios.
        
        Existing Components (with their IDs):
        {json.dumps([{
            'id': node.get('id'),
            'label': node.get('data', {}).get('label'),
            'type': node.get('type')
        } for node in template.get('nodes', [])], indent=2)}
        """
        
        # Build the question (like item definition)
        question = f"""
        SYSTEM REQUEST: Generate cybersecurity damage scenarios for the {system_name} system.
        
        {architecture_context}
        
        Generate realistic damage scenarios following ISO/SAE 21434 Clause 15.
        Each damage scenario must reference specific components from the architecture above.
        """
        
        # Add user/custom prompts if provided
        if user_prompt:
            question += f"\n\nAdditional User Requirements:\n{user_prompt}"
        
        if custom_prompt:
            question += f"\n\nCustom Requirements:\n{custom_prompt}"
        
        # Add dynamic fields if any
        if dynamic_prompt_lines:
            question += f"\n\nAdditional System Details:\n{dynamic_prompt_lines}"
        
        print("\n" + "="*80)
        print("ENRICHED QUERY (for LLM):")
        print("="*80)
        print(question[:1000] + "..." if len(question) > 1000 else question)
        print("="*80 + "\n")

        # ── Load documents and build pipeline (same as item definition) ──────
        print(f"Loading documents from Azure and building RAG pipeline...")
        
        all_docs = load_all_documents()
        pipeline, _ = build_pipeline(all_docs)
        
        # Retrieve documents
        print(f"Retrieving documents for system: {system_name}")
        
        retrieval_result = pipeline.run(
            {
                "text_embedder": {"text": system_name},
                "prompt_builder": {"question": question},
            },
            include_outputs_from=["retriever"],
        )
        
        retrieved_docs = retrieval_result["retriever"]["documents"]
        print(f"Retrieved {len(retrieved_docs)} documents")
        
        # ── Build prompt using TARA_PROMPT_TEMPLATE (same as item definition) ──
        print("Building prompt using TARA_PROMPT_TEMPLATE from prompt.py...")
        
        prompt_builder = PromptBuilder(
            template=TARA_PROMPT_TEMPLATE,
            required_variables=["documents", "question"],
        )
        
        prompt_result = prompt_builder.run(
            documents=retrieved_docs,
            question=question
        )
        
        rag_prompt = prompt_result["prompt"]
        
        print(f"RAG prompt built with {len(retrieved_docs)} retrieved documents")
        print(f"RAG prompt length: {len(rag_prompt)} characters")

        # ── Combine with custom prompt if provided ──────────────────────────
        if custom_prompt:
            enhanced_prompt = f"""
System: {system_name}

Additional Requirements: {custom_prompt}

{rag_prompt}
"""
        else:
            enhanced_prompt = rag_prompt

        # Add dynamic field lines if any
        if dynamic_prompt_lines:
            enhanced_prompt += f"\n\nAdditional System Details:\n{dynamic_prompt_lines}"

        # Add user prompt if provided
        if user_prompt:
            enhanced_prompt += f"\n\nUser Requirements:\n{user_prompt}"

        # ── Save the final prompt for debugging ─────────────────────────────
        print("\n" + "="*80)
        print("FINAL PROMPT SENT TO GEMINI:")
        print("="*80)
        print(enhanced_prompt[:2000] + "..." if len(enhanced_prompt) > 2000 else enhanced_prompt)
        print("="*80 + "\n")

        # Save to file for inspection
        try:
            with open("damage_scenario_prompt.txt", "w", encoding="utf-8") as f:
                f.write(enhanced_prompt)
            print("✅ Damage scenario prompt saved to damage_scenario_prompt.txt")
        except Exception as e:
            print(f"Could not save prompt to file: {e}")

        # ── Call Gemini ─────────────────────────────────────────────────────
        print("Calling Gemini API...")
        response = gemini_client.generate_content(enhanced_prompt)
        output = gemini_client.get_text(response).strip()

        # Print Gemini response
        print("\n" + "="*80)
        print("GEMINI RESPONSE (first 1000 chars):")
        print("="*80)
        print(output[:1000])
        print("="*80 + "\n")

        # Clean markdown fences and JS-style comments
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")
        cleaned = re.sub(r'//.*', '', cleaned)

        # ── Parse JSON using RAG's parse_and_fix ────────────────────────────
        tara_json = rag_parse_and_fix(cleaned)

        if tara_json is None:
            # Fallback to manual parsing
            try:
                tara_json = json.loads(cleaned)
                print("✅ Successfully parsed JSON from Gemini (manual)")
            except json.JSONDecodeError as e:
                print(f"❌ JSON parse error: {e}")
                print(f"Raw output: {cleaned[:500]}...")
                raise ValueError(f"Invalid JSON from Gemini: {e}")

        # ── Extract the damage scenarios structure ──────────────────────────
        # The prompt.py returns JSON with assets and damage_scenarios
        if "damage_scenarios" in tara_json:
            scenarios = tara_json["damage_scenarios"]
        else:
            scenarios = tara_json
        
        # Ensure the structure matches what the frontend expects
        # The Details should be in the format that get_damage_scene() expects
        if "Details" not in scenarios:
            # Try to extract from Derivations if that's what was returned
            if "Derivations" in scenarios and scenarios["Derivations"]:
                scenarios["Details"] = []
                for i, deriv in enumerate(scenarios["Derivations"], start=1):
                    detail = {
                        "Name": deriv.get("name", f"Damage Scenario {i}"),
                        "Description": deriv.get("damage_scene", deriv.get("description", "")),
                        "cyberLosses": deriv.get("cyberLosses", []),
                        "impacts": deriv.get("impacts", {
                            "Financial Impact": "Moderate",
                            "Safety Impact": "Moderate",
                            "Operational Impact": "Moderate",
                            "Privacy Impact": "Moderate"
                        }),
                        "key": i,
                        "_id": str(uuid.uuid4())
                    }
                    scenarios["Details"].append(detail)
            else:
                scenarios["Details"] = []

        # Ensure each detail has the required fields
        valid_node_ids = {node.get("id") for node in template.get("nodes", [])}
        valid_node_labels = {node.get("data", {}).get("label"): node.get("id") 
                            for node in template.get("nodes", [])}
        
        for detail in scenarios.get("Details", []):
            # Ensure _id exists
            if "_id" not in detail:
                detail["_id"] = str(uuid.uuid4())
            
            # Ensure key exists
            if "key" not in detail:
                detail["key"] = scenarios["Details"].index(detail) + 1
            
            # Ensure cyberLosses exists and references valid nodes
            if "cyberLosses" not in detail:
                detail["cyberLosses"] = []
            
            # Validate and fix node references
            validated_losses = []
            for loss in detail.get("cyberLosses", []):
                if loss.get("nodeId") not in valid_node_ids:
                    node_name = loss.get("node", "")
                    if node_name in valid_node_labels:
                        loss["nodeId"] = valid_node_labels[node_name]
                        loss["node"] = node_name
                        validated_losses.append(loss)
                    else:
                        print(f"Warning: Could not find node '{node_name}' for loss")
                else:
                    validated_losses.append(loss)
            detail["cyberLosses"] = validated_losses
            
            # Ensure impacts exists
            if "impacts" not in detail:
                detail["impacts"] = {
                    "Financial Impact": "Moderate",
                    "Safety Impact": "Moderate",
                    "Operational Impact": "Moderate",
                    "Privacy Impact": "Moderate"
                }

        print(f"Generated {len(scenarios.get('Details', []))} damage scenarios")

        # ── Store in database as "User-defined" type ─────────────────────────
        from datetime import datetime
        
        current_time = datetime.now()
        
        # Check if damage scenarios already exist for this model with User-defined type
        existing = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        
        if existing:
            # Update existing - preserve existing derivations if any
            update_data = {
                "$set": {
                    "Details": scenarios.get("Details", []),
                    "last_updated": current_time
                }
            }
            # Only update Derivations if they exist in the new data
            if "Derivations" in scenarios:
                update_data["$set"]["Derivations"] = scenarios["Derivations"]
            
            result = db.Damage_scenarios.update_one(
                {"model_id": model_id, "type": "User-defined"},
                update_data
            )
            operation = "updated"
            scenario_id = str(existing["_id"])
        else:
            # Insert new with type "User-defined"
            damage_doc = {
                "model_id": model_id,
                "type": "User-defined",  # Key change: Store as User-defined
                "Details": scenarios.get("Details", []),
                "Derivations": scenarios.get("Derivations", []),
                "created_at": current_time,
                "last_updated": current_time
            }
            result = db.Damage_scenarios.insert_one(damage_doc)
            operation = "created"
            scenario_id = str(result.inserted_id)

        # Convert ObjectIds to strings for safe JSON serialization
        def convert_objectid(obj):
            if isinstance(obj, ObjectId):
                return str(obj)
            if isinstance(obj, list):
                return [convert_objectid(i) for i in obj]
            if isinstance(obj, dict):
                return {k: convert_objectid(v) for k, v in obj.items()}
            return obj

        safe_scenarios = convert_objectid({
            "Details": scenarios.get("Details", []),
            "Derivations": scenarios.get("Derivations", [])
        })

        result_data = {
            "message": f"Damage scenarios {operation} successfully",
            "scenario_id": scenario_id,
            "model_id": model_id,
            "scenarios": safe_scenarios,
            "stats": {
                "total_scenarios": len(safe_scenarios.get("Details", []))
            }
        }

        if standalone:
            return result_data
        return jsonify(result_data), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        if standalone:
            raise e
        return jsonify({"error in damage scenario generation": str(e)}), 500

#4 - Threat scenario creation
# Manual threat creation
@modelprompt.route('/v1/generate/threat-scenarios', methods=['POST'])
def create_threat_scenarios(model_id=None):
    try:
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        damage_doc = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        if not damage_doc or "Details" not in damage_doc:
            return jsonify({"error": "No damage scenarios found for this model_id"}), 404

        threat_details = []

        for i, damage in enumerate(damage_doc["Details"], start=1):
            threat_detail = {
                "damage_key": damage["key"],
                "damage_name": damage["Name"],
                "id": f"DS{str(i).zfill(3)}",
                "rowId": damage["_id"],
                "Details": []
            }

            for loss in damage.get("cyberLosses", []):
                threat_node = {
                    "name": damage["Name"],
                    "node": loss["node"],
                    "nodeId": loss["nodeId"],
                    "props": [
                        {
                            "id": str(uuid.uuid4()),
                            "name": loss["name"],
                            "isSelected": True,
                            "is_risk_added": False,
                            "key": 1
                        }
                    ]
                }
                threat_detail["Details"].append(threat_node)

            threat_details.append(threat_detail)

        threat_scenario_doc = {
            "model_id": model_id,
            "type": "derived",
            "Details": threat_details
        }

        db.Threat_scenarios.replace_one(
            {"model_id": model_id, "type": "derived"},
            threat_scenario_doc,
            upsert=True
        )

        saved_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "derived"})
        saved_doc["_id"] = str(saved_doc["_id"])

        return jsonify({
            "message": "Threat scenarios created successfully",
            "model_id": model_id,
            "scenarios": saved_doc
        }), 201

    except Exception as e:
        return jsonify({"error in threat scenario": str(e)}), 500


#threat creation
def extract_json_from_text(text: str) -> str:
    """
    Extracts JSON part from Gemini response text.
    Assumes JSON is enclosed in braces {} or brackets [].
    """
    match = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
    return match.group(1) if match else text


def group_threats_by_node(threat_ids):
    grouped = defaultdict(list)
    for threat in threat_ids:
        key = threat['nodeId']
        grouped[key].append(threat)
    return grouped


# Derived threat scenario creation
def generate_single_derived_scenario(threat_group, user_prompt=None):
    """
    Generate a derived threat scenario name + description from a group of threats.
    If user_prompt is provided, it replaces the intro part of the prompt.
    """

    default_intro = f"""
        You are a cybersecurity expert. Based on the following related threats, generate a meaningful name and a concise description for a derived threat scenario. Do not use generic names like "Derived Threat Scenario".

        Here are the threats:
        {json.dumps(threat_group, indent=2)}
        """

    prompt_intro = user_prompt if user_prompt else default_intro

    prompt = f"""
        {prompt_intro}

        (for Data structure)
        Each threat includes:
        - `nodeId`: the component or function
        - `propId`: the impacted property (can be ignored)
        - `rowId`: the related damage scenario

        Return only a JSON object with:
        - name: (string) → A short, meaningful, human-readable title for the derived threat scenario
        - description: (string) → A concise natural-language summary of the combined threats.
        Do NOT return an array, object, or repeat the input JSON.
        The description should read like a human-written explanation,
        not raw data.
    """

    gemini_response = gemini_client.generate_content(prompt)
    try:
        content_text = gemini_client.get_text(gemini_response)

        cleaned = extract_json_from_text(content_text)
        cleaned = re.sub(r'[\x00-\x1F\x7F]', '', cleaned)
        cleaned = cleaned.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
        cleaned = re.sub(r",\s*}", "}", cleaned)
        cleaned = re.sub(r",\s*]", "]", cleaned)

        parsed = json.loads(cleaned)

        description = parsed.get("description", "")
        if not isinstance(description, str):
            if isinstance(description, list):
                description = " ".join(str(item) for item in description)
            else:
                description = json.dumps(description, ensure_ascii=False)

        return {
            "name": parsed.get("name", "Unnamed Derived Threat"),
            "description": description
        }

    except Exception as e:
        print("⚠️ Failed JSON parse, falling back. Raw text:\n", content_text)
        raise ValueError(f"Failed to parse Gemini response: {str(e)}")


def generate_derived_threat_scenarios(model_id, threat_ids, name="", description="", user_prompt=None):
    details = []

    if name or description:
        if not isinstance(description, str):
            if isinstance(description, list):
                description = " ".join(str(item) for item in description)
            else:
                description = json.dumps(description, ensure_ascii=False)

        derived = {
            "name": name or "Unnamed Derived Threat",
            "description": description,
            "id": str(uuid.uuid4()),
            "threat_ids": threat_ids
        }
        details.append(derived)
    else:
        grouped = group_threats_by_node(threat_ids)
        for group in grouped.values():
            result = generate_single_derived_scenario(group, user_prompt)

            description = result.get("description", "")
            if not isinstance(description, str):
                if isinstance(description, list):
                    description = " ".join(str(item) for item in description)
                else:
                    description = json.dumps(description, ensure_ascii=False)

            derived = {
                "name": result.get("name", "Unnamed Derived Threat"),
                "description": description,
                "id": str(uuid.uuid4()),
                "threat_ids": group
            }
            details.append(derived)

    if details:
        document = {
            "model_id": model_id,
            "type": "User-defined",
            "Details": details
        }
        db.Threat_scenarios.replace_one(
            {"model_id": model_id, "type": "User-defined"},
            document,
            upsert=True
        )

        saved_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        saved_doc["_id"] = str(saved_doc["_id"])
        return saved_doc

    return {}


@modelprompt.route('/v1/generate/derived-threat-scenarios', methods=['POST'])
def create_derived_threat_scenario():
    try:
        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        name = data.get('name', "")
        description = data.get('description', "")
        model_id = data.get('modelId', "")
        user_prompt = data.get('threatScenarioPrompt', "")
        
        # Handle threat_ids which might be a string (from form) or list (from JSON)
        threat_ids_raw = data.get('threatIds', "[]")
        if isinstance(threat_ids_raw, str):
            threat_ids = json.loads(threat_ids_raw)
        else:
            threat_ids = threat_ids_raw
        if not model_id or not threat_ids:
            return jsonify({"error": "Missing modelId or threatIds"}), 400

        results = generate_derived_threat_scenarios(model_id, threat_ids, name, description, user_prompt)
        return jsonify(results), 201

    except Exception as e:
        return jsonify({"error in derived threat scenario": str(e)}), 500

# Full threat scenario pipeline
@modelprompt.route('/v1/generate/full-threat-scenario', methods=['POST'])
def create_threat_and_derived_combined():
    try:
        start_time = time.time()

        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        # Get JSON data instead of form data
 
        model_id = data.get('modelId', "")
        name = data.get('name', "")
        description = data.get('description', "")
        user_prompt = data.get('threatScenarioPrompt', "")

        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        print(f"\n=== [COMBINED API] STARTED for model {model_id} ===")

        t1 = time.time()
        threat_response, status_code = create_threat_scenarios(model_id)
        print(f"[TIMING] Threat scenario generation took {time.time() - t1:.2f}s")

        if status_code != 201:
            print("[ERROR] Threat scenario generation failed")
            return threat_response, status_code

        threat_data = threat_response.get_json()
        print(f"[DEBUG] Threat scenarios created: {len(threat_data.get('scenarios', {}).get('Details', []))}")

        threat_ids = []
        for threat in threat_data.get("scenarios", {}).get("Details", []):
            for item in threat.get("Details", []):
                for prop in item.get("props", []):
                    threat_ids.append({
                        "nodeId": item["nodeId"],
                        "propId": prop["id"],
                        "rowId": threat["rowId"]
                    })
        print(f"[DEBUG] Collected {len(threat_ids)} threatIds for derived generation")

        derived_response_json = None
        derived_status = 500

        t2 = time.time()
        
        # For the internal call, you might need to use JSON instead of MultiDict
        with current_app.test_request_context(
            "/v1/generate/derived-threat-scenario",
            method="POST",
            data=MultiDict({
                "modelId": model_id,
                "name": name,
                "description": description,
                "threatScenarioPrompt": user_prompt,
                "threatIds": json.dumps(threat_ids)
            })
        ):
            try:
                print("[INFO] Calling create_derived_threat_scenario()...")
                derived_response, derived_status = create_derived_threat_scenario()
                if hasattr(derived_response, "get_json"):
                    derived_response_json = derived_response.get_json()
                print(f"[TIMING] Derived threat scenario generation took {time.time() - t2:.2f}s")
            except Exception as e:
                print("[ERROR] Derived threat scenario generation failed:", str(e))
                traceback.print_exc()

        total_time = time.time() - start_time
        print(f"=== [COMBINED API] FINISHED in {total_time:.2f}s ===\n")

        return jsonify({
            "message": "Threat + Derived Threat scenarios created successfully",
            "threat_scenarios": threat_data,
            "derived_threat_scenarios": derived_response_json,
            "derived_status": derived_status,
            "timing": {
                "threat_generation_sec": round(time.time() - t1, 2),
                "derived_generation_sec": round(time.time() - t2, 2),
                "total_sec": round(total_time, 2)
            }
        }), 201

    except Exception as e:
        print("[FATAL ERROR in combined API]:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Error in combined API", "details": str(e)}), 500

#5 - Attack Scenario Creation
def preprocess_threat_scenarios(threat_scenarios):
    """
    Flattens the Details in each threat scenario so Gemini can see scenario names and nodes clearly.
    Uses props id as threat_id so attack trees can map correctly.
    """
    processed = []
    for scenario in threat_scenarios:
        for detail in scenario.get("Details", []):
            row_id = detail.get("rowId")
            for d in detail.get("Details", []):
                for prop in d.get("props", []):
                    processed.append({
                        "rowId": row_id,
                        "scenario_name": d.get("name", ""),
                        "node": d.get("node", ""),
                        "nodeId": d.get("nodeId", ""),
                        "property": prop.get("name", ""),
                        "threat_id": prop.get("id"),
                        "threat_key": f"TS{prop.get('key', 0):03}"
                    })
    return processed

def generate_attack_trees_with_gemini(threat_scenarios, model_id, user_prompt=None):
    """
    Given a list of threat_scenarios and a model_id, call Gemini to generate attack trees.
    """
    default_prompt = """
        You are an expert in cyber threat modeling. Given the following derived threat scenarios, select the top 2 most critical scenarios and generate attack trees for each.
        Each scenario includes:
        - scenario_name: the name of the scenario
        - nodeId: the component's unique ID
        - type: for the nodes use "Event". The first node must be the threat scenario and type default
        - rowId: unique scenario identifier.

        RULES FOR ATTACK TREE GENERATION:
        1. Every attack tree MUST have at least one gate (OR Gate or AND Gate).
        2. The root node should be the threat scenario (type: "default")
        3. Events must be connected through gates - never directly to other events
        4. Include realistic attack steps that would lead to the threat scenario

        Return the result in the following JSON format (one scene per scenario):
        """

    data_structure_prompt = f"""
        (for Data structure)
        {{
        "model_id": "{model_id}",
        "type": "attack_trees",
        "scenes": [
            {{
            "ID": "uuid",
            "Name": "Attack Tree Name",
            "threat_id": "threat_id from props (not rowId)",
            "templates": {{
                "nodes": [
                {{
                    "id": "node1",
                    "name": "Root Threat",
                    "type": "default",
                    "threat_id": "same threat_id"
                }},
                {{
                    "id": "node2",
                    "name": "OR Gate Example",
                    "type": "OR Gate"
                }},
                {{
                    "id": "node3",
                    "name": "Attack Step 1",
                    "type": "Event"
                }}
                ],
                "edges": [
                {{
                    "id": "edge1",
                    "source": "node1",
                    "target": "node2"
                }},
                {{
                    "id": "edge2",
                    "source": "node2",
                    "target": "node3"
                }}
                ]
            }}
            }}
        ]
        }}

        Here are the threat scenarios:
        {json.dumps(threat_scenarios, default=str, indent=2)}

        IMPORTANT:
        - You MUST include at least one gate (OR or AND) in each attack tree
        - Events must connect through gates, not directly to other events
        - Make the attack trees realistic with plausible attack steps
        - Return ONLY valid JSON.
        """

    final_prompt = (user_prompt or default_prompt) + data_structure_prompt

    gemini_response = gemini_client.generate_content(final_prompt)

    try:
        content_text = gemini_client.get_text(gemini_response)
        cleaned = re.sub(r"```[a-z]*", "", content_text).strip().strip("`")
        return json.loads(cleaned)
    except Exception as e:
        raise ValueError(f"Failed to parse Gemini attack tree response: {str(e)}")


@modelprompt.route('/v1/generate/attack-tree', methods=['POST'])
def generate_attack_tree():
    try:

        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        model_id = data.get('modelId', '')
        user_prompt = data.get('attackscenarioPrompt', '')
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        threat_scenarios = list(
            db.Threat_scenarios.find({
                "model_id": model_id,
                "type": "derived"
            })
        )

        if not threat_scenarios:
            return jsonify({"error": "No derived threat scenarios found"}), 404

        processed_scenarios = preprocess_threat_scenarios(threat_scenarios)

        try:
            attack_tree_data = generate_attack_trees_with_gemini(processed_scenarios, model_id, user_prompt)
        except Exception as e:
            return jsonify({"error": f"Failed to generate attack trees: {str(e)}"}), 500

        try:
            raw_scenes = attack_tree_data.get("scenes", [])
            scenes = []

            for scene in raw_scenes:
                structured_templates = structure_attack_tree_templates(
                    scene.get("templates", {}),
                    processed_scenarios=processed_scenarios
                )

                scenes.append({
                    "ID": scene.get("ID"),
                    "Name": scene.get("Name"),
                    "threat_id": scene.get("threat_id"),
                    "templates": structured_templates
                })

            existing_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack_trees"})

            if existing_doc:
                db.Attacks.update_one(
                    {"_id": existing_doc["_id"]},
                    {"$push": {"scenes": {"$each": scenes}}}
                )
            else:
                db.Attacks.insert_one({
                    "model_id": model_id,
                    "type": "attack_trees",
                    "scenes": scenes
                })
        except Exception as e:
            return jsonify({"error": f"Failed to store attack trees in DB: {str(e)}"}), 500

        return jsonify(attack_tree_data), 200

    except Exception as e:
        return jsonify({"error in attack tree": str(e)}), 500


# Attacks
RATING_MAP = {
    category: {opt["value"]: opt["rating"] for opt in options}
    for category, options in AttackTableoptions.items()
}

def calculate_attack_feasibility(scene):
    """Calculate feasibility rating using the same scale as the frontend."""
    total_rating = 0
    for field in ["Elapsed Time", "Expertise", "Knowledge of the Item", "Window of Opportunity", "Equipment"]:
        value = scene.get(field)
        total_rating += RATING_MAP[field].get(value, 0)

    if 0 <= total_rating <= 13:
        return "High"
    elif 14 <= total_rating <= 19:
        return "Medium"
    elif 20 <= total_rating <= 24:
        return "Low"
    else:
        return "Very low"


def generate_possible_attacks_with_gemini(threat_scenarios, model_id, user_prompt=None):
    """
    Given derived threat scenarios, generate possible attacks for each scenario using Gemini.
    """
    options = {
        "Elapsed Time": [opt["value"] for opt in AttackTableoptions["Elapsed Time"]],
        "Expertise": [opt["value"] for opt in AttackTableoptions["Expertise"]],
        "Knowledge of the Item": [opt["value"] for opt in AttackTableoptions["Knowledge of the Item"]],
        "Window of Opportunity": [opt["value"] for opt in AttackTableoptions["Window of Opportunity"]],
        "Equipment": [opt["value"] for opt in AttackTableoptions["Equipment"]],
    }

    default_prompt = f"""
        You are an expert in cyber threat analysis.
        For each of the following derived threat scenarios, create one realistic possible attack.

        """

    data_structure_prompt = f"""
        (for Data structure)
        Rules:
        1. For each attack, use exactly these fields:
        - ID: UUID
        - Name: short descriptive attack name
        - Elapsed Time: one of {options["Elapsed Time"]}
        - Expertise: one of {options["Expertise"]}
        - Knowledge of the Item: one of {options["Knowledge of the Item"]}
        - Window of Opportunity: one of {options["Window of Opportunity"]}
        - Equipment: one of {options["Equipment"]}
        2. Do NOT include "Attack Feasibilities Rating" (this will be calculated automatically).
        3. Return ONLY valid JSON.

        Format:
        {{
        "model_id": "{model_id}",
        "type": "attack",
        "scenes": [
            {{
            "ID": "uuid",
            "Name": "Attack Name",
            "Elapsed Time": "...",
            "Expertise": "...",
            "Knowledge of the Item": "...",
            "Window of Opportunity": "...",
            "Equipment": "..."
            }}
        ]
        }}

        Here are the derived threat scenarios:
        {json.dumps(threat_scenarios, indent=2)}
        """

    final_prompt = (user_prompt or default_prompt) + data_structure_prompt

    gemini_response = gemini_client.generate_content(final_prompt)

    try:
        content_text = gemini_client.get_text(gemini_response)
        cleaned = re.sub(r"```[a-z]*", "", content_text).strip().strip("`")
        return json.loads(cleaned)
    except Exception as e:
        raise ValueError(f"Failed to parse Gemini attack response: {str(e)}")


@modelprompt.route('/v1/generate/attacks', methods=['POST'])
def generate_attacks():
    try:

        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        model_id = data.get('modelId', '')
        user_prompt = data.get('attackscenarioPrompt', '')
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        threat_scenarios = list(
            db.Threat_scenarios.find({
                "model_id": model_id,
                "type": "derived"
            })
        )
        if not threat_scenarios:
            return jsonify({"error": "No derived threat scenarios found"}), 404

        processed_scenarios = preprocess_threat_scenarios(threat_scenarios)
        attack_data = generate_possible_attacks_with_gemini(processed_scenarios, model_id, user_prompt)

        for scene in attack_data.get("scenes", []):
            scene["Attack Feasibilities Rating"] = calculate_attack_feasibility(scene)

        scenes = attack_data.get("scenes", [])
        existing_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack"})
        if existing_doc:
            db.Attacks.update_one(
                {"_id": existing_doc["_id"]},
                {"$push": {"scenes": {"$each": scenes}}}
            )
        else:
            db.Attacks.insert_one({
                "model_id": model_id,
                "type": "attack",
                "scenes": scenes
            })

        return jsonify(attack_data), 200

    except Exception as e:
        return jsonify({"error in attacks": str(e)}), 500


def filter_possible_events_with_gemini(attack_trees, model_id, user_prompt=None):
    """
    Given attack_trees and model_id, call Gemini to filter out possible attack events.
    """
    default_prompt = f"""
        You are an expert in automotive cyber threat modeling (ISO/SAE 21434).

        I will give you a JSON list of attack_trees for a system model (model_id: {model_id}).

        Your task:
        - From each attack_tree, review every node with type = "Event".
        - Decide which ones are 'possible attacks' worth converting into cybersecurity requirements.
        - Mark only those that:
        * Represent realistic, feasible attack events (technical plausibility)
        * Are directly relevant to the threat scenario they belong to
        * Are specific enough to warrant a countermeasure
        - Ignore placeholder events (like "Event", "Attack Step"), vague names, or nodes that cannot occur in practice.
        - Return ONLY valid JSON in the exact format:
        """

    data_structure_prompt = """
        (for Data structure)
        [
        {
            "attack_tree_scene_id": "scene ID of the attack tree",
            "attack_tree_scene_name": "scene Name of the attack tree",
            "event_id": "node ID of the Event",
            "event_name": "name of the Event",
            "threat_id": "threat_id from the attack tree scene",
            "threat_key": "threat key if available, else null"
        }
        ]

        Here are the attack_trees:
        """ + json.dumps(attack_trees, indent=2)

    final_prompt = (user_prompt or default_prompt) + data_structure_prompt

    gemini_response = gemini_client.generate_content(final_prompt)

    try:
        content_text = gemini_client.get_text(gemini_response)

        match = re.search(r"\[\s*\{.*\}\s*\]", content_text, re.DOTALL)
        if not match:
            raise ValueError(f"No JSON array found in Gemini output:\n{content_text}")

        json_str = match.group(0)
        return json.loads(json_str)

    except Exception as e:
        raise ValueError(f"Failed to parse Gemini possible events: {str(e)}")


def convert_possible_events(possible_events, model_id):
    """
    Converts possible event nodes into Attacks (type: attack)
    and Cybersecurity Requirements (type: cybersecurity_requirements).
    """
    for evt in possible_events:
        event_id         = evt["event_id"]
        event_name       = evt["event_name"]
        attack_scene_id  = evt["attack_tree_scene_id"]
        attack_scene_name = evt["attack_tree_scene_name"]
        threat_id        = evt.get("threat_id")
        threat_key       = evt.get("threat_key")

        existing_attack = db.Attacks.find_one({
            "model_id": model_id,
            "type": "attack",
            "scenes.Name": event_name
        })
        if not existing_attack:
            attack_scene = {
                "Approach": "",
                "Attack Feasibilities Rating": "",
                "Elapsed Time": "",
                "Equipment": "",
                "Expertise": "",
                "ID": event_id,
                "Knowledge of the Item": "",
                "Name": event_name,
                "Window of Opportunity": ""
            }
            db.Attacks.update_one(
                {"model_id": model_id, "type": "attack"},
                {"$push": {"scenes": attack_scene}},
                upsert=True
            )

        existing_cyber = db.Cybersecurity.find_one({
            "model_id": model_id,
            "type": "cybersecurity_requirements",
            "scenes.Name": event_name
        })
        if not existing_cyber:
            cyber_scene = {
                "ID": event_id,
                "Name": event_name,
                "Description": None,
                "threat_id": threat_id,
                "threat_key": threat_key,
                "attack_scene_id": attack_scene_id,
                "attack_scene_name": attack_scene_name
            }
            db.Cybersecurity.update_one(
                {"model_id": model_id, "type": "cybersecurity_requirements"},
                {"$push": {"scenes": cyber_scene}},
                upsert=True
            )


@modelprompt.route('/v1/convert/possible-events', methods=['POST'])
def convert_possible_events_from_attack_trees():
    try:

        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

            
        model_id = data.get("modelId", "")
        user_prompt = data.get('attackscenarioPrompt', '')
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        attack_trees_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack_trees"})
        if not attack_trees_doc:
            return jsonify({"error": "No attack_trees found"}), 404

        attack_trees = attack_trees_doc.get("scenes", [])
        possible_events = filter_possible_events_with_gemini(attack_trees, model_id, user_prompt)
        convert_possible_events(possible_events, model_id)

        return jsonify({"message": "Possible events converted successfully", "converted": possible_events}), 200

    except Exception as e:
        return jsonify({"error in converting possible events": str(e)}), 500


# Full attack scenario pipeline
@modelprompt.route('/v1/generate/full-attack-scenario', methods=['POST'])
def generate_full_attack_pipeline():
    try:
        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        model_id = data.get('modelId', '')
        user_prompt = data.get('attackscenarioPrompt', '')

        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        attack_tree_response, tree_status = generate_attack_tree()
        if tree_status != 200:
            return attack_tree_response, tree_status

        attack_tree_data = attack_tree_response.get_json()

        with current_app.test_request_context(
            data={"modelId": model_id, "attackscenarioPrompt": user_prompt}
        ):
            attacks_response, attacks_status = generate_attacks()
        if attacks_status != 200:
            return attacks_response, attacks_status

        attacks_data = attacks_response.get_json()

        with current_app.test_request_context(
            data={"modelId": model_id, "attackscenarioPrompt": user_prompt}
        ):
            convert_response, convert_status = convert_possible_events_from_attack_trees()
        if convert_status != 200:
            return convert_response, convert_status

        converted_data = convert_response.get_json()

        return jsonify({
            "message": "Full attack pipeline executed successfully",
            "attack_tree_data": attack_tree_data,
            "attacks_data": attacks_data,
            "converted_events": converted_data
        }), 200

    except Exception as e:
        return jsonify({"error in full attack pipeline": str(e)}), 500


#6 - Cybersecurity Generation
def extract_json_block(text):
    """
    Extract the first valid JSON object by tracking braces manually.
    """
    stack = []
    start = None

    for i, char in enumerate(text):
        if char == '{':
            if not stack:
                start = i
            stack.append(char)
        elif char == '}':
            if stack:
                stack.pop()
                if not stack:
                    return text[start:i + 1]
    return text  # Fallback


def generate_cybersecurity_artifact_with_gemini(artifact_type, system_name):
    prompt_templates = {
        "cybersecurity_requirements": (
            "Generate a list of cybersecurity requirements for the system '{system_name}'. "
            "For each, provide a unique ID and a Name. "
            "Return ONLY valid JSON in the format: { \"scenes\": [ { \"ID\": \"<uuid>\", \"Name\": \"<requirement name>\" } ] }. "
            "Do NOT include any explanation or extra text. The top-level key must be \"scenes\"."
        ),
        "cybersecurity_controls": (
            "Generate a list of cybersecurity controls for the system '{system_name}'. "
            "For each, provide a unique ID, Name, and Description. "
            "Return ONLY valid JSON in the format: { \"scenes\": [ { \"ID\": \"<uuid>\", \"Name\": \"<control name>\", \"Description\": \"<description>\", \"threat_id\": null } ] }. "
            "Do NOT include any explanation or extra text. The top-level key must be \"scenes\"."
        ),
        "cybersecurity_claims": (
            "Generate a list of cybersecurity claims for the system '{system_name}'. "
            "For each, provide a unique ID, Name, and Description. "
            "Return ONLY valid JSON in the format: { \"scenes\": [ { \"ID\": \"<uuid>\", \"Name\": \"<claim name>\", \"Description\": \"<description>\", \"threat_id\": null } ] }. "
            "Do NOT include any explanation or extra text. The top-level key must be \"scenes\"."
        ),
    }

    if artifact_type not in prompt_templates:
        raise ValueError(f"Unknown artifact type: {artifact_type}")

    prompt = prompt_templates[artifact_type].format(system_name=system_name)
    gemini_response = gemini_client.generate_content(prompt)
    content_text = gemini_client.get_text(gemini_response)
    cleaned = re.sub(r"[a-z]*", "", content_text).strip().strip("`")
    cleaned = extract_json_block(cleaned)
    try:
        return json.loads(cleaned)
    except Exception as e:
        print("Gemini Output (cleaned):", cleaned)


@modelprompt.route('/v1/generate/cybersecurity-artifacts', methods=['POST'])
def generate_cybersecurity_artifacts():
    """
    Generate and save cybersecurity requirements, controls, goals, and claims.
    """
    try:

        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form


        model_id = data.get('modelId', '')
        system_name = data.get('systemName', '')
        user_prompt = data.get('cybersecurityPrompt', '')

        if not model_id or not system_name:
            return jsonify({"error": "Missing modelId or systemName"}), 400

        default_prompt = f"""
            You are an expert in cybersecurity engineering (ISO/SAE 21434).
            Generate cybersecurity_requirements, cybersecurity_controls, cybersecurity_goals,
            and cybersecurity_claims for the system '{system_name}'.
            Return ONLY valid JSON in the format below (no explanation or extra text):
            """

        data_structure_prompt = """
            (for Data structure)
            {
            "cybersecurity_requirements": {
                "scenes": [{"ID": "<uuid>", "Name": "<requirement name>", "Description": "<description>", "threat_id": null}]
            },
            "cybersecurity_controls": {
                "scenes": [{"ID": "<uuid>", "Name": "<control name>", "Description": "<description>", "threat_id": null}]
            },
            "cybersecurity_claims": {
                "scenes": [{"ID": "<uuid>", "Name": "<claim name>", "Description": "<description>", "threat_id": null}]
            },
            "cybersecurity_goals": {
                "scenes": [{"ID": "<uuid>", "Name": "<goal name>", "Description": "<description>", "threat_id": null}]
            }
            }

            - Each section must have a "scenes" array as shown.
            - Do NOT include any explanation or extra text.
            """

        final_prompt = (user_prompt or default_prompt) + data_structure_prompt

        gemini_response = gemini_client.generate_content(final_prompt)
        content_text = gemini_client.get_text(gemini_response)

        cleaned = content_text.strip().strip("`").strip("json").strip()
        cleaned = extract_json_block(cleaned)

        try:
            all_scenes = json.loads(cleaned)
        except Exception as e:
            return jsonify({"error": f"Failed to parse Gemini response: {str(e)}", "raw": cleaned}), 500

        response = {}
        for artifact_type in [
            "cybersecurity_requirements",
            "cybersecurity_controls",
            "cybersecurity_claims",
            "cybersecurity_goals"
        ]:
            scenes_obj = all_scenes.get(artifact_type, {})
            scenes = scenes_obj.get("scenes")
            if not isinstance(scenes, list):
                return jsonify({
                    "error": f"Gemini response for {artifact_type} did not contain a 'scenes' list.",
                    "raw": scenes_obj
                }), 500

            doc = {
                "model_id": model_id,
                "type": artifact_type,
                "scenes": scenes
            }

            result = db.Cybersecurity.insert_one(doc)
            doc["_id"] = str(result.inserted_id)
            response[artifact_type] = doc

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error in generate_cybersecurity": str(e)}), 500


# Risk Treatment creation
@modelprompt.route("/v1/generate/generate-risk-treatments", methods=["POST"])
def auto_generate_risk_treatments():
    """
    Automatically generates all risk treatments for a given modelId.
    """
    try:
        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        model_id = data.get("modelId")
        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        threat_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "derived"})
        if not threat_doc:
            return jsonify({"error": f"No threat scenarios found for model {model_id}"}), 404

        details_list = threat_doc.get("Details", [])
        if not details_list:
            return jsonify({"error": "No threat scenario details found"}), 404

        generated_count = 0
        skipped_count = 0

        for threat in details_list:
            damage_id   = threat.get("rowId")
            damage_name = threat.get("damage_name")
            damage_key  = threat.get("id")

            for item in threat.get("Details", []):
                node_id   = item.get("nodeId")
                node_name = item.get("node")

                for prop in item.get("props", []):
                    if not prop.get("isSelected", False):
                        continue

                    stride_category = threat_type(prop.get("name", ""))
                    threat_key = f"TS{prop['key']:03}"

                    label = f"[{threat_key}] {stride_category} of {node_name} leads to {damage_name} [{damage_key}]"

                    with current_app.test_request_context(
                        method="POST",
                        data={
                            "nodeId": node_id,
                            "threatId": prop["id"],
                            "modelId": model_id,
                            "label": label,
                            "damageId": damage_id,
                            "key": threat_key,
                        },
                    ):
                        response = add_risk_treatment()
                        if hasattr(response, "status_code") and response.status_code == 200:
                            generated_count += 1
                        else:
                            skipped_count += 1

        return jsonify({
            "message": "Risk treatments generated successfully",
            "modelId": model_id,
            "generated_count": generated_count,
            "skipped_count": skipped_count
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 7 - Generate Full Model
@modelprompt.route('/v1/generate/full-model', methods=['POST'])
def generate_full_model():
        # Generate template
        template_response = generate_reactflow_template(standalone=True, request_data=request)
        scenario_request = {
            'modelId': template_response['model_id'],
            'systemName': template_response['system_name'],
            'template': json.dumps(template_response['template']),
            "damageScenarioPrompt": request.form.get('damageScenarioPrompt', ''),
        }

        # Generate damage scenarios
        scenarios_response = create_damage_scenarios(
            standalone=True,
            request_data=type('', (), {'form': scenario_request})()
        )
        scenarios_data = scenarios_response.get_json() if hasattr(scenarios_response, 'get_json') else scenarios_response

        # Generate threat scenarios
        threat_response = create_threat_scenarios(template_response['model_id'])
        threat_response_obj, _ = threat_response if isinstance(threat_response, tuple) else (threat_response, None)
        threat_data = threat_response_obj.get_json()

        # Risk treatment
        for threat in threat_data.get("scenarios", {}).get("Details", []):
            damage_id   = threat.get("rowId")
            damage_name = threat.get("damage_name")
            damage_key  = threat.get("id")

            for item in threat.get("Details", []):
                node_id   = item.get("nodeId")
                node_name = item.get("name")

                for prop in item.get("props", []):
                    stride_category = threat_type(prop.get("name", ""))
                    threat_key = f"TS{prop['key']:03}"
                    label = f"[{threat_key}] {stride_category} of {node_name} leads to {damage_name} [{damage_key}]"

                    with current_app.test_request_context(
                        method='POST',
                        data={
                            "nodeId": node_id,
                            "threatId": prop["id"],
                            "modelId": template_response['model_id'],
                            "label": label,
                            "damageId": damage_id,
                            "key": threat_key
                        }
                    ):
                        add_risk_treatment()

        # Prepare threatIds for derived threat scenario generation
        threat_ids = []
        for threat in threat_data.get("scenarios", {}).get("Details", []):
            for item in threat.get("Details", []):
                for prop in item.get("props", []):
                    threat_ids.append({
                        "nodeId": item["nodeId"],
                        "propId": prop["id"],
                        "rowId": threat["rowId"]
                    })

        # Generate derived threat scenarios
        derived_data = generate_derived_threat_scenarios(
            model_id=template_response['model_id'],
            threat_ids=threat_ids,
            user_prompt=request.form.get('threatScenarioPrompt', '')
        )

        # Generate attack trees
        with current_app.test_request_context(method='POST', data={'modelId': template_response['model_id'], "attackscenarioPrompt": request.form.get('attackscenarioPrompt', '')}):
            attack_response = generate_attack_tree()
            attack_tree_data = attack_response.get_json() if hasattr(attack_response, 'get_json') else {}

        with current_app.test_request_context(
            method='POST',
            data={
                "modelId": template_response['model_id'],
                "attackscenarioPrompt": request.form.get('attackscenarioPrompt', '')
            }
        ):
            possible_attacks = convert_possible_events_from_attack_trees()

        with current_app.test_request_context(
            method='POST',
            data={
                'modelId': template_response['model_id'],
                'systemName': template_response['system_name'],
                "cybersecurityPrompt": request.form.get('cybersecurityPrompt', '')
            }
        ):
            cyber_response = generate_cybersecurity_artifacts()

        with current_app.test_request_context(
            method='POST',
            data={
                "modelId": template_response['model_id'],
                "attackscenarioPrompt": request.form.get('attackscenarioPrompt', '')
            }
        ):
            attacks = generate_attacks()

        return current_app.response_class(
            response=json.dumps({
                "message": "Model Generated Successfully",
                "model": template_response,
            }, cls=JSONEncoder),
            status=201,
            mimetype='application/json'
        )


def clean_control_chars(s):
    # Remove unescaped control characters (except \n, \t if you want to keep them)
    return re.sub(r'[\x00-\x1F\x7F]', '', s)