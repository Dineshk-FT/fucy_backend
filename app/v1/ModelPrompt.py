from flask import Blueprint, request, jsonify, current_app
import ast
import json
import re
from db import db
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
from app.v1.RiskDeterminationAndTreatment import add_risk_treatment
from app.Methods.helpers import  structure_attack_tree_templates, AttackTableoptions, threat_type, safe_json_parse
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
from app.v1.rag.components import (
    resolve_ecu,
    build_enriched_query,
    stamp_uuids,
    crosslink_node_ids,
    parse_and_fix,
)
import jinja2

from dotenv import load_dotenv

# Specify the exact path to your .env file
env_path = os.path.join(os.path.dirname(__file__), '..', '..', '.env')  # Adjust path as needed
load_dotenv(env_path, override=True)  # override=True forces reload

# Or try this simpler approach:
load_dotenv(override=True)

# Now get the key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


modelprompt = Blueprint("modelprompt", __name__)


gemini_client = GeminiClient(GOOGLE_API_KEY, os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))

# Path to dataecu.json — adjust to match your project layout
ECU_DB_PATH = os.getenv("ECU_DB_PATH", "datasets/dataecu.json")

@modelprompt.route("/debug/env", methods=["GET"])
def debug_env():
    """Debug endpoint to check environment variables"""
    api_key = os.getenv("GOOGLE_API_KEY")
    return jsonify({
        "GOOGLE_API_KEY_exists": api_key is not None,
        "GOOGLE_API_KEY_length": len(api_key) if api_key else 0,
        "GOOGLE_API_KEY_preview": api_key[:10] + "..." if api_key else "Not set",
        "all_env_vars": {k: v for k, v in os.environ.items() if "KEY" in k or "API" in k}
    })

# @modelprompt.route("/test-gemini", methods=["GET"])
# def test_gemini():
#     """Test if Gemini API key is working"""
#     try:
#         response = gemini_client.generate_content("Say 'API key works!'")
#         content = gemini_client.get_text(response)
#         return jsonify({"success": True, "response": content})
#     except Exception as e:
#         return jsonify({"success": False, "error": str(e)}), 500

# @modelprompt.route("/debug/key-info", methods=["GET"])
# def debug_key_info():
#     """Get information about the API key being used"""
#     try:
#         # Try to get the project ID from the API response
#         response = gemini_client.generate_content("Tell me what project this API key belongs to")
#         content = gemini_client.get_text(response)
#         return jsonify({
#             "api_key_preview": os.getenv("GOOGLE_API_KEY", "")[:15] + "...",
#             "project_guess": content[:200] if content else "Unknown",
#             "full_response": content
#         })
#     except Exception as e:
#         error_msg = str(e)
#         # Extract project ID from error if present
#         import re
#         project_match = re.search(r'projects/(\d+)', error_msg)
#         return jsonify({
#             "api_key_preview": os.getenv("GOOGLE_API_KEY", "")[:15] + "...",
#             "error": error_msg[:500],
#             "project_id_from_error": project_match.group(1) if project_match else "Not found"
#         })


# @modelprompt.route("/debug/status", methods=["GET"])
# def debug_status():
#     """Check current configuration"""
#     return jsonify({
#         "api_key_loaded": bool(os.getenv("GOOGLE_API_KEY")),
#         "api_key_preview": os.getenv("GOOGLE_API_KEY", "")[:10] + "..." if os.getenv("GOOGLE_API_KEY") else "Not set",
#         "gemini_model": os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
#         "max_nodes_in_pipeline": 20,  # Should match pipeline.py
#         "status": "Ready" if os.getenv("GOOGLE_API_KEY") else "Missing API Key"
#     })

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


#2- Item definition prompt (COMPACT VERSION - Architecture Only)

@modelprompt.route("/v1/generate/model", methods=["POST"])
def generate_reactflow_template(standalone=False, request_data=None):
    """Generate ReactFlow template - with manual positioning, group handling, and property preservation from JSON."""
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

        # ── Imports ────────────────────────────────────────────────────────
        from app.v1.rag.components import (
            resolve_ecu as rag_resolve_ecu,
            build_enriched_query as rag_build_enriched_query,
            stamp_uuids as rag_stamp_uuids,
            crosslink_node_ids as rag_crosslink_node_ids,
        )
        from app.v1.rag.ingest import load_all_documents
        from app.v1.rag.pipeline import build_graph
        from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
        from app.Methods.new_helpers import (
            calculate_node_positions,
            recalculate_group_heights_from_children,
            position_ungrouped_nodes,
            adjust_group_sizes,
            build_basic_node,
            build_full_edge,
            generate_node_color,
            generate_edge_stroke
        )

        MAX_NODES = 14
        MAX_EDGES = 11
        MAX_GROUPS = 4

        # ── Build enriched query ───────────────────────────────────────────
        ecu_entry = rag_resolve_ecu(system_name)
        enriched_query = rag_build_enriched_query(system_name, ecu_entry)

        if dynamic_prompt_lines:
            enriched_query += f"\n\nAdditional System Details:\n{dynamic_prompt_lines}"
        if custom_prompt:
            enriched_query += f"\n\nCustom Requirements:\n{custom_prompt}"

        enriched_query += f"""
        IMPORTANT:
        - EXACTLY {MAX_NODES} component nodes
        - EXACTLY {MAX_EDGES} edges
        - Max {MAX_GROUPS} groups
        """

        # ── Run pipeline ───────────────────────────────────────────────────
        all_docs = load_all_documents()
        graph = build_graph(all_docs)

        result = graph.invoke({
            "user_query": system_name,
            "enriched_query": enriched_query,
            "documents": [],
            "architecture": {},
            "threats": [],
            "damage_details": [],
            "threat_scenarios": [],
            "attacks": [],
            "answer": "",
            "retry_count": 0,
            "full_prompt": "",
            "eval_score": 0,
            "eval_details": {}
        })

        final_answer = result.get("answer", "{}")

        try:
            tara_json = json.loads(final_answer) if isinstance(final_answer, str) else final_answer
        except Exception as e:
            raise ValueError(f"Invalid JSON from pipeline: {e}")

        # ── Extract template ───────────────────────────────────────────────
        template_data = None

        print(f"Pipeline template: ", tara_json.get("Assets", []))

        if "Assets" in tara_json and tara_json["Assets"]:
            first_asset = tara_json["Assets"][0]
            template_data = first_asset.get("template") or first_asset
        elif "template" in tara_json:
            template_data = tara_json["template"]
        elif "nodes" in tara_json:
            template_data = tara_json
        else:
            raise ValueError("Invalid response format")

        minimal_nodes = template_data.get("nodes", [])
        minimal_edges = template_data.get("edges", [])

        print(f"RAW LLM → Nodes: {len(minimal_nodes)}, Edges: {len(minimal_edges)}")

        # ── BUILD PROPERTY LOOKUP FROM FULL JSON ───────────────────────────
        full_pipeline_nodes = []
        try:
            if "Assets" in tara_json and tara_json["Assets"]:
                full_asset = tara_json["Assets"][0] if isinstance(tara_json["Assets"], list) else tara_json["Assets"]
                full_template = full_asset.get("template", {})
                full_pipeline_nodes = full_template.get("nodes", [])
                print(f"  🔍 Found {len(full_pipeline_nodes)} nodes in full pipeline JSON")
        except Exception as e:
            print(f"  ⚠️ Could not extract full pipeline nodes: {e}")

        # Create a lookup map: id -> properties from the full pipeline JSON
        pipeline_properties_map = {}
        for pn in full_pipeline_nodes:
            pn_id = pn.get("id", "")
            pn_props = pn.get("properties", None)
            if pn_id and pn_props and isinstance(pn_props, list) and len(pn_props) > 0:
                # Clean the properties - ensure they're all strings
                clean_props = []
                for p in pn_props:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", str(p))))
                    elif isinstance(p, str):
                        clean_props.append(p)
                    else:
                        clean_props.append(str(p))
                pipeline_properties_map[pn_id] = clean_props
                print(f"    📋 Pipeline ID '{pn_id}' has properties: {clean_props}")

        # Also build a label-based lookup for fallback
        pipeline_label_properties_map = {}
        for pn in full_pipeline_nodes:
            pn_label = pn.get("data", {}).get("label", "")
            pn_props = pn.get("properties", None)
            if pn_label and pn_props and isinstance(pn_props, list) and len(pn_props) > 0:
                clean_props = []
                for p in pn_props:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", str(p))))
                    elif isinstance(p, str):
                        clean_props.append(p)
                    else:
                        clean_props.append(str(p))
                pipeline_label_properties_map[pn_label] = clean_props

        # ── HARD LIMIT ON NODES AND EDGES ──────────────────────────────────
        group_nodes = [n for n in minimal_nodes if n.get("type") == "group"]
        component_nodes = [n for n in minimal_nodes if n.get("type") != "group"]

        # Limit number of groups
        group_nodes = group_nodes[:MAX_GROUPS]
        
        # Limit number of component nodes
        component_nodes = component_nodes[:MAX_NODES]
        
        # Ensure all nodes have required fields
        for node in component_nodes:
            if "data" not in node:
                node["data"] = {}
            if "label" not in node["data"] and "label" in node:
                node["data"]["label"] = node["label"]
            if "id" not in node:
                node["id"] = str(uuid.uuid4())
            if "type" not in node:
                node["type"] = "default"
            
            # ── PULL PROPERTIES FROM ORIGINAL JSON ──
            node_id = node.get("id", "")
            node_label = node.get("data", {}).get("label", "")
            
            # First check if the node already has properties
            existing_props = node.get("properties", None)
            
            if existing_props and isinstance(existing_props, list) and len(existing_props) > 0:
                # Properties already exist on the node, clean them
                clean_existing = []
                for p in existing_props:
                    if isinstance(p, dict):
                        clean_existing.append(p.get("name", p.get("value", str(p))))
                    elif isinstance(p, str):
                        clean_existing.append(p)
                    else:
                        clean_existing.append(str(p))
                node["properties"] = clean_existing
                print(f"    ✅ Node '{node_label}' has properties from template: {clean_existing}")
            else:
                # Try to get properties from the full pipeline JSON by ID
                pipeline_props = pipeline_properties_map.get(node_id, None)
                
                if pipeline_props:
                    node["properties"] = pipeline_props
                    print(f"    ✅ Pulled properties for '{node_label}' by ID: {pipeline_props}")
                else:
                    # Try label-based lookup
                    pipeline_props = pipeline_label_properties_map.get(node_label, None)
                    if pipeline_props:
                        node["properties"] = pipeline_props
                        print(f"    ✅ Pulled properties for '{node_label}' by label: {pipeline_props}")
                    else:
                        # Mark as missing - will set defaults later
                        node["_properties_missing"] = True
                        print(f"    ⚠️ No properties found for '{node_label}'")
        
        for node in group_nodes:
            if "data" not in node:
                node["data"] = {}
            if "label" not in node["data"] and "label" in node:
                node["data"]["label"] = node["label"]
            if "id" not in node:
                node["id"] = str(uuid.uuid4())
            node["type"] = "group"
            if "properties" not in node:
                node["properties"] = []
        
        final_nodes = group_nodes + component_nodes
        final_edges = minimal_edges[:MAX_EDGES]

        # ── BUILD EDGE PROPERTIES LOOKUP ──
        full_pipeline_edges = []
        try:
            if "Assets" in tara_json and tara_json["Assets"]:
                full_asset = tara_json["Assets"][0] if isinstance(tara_json["Assets"], list) else tara_json["Assets"]
                full_template = full_asset.get("template", {})
                full_pipeline_edges = full_template.get("edges", [])
        except:
            pass
        
        pipeline_edge_properties_map = {}
        for pe in full_pipeline_edges:
            pe_id = pe.get("id", "")
            pe_props = pe.get("properties", None)
            if pe_id and pe_props:
                pipeline_edge_properties_map[pe_id] = pe_props
        
        pipeline_edge_st_props_map = {}
        for pe in full_pipeline_edges:
            src = pe.get("source", "")
            tgt = pe.get("target", "")
            pe_props = pe.get("properties", None)
            if src and tgt and pe_props:
                pipeline_edge_st_props_map[f"{src}->{tgt}"] = pe_props

        print(f"AFTER TRIM → Nodes: {len(final_nodes)}, Edges: {len(final_edges)}")

        # ── MANUAL POSITIONING AND GROUP HANDLING ───────────────────────────
        print("\n" + "="*60)
        print("APPLYING MANUAL POSITIONING AND GROUP HANDLING")
        print("="*60)
        
        # Step 1: Ensure parent-child relationships are preserved
        print("  🔗 Step 1: Building parent-child relationships...")
        group_ids = {n.get("id") for n in final_nodes if n.get("type") == "group"}
        
        for node in final_nodes:
            if node.get("type") != "group":
                parent_candidates = [g for g in final_nodes if g.get("type") == "group"]
                
                if node.get("parentId") and node["parentId"] in group_ids:
                    pass
                elif parent_candidates and not node.get("parentId"):
                    node_label = node.get("data", {}).get("label", "").lower()
                    for group in parent_candidates:
                        group_label = group.get("data", {}).get("label", "").lower()
                        if group_label and (group_label in node_label or node_label in group_label):
                            node["parentId"] = group.get("id")
                            print(f"    Assigned {node.get('id')} to group {group.get('id')}")
                            break
        
        # Step 2: Calculate positions with proper group containment
        print("  📍 Step 2: Calculating positions with group containment...")
        positioned_nodes = calculate_node_positions(final_nodes, final_edges)
        
        # Step 3: Verify all children are inside their parent groups
        print("  🔍 Step 3: Verifying children are inside parent groups...")
        group_map = {n.get("id"): n for n in positioned_nodes if n.get("type") == "group"}
        
        for node in positioned_nodes:
            if node.get("type") != "group" and node.get("parentId"):
                parent = group_map.get(node["parentId"])
                if parent:
                    parent_x = parent.get("position", {}).get("x", 0)
                    parent_y = parent.get("position", {}).get("y", 0)
                    parent_w = parent.get("width", 800)
                    parent_h = parent.get("height", 500)
                    
                    node_x = node.get("position", {}).get("x", 0)
                    node_y = node.get("position", {}).get("y", 0)
                    node_w = node.get("width", 150)
                    node_h = node.get("height", 60)
                    
                    if (node_x < parent_x or node_x + node_w > parent_x + parent_w or
                        node_y < parent_y or node_y + node_h > parent_y + parent_h):
                        print(f"    ⚠️ Node {node.get('id')} is outside its parent group! Repositioning...")
                        padding = 30
                        rel_x = padding + ((node_x - parent_x) % (parent_w - node_w - 2*padding)) if parent_w > node_w + 2*padding else padding
                        rel_y = padding + ((node_y - parent_y) % (parent_h - node_h - 2*padding)) if parent_h > node_h + 2*padding else padding
                        node["position"] = {"x": parent_x + rel_x, "y": parent_y + rel_y}
                        node["positionAbsolute"] = node["position"].copy()
                        print(f"    Repositioned to {node['position']}")
        
        # Step 4: Adjust group sizes based on children
        print("  📦 Step 4: Adjusting group sizes based on children...")
        positioned_nodes = recalculate_group_heights_from_children(positioned_nodes)
        
        # Step 5: Position any remaining ungrouped nodes
        print("  🔧 Step 5: Positioning ungrouped nodes...")
        positioned_nodes = position_ungrouped_nodes(positioned_nodes, final_edges)
        
        # Step 6: Final pass to adjust group sizes again
        print("  📐 Step 6: Final group size adjustment...")
        positioned_nodes = adjust_group_sizes(positioned_nodes)
        
        # Step 7: Apply styling and SET FINAL PROPERTIES
        print("  🎨 Step 7: Applying styling and setting properties...")
        
        VALID_CYBER_PROPS = {"Integrity", "Confidentiality", "Authenticity", 
                             "Authorization", "Availability", "Non-repudiation"}
        DEFAULT_COMPONENT_PROPERTIES = ["Integrity", "Confidentiality", "Authenticity", 
                                         "Authorization", "Availability", "Non-repudiation"]
        DEFAULT_EDGE_PROPERTIES = ["Integrity"]
        DEFAULT_GROUP_PROPERTIES = []
        
        for node in positioned_nodes:
            node_type = node.get("type", "default")
            is_group = node_type == "group"
            
            # Set default dimensions if missing
            if is_group:
                if "width" not in node:
                    node["width"] = 800
                if "height" not in node:
                    node["height"] = 500
            else:
                if "width" not in node:
                    node["width"] = 150
                if "height" not in node:
                    node["height"] = 60
            
            # Generate random colors
            colors = generate_node_color(node_type)
            
            # Ensure data object exists
            if "data" not in node:
                node["data"] = {}
            
            # Set label if missing
            if "label" not in node["data"]:
                node["data"]["label"] = node.get("id", "Node")
            
            # Set nodeId
            node["data"]["nodeId"] = node.get("id")
            
            # ── FINAL PROPERTIES RESOLUTION ──
            node_label = node.get("data", {}).get("label", node.get("id", "unknown"))
            raw_properties = node.get("properties", None)
            was_missing = node.pop("_properties_missing", False)
            
            if is_group:
                final_properties = DEFAULT_GROUP_PROPERTIES
                print(f"    📦 Group '{node_label}': {final_properties}")
            elif raw_properties is not None and isinstance(raw_properties, list):
                # ✅ FIX: Explicitly check for len == 0 and preserve the empty list
                if len(raw_properties) == 0:
                    final_properties = []
                    source = "pipeline" if not was_missing else "pipeline (late binding)"
                    print(f"    ✅ Component '{node_label}' [{source}] preserved empty properties: {final_properties}")
                else:
                    # Clean up the properties - preserve exactly what came from pipeline
                    clean_props = []
                    for p in raw_properties:
                        if isinstance(p, dict):
                            prop_name = p.get("name") or p.get("value") or p.get("property") or str(p)
                            clean_props.append(str(prop_name))
                        elif isinstance(p, str):
                            clean_props.append(p)
                        else:
                            clean_props.append(str(p))
                    
                    # Remove duplicates while preserving order
                    seen = set()
                    unique_props = []
                    for p in clean_props:
                        if p not in seen:
                            seen.add(p)
                            unique_props.append(p)
                    
                    # Filter to only valid cybersecurity properties
                    filtered_props = [p for p in unique_props if p in VALID_CYBER_PROPS]
                    
                    if filtered_props:
                        final_properties = filtered_props
                        source = "pipeline" if not was_missing else "pipeline (late binding)"
                        print(f"    ✅ Component '{node_label}' [{source}]: {final_properties}")
                    else:
                        # Empty or invalid - use defaults only for components
                        final_properties = DEFAULT_COMPONENT_PROPERTIES
                        print(f"    ⚠️ Component '{node_label}' has no valid props, using defaults: {final_properties}")
            else:
                # Properties was None (truly missing)
                final_properties = DEFAULT_COMPONENT_PROPERTIES
                print(f"    ⚠️ Component '{node_label}' has NO props (None), using defaults: {final_properties}")
            
            node["properties"] = final_properties
            
            # Set style with random colors
            node["data"]["style"] = {
                "backgroundColor": colors["backgroundColor"],
                "borderColor": "#999999" if is_group else "#555555",
                "borderStyle": "dashed" if is_group else "solid",
                "borderWidth": "1px" if is_group else "2px",
                "color": colors["color"],
                "fontFamily": "Inter",
                "fontSize": "14px" if is_group else "12px",
                "fontStyle": "normal",
                "fontWeight": 600 if is_group else 500,
                "height": node["height"],
                "textAlign": "center",
                "textDecoration": "none",
                "width": node["width"]
            }
            
            if is_group:
                node["zIndex"] = 0
            elif node.get("parentId"):
                node["zIndex"] = 1
            else:
                node["zIndex"] = 2
            
            node["dragging"] = False
            node["selected"] = False
            node["resizing"] = False
            node["isAsset"] = False
            
            if "position" in node and "positionAbsolute" not in node:
                node["positionAbsolute"] = node["position"].copy()
        
        # Step 8: Process edges with properties
        print("  🔗 Step 8: Processing edges...")
        valid_node_ids = {n.get("id") for n in positioned_nodes}
        
        processed_edges = []
        for edge in final_edges:
            source_id = edge.get("source")
            target_id = edge.get("target")
            
            if source_id not in valid_node_ids or target_id not in valid_node_ids:
                print(f"    ⚠️ Skipping edge {source_id} → {target_id} (node not found)")
                continue
            
            edge_label = edge.get("label", edge.get("data", {}).get("label", ""))
            if not edge_label:
                edge_label = edge.get("name", "Connection")
            
            edge_id = edge.get("id", "")
            edge_key = f"{source_id}->{target_id}"
            
            # Pull edge properties
            edge_props = None
            
            if edge_id and edge_id in pipeline_edge_properties_map:
                edge_props = pipeline_edge_properties_map[edge_id]
            elif edge_key in pipeline_edge_st_props_map:
                edge_props = pipeline_edge_st_props_map[edge_key]
            elif "properties" in edge and edge["properties"] is not None:
                edge_props = edge.get("properties")
            
            # ✅ FIX: Explicitly preserve explicitly empty edge lists
            if edge_props is not None and isinstance(edge_props, list):
                if len(edge_props) == 0:
                    final_edge_props = []
                else:
                    clean_edge_props = []
                    for p in edge_props:
                        if isinstance(p, dict):
                            clean_edge_props.append(p.get("name", p.get("value", "Integrity")))
                        else:
                            clean_edge_props.append(str(p))
                    final_edge_props = [p for p in clean_edge_props if p in VALID_CYBER_PROPS]
                    if not final_edge_props:
                        final_edge_props = DEFAULT_EDGE_PROPERTIES
            else:
                final_edge_props = DEFAULT_EDGE_PROPERTIES
            
            stroke_color = generate_edge_stroke()
            
            full_edge = {
                "id": f"reactflow__edge-{source_id}b-{target_id}right",
                "source": source_id,
                "target": target_id,
                "sourceHandle": "b",
                "targetHandle": "right",
                "type": "step",
                "animated": True,
                "selected": False,
                "properties": final_edge_props,
                "data": {
                    "label": edge_label,
                    "offset": 0,
                    "t": 0.5
                },
                "markerEnd": {
                    "color": stroke_color,
                    "height": 18,
                    "type": "arrowclosed",
                    "width": 18
                },
                "markerStart": {
                    "color": stroke_color,
                    "height": 18,
                    "orient": "auto-start-reverse",
                    "type": "arrowclosed",
                    "width": 18
                },
                "style": {
                    "end": True,
                    "start": True,
                    "stroke": stroke_color,
                    "strokeDasharray": "0",
                    "strokeWidth": 2
                }
            }
            
            processed_edges.append(full_edge)
        
        # Final verification
        components_inside_groups = [n for n in positioned_nodes if n.get("type") != "group" and n.get("parentId")]
        components_outside = [n for n in positioned_nodes if n.get("type") != "group" and not n.get("parentId")]
        
        print(f"\n  ✅ Final Layout Summary:")
        print(f"     Groups: {len([n for n in positioned_nodes if n.get('type') == 'group'])}")
        print(f"     Components inside groups: {len(components_inside_groups)}")
        print(f"     Components outside groups: {len(components_outside)}")
        print(f"     Edges: {len(processed_edges)}")
        
        print(f"\n  📋 Final Properties:")
        for node in positioned_nodes:
            node_label = node.get("data", {}).get("label", node.get("id"))
            node_props = node.get("properties", [])
            print(f"     • {node_label}: {node_props}")
        print("="*60 + "\n")

        final_template = {
            "nodes": positioned_nodes,
            "edges": processed_edges,
        }

        # ── Derivations & Details ──────────────────────────────────────────
        derivations_from_pipeline = []
        details_from_pipeline = []

        if "Assets" in tara_json and tara_json["Assets"]:
            first_asset = tara_json["Assets"][0]
            derivations_from_pipeline = first_asset.get("Derivations", [])
            details_from_pipeline = first_asset.get("Details", [])

        if not derivations_from_pipeline and not details_from_pipeline:
            derivations_from_pipeline, details_from_pipeline = getDerivationsAndDetails(final_template, {})

        # ── Store DB ───────────────────────────────────────────────────────
        from datetime import datetime

        current = datetime.now()

        model_doc = {
            "name": system_name,
            "template": [],
            "created_by": created_by,
            "created_at": current,
            "last_updated": current,
            "user_id": user_id,
            "status": 1,
            "type": "model",
        }

        result_model = db.Models.insert_one(model_doc)
        model_id = str(result_model.inserted_id)

        asset_result = db.Assets.insert_one({
            "model_id": model_id,
            "template": final_template,
            "asset_name": f"{system_name}-asset",
            "asset_properties": "",
            "Details": details_from_pipeline,
        })
        asset_id = str(asset_result.inserted_id)
        db.Damage_scenarios.update_one(
            {"model_id": model_id, "type": "Derived"},
            {
                "$set": {
                    "model_id": model_id,
                    "type": "Derived",
                    "Derivations": derivations_from_pipeline,
                    "Details": details_from_pipeline,
                }
            },
            upsert=True,
        )

        result_data = {
            "message": "Generated successfully (with properties from pipeline JSON)",
            "model_id": model_id,
            "asset_id": asset_id,
            "template": final_template,
            "system_name": system_name,
            "derivations": derivations_from_pipeline,
            "details": details_from_pipeline,
            "positioning_stats": {
                "total_nodes": len(positioned_nodes),
                "group_nodes": len([n for n in positioned_nodes if n.get("type") == "group"]),
                "component_nodes": len([n for n in positioned_nodes if n.get("type") != "group"]),
                "edges": len(processed_edges)
            }
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
        return jsonify({"error": str(e)}), 500

#3 - Damage scenario creation
def generate_object_id():
    """Generate MongoDB-style ObjectId"""
    return ''.join(random.choices(string.hexdigits.lower(), k=24))

# Wrapper Flask endpoint
@modelprompt.route('/v1/generate/damage-scenarios', methods=['POST'])
def create_damage_scenarios_with_rag(standalone=False, request_data=None):
    """Generate damage scenarios using RAG-enhanced prompts - stores as User-defined type only"""
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

        # ✅ FIX: Fetch reference data and FORCE bms_1.json explicitly first
        from app.v1.rag.components import resolve_ecu, resolve_reference_report
        from app.v1.rag.azure_client import get_azure_client
        from app.v1.rag.config import AZURE_PATHS
        
        client = get_azure_client()
        reference_data = None
        
        # 1. First explicitly try to pull bms_1.json from REPORTS_DB
        try:
            reports_path = AZURE_PATHS["REPORTS_PATH"].rstrip('/')
            bms_1_blob = f"{reports_path}/bms_1.json"
            print(f"  🔍 Attempting to explicitly pull reference: {bms_1_blob}")
            bms_1_data = client.download_json(bms_1_blob)
            
            if bms_1_data:
                reference_data = bms_1_data
                print("  ✅ Successfully pulled existing damage scenes from bms_1.json")
        except Exception as e:
            print(f"  ⚠️ Could not pull bms_1.json explicitly: {e}")

        # 2. Fallback: if bms_1.json isn't found, do the standard fuzzy match
        if not reference_data:
            ecu_entry = resolve_ecu(system_name)
            reference_data = resolve_reference_report(ecu_entry, system_name)
        
        valid_node_labels = {node.get("data", {}).get("label", "").lower().strip(): node.get("id") 
                            for node in template.get("nodes", []) if node.get("type") != "group"}

        # Fallback: first available non-group node
        _fallback_label = next(iter(valid_node_labels), None)
        _fallback_id    = valid_node_labels.get(_fallback_label) if _fallback_label else None

        def _match_node(node_name: str):
            """Exact → substring → word-overlap matching against current architecture."""
            if not node_name:
                return None, None
            nl = node_name.lower().strip()
            if nl in valid_node_labels:
                return valid_node_labels[nl], nl
            for label, nid in valid_node_labels.items():
                if nl in label or label in nl:
                    return nid, label
            # Word-level overlap
            nw = set(nl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
            best_score, best = 0, None
            for label, nid in valid_node_labels.items():
                lw = set(label.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
                score = len(nw & lw)
                if score > best_score:
                    best_score, best = score, (nid, label)
            if best and best_score > 0:
                return best
            return None, None

        existing_scenarios = []
        if reference_data and "Damage_scenarios" in reference_data:
            for ds_block in reference_data["Damage_scenarios"]:
                scenarios_to_process = []
                # Handle varying JSON schema structures gracefully
                if ds_block.get("type") == "User-defined":
                    scenarios_to_process = ds_block.get("Details", [])
                elif "Name" in ds_block and "cyberLosses" in ds_block:
                    scenarios_to_process = [ds_block]

                for detail in scenarios_to_process:
                    detail_copy = json.loads(json.dumps(detail))
                    remapped_losses = []

                    for loss in detail_copy.get("cyberLosses", []):
                        node_name = loss.get("node", "")
                        matched_nid, matched_label = _match_node(node_name)

                        if matched_nid:
                            loss["nodeId"] = matched_nid
                            loss["node"]   = matched_label
                        elif _fallback_id:
                            # Fallback — never silently drop a loss
                            loss["nodeId"] = _fallback_id
                            loss["node"]   = _fallback_label
                            print(f"  ⚠️  No match for '{node_name}' — assigned to fallback '{_fallback_label}'")

                        loss["id"] = str(uuid.uuid4())
                        remapped_losses.append(loss)

                    # KEY FIX: ALWAYS include every reference scenario
                    if remapped_losses:
                        detail_copy["cyberLosses"] = remapped_losses
                    detail_copy["_id"] = str(uuid.uuid4())
                    existing_scenarios.append(detail_copy)

        print(f"✅ Found {len(existing_scenarios)} valid existing damage scenarios from reference.")

        # ── Build User-defined Damage Scenarios using the prompt ──
        
        from app.v1.rag.prompt import DAMAGE_PROMPT
        import jinja2
        
        # Render the DAMAGE_PROMPT template
        tmpl = jinja2.Template(DAMAGE_PROMPT)
        base_prompt = tmpl.render(
            architecture=json.dumps({"template": template}, indent=2)
        )
        
        # Add user/custom prompts
        additional_instructions = ""
        
        if user_prompt:
            additional_instructions += f"\n\n### ADDITIONAL USER REQUIREMENTS:\n{user_prompt}\n"
        
        if custom_prompt:
            additional_instructions += f"\n\n### CUSTOM REQUIREMENTS:\n{custom_prompt}\n"
        
        if dynamic_prompt_lines:
            additional_instructions += f"\n\n### ADDITIONAL SYSTEM DETAILS:\n{dynamic_prompt_lines}\n"
            
        # ✅ FIX: Provide existing scenarios to Gemini so it only generates extras
        if existing_scenarios:
            additional_instructions += f"\n\n### EXISTING SCENARIOS (DO NOT REGENERATE THESE):\n{json.dumps(existing_scenarios, indent=2)}\n\n"
            target_extras = max(3, 10 - len(existing_scenarios))
            additional_instructions += f"Generate {target_extras} EXTRA damage scenarios covering different components. Return ONLY the new scenarios in your JSON output.\n"
        
        # Combine the prompt
        final_prompt = base_prompt + additional_instructions

        print("\n" + "="*80)
        print("FINAL PROMPT (first 1500 chars):")
        print("="*80)
        print(final_prompt[:1500] + "..." if len(final_prompt) > 1500 else final_prompt)
        print("="*80 + "\n")

        # Save prompt for debugging
        try:
            with open("damage_scenario_prompt.txt", "w", encoding="utf-8") as f:
                f.write(final_prompt)
            print("✅ Damage scenario prompt saved to damage_scenario_prompt.txt")
        except Exception as e:
            print(f"Could not save prompt: {e}")

        # ── Call Gemini using the RAG generator from pipeline ──
        from app.v1.rag.pipeline import setup as pipeline_setup
        from app.v1.rag.ingest import load_all_documents
        
        print("Loading documents and calling Gemini with RAG context...")
        all_docs = load_all_documents()
        retriever, generator, text_embedder = pipeline_setup(all_docs)
        
        # Retrieve relevant documents for context
        embedding = text_embedder.run(text=system_name)["embedding"]
        retrieval_result = retriever.run(query_embedding=embedding)
        retrieved_docs = retrieval_result["documents"][:3]  # Top 3 documents
        
        # Add retrieved documents context to prompt
        doc_context = "\n\n### RETRIEVED REFERENCE DOCUMENTS:\n"
        for doc in retrieved_docs:
            content = getattr(doc, 'content', str(doc))[:1500]  # Limit content length
            source = getattr(doc, 'meta', {}).get('source', 'Unknown')
            doc_context += f"\n---\nSource: {source}\n{content}\n---\n"
        
        final_prompt_with_context = final_prompt + doc_context
        
        print("Calling Gemini API...")
        result = generator.run(parts=[final_prompt_with_context])
        output = result["replies"][0] if result["replies"] else "{}"
        
        # Clean markdown fences
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")
        cleaned = re.sub(r'//.*', '', cleaned)
        
        # Fix common JSON issues
        cleaned = re.sub(r',\s*}', '}', cleaned)
        cleaned = re.sub(r',\s*]', ']', cleaned)

        # Parse JSON - expect { "type": "User-defined", "Details": [...] }
        try:
            # Try to extract JSON if there's extra text
            json_match = re.search(r'\{.*\}(?=\s*$|\s*\[)', cleaned, re.DOTALL)
            if json_match:
                cleaned = json_match.group(0)
            
            damage_data = json.loads(cleaned)
            
            # Extract Details array
            user_defined_details = []
            
            if "Details" in damage_data:
                user_defined_details = damage_data["Details"]
            elif "type" in damage_data and damage_data["type"] == "User-defined":
                user_defined_details = damage_data.get("Details", [])
            elif isinstance(damage_data, list):
                user_defined_details = damage_data
            else:
                # Try to find Details anywhere
                for key, value in damage_data.items():
                    if isinstance(value, list) and len(value) > 0:
                        if isinstance(value[0], dict) and "Name" in value[0]:
                            user_defined_details = value
                            break
            
            print(f"✅ Extracted {len(user_defined_details)} EXTRA damage scenarios from response")
            
            if not user_defined_details and not existing_scenarios:
                raise ValueError("No Details array found in response")
            
        except (json.JSONDecodeError, ValueError) as e:
            print(f"❌ Failed to parse response: {e}")
            print(f"Raw output: {cleaned[:500]}")
            
            if existing_scenarios:
                print("⚠️ Falling back exclusively to existing reference scenarios due to LLM failure.")
                user_defined_details = []
            else:
                return jsonify({
                    "error": "Failed to generate valid damage scenarios",
                    "details": str(e),
                    "raw_response": cleaned[:1000]
                }), 500

        # ── Validate and enhance each detail ──
        valid_node_ids = {node.get("id") for node in template.get("nodes", [])}
        valid_node_labels = {node.get("data", {}).get("label"): node.get("id") 
                            for node in template.get("nodes", [])}
        
        validated_details = []
        for i, detail in enumerate(user_defined_details):
            if not isinstance(detail, dict):
                continue
                
            # Ensure required fields
            if "Name" not in detail or not detail["Name"]:
                continue
            
            if "Description" not in detail or not detail["Description"]:
                continue
            
            # Ensure cyberLosses
            if "cyberLosses" not in detail or not detail["cyberLosses"]:
                continue
            
            # Validate and fix nodeIds in cyberLosses
            validated_losses = []
            for loss in detail.get("cyberLosses", []):
                if not isinstance(loss, dict):
                    continue
                    
                loss_node_id = loss.get("nodeId", "")
                loss_node_name = loss.get("node", "")
                
                # Check if nodeId is valid
                if loss_node_id not in valid_node_ids:
                    # Try to find by label
                    if loss_node_name in valid_node_labels:
                        loss["nodeId"] = valid_node_labels[loss_node_name]
                        loss["node"] = loss_node_name
                        validated_losses.append(loss)
                    else:
                        # Try partial match
                        found = False
                        for label, nid in valid_node_labels.items():
                            if loss_node_name.lower() in label.lower() or label.lower() in loss_node_name.lower():
                                loss["nodeId"] = nid
                                loss["node"] = label
                                validated_losses.append(loss)
                                found = True
                                break
                        if not found:
                            print(f"Scenario {i+1}: Cannot find node '{loss_node_name}' in architecture. Dropping cyberLoss.")
                else:
                    validated_losses.append(loss)
            
            detail["cyberLosses"] = validated_losses
            
            # Ensure impacts
            if "impacts" not in detail:
                detail["impacts"] = {
                    "Financial Impact": "Moderate",
                    "Safety Impact": "Moderate",
                    "Operational Impact": "Moderate",
                    "Privacy Impact": "Negligible"
                }
            
            # Ensure each cyberLoss has required fields
            for loss in detail["cyberLosses"]:
                if "id" not in loss or not loss["id"]:
                    loss["id"] = str(uuid.uuid4())
                if "is_risk_added" not in loss:
                    loss["is_risk_added"] = False
                if "isSelected" not in loss:
                    loss["isSelected"] = True
            
            # Add required fields
            if "_id" not in detail:
                detail["_id"] = str(uuid.uuid4())
            
            validated_details.append(detail)
        
        print(f"✅ Validated {len(validated_details)} extra damage scenarios")

        # ✅ FIX: Combine existing scenarios with the newly generated extras
        combined_details = existing_scenarios + validated_details
        
        # Safely re-key them sequentially
        for i, detail in enumerate(combined_details):
            detail["key"] = i + 1

        print(f"✅ Total Damage Scenarios to save: {len(combined_details)}")

        # ── Store in database as "User-defined" type only ──
        from datetime import datetime
        
        current_time = datetime.now()
        
        existing = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        
        if existing:
            result = db.Damage_scenarios.update_one(
                {"model_id": model_id, "type": "User-defined"},
                {
                    "$set": {
                        "Details": combined_details,
                        "last_updated": current_time
                    }
                }
            )
            operation = "updated"
            scenario_id = str(existing["_id"])
        else:
            damage_doc = {
                "model_id": model_id,
                "type": "User-defined",
                "Details": combined_details,
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
            "Details": combined_details
        })

        result_data = {
            "message": f"Damage scenarios {operation} successfully",
            "scenario_id": scenario_id,
            "model_id": model_id,
            "scenarios": safe_scenarios,
            "stats": {
                "total_scenarios": len(combined_details),
                "pulled_from_reference": len(existing_scenarios),
                "generated_extras": len(validated_details)
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


# Helper function to extract JSON from text (implement based on your needs)
def extract_json_from_text(text):
    """
    Extract JSON from text that might contain markdown or other formatting.
    """
    if not text:
        return "{}"
    
    # Remove markdown code blocks
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*', '', text)
    
    # Find JSON object or array
    json_match = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
    if json_match:
        return json_match.group(1)
    
    return text



def group_threats_by_node(threat_ids):
    grouped = defaultdict(list)
    for threat in threat_ids:
        key = threat['nodeId']
        grouped[key].append(threat)
    return grouped

def generate_single_derived_scenario(threat_group, user_prompt=None, max_retries=2, generator=None, doc_context="", dynamic_prompt_lines="", custom_prompt=""):
    """
    Generate a derived threat scenario name + description from a group of threats.
    If user_prompt is provided, it replaces the intro part of the prompt.
    Includes retry logic for JSON parsing failures.
    """
    
    default_intro = f"""
        You are a cybersecurity expert. Based on the following related threats, generate a meaningful name and a concise description for a derived threat scenario. Do not use generic names like "Derived Threat Scenario".

        Here are the threats:
        {json.dumps(threat_group, indent=2)}
        """

    prompt_intro = user_prompt if user_prompt else default_intro
    
    additional_instructions = ""
    if custom_prompt:
        additional_instructions += f"\n\n### CUSTOM REQUIREMENTS:\n{custom_prompt}\n"
    if dynamic_prompt_lines:
        additional_instructions += f"\n\n### ADDITIONAL SYSTEM DETAILS:\n{dynamic_prompt_lines}\n"

    for attempt in range(max_retries + 1):
        try:
            prompt = f"""
                {prompt_intro}
                {additional_instructions}
                {doc_context}

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

            if generator:
                result = generator.run(parts=[prompt])
                content_text = result["replies"][0] if result["replies"] else "{}"
            else:
                gemini_response = gemini_client.generate_content(prompt)
                content_text = gemini_client.get_text(gemini_response)

            # Clean and parse JSON
            cleaned = extract_json_from_text(content_text)
            cleaned = re.sub(r'[\x00-\x1F\x7F]', '', cleaned)
            cleaned = cleaned.strip()
            
            # Remove markdown code blocks if present
            if cleaned.startswith("```"):
                cleaned = re.sub(r'^```\w*\n?', '', cleaned)
                cleaned = re.sub(r'\n?```$', '', cleaned)
            
            # Fix common JSON issues
            cleaned = re.sub(r',\s*}', '}', cleaned)  # Remove trailing commas in objects
            cleaned = re.sub(r',\s*]', ']', cleaned)  # Remove trailing commas in arrays
            cleaned = re.sub(r'([{,])\s*\'', r'\1"', cleaned)  # Replace single quotes with double quotes
            cleaned = re.sub(r'\'\s*:', '":', cleaned)  # Fix keys with single quotes
            
            # Try to extract JSON if there's extra text
            json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
            if json_match:
                cleaned = json_match.group(0)
            
            parsed = json.loads(cleaned)

            # Ensure description is a string
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
            
        except (json.JSONDecodeError, ValueError, AttributeError) as e:
            if attempt < max_retries:
                print(f"⚠️ Attempt {attempt + 1} failed for JSON parsing. Retrying...")
                print(f"   Error: {str(e)}")
                print(f"   Raw text preview: {content_text[:200]}...")
                # Modify prompt for retry to emphasize JSON format
                user_prompt = f"""
                    {prompt_intro}
                    
                    IMPORTANT: You MUST return ONLY valid JSON. No markdown, no extra text, no explanations.
                    The response must be exactly in this format:
                    {{"name": "Your scenario name here", "description": "Your description here"}}
                    
                    Previous attempt failed with error: {str(e)}
                    Make sure your response is valid JSON with no trailing commas or unescaped characters.
                """
                continue
            else:
                print("⚠️ Failed to parse Gemini response after all retries. Raw text:\n", content_text)
                # Return a fallback instead of raising exception
                return {
                    "name": "Generated Derived Threat",
                    "description": f"Derived from {len(threat_group)} related threats. (Auto-generated due to parsing error)"
                }


# In ModelPrompt.py, replace generate_derived_threat_scenarios function

def generate_derived_threat_scenarios(model_id, threat_ids, name="", description="", user_prompt=None, system_name="", dynamic_prompt_lines="", custom_prompt=""):
    """
    Generate derived threat scenarios.
    Pulls existing scenes from reference JSON, generates extras via LLM.
    No fallbacks - if LLM fails, report the failure.
    """
    details = []
    
    if name or description:
        # User provided explicit name/description
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
        try:
            grouped = group_threats_by_node(threat_ids)
            print(f"[INFO] Grouped {len(threat_ids)} threats into {len(grouped)} groups")
            
            # ── Pull existing derived scenarios from reference ──
            existing_derived_map = {}
            unmapped_ref_threats = []
            current_node_label_to_id = {}
            
            try:
                asset_doc = db.Assets.find_one({"model_id": model_id})
                if asset_doc and "template" in asset_doc:
                    for n in asset_doc["template"].get("nodes", []):
                        if n.get("type") != "group":
                            lbl = n.get("data", {}).get("label", "").lower()
                            if lbl:
                                current_node_label_to_id[lbl] = n.get("id")
            except Exception as e:
                print(f"[WARNING] Could not fetch current architecture nodes: {e}")
                
            if system_name:
                try:
                    from app.v1.rag.azure_client import get_azure_client
                    from app.v1.rag.config import AZURE_PATHS
                    
                    client = get_azure_client()
                    reference_data = None
                    
                    # Try to pull bms_1.json first
                    try:
                        reports_path = AZURE_PATHS["REPORTS_PATH"].rstrip('/')
                        bms_1_blob = f"{reports_path}/bms_1.json"
                        print(f"  🔍 Pulling reference: {bms_1_blob}")
                        bms_1_data = client.download_json(bms_1_blob)
                        
                        if bms_1_data:
                            reference_data = bms_1_data
                            print("  ✅ Loaded bms_1.json")
                    except Exception as e:
                        print(f"  ⚠️ Could not pull bms_1.json: {e}")

                    if not reference_data:
                        from app.v1.rag.components import resolve_ecu, resolve_reference_report
                        ecu_entry = resolve_ecu(system_name)
                        reference_data = resolve_reference_report(ecu_entry, system_name)
                    
                    if reference_data:
                        # Build ref_id_to_label map
                        ref_id_to_label = {}
                        ref_assets = reference_data.get("Assets", [])
                        if ref_assets:
                            ref_asset = ref_assets[0] if isinstance(ref_assets, list) else ref_assets
                            for n in ref_asset.get("template", {}).get("nodes", []):
                                if n.get("type") != "group":
                                    ref_id_to_label[n.get("id")] = n.get("data", {}).get("label", "").lower()
                        
                        # Extract existing derived scenes from reference Threat_scenarios
                        for ts_block in reference_data.get("Threat_scenarios", []):
                            ts_type = ts_block.get("type", "")
                            
                            if ts_type in ["User-defined", "derived", "Derived"]:
                                ref_details = ts_block.get("Details", [])
                                
                                for ref_dt in ref_details:
                                    ref_name = ref_dt.get("name", ref_dt.get("Name", ""))
                                    ref_desc = ref_dt.get("description", ref_dt.get("Description", ""))
                                    
                                    # Skip auto-generated derivations (loss of Integrity, etc.)
                                    skip_keywords = ["loss of", "ds due to", "check for ds"]
                                    if not ref_name or not ref_desc or any(kw in ref_name.lower() for kw in skip_keywords):
                                        continue
                                    
                                    ref_threats = ref_dt.get("threat_ids", [])
                                    ref_node_id = None
                                    
                                    if ref_threats and isinstance(ref_threats, list) and len(ref_threats) > 0:
                                        first_threat = ref_threats[0]
                                        if isinstance(first_threat, dict):
                                            ref_node_id = first_threat.get("nodeId", "")
                                        elif isinstance(first_threat, str):
                                            ref_node_id = first_threat
                                    
                                    ref_label = ref_id_to_label.get(ref_node_id, "") if ref_node_id else ""
                                    
                                    mapped = False
                                    if ref_label and ref_label in current_node_label_to_id:
                                        current_node_id = current_node_label_to_id[ref_label]
                                        if current_node_id not in existing_derived_map:
                                            existing_derived_map[current_node_id] = {
                                                "name": ref_name,
                                                "description": ref_desc,
                                                "threat_ids": ref_threats
                                            }
                                            mapped = True
                                            print(f"  ✅ Mapped: {ref_name} -> {ref_label}")
                                    
                                    if not mapped and ref_name and ref_desc:
                                        unmapped_ref_threats.append({
                                            "name": ref_name,
                                            "description": ref_desc,
                                            "threat_ids": ref_threats
                                        })
                        
                        print(f"  📋 Found {len(existing_derived_map)} mapped, {len(unmapped_ref_threats)} unmapped reference scenes")
                        
                except Exception as e:
                    print(f"[WARNING] Failed to process reference data: {e}")
            
            # ── Assign scenarios to threat groups ──
            for group_key, group in grouped.items():
                try:
                    # 1. Try exact node-mapped scenario
                    if group_key in existing_derived_map:
                        ref_dt = existing_derived_map[group_key]
                        derived = {
                            "name": ref_dt["name"],
                            "description": ref_dt["description"],
                            "id": str(uuid.uuid4()),
                            "threat_ids": group
                        }
                        details.append(derived)
                        print(f"[SUCCESS] Reused: {derived['name']}")
                    
                    # 2. Try unmapped pool
                    elif unmapped_ref_threats:
                        ref_dt = unmapped_ref_threats.pop(0)
                        derived = {
                            "name": ref_dt["name"],
                            "description": ref_dt["description"],
                            "id": str(uuid.uuid4()),
                            "threat_ids": group
                        }
                        details.append(derived)
                        print(f"[SUCCESS] Reused (Fallback): {derived['name']}")
                    
                    # 3. Generate extra via LLM
                    else:
                        print(f"[INFO] Generating EXTRA via LLM for group: {group_key}")
                        
                        # Set up RAG context for generation
                        doc_context = ""
                        generator = None
                        
                        try:
                            from app.v1.rag.pipeline import setup as pipeline_setup
                            from app.v1.rag.ingest import load_all_documents
                            
                            all_docs = load_all_documents()
                            retriever, generator, text_embedder = pipeline_setup(all_docs)
                            
                            if system_name:
                                embedding = text_embedder.run(text=system_name)["embedding"]
                                retrieval_result = retriever.run(query_embedding=embedding)
                                retrieved_docs = retrieval_result["documents"][:3]
                                
                                doc_context = "\n\n### RETRIEVED REFERENCE DOCUMENTS:\n"
                                for doc in retrieved_docs:
                                    content = getattr(doc, 'content', str(doc))[:1500]
                                    source = getattr(doc, 'meta', {}).get('source', 'Unknown')
                                    doc_context += f"\n---\nSource: {source}\n{content}\n---\n"
                        except Exception as e:
                            print(f"[WARNING] Failed to load RAG context: {e}")
                        
                        result = generate_single_derived_scenario(
                            group, 
                            user_prompt,
                            generator=generator,
                            doc_context=doc_context,
                            dynamic_prompt_lines=dynamic_prompt_lines,
                            custom_prompt=custom_prompt
                        )
                        
                        description_text = result.get("description", "")
                        if not isinstance(description_text, str):
                            if isinstance(description_text, list):
                                description_text = " ".join(str(item) for item in description_text)
                            else:
                                description_text = json.dumps(description_text, ensure_ascii=False)
                        
                        derived = {
                            "name": result.get("name", "Unnamed Derived Threat"),
                            "description": description_text,
                            "id": str(uuid.uuid4()),
                            "threat_ids": group
                        }
                        details.append(derived)
                        print(f"[SUCCESS] Generated: {derived['name']}")
                    
                except Exception as e:
                    print(f"[ERROR] Failed to generate for group {group_key}: {str(e)}")
                    traceback.print_exc()
                    # Just skip this group - no fallback
                    continue
                    
        except Exception as e:
            print(f"[CRITICAL] Error in grouping threats: {str(e)}")
            traceback.print_exc()
            # Return empty - no fallback
            return {}
    
    # Save to database
    if details:
        document = {
            "model_id": model_id,
            "type": "User-defined",
            "Details": details,
            "generated_at": time.time(),
            "total_derived": len(details)
        }
        
        try:
            db.Threat_scenarios.replace_one(
                {"model_id": model_id, "type": "User-defined"},
                document,
                upsert=True
            )
            
            saved_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
            if saved_doc:
                saved_doc["_id"] = str(saved_doc["_id"])
            return saved_doc
        except Exception as e:
            print(f"[ERROR] Failed to save: {str(e)}")
            document["_id"] = "unsaved"
            return document
    
    return {}



@modelprompt.route('/v1/generate/derived-threat-scenarios', methods=['POST'])
def create_derived_threat_scenario():
    """
    Endpoint to generate derived threat scenarios.
    Always returns 201 if processing completes (even with errors in individual scenarios).
    """
    try:
        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        name = data.get('name', "")
        description = data.get('description', "")
        model_id = data.get('modelId', "")
        system_name = data.get('systemName', "")
        user_prompt = data.get('threatScenarioPrompt', "")
        custom_prompt = data.get('itemDefinitionPrompt', "")
        
        # Handle dynamic fields
        static_fields = {"modelId", "systemName", "threatIds", "name", "description", "threatScenarioPrompt", "itemDefinitionPrompt"}
        if request.is_json:
            dynamic_fields = {k: v for k, v in data.items() if k not in static_fields}
        else:
            dynamic_fields = {k: request.form.get(k) for k in request.form if k not in static_fields}
            
        dynamic_prompt_lines = "\n".join([
            f"{key.replace('_', ' ').title()}: {value}"
            for key, value in dynamic_fields.items()
        ])
        
        # Handle threat_ids which might be a string (from form) or list (from JSON)
        threat_ids_raw = data.get('threatIds', "[]")
        if isinstance(threat_ids_raw, str):
            threat_ids = json.loads(threat_ids_raw)
        else:
            threat_ids = threat_ids_raw
            
        if not model_id or not threat_ids:
            return jsonify({"error": "Missing modelId or threatIds"}), 400

        # Generate derived scenarios (handles errors internally)
        results = generate_derived_threat_scenarios(
            model_id=model_id, 
            threat_ids=threat_ids, 
            name=name, 
            description=description, 
            user_prompt=user_prompt,
            system_name=system_name,
            dynamic_prompt_lines=dynamic_prompt_lines,
            custom_prompt=custom_prompt
        )
        
        # Check if we got partial results
        if results and results.get("Details"):
            failed_count = results.get("failed_count", 0)
            if failed_count > 0:
                return jsonify({
                    "message": f"Derived scenarios generated with {failed_count} failures",
                    "data": results,
                    "partial_success": True
                }), 201
            else:
                return jsonify({
                    "message": "Derived scenarios generated successfully",
                    "data": results
                }), 201
        else:
            return jsonify({
                "error": "No derived scenarios could be generated",
                "details": "Check logs for more information"
            }), 500

    except Exception as e:
        print(f"[ERROR] in create_derived_threat_scenario: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": "Failed to process derived threat scenario request", "details": str(e)}), 500


@modelprompt.route('/v1/generate/full-threat-scenario', methods=['POST'])
def create_threat_and_derived_combined():
    """
    Combined endpoint that generates both threat scenarios and derived threat scenarios.
    Threat scenarios are critical, derived scenarios are best-effort.
    Always returns success if threat scenarios succeed, even if derived scenarios fail.
    """
    try:
        start_time = time.time()

        # Check if the request is JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
            
        model_id = data.get('modelId', "")
        name = data.get('name', "")
        description = data.get('description', "")
        system_name = data.get('systemName', "")
        user_prompt = data.get('threatScenarioPrompt', "")
        custom_prompt = data.get('itemDefinitionPrompt', "")
        
        static_fields = {"modelId", "name", "description", "threatScenarioPrompt", "systemName", "itemDefinitionPrompt"}
        if request.is_json:
            dynamic_fields = {k: v for k, v in data.items() if k not in static_fields}
        else:
            dynamic_fields = {k: request.form.get(k) for k in request.form if k not in static_fields}
            
        dynamic_prompt_lines = "\n".join([
            f"{key.replace('_', ' ').title()}: {value}"
            for key, value in dynamic_fields.items()
        ])

        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        print(f"\n=== [COMBINED API] STARTED for model {model_id} ===")

        # Step 1: Generate threat scenarios (critical)
        t1 = time.time()
        try:
            threat_response, status_code = create_threat_scenarios(model_id)
            threat_generation_time = time.time() - t1
            print(f"[TIMING] Threat scenario generation took {threat_generation_time:.2f}s")
            
            if status_code != 201:
                print("[ERROR] Threat scenario generation failed")
                return threat_response, status_code
                
            threat_data = threat_response.get_json() if hasattr(threat_response, 'get_json') else threat_response
            print(f"[SUCCESS] Threat scenarios created: {len(threat_data.get('scenarios', {}).get('Details', []))}")
            
        except Exception as e:
            print(f"[FATAL] Threat scenario generation failed: {str(e)}")
            traceback.print_exc()
            return jsonify({"error": "Threat scenario generation failed", "details": str(e)}), 500

        # Step 2: Collect threat IDs for derived scenario generation
        threat_ids = []
        try:
            scenarios = threat_data.get("scenarios", {})
            details = scenarios.get("Details", [])
            
            for threat in details:
                for item in threat.get("Details", []):
                    for prop in item.get("props", []):
                        threat_ids.append({
                            "nodeId": item["nodeId"],
                            "propId": prop["id"],
                            "rowId": threat["rowId"]
                        })
            print(f"[INFO] Collected {len(threat_ids)} threatIds for derived generation")
        except Exception as e:
            print(f"[WARNING] Failed to collect threat IDs: {str(e)}")
            threat_ids = []

        # Step 3: Generate derived scenarios (best-effort, non-critical)
        derived_response_json = None
        derived_status = None
        derived_generation_time = 0
        
        if threat_ids:
            t2 = time.time()
            try:
                # Create request data for derived scenario generation
                derived_request_data = {
                    "modelId": model_id,
                    "name": name,
                    "description": description,
                    "threatScenarioPrompt": user_prompt,
                    "threatIds": threat_ids
                }
                
                # Call the derived scenario generation function directly
                # This avoids request context issues
                derived_result = generate_derived_threat_scenarios(
                    model_id=model_id,
                    threat_ids=threat_ids,
                    name=name,
                    description=description,
                    user_prompt=user_prompt,
                    system_name=system_name,
                    dynamic_prompt_lines=dynamic_prompt_lines,
                    custom_prompt=custom_prompt
                )
                
                derived_generation_time = time.time() - t2
                print(f"[TIMING] Derived threat scenario generation took {derived_generation_time:.2f}s")
                
                if derived_result:
                    derived_response_json = derived_result
                    derived_status = 201
                    failed_count = derived_result.get("failed_count", 0)
                    if failed_count > 0:
                        print(f"[WARNING] Derived scenarios generated with {failed_count} failures")
                    else:
                        print("[SUCCESS] All derived scenarios generated successfully")
                else:
                    derived_response_json = {"error": "No derived scenarios generated"}
                    derived_status = 500
                    
            except Exception as e:
                derived_generation_time = time.time() - t2
                print(f"[WARNING] Derived threat scenario generation failed: {str(e)}")
                traceback.print_exc()
                derived_response_json = {
                    "error": "Derived scenario generation failed",
                    "details": str(e),
                    "partial": True
                }
                derived_status = 500
        else:
            print("[INFO] No threat IDs available, skipping derived scenario generation")
            derived_response_json = {"message": "No threats to generate derived scenarios from"}
            derived_status = 204

        total_time = time.time() - start_time
        print(f"=== [COMBINED API] FINISHED in {total_time:.2f}s ===\n")

        # Always return success if threat scenarios were generated
        response_data = {
            "message": "Threat scenarios created successfully",
            "threat_scenarios": threat_data,
            "derived_threat_scenarios": derived_response_json,
            "timing": {
                "threat_generation_sec": round(threat_generation_time, 2),
                "derived_generation_sec": round(derived_generation_time, 2),
                "total_sec": round(total_time, 2)
            }
        }
        
        # Add warning if derived scenarios failed
        if derived_status != 201:
            response_data["warning"] = "Derived threat scenarios could not be generated or were partially generated"
            response_data["derived_status"] = derived_status
        
        return jsonify(response_data), 201

    except Exception as e:
        print("[FATAL ERROR in combined API]:", str(e))
        traceback.print_exc()
        return jsonify({
            "error": "Unexpected error in combined API", 
            "details": str(e)
        }), 500


# Helper function to group threats by node (implement based on your needs)
def group_threats_by_node(threat_ids):
    """
    Group threat IDs by nodeId.
    Returns a dictionary with nodeId as key and list of threats as value.
    """
    grouped = {}
    for threat in threat_ids:
        node_id = threat.get("nodeId", "unknown")
        if node_id not in grouped:
            grouped[node_id] = []
        grouped[node_id].append(threat)
    return grouped



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

# Add this to your ModelPrompt.py file

@modelprompt.route('/v1/generate/item-and-damage', methods=['POST'])
def generate_item_and_damage():
    """
    Generate both item definition (template) and damage scenarios in a single call.
    Similar to generate_full_model but only for item definition and damage scenarios.
    """
    try:
        print("\n" + "="*80)
        print("GENERATING ITEM DEFINITION AND DAMAGE SCENARIOS")
        print("="*80 + "\n")
        
        # ── Generate Item Definition (Template) ──────────────────────────────
        print("Step 1: Generating Item Definition...")
        template_response = generate_reactflow_template(standalone=True, request_data=request)
        start_time = time.time()
        model_id = template_response['model_id']
        system_name = template_response['system_name']
        
        print(f"✓ Item Definition generated")
        print(f"  Model ID: {model_id}")
        print(f"  Nodes: {len(template_response['template'].get('nodes', []))}")
        print(f"  Edges: {len(template_response['template'].get('edges', []))}")
        
        # ── Generate Damage Scenarios ────────────────────────────────────────
        print("\nStep 2: Generating Damage Scenarios...")
        
        # Prepare request data for damage scenarios
        damage_request_data = {
            'modelId': model_id,
            'systemName': system_name,
            'template': json.dumps(template_response['template']),
            'damageScenarioPrompt': request.form.get('damageScenarioPrompt', '') if not request.is_json else request.get_json().get('damageScenarioPrompt', ''),
            'itemDefinitionPrompt': request.form.get('itemDefinitionPrompt', '') if not request.is_json else request.get_json().get('itemDefinitionPrompt', ''),
        }
        
        # Also pass dynamic fields from the original request
        if request.is_json:
            data = request.get_json()
            static_fields = {"createdBy", "systemName", "itemDefinitionPrompt", "damageScenarioPrompt", "modelId"}
            for key, value in data.items():
                if key not in static_fields:
                    damage_request_data[key] = value
        else:
            for key, value in request.form.items():
                if key not in ["createdBy", "systemName", "itemDefinitionPrompt", "damageScenarioPrompt", "modelId"]:
                    damage_request_data[key] = value
        
        # Create a mock request object for damage scenario generation
        class MockRequest:
            def __init__(self, data):
                self.form = MultiDict(data)
                self.is_json = False
        
        mock_request = MockRequest(damage_request_data)
        
        # Generate damage scenarios
        scenarios_response = create_damage_scenarios_with_rag(standalone=True, request_data=mock_request)
        
        print(f"✓ Damage Scenarios generated")
        print(f"  Total scenarios: {scenarios_response.get('stats', {}).get('total_scenarios', 0)}")
        
        # ── Return combined response ─────────────────────────────────────────
        total_time = time.time() - start_time if 'start_time' in dir() else 0
        
        result_data = {
            "message": "Item definition and damage scenarios generated successfully",
            "model_id": model_id,
            "system_name": system_name,
            "template": template_response['template'],
            "damage_scenarios": scenarios_response.get('scenarios', {}),
            "stats": {
                "nodes_count": len(template_response['template'].get('nodes', [])),
                "edges_count": len(template_response['template'].get('edges', [])),
                "damage_scenarios_count": scenarios_response.get('stats', {}).get('total_scenarios', 0),
                "generation_time_sec": round(total_time, 2)
            }
        }
        
        return current_app.response_class(
            response=json.dumps(result_data, cls=JSONEncoder),
            status=201,
            mimetype="application/json",
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error in item and damage generation": str(e)}), 500