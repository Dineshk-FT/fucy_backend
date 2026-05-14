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
        
        # We don't need the generic position calculators anymore, keeping only what's needed
        from app.Methods.new_helpers import (
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
                clean_props = []
                for p in pn_props:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", str(p))))
                    elif isinstance(p, str):
                        clean_props.append(p)
                    else:
                        clean_props.append(str(p))
                pipeline_properties_map[pn_id] = clean_props

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

        group_nodes = group_nodes[:MAX_GROUPS]
        component_nodes = component_nodes[:MAX_NODES]
        
        for node in component_nodes:
            if "data" not in node:
                node["data"] = {}
            if "label" not in node["data"] and "label" in node:
                node["data"]["label"] = node["label"]
            if "id" not in node:
                node["id"] = str(uuid.uuid4())
            if "type" not in node:
                node["type"] = "default"
            
            node_id = node.get("id", "")
            node_label = node.get("data", {}).get("label", "")
            
            existing_props = node.get("properties", None)
            
            if existing_props and isinstance(existing_props, list) and len(existing_props) > 0:
                clean_existing = []
                for p in existing_props:
                    if isinstance(p, dict):
                        clean_existing.append(p.get("name", p.get("value", str(p))))
                    elif isinstance(p, str):
                        clean_existing.append(p)
                    else:
                        clean_existing.append(str(p))
                node["properties"] = clean_existing
            else:
                pipeline_props = pipeline_properties_map.get(node_id, None)
                if pipeline_props:
                    node["properties"] = pipeline_props
                else:
                    pipeline_props = pipeline_label_properties_map.get(node_label, None)
                    if pipeline_props:
                        node["properties"] = pipeline_props
                    else:
                        node["_properties_missing"] = True
        
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

        # ── B40-STYLE MANUAL POSITIONING AND GROUP HANDLING ─────────────────
        print("\n" + "="*60)
        print("APPLYING B40-STYLE GRID POSITIONING")
        print("="*60)
        
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
                            break

        print("  📍 Step 2-6: Applying rigid B40-style grid coordinates...")
        positioned_nodes = final_nodes
        groups = [n for n in positioned_nodes if n.get("type") == "group"]
        components = [n for n in positioned_nodes if n.get("type") != "group"]
        
        # Un-nest groups to enforce absolute horizontal layout
        for g in groups:
            g["parentId"] = None
            
        current_group_x = -96
        group_y = -44
        group_positions = {}
        
        for g in groups:
            children = [n for n in components if n.get("parentId") == g.get("id")]
            num_children = len(children)
            cols = min(num_children, 3) if num_children > 0 else 1
            rows = (num_children - 1) // 3 + 1 if num_children > 0 else 1
            
            # Replicate B40 spacing layout
            g_width = max(740, 60 + cols * 210 + 50)
            g_height = max(320, 60 + rows * 120 + 60)
            
            g["position"] = {"x": current_group_x, "y": group_y}
            g["positionAbsolute"] = {"x": current_group_x, "y": group_y}
            g["width"] = g_width
            g["height"] = g_height
            if "style" not in g:
                g["style"] = {}
            g["style"]["width"] = g_width
            g["style"]["height"] = g_height
            
            group_positions[g.get("id")] = {"x": current_group_x, "y": group_y}
            current_group_x += g_width + 160

        child_counters = {}
        ungrouped_counter = 0
        
        for n in components:
            # Force exact B40 dimension sizing
            n["width"] = 160
            n["height"] = 40
            if "style" not in n:
                n["style"] = {}
            n["style"]["width"] = 160
            n["style"]["height"] = 40
            
            pid = n.get("parentId")
            if pid and pid in group_positions:
                ci = child_counters.get(pid, 0)
                col = ci % 3
                row = ci // 3
                
                rel_x = 60 + (col * 210)
                rel_y = 60 + (row * 120)
                
                n["relative_x"] = rel_x
                n["relative_y"] = rel_y
                n["position"] = {
                    "x": group_positions[pid]["x"] + rel_x,
                    "y": group_positions[pid]["y"] + rel_y
                }
                n["positionAbsolute"] = n["position"].copy()
                n["zIndex"] = 1
                child_counters[pid] = ci + 1
            else:
                col = ungrouped_counter % 3
                row = ungrouped_counter // 3
                n["position"] = {
                    "x": 100 + (col * 400),
                    "y": 806 + (row * 120)
                }
                n["positionAbsolute"] = n["position"].copy()
                n["zIndex"] = 2
                ungrouped_counter += 1
        
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
            
            # Explicitly clear bad properties to apply uniform 160x40 layout
            if is_group:
                if "width" not in node:
                    node["width"] = 800
                if "height" not in node:
                    node["height"] = 500
            else:
                node["width"] = 160
                node["height"] = 40
            
            colors = generate_node_color(node_type)
            
            if "data" not in node:
                node["data"] = {}
            
            if "label" not in node["data"]:
                node["data"]["label"] = node.get("id", "Node")
            
            node["data"]["nodeId"] = node.get("id")
            
            # ── FINAL PROPERTIES RESOLUTION ──
            node_label = node.get("data", {}).get("label", node.get("id", "unknown"))
            raw_properties = node.get("properties", None)
            was_missing = node.pop("_properties_missing", False)
            
            if is_group:
                final_properties = DEFAULT_GROUP_PROPERTIES
            elif raw_properties is not None and isinstance(raw_properties, list):
                if len(raw_properties) == 0:
                    final_properties = []
                else:
                    clean_props = []
                    for p in raw_properties:
                        if isinstance(p, dict):
                            prop_name = p.get("name") or p.get("value") or p.get("property") or str(p)
                            clean_props.append(str(prop_name))
                        elif isinstance(p, str):
                            clean_props.append(p)
                        else:
                            clean_props.append(str(p))
                    
                    seen = set()
                    unique_props = []
                    for p in clean_props:
                        if p not in seen:
                            seen.add(p)
                            unique_props.append(p)
                    
                    filtered_props = [p for p in unique_props if p in VALID_CYBER_PROPS]
                    
                    if filtered_props:
                        final_properties = filtered_props
                    else:
                        final_properties = DEFAULT_COMPONENT_PROPERTIES
            else:
                final_properties = DEFAULT_COMPONENT_PROPERTIES
            
            node["properties"] = final_properties
            
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
                continue
            
            edge_label = edge.get("label", edge.get("data", {}).get("label", ""))
            if not edge_label:
                edge_label = edge.get("name", "Connection")
            
            edge_id = edge.get("id", "")
            edge_key = f"{source_id}->{target_id}"
            
            edge_props = None
            
            if edge_id and edge_id in pipeline_edge_properties_map:
                edge_props = pipeline_edge_properties_map[edge_id]
            elif edge_key in pipeline_edge_st_props_map:
                edge_props = pipeline_edge_st_props_map[edge_key]
            elif "properties" in edge and edge["properties"] is not None:
                edge_props = edge.get("properties")
            
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
    """Generate damage scenarios using RAG-enhanced prompts while preserving existing reference assets."""
    try:
        if not request_data:
            request_data = request

        # Parse request data
        if request.is_json:
            data = request.get_json()
            model_id = data.get("modelId")
            system_name = data.get("systemName", "")
            template_raw = data.get("template", "{}")
            user_prompt = data.get("damageScenarioPrompt", "")
        else:
            model_id = request_data.form.get("modelId")
            system_name = request_data.form.get("systemName", "")
            template_raw = request_data.form.get("template", "{}")
            user_prompt = request_data.form.get("damageScenarioPrompt", "")

        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        try:
            template = json.loads(template_raw) if template_raw else {}
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid template JSON"}), 400

        # --- STEP 1: Build a comprehensive map of ALL valid assets (Nodes AND Edges) ---
        # This is the key fix to ensure CAN1/CAN2 edges are pulled.
        valid_assets = {}
        
        # Map Component Nodes
        for node in template.get("nodes", []):
            if node.get("type") != "group":
                label = node.get("data", {}).get("label", "").lower().strip()
                valid_assets[label] = node.get("id")

        # Map Edges (Crucial for communication-based damage scenes)
        for edge in template.get("edges", []):
            label = edge.get("data", {}).get("label", "").lower().strip()
            if label:
                valid_assets[label] = edge.get("id")
        
        # --- STEP 2: Enhanced matching function ---
        def _match_asset(asset_name: str):
            if not asset_name:
                return None, None
            al = asset_name.lower().strip()
            # Exact match
            if al in valid_assets:
                return valid_assets[al], al
            # Substring match (e.g., "CAN1" matching a specific edge label)
            for label, aid in valid_assets.items():
                if al in label or label in al:
                    return aid, label
            return None, None

        # --- STEP 3: Pull reference data and remap ---
        from app.v1.rag.components import resolve_ecu, resolve_reference_report
        from app.v1.rag.azure_client import get_azure_client
        from app.v1.rag.config import AZURE_PATHS
        import copy

        client = get_azure_client()
        reference_data = None
        
        # Attempt to pull the authoritative bms_1.json
        try:
            reports_path = AZURE_PATHS["REPORTS_PATH"].rstrip('/')
            bms_1_blob = f"{reports_path}/bms_1.json"
            reference_data = client.download_json(bms_1_blob)
        except Exception as e:
            print(f"⚠️ Falling back from bms_1.json: {e}")

        if not reference_data:
            ecu_entry = resolve_ecu(system_name)
            reference_data = resolve_reference_report(ecu_entry, system_name)

        existing_scenarios = []
        if reference_data and "Damage_scenarios" in reference_data:
            for ds_block in reference_data["Damage_scenarios"]:
                scenarios_to_process = []
                if ds_block.get("type") == "User-defined":
                    scenarios_to_process = ds_block.get("Details", [])
                
                for detail in scenarios_to_process:
                    detail_copy = copy.deepcopy(detail)
                    remapped_losses = []
                    for loss in detail_copy.get("cyberLosses", []):
                        asset_name = loss.get("node", "")
                        matched_id, matched_label = _match_asset(asset_name)
                        if matched_id:
                            loss["nodeId"] = matched_id
                            loss["node"] = matched_label
                            loss["id"] = str(uuid.uuid4())
                            remapped_losses.append(loss)
                    
                    if remapped_losses:
                        detail_copy["cyberLosses"] = remapped_losses
                        detail_copy["_id"] = str(uuid.uuid4())
                        existing_scenarios.append(detail_copy)

        # --- STEP 4: Generate extras via Gemini/RAG ---
        from app.v1.rag.prompt import DAMAGE_PROMPT
        import jinja2
        from app.v1.rag.pipeline import setup as pipeline_setup
        from app.v1.rag.ingest import load_all_documents

        tmpl = jinja2.Template(DAMAGE_PROMPT)
        final_prompt = tmpl.render(
            question=system_name,
            architecture=json.dumps({"template": template}, indent=2)
        )
        
        # Inject existing scenarios to prevent duplicates[cite: 5]
        if existing_scenarios:
            final_prompt += f"\n### EXISTING SCENARIOS:\n{json.dumps(existing_scenarios, indent=2)}\n"
            final_prompt += "Generate only 3-5 ADDITIONAL scenarios for assets NOT listed above."

        all_docs = load_all_documents()
        _, generator, _ = pipeline_setup(all_docs)
        result = generator.run(parts=[final_prompt])
        output = result["replies"][0] if result["replies"] else "{}"

        # Clean and parse new scenarios
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")
        try:
            new_data = json.loads(cleaned)
            new_details = new_data.get("Details", [])
        except:
            new_details = []

        # --- STEP 5: Combine, Key, and Save ---
        combined_details = existing_scenarios + new_details
        for i, detail in enumerate(combined_details):
            detail["key"] = i + 1

        db.Damage_scenarios.update_one(
            {"model_id": model_id, "type": "User-defined"},
            {"$set": {"Details": combined_details, "last_updated": datetime.now()}},
            upsert=True
        )

        return jsonify({"message": "Damage scenarios updated with full asset remapping", "count": len(combined_details)}), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


#4 - Threat scenario creation
# Manual threat creation
@modelprompt.route('/v1/generate/threat-scenarios', methods=['POST'])
def create_threat_scenarios(model_id=None):
    try:
        if not model_id:
            model_id = request.form.get("modelId")

        damage_doc = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        if not damage_doc or "Details" not in damage_doc:
            return jsonify({"error": "No damage scenarios found for this model_id"}), 404

        threat_details = []

        for i, damage in enumerate(damage_doc["Details"], start=1):
            # Handle _id safely - convert ObjectId to string if it exists
            row_id = str(damage.get("_id", f"temp_{i}")) if damage.get("_id") else f"temp_{i}"
            
            threat_detail = {
                "damage_key": damage.get("key", ""),
                "damage_name": damage.get("Name", ""),
                "id": f"DS{str(i).zfill(3)}",
                "rowId": row_id,
                "Details": []
            }

            for loss in damage.get("cyberLosses", []):
                threat_node = {
                    "name": damage.get("Name", ""),
                    "node": loss.get("node", ""),
                    "nodeId": loss.get("nodeId", ""),
                    "props": [
                        {
                            "id": str(uuid.uuid4()),
                            "name": loss.get("name", ""),
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
        # print(f"Saved threat scenario document: {saved_doc}")
        
        # Convert ObjectId to string for JSON serialization
        if saved_doc and "_id" in saved_doc:
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

def generate_single_derived_scenario(threat_group, user_prompt=None, max_retries=3, generator=None, doc_context="", dynamic_prompt_lines="", custom_prompt=""):
    """
    Generate a derived threat scenario name + description from a group of threats.
    If user_prompt is provided, it replaces the intro part of the prompt.
    Includes retry logic for JSON parsing failures and API rate limits.
    """
    import time
    
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
            # FIXED: Added the `cleaned` string argument here
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
            
        except Exception as e:
            error_str = str(e)
            
            # Catch Rate Limits (429) specifically and pause execution
            if "429" in error_str or "Quota" in error_str or "ResourceExhausted" in error_str:
                wait_time = 15 # Safe default wait
                # Extract wait time from error message if available
                match = re.search(r"retry in ([\d.]+)s", error_str)
                if match:
                    wait_time = int(float(match.group(1))) + 2
                
                print(f"  ⏳ [RATE LIMIT] Gemini API quota exceeded. Pausing for {wait_time} seconds...")
                time.sleep(wait_time)
                
                if attempt < max_retries:
                    continue # Retry the exact same request
                else:
                    return {
                        "name": "Generated Derived Threat (Rate Limited)",
                        "description": f"Derived from {len(threat_group)} related threats. (Auto-generated due to API rate limits)"
                    }

            # Handle JSON parsing errors
            if attempt < max_retries:
                print(f"⚠️ Attempt {attempt + 1} failed for JSON parsing. Retrying...")
                # Modify prompt for retry to emphasize JSON format
                prompt_intro = f"""
                    {prompt_intro}
                    
                    IMPORTANT: You MUST return ONLY valid JSON. No markdown, no extra text, no explanations.
                    The response must be exactly in this format:
                    {{"name": "Your scenario name here", "description": "Your description here"}}
                """
                time.sleep(2) # Brief pause before standard retry
                continue
            else:
                print("⚠️ Failed to parse Gemini response after all retries. Error:", str(e))
                return {
                    "name": "Generated Derived Threat",
                    "description": f"Derived from {len(threat_group)} related threats. (Auto-generated due to parsing error)"
                }


def generate_derived_threat_scenarios(
    model_id,
    threat_ids,
    name="",
    description="",
    user_prompt=None,
    system_name="",
    dynamic_prompt_lines="",
    custom_prompt="",
):
    import jinja2
    import time
    from app.v1.rag.pipeline import setup as pipeline_setup
    from app.v1.rag.ingest import load_all_documents
    from app.v1.rag.components import resolve_ecu, resolve_reference_report
    import uuid, json, re, os, traceback
    from db import db
    from bson import ObjectId

    details = []

    if name or description:
        if not isinstance(description, str):
            if isinstance(description, list):
                description = " ".join(str(i) for i in description)
            else:
                description = json.dumps(description, ensure_ascii=False)
        details.append({
            "name": name or "Unnamed Derived Threat",
            "description": description,
            "id": str(uuid.uuid4()),
            "threat_ids": threat_ids,
        })
        return {"Details": details}

    try:
        full_threat_list = list(threat_ids)
        claimed_threat_signatures = set()

        # ── 1. Build label ↔ id maps for the CURRENT architecture ─────────────
        current_node_label_to_id = {}
        current_edge_label_to_id = {}
        current_all_ids = set()
        # FIX 1: also build id→label so we can enrich the LLM prompt later
        current_node_id_to_label = {}

        try:
            asset_doc = db.Assets.find_one({"model_id": model_id})
            if asset_doc and "template" in asset_doc:
                for n in asset_doc["template"].get("nodes", []):
                    if n.get("type") != "group":
                        nid = n.get("id")
                        lbl = (
                            n.get("data", {}).get("label") or n.get("label", "")
                        ).lower().strip()
                        if lbl:
                            current_node_label_to_id[lbl] = nid
                        if nid:
                            current_all_ids.add(nid)
                            current_node_id_to_label[nid] = lbl  # FIX 1
                for e in asset_doc["template"].get("edges", []):
                    eid = e.get("id")
                    lbl = (
                        e.get("data", {}).get("label") or e.get("label", "")
                    ).lower().strip()
                    if lbl:
                        current_edge_label_to_id[lbl] = eid
                    if eid:
                        current_all_ids.add(eid)
        except Exception as exc:
            print(f"[WARNING] Could not fetch current architecture nodes/edges: {exc}")

        def _fuzzy_match(name, map1, map2):
            if not name:
                return None
            nl = name.lower().strip()
            for m in (map1, map2):
                if nl in m:
                    return m[nl]
                for lbl, nid in m.items():
                    if nl in lbl or lbl in nl:
                        return nid
                nw = set(nl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
                best_score, best = 0, None
                for lbl, nid in m.items():
                    lw = set(lbl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
                    score = len(nw & lw)
                    if score > best_score:
                        best_score, best = score, nid
                if best and best_score > 0:
                    return best
            return None

        # ── 2. Resolve system_name ────────────────────────────────────────────
        # FIX 2: Try ObjectId cast when doing the DB lookup so it actually finds the doc
        resolved_system_name = system_name
        if not resolved_system_name:
            try:
                try:
                    oid = ObjectId(model_id)
                    model_doc = db.Models.find_one({"_id": oid})
                except Exception:
                    model_doc = None
                if not model_doc:
                    model_doc = db.Models.find_one({"model_id": model_id})
                if model_doc:
                    resolved_system_name = model_doc.get(
                        "name", model_doc.get("systemName", "")
                    )
                    print(f"  ✅ Resolved system_name from DB: '{resolved_system_name}'")
            except Exception as exc:
                print(f"[WARNING] Could not resolve system_name from DB: {exc}")

        # ── 3. Load reference JSON ────────────────────────────────────────────
        reference_data = None
        ref_id_to_label = {}

        try:
            from app.v1.rag.azure_client import get_azure_client
            from app.v1.rag.config import AZURE_PATHS

            client = get_azure_client()

            try:
                reports_path = AZURE_PATHS["REPORTS_PATH"].rstrip("/")
                bms_1_blob = f"{reports_path}/bms_1.json"
                reference_data = client.download_json(bms_1_blob)
                if reference_data:
                    print("  ✅ Loaded bms_1.json for reference threats")
            except Exception as exc:
                print(f"  ⚠️ Could not pull bms_1.json: {exc}")

            if not reference_data and resolved_system_name:
                ecu_entry = resolve_ecu(resolved_system_name)
                reference_data = resolve_reference_report(ecu_entry, resolved_system_name)

            if reference_data:
                ref_assets = reference_data.get("Assets", [])
                if ref_assets:
                    ref_asset = ref_assets[0] if isinstance(ref_assets, list) else ref_assets
                    for n in ref_asset.get("template", {}).get("nodes", []):
                        if n.get("type") != "group":
                            lbl = (
                                n.get("data", {}).get("label") or n.get("label", "")
                            ).lower().strip()
                            if lbl:
                                ref_id_to_label[n.get("id")] = lbl
                    for e in ref_asset.get("template", {}).get("edges", []):
                        lbl = (
                            e.get("data", {}).get("label") or e.get("label", "")
                        ).lower().strip()
                        if lbl:
                            ref_id_to_label[e.get("id")] = lbl
        except Exception as exc:
            print(f"[WARNING] Failed to process reference data: {exc}")

        # ── 4. Extract + remap User-defined reference scenarios ───────────────
        extracted_ref_scenarios = []

        if reference_data:
            for ts_block in reference_data.get("Threat_scenarios", []):
                if ts_block.get("type", "").lower() not in ("user-defined", "user_defined"):
                    continue

                for ref_dt in ts_block.get("Details", []):
                    ref_name = ref_dt.get("name", ref_dt.get("Name", ""))
                    ref_desc = ref_dt.get("description", ref_dt.get("Description", ""))

                    skip_keywords = ["loss of", "ds due to", "check for ds"]
                    if not ref_name or not ref_desc or any(
                        kw in ref_name.lower() for kw in skip_keywords
                    ):
                        continue

                    target_current_node_ids = set()
                    for tid in ref_dt.get("threat_ids", []):
                        ref_nid = tid.get("nodeId", "")
                        curr_nid = None
                        if ref_nid in current_all_ids:
                            curr_nid = ref_nid
                        else:
                            ref_lbl = ref_id_to_label.get(ref_nid, "")
                            if ref_lbl:
                                if ref_nid.startswith("reactflow__edge"):
                                    curr_nid = _fuzzy_match(ref_lbl, current_edge_label_to_id, current_node_label_to_id)
                                else:
                                    curr_nid = _fuzzy_match(ref_lbl, current_node_label_to_id, current_edge_label_to_id)

                        if curr_nid:
                            target_current_node_ids.add(curr_nid)

                    edge_expansions = set()
                    for nid in target_current_node_ids:
                        for threat in full_threat_list:
                            tid_nid = threat.get("nodeId", "")
                            if tid_nid.startswith("reactflow__edge") and nid in tid_nid:
                                edge_expansions.add(tid_nid)
                    if edge_expansions:
                        target_current_node_ids.update(edge_expansions)

                    if not target_current_node_ids:
                        continue

                    claimed = []
                    for threat in full_threat_list:
                        if threat.get("nodeId") in target_current_node_ids:
                            claimed.append(threat)
                            claimed_threat_signatures.add(
                                (threat.get("nodeId", ""), threat.get("propId", ""), threat.get("rowId", ""))
                            )

                    if claimed:
                        mapped_scenario = {
                            "name": ref_name,
                            "description": ref_desc,
                            "id": str(uuid.uuid4()),
                            "threat_ids": claimed,
                        }
                        details.append(mapped_scenario)
                        extracted_ref_scenarios.append(mapped_scenario)
                        print(f"  ✅ Mapped reference scenario '{ref_name}': {len(claimed)} threat_ids claimed.")
                    else:
                        print(f"  ⚠️  Reference scenario '{ref_name}' resolved {len(target_current_node_ids)} node(s) but no threat_ids match — skipping.")

        available_threats = []
        for threat in full_threat_list:
            sig = (threat.get("nodeId", ""), threat.get("propId", ""), threat.get("rowId", ""))
            if sig not in claimed_threat_signatures:
                available_threats.append(threat)

        try:
            os.makedirs("outputs/debug", exist_ok=True)
            with open("outputs/debug/api_reference_derived_threats.json", "w", encoding="utf-8") as f:
                json.dump({
                    "system_name": resolved_system_name,
                    "extracted_user_defined_scenarios": extracted_ref_scenarios,
                    "remaining_unmapped_threats": available_threats,
                }, f, indent=2)
        except Exception as exc:
            print(f"[DEBUG LOGGING FAILED]: {exc}")

        # ── 5. Group remaining unmapped threats and send to LLM ──────────────
        unmapped_groups_raw = group_threats_by_node(available_threats)

        # FIX 3: alias long reactflow edge IDs AND build a node-label enriched
        # summary so the LLM knows what each group actually represents
        alias_to_original = {}
        original_to_alias = {}
        # FIX 3: label lookup per group key (for LLM context)
        alias_to_node_label = {}
        alias_counter = 1

        for key in unmapped_groups_raw:
            if key.startswith("reactflow__edge"):
                alias = f"edge_group_{alias_counter}"
                alias_counter += 1
                alias_to_original[alias] = key
                original_to_alias[key] = alias
                alias_to_node_label[alias] = f"Communication Edge ({alias})"
            else:
                # FIX 3: resolve UUID key to human-readable node label
                node_label = current_node_id_to_label.get(key, "")
                alias_to_node_label[key] = node_label.title() if node_label else key

        unmapped_groups = {
            original_to_alias.get(k, k): v for k, v in unmapped_groups_raw.items()
        }

        if unmapped_groups:
            print(f"[INFO] Generating {len(unmapped_groups)} scenarios via single LLM batch call...")

            doc_context = ""
            generator = None
            try:
                all_docs = load_all_documents()
                retriever, generator, text_embedder = pipeline_setup(all_docs)

                if resolved_system_name:
                    embedding = text_embedder.run(text=resolved_system_name)["embedding"]
                    retrieval_result = retriever.run(query_embedding=embedding)
                    doc_context = "\n\n### RETRIEVED REFERENCE DOCUMENTS:\n"
                    for doc in retrieval_result["documents"][:3]:
                        doc_context += (
                            f"\n---\nSource: {getattr(doc, 'meta', {}).get('source', 'Unknown')}\n"
                            f"{getattr(doc, 'content', str(doc))[:1500]}\n---\n"
                        )
            except Exception as exc:
                print(f"[WARNING] Failed to load RAG context: {exc}")

            # FIX 3: build an enriched group summary with human-readable labels
            enriched_group_summary = {}
            for g_id, threats in unmapped_groups.items():
                node_label = alias_to_node_label.get(g_id, g_id)
                enriched_group_summary[g_id] = {
                    "component": node_label,
                    "threat_count": len(threats),
                    "threat_properties": list({
                        t.get("propId", "") for t in threats
                    })
                }

            # FIX 2: build prompt_intro ONCE, not embedded inside the prompt template
            # that already has its own instruction line
            if user_prompt:
                prompt_intro = user_prompt
            else:
                prompt_intro = (
                    f"You are a cybersecurity expert performing ISO 21434 TARA for an automotive system"
                    + (f" ({resolved_system_name})" if resolved_system_name else "")
                    + f". Generate specific, meaningful attack scenario names and descriptions for each threat group below. "
                    f"Do not use generic names like 'Derived Threat Scenario'."
                )

            additional_instructions = ""
            if custom_prompt:
                additional_instructions += f"\n\n### CUSTOM REQUIREMENTS:\n{custom_prompt}\n"
            if dynamic_prompt_lines:
                additional_instructions += f"\n\n### ADDITIONAL SYSTEM DETAILS:\n{dynamic_prompt_lines}\n"

            # FIX 2 + FIX 3: single clean prompt, no duplication, includes node labels
            prompt = f"""{prompt_intro}
{additional_instructions}
{doc_context}

### THREAT GROUPS REQUIRING SCENARIOS:
Each group targets a specific component. Use the "component" field to name the scenario appropriately.
Include: targeted component, attack vector, attacker goal, and related damage scenario in the description.
Use STRIDE categories (Spoofing, Tampering, Repudiation, Info Disclosure, Denial of Service, Elevation of Privilege).

{json.dumps(enriched_group_summary, indent=2)}

### FULL THREAT ID REFERENCE (for threat_ids linking):
{json.dumps(unmapped_groups, indent=2)}

### TASK:
Generate a JSON dictionary where the keys are the EXACT group IDs from above, and the values are objects with 'name' and 'description'.

Example:
{{
  "group-id-1": {{
    "name": "Specific Attack Scenario Name",
    "description": "Detailed description covering attack vector, attacker goal, and damage."
  }}
}}

Return ONLY a valid JSON object. No markdown fences. No extra text.
"""

            try:
                os.makedirs("outputs/debug", exist_ok=True)
                with open("outputs/debug/api_rag_llm_feed.txt", "w", encoding="utf-8") as f:
                    f.write("=== RAG DOC CONTEXT FED TO LLM ===\n")
                    f.write(doc_context if doc_context else "No RAG context fetched.")
                    f.write("\n\n=== FULL PROMPT FED TO LLM ===\n")
                    f.write(prompt)
            except Exception as exc:
                print(f"[DEBUG LOGGING FAILED]: {exc}")

            for attempt in range(3):
                try:
                    if generator:
                        result = generator.run(parts=[prompt])
                        content_text = result["replies"][0] if result["replies"] else "{}"
                    else:
                        gemini_response = gemini_client.generate_content(prompt)
                        content_text = gemini_client.get_text(gemini_response)

                    cleaned = extract_json_from_text(content_text)
                    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", cleaned)
                    if cleaned.startswith("```"):
                        cleaned = re.sub(r"^```\w*\n?", "", cleaned).replace("```", "")

                    json_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
                    if json_match:
                        cleaned = json_match.group(0)

                    batch_results = json.loads(cleaned)

                    for g_id, g_data in batch_results.items():
                        original_key = alias_to_original.get(g_id, g_id)
                        if g_id in unmapped_groups or original_key in unmapped_groups_raw:
                            threat_list = unmapped_groups.get(g_id) or unmapped_groups_raw.get(original_key, [])
                            desc = g_data.get("description", "")
                            if isinstance(desc, list):
                                desc = " ".join(str(i) for i in desc)
                            elif not isinstance(desc, str):
                                desc = str(desc)

                            details.append({
                                "name": g_data.get("name", "Generated Threat Scenario"),
                                "description": desc,
                                "id": str(uuid.uuid4()),
                                "threat_ids": threat_list,
                            })
                            unmapped_groups.pop(g_id, None)
                            unmapped_groups_raw.pop(original_key, None)

                    if unmapped_groups:
                        raise ValueError(f"LLM did not return scenarios for all groups. Missing: {list(unmapped_groups.keys())}")

                    break

                except Exception as exc:
                    err = str(exc)
                    if "429" in err or "Quota" in err or "ResourceExhausted" in err:
                        wait = 15
                        m = re.search(r"retry in ([\d.]+)s", err)
                        if m:
                            wait = int(float(m.group(1))) + 2
                        print(f"  ⏳ [RATE LIMIT] Batch paused for {wait}s...")
                        time.sleep(wait)
                        continue

                    print(f"⚠️ Batch attempt {attempt + 1} failed: {exc}")
                    if attempt == 2:
                        raise RuntimeError(f"Failed to generate derived threat scenarios via LLM. Last error: {err}")
                    time.sleep(2)

    except Exception as exc:
        print(f"[CRITICAL] Error in derived threat scenario generation: {exc}")
        traceback.print_exc()
        raise exc

    # ── 6. Save to database ───────────────────────────────────────────────────
    if details:
        document = {
            "model_id": model_id,
            "type": "User-defined",
            "Details": details,
            "generated_at": time.time(),
            "total_derived": len(details),
        }

        try:
            db.Threat_scenarios.replace_one(
                {"model_id": model_id, "type": "User-defined"},
                document,
                upsert=True,
            )
            saved_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
            if saved_doc:
                saved_doc["_id"] = str(saved_doc["_id"])
            return saved_doc
        except Exception as exc:
            print(f"[ERROR] Failed to save: {exc}")
            raise exc

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

            # create_threat_scenarios returns { "message": ..., "model_id": ..., "scenarios": { ..., "Details": [...] } }
            # So Details lives under threat_data["scenarios"], not at the top level.
            scenarios_doc = threat_data.get("scenarios", {}) or {}
            details = scenarios_doc.get("Details", [])
            print(f"[SUCCESS] Threat scenarios created: {len(details)}")
            
        except Exception as e:
            print(f"[FATAL] Threat scenario generation failed: {str(e)}")
            traceback.print_exc()
            return jsonify({"error": "Threat scenario generation failed", "details": str(e)}), 500

        # Step 2: Collect threat IDs for derived scenario generation
        threat_ids = []
        try:
            # details comes from threat_data["scenarios"]["Details"]
            for threat in details:
                for item in threat.get("Details", []):
                    for prop in item.get("props", []):
                        # FIX 2: use ref_threat_id (exact reference JSON ID) with
                        # fallback to prop["id"] so nothing is silently dropped
                        threat_ids.append({
                            "nodeId": item["nodeId"],
                            "propId": prop.get("ref_threat_id") or prop.get("id"),
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

        response_data = {
            "message": "Threat scenarios created successfully",
            "threat_scenarios": threat_data,
            "derived_threat_scenarios": derived_response_json,
            # "timing": {
            #     "threat_generation_sec": round(threat_generation_time, 2),
            #     "derived_generation_sec": round(derived_generation_time, 2),
            #     "total_sec": round(total_time, 2)
            # }
        }
        
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
    """Generate attack trees with reference extraction + LLM extras pattern."""
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        model_id = data.get('modelId', '')
        user_prompt = data.get('attackscenarioPrompt', '')
        system_name = data.get('systemName', '')
        
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        # ── Load threat scenarios ──────────────────────────────────────────
        user_defined_ts = list(
            db.Threat_scenarios.find({
                "model_id": model_id,
                "type": "User-defined"
            })
        )

        if not user_defined_ts:
            return jsonify({"error": "No user-defined threat scenarios found"}), 404

        # ── Pull reference data ──────────────────────────────────────────
        from app.v1.rag.components import resolve_ecu, resolve_reference_report
        from app.v1.rag.azure_client import get_azure_client
        from app.v1.rag.config import AZURE_PATHS
        import copy

        reference_data = None
        
        # Try bms_1.json first
        try:
            client = get_azure_client()
            reports_path = AZURE_PATHS["REPORTS_PATH"].rstrip('/')
            bms_1_blob = f"{reports_path}/bms_1.json"
            reference_data = client.download_json(bms_1_blob)
            if reference_data:
                print("  ✅ Loaded bms_1.json for attack tree reference")
        except Exception as e:
            print(f"  ⚠️ Could not pull bms_1.json: {e}")

        if not reference_data and system_name:
            ecu_entry = resolve_ecu(system_name)
            reference_data = resolve_reference_report(ecu_entry, system_name)

        # ── Extract existing attack trees from reference ───────────────────
        existing_attack_trees = []
        existing_attacks = []
        
        if reference_data and "Attacks" in reference_data:
            for attack_block in reference_data["Attacks"]:
                attack_type = attack_block.get("type", "")
                
                if attack_type == "attack_trees":
                    for scene in attack_block.get("scenes", []):
                        scene_copy = copy.deepcopy(scene)
                        if "templates" in scene_copy:
                            node_id_mapping = {}
                            for node in scene_copy["templates"].get("nodes", []):
                                old_id = node.get("id", "")
                                new_id = str(uuid.uuid4())
                                node_id_mapping[old_id] = new_id
                                node["id"] = new_id
                                if "nodeId" in node:
                                    node["nodeId"] = new_id
                            for edge in scene_copy["templates"].get("edges", []):
                                if edge.get("source") in node_id_mapping:
                                    edge["source"] = node_id_mapping[edge["source"]]
                                if edge.get("target") in node_id_mapping:
                                    edge["target"] = node_id_mapping[edge["target"]]
                        existing_attack_trees.append(scene_copy)
                
                elif attack_type == "attack":
                    for scene in attack_block.get("scenes", []):
                        existing_attacks.append(copy.deepcopy(scene))

        print(f"  ✅ Extracted {len(existing_attack_trees)} attack trees and {len(existing_attacks)} attacks from reference")

        # ── Check if we have uncovered scenarios that need LLM ────────────
        covered_names = set()
        for tree in existing_attack_trees:
            name = tree.get("Name", "").lower().strip()
            covered_names.add(name)

        uncovered_ts = []
        for ts_block in user_defined_ts:
            for detail in ts_block.get("Details", []):
                name = detail.get("name", "").strip()
                if name and name.lower() not in covered_names:
                    uncovered_ts.append(detail)

        print(f"  ℹ️  {len(uncovered_ts)} uncovered threat scenarios out of {sum(len(ts.get('Details', [])) for ts in user_defined_ts)}")

        # ⚡ CRITICAL FIX: Skip LLM if no uncovered scenarios
        if not uncovered_ts and existing_attack_trees:
            print("  ✅ All threat scenarios already covered - saving reference data only")
            
            # Save existing reference data
            existing_tree_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack_trees"})
            if existing_tree_doc:
                db.Attacks.update_one(
                    {"_id": existing_tree_doc["_id"]},
                    {"$set": {"scenes": existing_attack_trees}}
                )
            else:
                db.Attacks.insert_one({
                    "model_id": model_id,
                    "type": "attack_trees",
                    "scenes": existing_attack_trees
                })

            existing_attack_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack"})
            if existing_attack_doc:
                db.Attacks.update_one(
                    {"_id": existing_attack_doc["_id"]},
                    {"$set": {"scenes": existing_attacks}}
                )
            else:
                db.Attacks.insert_one({
                    "model_id": model_id,
                    "type": "attack",
                    "scenes": existing_attacks
                })

            return jsonify({
                "message": "Attack trees loaded from reference (all scenarios already covered)",
                "model_id": model_id,
                "stats": {
                    "total_trees": len(existing_attack_trees),
                    "from_reference": len(existing_attack_trees),
                    "new_from_llm": 0,
                    "total_attacks": len(existing_attacks),
                    "from_reference_attacks": len(existing_attacks),
                    "new_attacks": 0,
                    "skipped_llm": True
                }
            }), 200

        # ── Generate extras via LLM for uncovered scenarios ───────────────
        new_attack_trees = []
        new_attacks = []
        
        if uncovered_ts:
            print(f"  🤖 Calling LLM for {len(uncovered_ts)} uncovered scenarios...")
            llm_start = time.time()
            
            # Use the faster gemini_client directly instead of pipeline
            prompt = build_attack_tree_prompt(
                system_name=system_name or "Automotive ECU System",
                uncovered_ts=uncovered_ts,
                architecture=assets_doc.get("template", {}) if (assets_doc := db.Assets.find_one({"model_id": model_id})) else {},
                existing_count=len(existing_attack_trees)
            )
            
            try:
                gemini_response = gemini_client.generate_content(prompt)
                content_text = gemini_client.get_text(gemini_response)
                
                # Better JSON cleaning
                content_text = content_text.strip()
                # Remove any non-JSON prefix
                json_start = content_text.find('{')
                if json_start > 0:
                    content_text = content_text[json_start:]
                json_end = content_text.rfind('}')
                if json_end > 0:
                    content_text = content_text[:json_end + 1]
                    
                cleaned = re.sub(r"```[a-z]*\n?", "", content_text).strip()
                attack_data = json.loads(cleaned)
                
                for tree in attack_data.get("attack_trees", []):
                    if "templates" in tree:
                        tree["templates"] = structure_attack_tree_templates(
                            tree["templates"],
                            processed_scenarios=preprocess_threat_scenarios(list(db.Threat_scenarios.find({"model_id": model_id, "type": "derived"})))
                        )
                    tree["ID"] = str(uuid.uuid4())
                    new_attack_trees.append(tree)
                
                for attack in attack_data.get("attacks", []):
                    attack["ID"] = str(uuid.uuid4())
                    if "Attack Feasibilities Rating" not in attack:
                        attack["Attack Feasibilities Rating"] = calculate_attack_feasibility(attack)
                    new_attacks.append(attack)
                    
                print(f"  ✅ LLM generated {len(new_attack_trees)} trees in {time.time() - llm_start:.2f}s")
                
            except Exception as e:
                print(f"  ⚠️ LLM failed after {time.time() - llm_start:.2f}s: {e}")
                print(f"  📝 Saving reference data only (LLM extras failed)")
                # Don't generate fallback trees - they're usually poor quality
                # Just save the reference data

        # ── Combine and save ────────────────────────────────────────────────
        combined_trees = existing_attack_trees + new_attack_trees
        combined_attacks = existing_attacks + new_attacks

        # Save to database
        existing_tree_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack_trees"})
        if existing_tree_doc:
            db.Attacks.update_one(
                {"_id": existing_tree_doc["_id"]},
                {"$set": {"scenes": combined_trees}}
            )
        else:
            db.Attacks.insert_one({
                "model_id": model_id,
                "type": "attack_trees",
                "scenes": combined_trees
            })

        existing_attack_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack"})
        if existing_attack_doc:
            db.Attacks.update_one(
                {"_id": existing_attack_doc["_id"]},
                {"$set": {"scenes": combined_attacks}}
            )
        else:
            db.Attacks.insert_one({
                "model_id": model_id,
                "type": "attack",
                "scenes": combined_attacks
            })

        return jsonify({
            "message": "Attack trees generated successfully",
            "model_id": model_id,
            "stats": {
                "total_trees": len(combined_trees),
                "from_reference": len(existing_attack_trees),
                "new_from_llm": len(new_attack_trees),
                "total_attacks": len(combined_attacks),
                "from_reference_attacks": len(existing_attacks),
                "new_attacks": len(new_attacks)
            }
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error in attack tree generation": str(e)}), 500


def build_attack_tree_prompt(system_name, uncovered_ts, architecture, existing_count):
    """Build a simplified prompt for attack tree generation."""
    return f"""
You are a Red-Team automotive cybersecurity expert performing ISO 21434 TARA analysis.

SYSTEM: {system_name}

ARCHITECTURE COMPONENTS:
{json.dumps([n.get('data', {}).get('label', '') for n in architecture.get('nodes', []) if n.get('type') != 'group'], indent=2)}

UNCOVERED THREAT SCENARIOS (need attack trees):
{json.dumps(uncovered_ts, indent=2)}

TASK:
Generate attack trees for THESE SPECIFIC threat scenarios. 
Create {min(len(uncovered_ts), 3)} attack trees with realistic automotive attack vectors.

REQUIREMENTS:
1. Root node = threat scenario name
2. Include OR Gates connecting attack vectors
3. Attack vectors should target SPECIFIC components from the architecture
4. Use realistic methods: CAN injection, JTAG/SWD exploitation, firmware tampering, SPI MITM, etc.

OUTPUT FORMAT - Return ONLY valid JSON:
{{
  "attack_trees": [
    {{
      "ID": "uuid",
      "Name": "Attack Tree Name",
      "threat_id": "",
      "templates": {{
        "nodes": [...],
        "edges": [...]
      }}
    }}
  ],
  "attacks": [
    {{
      "ID": "uuid",
      "Name": "Attack Name",
      "Elapsed Time": "<= 1 week",
      "Expertise": "Proficient",
      "Knowledge of the Item": "Restricted information",
      "Window of Opportunity": "Moderate",
      "Equipment": "Specialized"
    }}
  ]
}}
"""


def generate_simple_attack_tree(ts_detail, processed_scenarios):
    """
    Generate a simple default attack tree when LLM fails.
    """
    ts_name = ts_detail.get("name", "Attack Scenario")
    ts_id = ts_detail.get("id", str(uuid.uuid4()))
    
    root_id = str(uuid.uuid4())
    gate_id = str(uuid.uuid4())
    event1_id = str(uuid.uuid4())
    event2_id = str(uuid.uuid4())
    
    nodes = [
        {
            "id": root_id,
            "type": "default",
            "position": {"x": 592, "y": -113},
            "data": {
                "label": f"[{ts_name}]",
                "nodeId": root_id,
                "nodeType": "derived",
                "connections": [{"id": gate_id, "type": "OR Gate"}],
                "style": {
                    "backgroundColor": "transparent",
                    "borderColor": "black",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "color": "black",
                    "fontFamily": "Inter",
                    "fontSize": "16px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "height": 60,
                    "textAlign": "center",
                    "textDecoration": "none",
                    "width": 150
                }
            },
            "width": 150,
            "height": 60,
            "nodeType": "derived",
            "threat_ids": []
        },
        {
            "id": gate_id,
            "type": "OR Gate",
            "position": {"x": 617, "y": 126},
            "data": {
                "label": "OR Gate",
                "connections": [],
                "style": {
                    "borderColor": "black",
                    "borderRadius": "8px",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "boxShadow": "0 2px 6px rgba(0,0,0,0.1)",
                    "color": "white",
                    "fontFamily": "Inter",
                    "fontSize": "16px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "padding": "8px 12px",
                    "textAlign": "center",
                    "textDecoration": "none"
                }
            },
            "width": 100,
            "height": 100
        },
        {
            "id": event1_id,
            "type": "Event",
            "position": {"x": 290, "y": 256},
            "data": {
                "label": "Hardware Attack Vector",
                "connections": [],
                "style": {
                    "borderColor": "black",
                    "borderRadius": "8px",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "boxShadow": "0 2px 6px rgba(0,0,0,0.1)",
                    "color": "white",
                    "fontFamily": "Inter",
                    "fontSize": "16px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "padding": "8px 12px",
                    "textAlign": "center",
                    "textDecoration": "none"
                }
            },
            "width": 198,
            "height": 92
        },
        {
            "id": event2_id,
            "type": "Event",
            "position": {"x": 846, "y": 256},
            "data": {
                "label": "Network Attack Vector",
                "connections": [],
                "style": {
                    "borderColor": "black",
                    "borderRadius": "8px",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "boxShadow": "0 2px 6px rgba(0,0,0,0.1)",
                    "color": "white",
                    "fontFamily": "Inter",
                    "fontSize": "16px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "padding": "8px 12px",
                    "textAlign": "center",
                    "textDecoration": "none"
                }
            },
            "width": 198,
            "height": 92
        }
    ]
    
    edges = [
        {
            "id": f"{root_id}-{gate_id}",
            "source": root_id,
            "target": gate_id,
            "type": "step",
            "markerEnd": {"color": "black", "height": 20, "type": "arrowclosed", "width": 20},
            "style": {"stroke": "#808080"}
        },
        {
            "id": f"{gate_id}-{event1_id}",
            "source": gate_id,
            "target": event1_id,
            "type": "step",
            "markerEnd": {"color": "black", "height": 20, "type": "arrowclosed", "width": 20},
            "style": {"stroke": "#808080"}
        },
        {
            "id": f"{gate_id}-{event2_id}",
            "source": gate_id,
            "target": event2_id,
            "type": "step",
            "markerEnd": {"color": "black", "height": 20, "type": "arrowclosed", "width": 20},
            "style": {"stroke": "#808080"}
        }
    ]
    
    return {
        "ID": str(uuid.uuid4()),
        "Name": ts_name,
        "threat_id": ts_id,
        "templates": {
            "nodes": nodes,
            "edges": edges
        },
        "damage_id": "",
        "threat_key": "",
        "overall_rating": ""
    }


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


def convert_possible_events_internal(model_id, user_prompt=None):
    """
    Internal function for converting possible events without Flask Response overhead.
    """
    attack_trees_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack_trees"})
    if not attack_trees_doc:
        return {"message": "No attack_trees found to convert", "converted": 0}

    attack_trees = attack_trees_doc.get("scenes", [])
    if not attack_trees:
        return {"message": "No attack trees to convert", "converted": 0}

    try:
        possible_events = filter_possible_events_with_gemini(attack_trees, model_id, user_prompt)
        convert_possible_events(possible_events, model_id)
        return {"message": "Possible events converted successfully", "converted": len(possible_events)}
    except Exception as e:
        print(f"  ⚠️ Event conversion warning: {e}")
        return {"message": f"Event conversion completed with warnings", "converted": 0}


def generate_cybersecurity_artifacts_internal(model_id, system_name, user_prompt=None):
    """
    Internal function for generating cybersecurity artifacts.
    """
    try:
        # Check if already have cybersecurity data
        existing = list(db.Cybersecurity.find({"model_id": model_id}))
        if existing:
            return {"message": "Cybersecurity artifacts already exist", "existing_count": len(existing)}

        default_prompt = f"""
            You are an expert in cybersecurity engineering (ISO/SAE 21434).
            Generate cybersecurity_requirements, cybersecurity_controls, cybersecurity_goals,
            and cybersecurity_claims for the system '{system_name}'.
            Return ONLY valid JSON.
            """

        data_structure_prompt = """
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
            """

        final_prompt = (user_prompt or default_prompt) + data_structure_prompt

        gemini_response = gemini_client.generate_content(final_prompt)
        content_text = gemini_client.get_text(gemini_response)

        cleaned = content_text.strip().strip("`").strip("json").strip()
        cleaned = extract_json_block(cleaned)
        all_scenes = json.loads(cleaned)

        response = {}
        for artifact_type in [
            "cybersecurity_requirements",
            "cybersecurity_controls",
            "cybersecurity_claims",
            "cybersecurity_goals"
        ]:
            scenes_obj = all_scenes.get(artifact_type, {})
            scenes = scenes_obj.get("scenes", [])
            
            doc = {
                "model_id": model_id,
                "type": artifact_type,
                "scenes": scenes
            }
            
            result = db.Cybersecurity.insert_one(doc)
            doc["_id"] = str(result.inserted_id)
            response[artifact_type] = doc

        return response
    except Exception as e:
        print(f"  ⚠️ Cybersecurity generation warning: {e}")
        return {"message": "Cybersecurity generation skipped", "error": str(e)}


# Full attack scenario pipeline
@modelprompt.route('/v1/generate/full-attack-scenario', methods=['POST'])
def generate_full_attack_pipeline():
    """
    Full attack scenario pipeline - optimized version.
    Skips LLM call if all scenarios are covered by reference data.
    """
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        model_id = data.get('modelId', '')
        system_name = data.get('systemName', '')
        user_prompt = data.get('attackscenarioPrompt', '')

        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        print(f"\n=== [FULL ATTACK PIPELINE] STARTED for model {model_id} ===")
        total_start = time.time()
        
        # Step 1: Generate attack trees (this now handles reference extraction internally)
        t1 = time.time()
        attack_tree_response = generate_attack_tree()
        attack_tree_time = time.time() - t1
        
        # Extract data from response
        if hasattr(attack_tree_response, 'get_json'):
            attack_tree_data = attack_tree_response.get_json()
            attack_tree_status = attack_tree_response.status_code
        else:
            attack_tree_data = attack_tree_response[0].get_json() if isinstance(attack_tree_response, tuple) else attack_tree_response
            attack_tree_status = 200
        
        print(f"[TIMING] Attack tree generation took {attack_tree_time:.2f}s")
        
        if attack_tree_status != 200:
            return attack_tree_response, attack_tree_status

        # Step 2: Convert possible events to cybersecurity requirements
        t2 = time.time()
        convert_result = convert_possible_events_internal(model_id, user_prompt)
        convert_time = time.time() - t2
        print(f"[TIMING] Event conversion took {convert_time:.2f}s")

        # Step 3: Generate cybersecurity artifacts
        t3 = time.time()
        cyber_result = generate_cybersecurity_artifacts_internal(model_id, system_name, user_prompt)
        cyber_time = time.time() - t3
        print(f"[TIMING] Cybersecurity generation took {cyber_time:.2f}s")

        total_time = time.time() - total_start
        print(f"=== [FULL ATTACK PIPELINE] FINISHED in {total_time:.2f}s ===\n")

        return jsonify({
            "message": "Full attack pipeline executed successfully",
            "attack_tree_data": attack_tree_data,
            "converted_events": convert_result,
            "cybersecurity_data": cyber_result,
            "timing": {
                "attack_tree_sec": round(attack_tree_time, 2),
                "convert_events_sec": round(convert_time, 2),
                "cybersecurity_sec": round(cyber_time, 2),
                "total_sec": round(total_time, 2)
            }
        }), 200

    except Exception as e:
        traceback.print_exc()
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
        scenarios_response = create_damage_scenarios_with_rag(
            standalone=True,
            request_data=type('', (), {'form': scenario_request, 'is_json': False})()
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