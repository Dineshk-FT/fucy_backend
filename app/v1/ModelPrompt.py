from flask import Blueprint, request, jsonify, current_app
import ast
import json
import re
from db import db
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
from app.v1.RiskDeterminationAndTreatment import add_risk_treatment
from app.Methods.helpers import build_full_edge, build_basic_node,calculate_node_positions,structure_attack_tree_templates,AttackTableoptions,threat_type,safe_json_parse
from app.v1.gemini import GeminiClient
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

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


modelprompt = Blueprint("modelprompt", __name__)
gemini_client = GeminiClient(os.getenv("GOOGLE_API_KEY"), os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))


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
        prompt = build_prompt(system_name, user_prompt)
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
    """Generate ReactFlow template - can be called as route or function"""
    try:
        if not request_data:
            request_data = request

        # Static fields
        user_id = request.headers.get("user-id")
        created_by = request_data.form.get("createdBy", "system")
        system_name = request_data.form.get("systemName", "Test System")

        # Optional user-provided descriptive prompt (above data structure)
        custom_prompt = request_data.form.get("itemDefinitionPrompt")

        # Dynamically collect all other form fields (excluding static + prompt)
        static_fields = {"createdBy", "systemName", "prompt"}
        dynamic_fields = {
            key: request_data.form.get(key)
            for key in request_data.form
            if key not in static_fields
        }

        # Convert dynamic fields into prompt format
        dynamic_prompt_lines = "\n".join([
            f"{key.replace('_', ' ').title()}: {value}"
            for key, value in dynamic_fields.items()
        ])

        # --- Default description (above Data structure) ---
        default_description = """
            You are an automotive cybersecurity engineer following ISO/SAE 21434 standards.  
            Your task is to create a detailed **Item Definition** and an accompanying **System Diagram** for performing a Threat Analysis and Risk Assessment (TARA).  
            The output must follow the structure defined in ISO/SAE 21434 Clause 9.4 (Item Definition) and should include:

            1. **Item Name** - The name of the system or feature.
            2. **Item Purpose** - The high-level purpose and intended functionality.
            3. **Operational Description** - How the item operates, key functions, and operational scenarios.
            4. **Boundaries of the Item** - What is inside and outside the scope (physical and logical boundaries).
            5. **Interfaces** - All relevant physical, data, and network interfaces.
            6. **Assumptions and Constraints** - Any limitations, regulations, or environmental conditions.
            7. **Dependencies** - Dependencies on other systems or components.
            8. **Stakeholders** - Relevant stakeholders (OEM, supplier, regulator, user, etc.).
            9. **System Diagram** - A block diagram showing major components, interfaces, and external connections.

            **Requirements for the System Diagram**:
            - Clearly identify ECUs, sensors, actuators, communication buses, and external entities (e.g., cloud services, mobile apps).
            - Use clear labels for each component and interface.
            - Show data flows and connection types (wired, wireless, CAN, Ethernet, Bluetooth, etc.).
            - Represent external systems and boundaries distinctly.

            **Constraints:**
            - Follow ISO/SAE 21434 terminology.
            - Keep the description technology-neutral unless otherwise specified.
            - Ensure the diagram supports later TARA steps such as asset identification, threat scenario development, and impact analysis.

            Now, generate the Item Definition and System Diagram for the following automotive system:
            """

        # --- Mandatory Data structure section ---
        data_structure_section = """
            (For Data structure)
            Include :
            - Nodes must have: id, type ("default" or "group"), data.label, properties.
            - Edges must have: id, type ("step"), source, target, sourceHandle, targetHandle, data.label, properties.
            - A node's properties must be a list of one or more of the following: Integrity, Confidentiality, Authenticity, Availability, Non-repudiation, Authorization. Properties must contain only one of the following: Integrity, Confidentiality, Authenticity, Availability, Non-repudiation, Authorization.

            Constraints:
            - If multiple related nodes exist, create possible group node to contain them.
            - Do not include position information - positions will be calculated automatically.
            - Specify parent-child relationships using parentId where applicable.

            Example:
            {
            "nodes": [
                {
                "id": "1",
                "type": "default",
                "data": {"label": "BMU"},
                "properties": ["Confidentiality"]
                }
            ],
            "edges": [
                {
                "id": "e1-2",
                "type": "step",
                "source": "1",
                "target": "2",
                "sourceHandle": "bottom",
                "targetHandle": "top",
                "data": {"label": "CAN"},
                "properties": ["Integrity"]
                }
            ]
            }
            """

        # --- Final prompt assembly ---
        prompt = f"""
            Return ONLY valid JSON for a React Flow diagram for the system below:

            {custom_prompt if custom_prompt else default_description}

            System Name: {system_name}
            {dynamic_prompt_lines}

            {data_structure_section}
            """

        # Call Gemini
        response = gemini_client.generate_content(prompt)
        output = gemini_client.get_text(response).strip()
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")

        # Parse JSON
        try:
    # Remove JS-style comments before parsing
            cleaned_no_comments = re.sub(r'//.*', '', cleaned)
            data = json.loads(cleaned_no_comments)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON from Gemini: {e}\nRaw: {cleaned}")

        if 'templates' in data:
            minimal_nodes = data['templates']['nodes']
            minimal_edges = data['templates']['edges']
        elif 'nodes' in data and 'edges' in data:
            minimal_nodes = data['nodes']
            minimal_edges = data['edges']
        else:
            raise ValueError("Invalid response format from Gemini")

        # Build full template
        full_nodes = [build_basic_node(n) for n in minimal_nodes]
        positioned_nodes = calculate_node_positions(full_nodes)
        full_edges = [build_full_edge(e) for e in minimal_edges]

        final_result = {
            "nodes": positioned_nodes,
            "edges": full_edges
        }

        # Store model
        current = datetime.now()
        model_doc = {
            "name": system_name,
            "template": [],
            "created_by": created_by,
            "created_at": current,
            "last_updated": current,
            "user_id": user_id,
            "status": 1,
            "type": "model"
        }
        result = db.Models.insert_one(model_doc)
        # print("result",result)
        model_id = str(result.inserted_id)

        # Store asset
        Derivations, Details = getDerivationsAndDetails(final_result)
        db.Assets.insert_one({
            "model_id": model_id,
            "template": final_result,
            "asset_name": f"{system_name}-asset",
            "asset_properties": "",
            "Details": Details
        })

        db.Damage_scenarios.update_one(
            {"model_id": model_id, "type": "Derived"},
            {
                "$set": {
                    "model_id": model_id,
                    "type": "Derived",
                    "Derivations": Derivations,
                    "Details": Details
                }
            },
            upsert=True
        )

        result_data = {
            "message": "Template generated and stored successfully",
            "model_id": model_id,
            "template": final_result,
            "system_name": system_name
        }

        if standalone:
            return result_data
        return current_app.response_class(
            response=json.dumps(result_data, cls=JSONEncoder),
            status=201,
            mimetype='application/json'
        )

    except Exception as e:
        if standalone:
            raise e
        return jsonify({"error in item definition": str(e)}), 500

#3 - Damage scenario creation
def generate_object_id():
    """Generate MongoDB-style ObjectId"""
    return ''.join(random.choices(string.hexdigits.lower(), k=24))

# Wrapper Flask endpoint
@modelprompt.route('/v1/generate/damage-scenarios', methods=['POST'])
def create_damage_scenarios(standalone=False, request_data=None):
    """Core function to generate damage scenarios (can be called standalone or as route)"""
    try:
        req_data = request_data if request_data else request

        model_id = req_data.form.get('modelId')
        system_name = req_data.form.get('systemName', '')
        template_raw = req_data.form.get('template', '{}')
        user_prompt = req_data.form.get('damageScenarioPrompt', '')  # 👈 Optional user prompt

        if not model_id:
            if standalone:
                raise ValueError("modelId is required")
            return jsonify({"error": "modelId is required"}), 400

        # Parse template safely
        try:
            template = json.loads(template_raw) if template_raw else {}
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid template JSON"}), 400

        print("DEBUG: Parsed template:", template)

        # Build default prompt
        default_prompt = f"""
            Generate exactly 2 damage scenarios for the '{system_name}' system in JSON format.

            System Components:
            {json.dumps(template.get('nodes', []), indent=2)}

            Relationships:
            {json.dumps(template.get('edges', []), indent=2)}

            Requirements:
            1. Create different scenarios targeting different critical components
            2. Each MUST include:
            - Damage scenario details
            - Realistic cyber losses (integrity/confidentiality/availability)
            - Plausible impact ratings (Major/Moderate/Minor)
            """

        prompt_intro = user_prompt if user_prompt else default_prompt

        prompt = f"""
        {prompt_intro}

        (for Data structure)
        Use EXACTLY this structure:
        {{
        "system_name": "{system_name}",
        "model_id": "{model_id}",
        "type": "User-defined",
        "Details": [
            {{
            "Description": "damage scenario description",
            "Name": "damage scenario name",
            "cyberLosses": [
                {{
                "id": "uuid",
                "name": "loss type",
                "isSelected": true,
                "node": "component name",
                "nodeId": "component_id"
                }}
            ],
            "impacts": {{
                "Financial Impact": "(Severe/Major/Moderate/Minor/Negligible)",
                "Safety Impact": "(Severe/Major/Moderate/Minor/Negligible)",
                "Operational Impact": "(Severe/Major/Moderate/Minor/Negligible)",
                "Privacy Impact": "(Severe/Major/Moderate/Minor/Negligible)"
            }},
            "key": 1,
            "_id": "scenario_id"
            }}
        ]
        }}
        """

        print("DEBUG: Final Prompt Sent to Model:\n", prompt)

        response = gemini_client.generate_content(prompt)
        raw_output = gemini_client.get_text(response).strip()
        print("DEBUG: Raw AI Output:", raw_output)

        cleaned = re.sub(r"```[a-z]*", "", raw_output).strip("` \n")
        scenarios = json.loads(cleaned)
        scenarios["model_id"] = model_id

        # Ensure _id and key are assigned
        for i, detail in enumerate(scenarios.get("Details", []), start=1):
            detail["_id"] = detail.get("_id", str(uuid.uuid4()))
            detail["key"] = detail.get("key", i)
            for loss in detail.get("cyberLosses", []):
                loss["id"] = loss.get("id", str(uuid.uuid4()))
                loss["isSelected"] = loss.get("isSelected", True)

        # Insert into DB
        damage_result = db.Damage_scenarios.insert_one(scenarios)

        # Convert ObjectIds to strings for safe JSON serialization
        def convert_objectid(obj):
            if isinstance(obj, ObjectId):
                return str(obj)
            if isinstance(obj, list):
                return [convert_objectid(i) for i in obj]
            if isinstance(obj, dict):
                return {k: convert_objectid(v) for k, v in obj.items()}
            return obj

        safe_scenarios = convert_objectid(scenarios)

        result = {
            "message": "Damage scenarios created successfully",
            "scenario_id": str(damage_result.inserted_id),
            "model_id": model_id,
            "scenarios": safe_scenarios,
        }

        if standalone:
            return result
        return jsonify(result), 201

    except json.JSONDecodeError as e:
        print("ERROR: JSON Decode Error:", str(e))
        traceback.print_exc()
        if standalone:
            raise ValueError("Invalid response format from AI")
        return jsonify({"error": "Invalid response format from AI", "details": str(e)}), 500

    except Exception as e:
        print("ERROR: Unexpected Exception:", str(e))
        traceback.print_exc()
        if standalone:
            raise
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500


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

        # 🔄 Replace existing derived threat scenarios for this model_id
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

    # Default intro part
    default_intro = f"""
        You are a cybersecurity expert. Based on the following related threats, generate a meaningful name and a concise description for a derived threat scenario. Do not use generic names like "Derived Threat Scenario".

        Here are the threats:
        {json.dumps(threat_group, indent=2)}
        """

    # Use user prompt if provided, else fallback
    prompt_intro = user_prompt if user_prompt else default_intro

    # Mandatory Data structure part
  # Mandatory Data structure part
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

    # Call Gemini
    gemini_response = gemini_client.generate_content(prompt)
    try:
        content_text = gemini_client.get_text(gemini_response)

        # Extract only the JSON part
        cleaned = extract_json_from_text(content_text)

        # Remove control chars
        cleaned = re.sub(r'[\x00-\x1F\x7F]', '', cleaned)

        # Repair common JSON issues
        cleaned = cleaned.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")  # remove code fences
        cleaned = re.sub(r",\s*}", "}", cleaned)  # remove trailing commas before }
        cleaned = re.sub(r",\s*]", "]", cleaned)  # remove trailing commas before ]

        parsed = json.loads(cleaned)

        # 🛠 Ensure description is always a string
        description = parsed.get("description", "")
        if not isinstance(description, str):
            # Convert list/dict → readable string
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
        # 🛠 Guarantee string description
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

            # 🛠 Guarantee string description
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
        # 🔄 Replace existing document for this model_id OR insert if not exists
        db.Threat_scenarios.replace_one(
            {"model_id": model_id, "type": "User-defined"},
            document,
            upsert=True
        )

        # Fetch the replaced document with _id
        saved_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        saved_doc["_id"] = str(saved_doc["_id"])
        return saved_doc

    return {}


@modelprompt.route('/v1/generate/derived-threat-scenarios', methods=['POST'])
def create_derived_threat_scenario():
    try:
        name = request.form.get('name', "")
        description = request.form.get('description', "")
        model_id = request.form.get('modelId', "")
        user_prompt = request.form.get('threatScenarioPrompt', "")
        threat_ids_raw = request.form.get('threatIds', "[]")

        threat_ids = json.loads(threat_ids_raw)

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

        model_id = request.form.get('modelId', "")
        name = request.form.get('name', "")
        description = request.form.get('description', "")
        user_prompt = request.form.get('threatScenarioPrompt', "")

        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        print(f"\n=== [COMBINED API] STARTED for model {model_id} ===")

        # 1️⃣ STEP 1: Threat Scenario Generation
        t1 = time.time()
        threat_response, status_code = create_threat_scenarios(model_id)
        print(f"[TIMING] Threat scenario generation took {time.time() - t1:.2f}s")

        if status_code != 201:
            print("[ERROR] Threat scenario generation failed")
            return threat_response, status_code

        threat_data = threat_response.get_json()
        print(f"[DEBUG] Threat scenarios created: {len(threat_data.get('scenarios', {}).get('Details', []))}")

        # Extract threat IDs
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

        # 2️⃣ STEP 2: Derived Threat Scenario Generation (AI Call)
        derived_response_json = None
        derived_status = 500

        t2 = time.time()
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
    
    
#5 - Attack Scenarion Creation
# generate Attack Tree
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
                        "rowId": row_id,                       # still keep rowId for damage link
                        "scenario_name": d.get("name", ""),
                        "node": d.get("node", ""),
                        "nodeId": d.get("nodeId", ""),
                        "property": prop.get("name", ""),
                        "threat_id": prop.get("id"),           # <-- use this instead of rowId
                        "threat_key": f"TS{prop.get('key', 0):03}"
                    })
    return processed

def generate_attack_trees_with_gemini(threat_scenarios, model_id, user_prompt=None):
    """
    Given a list of threat_scenarios and a model_id, call Gemini to generate attack trees.
    If user_prompt is provided, it replaces the default natural language instructions
    but still keeps the same JSON data structure format.
    """
    # --- Default Natural Language Prompt ---
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

    # --- Data Structure Format Prompt ---
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

    # Use user prompt if provided, otherwise fallback to default
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
        # 1. Get model_id from request
        model_id = request.form.get('modelId', '')
        user_prompt = request.form.get('attackscenarioPrompt', '')
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        # 2. Fetch all derived threat scenarios for this model_id
        threat_scenarios = list(
            db.Threat_scenarios.find({
                "model_id": model_id,
                "type": "derived"
            })
        )

        if not threat_scenarios:
            return jsonify({"error": "No derived threat scenarios found"}), 404

        # 3. Preprocess for Gemini
        processed_scenarios = preprocess_threat_scenarios(threat_scenarios)

        # 4. Generate attack trees using Gemini
        try:
            attack_tree_data = generate_attack_trees_with_gemini(processed_scenarios, model_id, user_prompt)
        except Exception as e:
            return jsonify({"error": f"Failed to generate attack trees: {str(e)}"}), 500

        # 5. Save all scenes into a single document in DB
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
                "threat_id": scene.get("threat_id"),   # now this comes from props id
                "templates": structured_templates
            })


                # print("scenes", scenes)
                # return jsonify(scenes), 200
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

        # 6. Return the generated attack trees
        return jsonify(attack_tree_data), 200

    except Exception as e:
        return jsonify({"error in attack tree": str(e)}), 500

# Attacks
# Map ratings from AttackTableoptions for quick lookup
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

    # Match frontend logic
    if 0 <= total_rating <= 13:
        return "High"
    elif 14 <= total_rating <= 19:
        return "Medium"
    elif 20 <= total_rating <= 24:
        return "Low"
    else:
        return "Very low"


# Attacks creattion
def generate_possible_attacks_with_gemini(threat_scenarios, model_id, user_prompt=None):
    """
    Given derived threat scenarios, generate possible attacks for each scenario using Gemini.
    Returns parsed JSON without rating; rating is computed here.
    If user_prompt is provided, it replaces the default instructions,
    while the JSON data structure format remains unchanged.
    """

    options = {
        "Elapsed Time": [opt["value"] for opt in AttackTableoptions["Elapsed Time"]],
        "Expertise": [opt["value"] for opt in AttackTableoptions["Expertise"]],
        "Knowledge of the Item": [opt["value"] for opt in AttackTableoptions["Knowledge of the Item"]],
        "Window of Opportunity": [opt["value"] for opt in AttackTableoptions["Window of Opportunity"]],
        "Equipment": [opt["value"] for opt in AttackTableoptions["Equipment"]],
    }

    # --- Default Instructions ---
    default_prompt = f"""
        You are an expert in cyber threat analysis.  
        For each of the following derived threat scenarios, create one realistic possible attack.

        """

    # --- Data Structure Prompt ---
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

    # Use user prompt if provided, otherwise fallback to default
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
        # 1. Get model_id
        model_id = request.form.get('modelId', '')
        user_prompt = request.form.get('attackscenarioPrompt', '')
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        # 2. Fetch derived threat scenarios
        threat_scenarios = list(
            db.Threat_scenarios.find({
                "model_id": model_id,
                "type": "derived"
            })
        )
        if not threat_scenarios:
            return jsonify({"error": "No derived threat scenarios found"}), 404

        # 3. Preprocess for Gemini
        processed_scenarios = preprocess_threat_scenarios(threat_scenarios)

        # 4. Generate attacks (no rating yet)
        attack_data = generate_possible_attacks_with_gemini(processed_scenarios, model_id, user_prompt)

        # 5. Compute ratings
        for scene in attack_data.get("scenes", []):
            scene["Attack Feasibilities Rating"] = calculate_attack_feasibility(scene)

        # 6. Save to DB
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

        # 7. Return results
        return jsonify(attack_data), 200

    except Exception as e:
        return jsonify({"error in attacks": str(e)}), 500


# convertion of events to attack and requirements
def filter_possible_events_with_gemini(attack_trees, model_id, user_prompt=None):
    """
    Given attack_trees and model_id, call Gemini to filter out possible attack events.
    If user_prompt is provided, it replaces the default natural language instructions,
    while the JSON data structure format remains unchanged.
    """

    # --- Default Natural Language Prompt ---
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

    # --- Data Structure Prompt ---
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

    # Use user prompt if provided, otherwise fallback to default
    final_prompt = (user_prompt or default_prompt) + data_structure_prompt

    gemini_response = gemini_client.generate_content(final_prompt)

    try:
        content_text = gemini_client.get_text(gemini_response)

        # Extract JSON array in case Gemini adds explanation
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
        event_id = evt["event_id"]
        event_name = evt["event_name"]
        attack_scene_id = evt["attack_tree_scene_id"]
        attack_scene_name = evt["attack_tree_scene_name"]
        threat_id = evt.get("threat_id")
        threat_key = evt.get("threat_key")

        # ---- Insert into Attacks ----
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

        # ---- Insert into Cybersecurity Requirements ----
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
        model_id = request.form.get("modelId", "")
        user_prompt = request.form.get('attackscenarioPrompt', '')
        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        # Get attack_trees for this model
        attack_trees_doc = db.Attacks.find_one({"model_id": model_id, "type": "attack_trees"})
        if not attack_trees_doc:
            return jsonify({"error": "No attack_trees found"}), 404

        attack_trees = attack_trees_doc.get("scenes", [])

        # Ask Gemini to filter possible events
        possible_events = filter_possible_events_with_gemini(attack_trees, model_id, user_prompt)

        # Convert to Attacks + Cybersecurity Requirements
        convert_possible_events(possible_events, model_id)

        return jsonify({"message": "Possible events converted successfully", "converted": possible_events}), 200

    except Exception as e:
        return jsonify({"error in converting possible events" : str(e)}), 500
    
# Full attack scenario pipeline
@modelprompt.route('/v1/generate/full-attack-scenario', methods=['POST'])
def generate_full_attack_pipeline():
    try:
        model_id = request.form.get('modelId', '')
        user_prompt = request.form.get('attackscenarioPrompt', '')

        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        # 1️⃣ Call generate_attack_tree
        attack_tree_response, tree_status = generate_attack_tree()
        if tree_status != 200:
            return attack_tree_response, tree_status  # stop if failed

        attack_tree_data = attack_tree_response.get_json()

        # 2️⃣ Call generate_attacks
        with current_app.test_request_context(
            data={"modelId": model_id, "attackscenarioPrompt": user_prompt}
        ):
            attacks_response, attacks_status = generate_attacks()
        if attacks_status != 200:
            return attacks_response, attacks_status

        attacks_data = attacks_response.get_json()

        # 3️⃣ Call convert_possible_events_from_attack_trees
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
    # print(f"Gemini Output for {artifact_type}:", content_text)  # Debug log
    cleaned = re.sub(r"[a-z]*", "", content_text).strip().strip("`")
    cleaned = extract_json_block(cleaned)
    # print("Gemini Output (cleaned):", cleaned)
    try:
        return json.loads(cleaned)
    except Exception as e:
        print("Gemini Output (cleaned):", cleaned)
        # Return the raw output in the error for easier debugging


@modelprompt.route('/v1/generate/cybersecurity-artifacts', methods=['POST'])
def generate_cybersecurity_artifacts():
    """
    Generate and save cybersecurity requirements, controls, goals, and claims
    for a given modelId and systemName, each stored as a document in db.Cybersecurity.
    If user_prompt is provided, it replaces the default natural language instructions,
    while the JSON data structure format remains unchanged.
    """
    try:
        model_id = request.form.get('modelId', '')
        system_name = request.form.get('systemName', '')
        user_prompt = request.form.get('cybersecurityPrompt', '')

        if not model_id or not system_name:
            return jsonify({"error": "Missing modelId or systemName"}), 400

        # --- Default Instructions ---
        default_prompt = f"""
            You are an expert in cybersecurity engineering (ISO/SAE 21434).
            Generate cybersecurity_requirements, cybersecurity_controls, cybersecurity_goals, 
            and cybersecurity_claims for the system '{system_name}'.
            Return ONLY valid JSON in the format below (no explanation or extra text):
            """

        # --- Data Structure Format ---
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

        # Use user prompt if provided, otherwise fallback to default
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

            # 💾 Save to database
            result = db.Cybersecurity.insert_one(doc)
            doc["_id"] = str(result.inserted_id)  # Convert ObjectId to string
            response[artifact_type] = doc

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error in generate_cybersecurity": str(e)}), 500
    
# Risk Tremenet creation
@modelprompt.route("/v1/generate/generate-risk-treatments", methods=["POST"])
def auto_generate_risk_treatments():
    """
    Automatically generates all risk treatments for a given modelId
    using the stored Threat_scenarios collection.

    Expected form-data:
      modelId: <model_id>
    """
    try:
        model_id = request.form.get("modelId")
        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        # 🔍 Fetch threat scenarios for this model
        threat_doc = db.Threat_scenarios.find_one({"model_id": model_id, "type": "derived"})
        if not threat_doc:
            return jsonify({"error": f"No threat scenarios found for model {model_id}"}), 404

        details_list = threat_doc.get("Details", [])
        if not details_list:
            return jsonify({"error": "No threat scenario details found"}), 404

        generated_count = 0
        skipped_count = 0

        for threat in details_list:
            damage_id = threat.get("rowId")
            damage_name = threat.get("damage_name")
            damage_key = threat.get("id")  # e.g., DS001

            for item in threat.get("Details", []):
                node_id = item.get("nodeId")
                node_name = item.get("node")

                for prop in item.get("props", []):
                    if not prop.get("isSelected", False):
                        continue

                    stride_category = threat_type(prop.get("name", ""))
                    threat_key = f"TS{prop['key']:03}"

                    label = f"[{threat_key}] {stride_category} of {node_name} leads to {damage_name} [{damage_key}]"

                    # 🚀 Use existing API logic via test request context
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
    # try:
        # Generate template
        template_response = generate_reactflow_template(standalone=True, request_data=request)
        # print("Template Response:", template_response)
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

        # risk treatment
        for threat in threat_data.get("scenarios", {}).get("Details", []):
            damage_id = threat.get("rowId")
            damage_name = threat.get("damage_name")
            damage_key = threat.get("id")  # e.g., DS001, DS002

            for item in threat.get("Details", []):
                node_id = item.get("nodeId")
                node_name = item.get("name")

                for prop in item.get("props", []):
                    # Use threat_type mapper for STRIDE category
                    stride_category = threat_type(prop.get("name", ""))
                    threat_key = f"TS{prop['key']:03}"

                    # Build consistent label
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

        # Generate attack trees via Flask route
        with current_app.test_request_context(method='POST', data={'modelId': template_response['model_id'], "attackscenarioPrompt": request.form.get('attackscenarioPrompt', '')}):
            attack_response = generate_attack_tree()
            attack_tree_data = attack_response.get_json() if hasattr(attack_response, 'get_json') else {}

        with current_app.test_request_context(
            method='POST',
            data={
                "modelId":template_response['model_id'],
                "attackscenarioPrompt": request.form.get('attackscenarioPrompt', '')
            }
        ):
            possible_attacks = convert_possible_events_from_attack_trees()
        # Generate cybersecurity artifacts via test request context
        with current_app.test_request_context(
            method='POST',
            data={
                'modelId': template_response['model_id'],
                'systemName': template_response['system_name'],
                "cybersecurityPrompt": request.form.get('cybersecurityPrompt', '')
            }
        ):
            cyber_response = generate_cybersecurity_artifacts()
            # cyber_data = cyber_response.get_json() if hasattr(cyber_response, 'get_json') else {}

        with current_app.test_request_context(
            method='POST',
            data={
                "modelId":template_response['model_id'],
                "attackscenarioPrompt": request.form.get('attackscenarioPrompt', '')
            }
        ):
            attacks = generate_attacks()
            # attack_data = attacks.get_json() if hasattr(attacks, 'get_json') else {}

        return current_app.response_class(
            response=json.dumps({
                "message":"Model Generated Successfully",
                "model": template_response,
                # "attacks": attacks,
                # "threat_data": threat_data,
            }, cls=JSONEncoder),
            status=201,
            mimetype='application/json'
        )

    # except Exception as e:
    #     return jsonify({"error in generating model": str(e)}), 500


def clean_control_chars(s):
    # Remove unescaped control characters (except \n, \t if you want to keep them)
    return re.sub(r'[\x00-\x1F\x7F]', '', s)
