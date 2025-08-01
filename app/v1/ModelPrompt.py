from flask import Blueprint, request, jsonify
import google.generativeai as genai
from config import Config
import ast
import json
import re
from db import db
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
from app.Methods.helpers import build_full_edge, build_basic_node,calculate_node_positions
import random
import uuid
import string
from collections import defaultdict

modelprompt = Blueprint("modelprompt", __name__)

genai.configure(api_key=Config.GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash')

@modelprompt.route('/v1/create-model', methods=['POST'])
def generate_reactflow_template():
    try:
        # 🔹 1️⃣ Get inputs
        system_name = request.form.get('systemName', 'Test System')
        algorithms = request.form.get('algorithms', '["Algorithm 1", "Algorithm 2"]')
        communication_interfaces = request.form.get('communicationInterfaces', '["Interface 1", "Interface 2"]')
        cell_chemistry = request.form.get('cellChemistry', '["Chemistry 1", "Chemistry 2"]')

        # 🔹 2️⃣ Setup Gemini
        model = genai.GenerativeModel('gemini-2.5-flash')

        prompt = f"""
Return ONLY valid JSON for a React Flow diagram for the system below:

System Name: {system_name}
Algorithms: {algorithms}
Communication Interfaces: {communication_interfaces}
Cell Chemistry: {cell_chemistry}

Include:
  - Nodes must have: id, type ("default" or "group"), data.label, properties.
  - Edges must have: id, type ("step"), source, target, sourceHandle, targetHandle, data.label, properties.
  - Properties should contains only one of the following: Integrity, Confidentiality, Authenticity, Availability, Non-repudiation, Authorization.

Constraints:
  - If multiple related nodes exist, create at least one group node to contain them.
  - Do not include position information - positions will be calculated automatically.
  - Specify parent-child relationships using parentId where applicable.

Example:
{{
  "templates": {{
    "nodes": [
      {{
        "id": "1",
        "type": "default",
        "data": {{"label": "BMU"}},
        "properties": ["Confidentiality"]
      }},
      {{
        "id": "group-1",
        "type": "group",
        "data": {{"label": "Algorithms Group"}},
        "properties": []
      }},
      {{
        "id": "algo-1",
        "type": "default",
        "parentId": "group-1",
        "data": {{"label": "Algorithm 1"}},
        "properties": ["Integrity"]
      }}
    ],
    "edges": [
      {{
        "id": "e1-2",
        "type": "step",
        "source": "1",
        "target": "algo-1",
        "sourceHandle": "bottom",
        "targetHandle": "top",
        "data": {{"label": "CAN"}},
        "properties": ["Integrity"]
      }}
    ]
  }}
}}
"""

        # 🔹 3️⃣ Call Gemini
        response = model.generate_content(prompt)
        output = response.text.strip()
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")

        # 🔹 4️⃣ Parse minimal JSON
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            data = ast.literal_eval(cleaned)

        minimal_nodes = data["templates"]["nodes"]
        minimal_edges = data["templates"]["edges"]

        # Build full nodes first without positions
        full_nodes = [build_basic_node(n) for n in minimal_nodes]
        
        # Then calculate all positions carefully
        positioned_nodes = calculate_node_positions(full_nodes)
        
        full_edges = [build_full_edge(e) for e in minimal_edges]

        final_result = {
            "templates": {
                "nodes": positioned_nodes,
                "edges": full_edges
            }
        }

        return jsonify(final_result), 200

    except Exception as e:
        print(f"!! Final exception: {e}")
        return jsonify({"error": str(e)}), 500
    
# Damage scene creation
def generate_object_id():
    """Generate MongoDB-style ObjectId"""
    return ''.join(random.choices(string.hexdigits.lower(), k=24))


@modelprompt.route('/v1/create-damage-scene', methods=['POST'])
def generate_damage_scenarios(system_name, reactflow_template):
    """Standalone endpoint to generate AI-powered damage scenarios"""
    try:
        # 1. Validate input
        if not system_name or not reactflow_template:
            return {"error": "System name and template are required"}, 400

        # 2. Extract nodes and edges from template
        nodes = reactflow_template.get("nodes", [])
        edges = reactflow_template.get("edges", [])

        if not nodes:
            return {"error": "No nodes found in template"}, 400

        # 3. Setup AI model
        model = genai.GenerativeModel('gemini-2.5-flash')

        # 4. Create the AI prompt
        prompt = f"""
Generate exactly 2 damage scenarios for the '{system_name}' system in JSON format.
Use ONLY the structure and fields shown in the example.

System Components:
{json.dumps(nodes, indent=2)}

Relationships:
{json.dumps(edges, indent=2)}

Requirements:
1. Create TWO different scenarios targeting different critical components
2. Each MUST include:
   - Realistic cyber losses (integrity/confidentiality/availability)
   - Plausible impact ratings (Major/Moderate/Minor)
   - References to actual node IDs from components
3. Use EXACTLY this structure:
{{
  "system_name": "{system_name}",
  "model_id": "generated_model_id",
  "type": "User-defined",
  "Details": [
    {{
      "Description": "scenario description",
      "Name": "scenario name",
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
        "Financial Impact": "rating",
        "Safety Impact": "rating",
        "Operational Impact": "rating",
        "Privacy Impact": "rating"
      }},
      "key": 1,
      "_id": "scenario_id"
    }}
  ]
}}

IMPORTANT:
- Return ONLY valid JSON
- Make scenarios specific to {system_name}
- Use ACTUAL node IDs from components
- Make impact ratings realistic
"""

        # 5. Get AI response
        response = model.generate_content(prompt)
        raw_output = response.text.strip()

        # 6. Clean and parse the output
        cleaned = re.sub(r"```[a-z]*", "", raw_output).strip("` \n")
        scenarios = json.loads(cleaned)

        # 7. Add system context and generated IDs
        scenarios["system_name"] = system_name
        scenarios["_id"] = {"$oid": generate_object_id()}
        scenarios["model_id"] = scenarios.get("model_id", generate_object_id())

        for i, detail in enumerate(scenarios.get("Details", []), start=1):
            detail["_id"] = detail.get("_id", str(uuid.uuid4()))
            detail["key"] = detail.get("key", i)
            detail["impact_justification"] = detail.get("impact_justification", "")

            for loss in detail.get("cyberLosses", []):
                loss["id"] = loss.get("id", str(uuid.uuid4()))
                loss["is_risk_added"] = loss.get("is_risk_added", False)
                loss["isSelected"] = loss.get("isSelected", True)

        return scenarios, 200

    except json.JSONDecodeError:
        return {"error": "Failed to parse AI response"}, 500
    except Exception as e:
        return {"error": f"Scenario generation failed: {str(e)}"}, 500


# Wrapper Flask endpoint
@modelprompt.route('/v1/generate/damage-scenarios', methods=['POST'])
def create_damage_scenarios():
    try:
        system_name = request.form.get('systemName', "")
        template_raw = request.form.get('template', {})

        if not template_raw:
            return jsonify({"error": "Missing template"}), 400

        template = json.loads(template_raw)

        # Generate scenarios
        scenarios, status_code = generate_damage_scenarios(system_name, template)
        return jsonify(scenarios), status_code

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#threat creation
def extract_json_from_text(text):
    try:
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        return text.strip()
    except Exception:
        return text.strip()


def group_threats_by_node(threat_ids):
    grouped = defaultdict(list)
    for threat in threat_ids:
        key = threat['nodeId']
        grouped[key].append(threat)
    return grouped


def generate_single_derived_scenario(threat_group):
    prompt = f"""
You are a cybersecurity expert. Based on the following related threats, generate a meaningful name and a concise description for a derived threat scenario. Do not use generic names like "Derived Threat Scenario".

Here are the threats:
{json.dumps(threat_group, indent=2)}

Each threat includes:
- `nodeId`: the component or function
- `propId`: the impacted property (can be ignored)
- `rowId`: the related damage scenario

Return only a JSON object with:
- name: (string)
- description: (string)
"""
    gemini_response = model.generate_content(prompt)

    try:
        content_text = (
            gemini_response.text
            if hasattr(gemini_response, 'text')
            else gemini_response.candidates[0].content.parts[0].text
        )
        cleaned = extract_json_from_text(content_text)
        return json.loads(cleaned)
    except Exception as e:
        print("Gemini Output:", gemini_response)
        raise ValueError(f"Failed to parse Gemini response: {str(e)}")


@modelprompt.route('/v1/generate/derived-threat-scenarios', methods=['POST'])
def create_derived_threat_scenario():
    try:
        name = request.form.get('name', "")
        description = request.form.get('description', "")
        model_id = request.form.get('modelId', "")
        threat_ids_raw = request.form.get('threatIds', "[]")

        threat_ids = json.loads(threat_ids_raw)

        if not model_id or not threat_ids:
            return jsonify({"error": "Missing modelId or threatIds"}), 400

        results = []

        # Manual override (single scenario)
        if name or description:
            results.append({
                "id": str(uuid.uuid4()),
                "name": name or "Unnamed Derived Threat",
                "description": description or "",
                "model_id": model_id,
                "threat_ids": threat_ids,
                "type": "User-defined"
            })
        else:
            grouped = group_threats_by_node(threat_ids)
            for group in grouped.values():
                result = generate_single_derived_scenario(group)
                results.append({
                    "id": str(uuid.uuid4()),
                    "name": result.get("name", "Unnamed Derived Threat"),
                    "description": result.get("description", ""),
                    "model_id": model_id,
                    "threat_ids": group,
                    "type": "User-defined"
                })

        return jsonify(results), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# generate Attack Tree
def preprocess_threat_scenarios(threat_scenarios):
    """
    Flattens the Details in each threat scenario so Gemini can see scenario names and nodes clearly.
    Returns a list of dicts with rowId, scenario_name, node, nodeId, and properties.
    """
    processed = []
    for scenario in threat_scenarios:
        for detail in scenario.get("Details", []):
            row_id = detail.get("rowId")
            for d in detail.get("Details", []):
                processed.append({
                    "rowId": row_id,
                    "scenario_name": d.get("name", ""),
                    "node": d.get("node", ""),
                    "nodeId": d.get("nodeId", ""),
                    "properties": [p.get("name") for p in d.get("props", [])]
                })
    return processed

def generate_attack_trees_with_gemini(threat_scenarios, model_id):
    """
    Given a list of threat_scenarios and a model_id, call Gemini to generate attack trees.
    Returns the parsed attack tree data (dict).
    """
    prompt = f"""
You are an expert in cyber threat modeling. Given the following derived threat scenarios, select the top 2 most critical scenarios and generate attack trees for each.
Each scenario includes:
- scenario_name: the name of the scenario
- node: the main component or function
- nodeId: the component's unique ID
- properties: impacted properties (e.g., Integrity, Availability)
- rowId: unique scenario identifier

Return the result in the following JSON format (one scene per scenario):

{{
  "model_id": "{model_id}",
  "type": "attack_trees",
  "scenes": [
    {{
      "ID": "uuid",
      "Name": "Attack Tree Name",
      "threat_id": "rowId from scenario",
      "templates": {{
        "nodes": [ ... ],
        "edges": [ ... ]
      }}
    }}
  ]
}}

Here are the threat scenarios:
{json.dumps(threat_scenarios, default=str, indent=2)}

IMPORTANT:
- Use the actual rowId from the scenario as threat_id.
- Use scenario_name and node for context.
- Generate realistic nodes and edges for the attack tree.
- Return ONLY valid JSON.
"""
    gemini_response = model.generate_content(prompt)
    try:
        content_text = (
            gemini_response.text
            if hasattr(gemini_response, 'text')
            else gemini_response.candidates[0].content.parts[0].text
        )
        cleaned = re.sub(r"```[a-z]*", "", content_text).strip().strip("`")
        return json.loads(cleaned)
    except Exception as e:
        print("Gemini Output:", gemini_response)
        raise ValueError(f"Failed to parse Gemini attack tree response: {str(e)}")


@modelprompt.route('/v1/generate/attack-tree', methods=['POST'])
def generate_attack_tree():
    try:
        # 1. Get model_id from request
        model_id = request.form.get('modelId', '')
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
            attack_tree_data = generate_attack_trees_with_gemini(processed_scenarios, model_id)
        except Exception as e:
            return jsonify({"error": f"Failed to generate attack trees: {str(e)}"}), 500

        # 5. Return the generated attack trees (do not save yet)
        return jsonify(attack_tree_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500