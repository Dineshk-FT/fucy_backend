from flask import Blueprint, request, jsonify, current_app
import google.generativeai as genai
from config import Config
import ast
import json
import re
from db import db
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
from app.Methods.helpers import build_full_edge, build_basic_node,calculate_node_positions,structure_attack_tree_templates
import random
import uuid
import string
from collections import defaultdict
from datetime import datetime
from bson import ObjectId
import bson

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


modelprompt = Blueprint("modelprompt", __name__)

genai.configure(api_key=Config.GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash')

@modelprompt.route("/v1/generate/model", methods=["POST"])
def generate_reactflow_template(standalone=False, request_data=None):
    """Generate ReactFlow template - can be called as route or function"""
    try:
        if not request_data:
            request_data = request

        # Get inputs
        user_id = request.headers.get("user-id")
        created_by = request_data.form.get("createdBy", "system")
        system_name = request_data.form.get('systemName', 'Test System')
        algorithms = request_data.form.get('algorithms', '["Algorithm 1", "Algorithm 2"]')
        communication_interfaces = request_data.form.get('communicationInterfaces', '["Interface 1", "Interface 2"]')
        cell_chemistry = request_data.form.get('cellChemistry', '["Chemistry 1", "Chemistry 2"]')

        # Setup Gemini prompt
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
  "nodes": [
    {{
      "id": "1",
      "type": "default",
      "data": {{"label": "BMU"}},
      "properties": ["Confidentiality"]
    }}
  ],
  "edges": [
    {{
      "id": "e1-2",
      "type": "step",
      "source": "1",
      "target": "2",
      "sourceHandle": "bottom",
      "targetHandle": "top",
      "data": {{"label": "CAN"}},
      "properties": ["Integrity"]
    }}
  ]
}}
"""

        # Call Gemini
        response = model.generate_content(prompt)
        output = response.text.strip()
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")

        # Parse JSON
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            data = ast.literal_eval(cleaned)

        # Handle different response formats
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
            "user_id":user_id,
            "status": 1,
            "type": "model"
        }
        result = db.Models.insert_one(model_doc)
        model_id = str(result.inserted_id)

        # Store asset
        Derivations, Details = getDerivationsAndDetails(final_result, {})

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
            "model_id": str(model_id),
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
        return jsonify({"error": str(e)}), 500
     
# Damage scene creation
def generate_object_id():
    """Generate MongoDB-style ObjectId"""
    return ''.join(random.choices(string.hexdigits.lower(), k=24))

# Wrapper Flask endpoint
def create_damage_scenarios(standalone=False, request_data=None):
    """Core function to generate damage scenarios (can be called standalone or as route)"""
    try:
        req_data = request_data if request_data else request

        model_id = req_data.form.get('modelId')
        system_name = req_data.form.get('systemName', '')
        template_raw = req_data.form.get('template', '{}')

        if not model_id:
            if standalone:
                raise ValueError("modelId is required")
            return jsonify({"error": "modelId is required"}), 400

        template = json.loads(template_raw) if template_raw else {}

        # 🔄 Updated prompt: Only generate damage scenarios (no threat_scenario inside)
        prompt = f"""
Generate exactly 2 damage scenarios for the '{system_name}' system in JSON format.

System Components:
{json.dumps(template.get('nodes', []), indent=2)}

Relationships:
{json.dumps(template.get('edges', []), indent=2)}

Requirements:
1. Create TWO different scenarios targeting different critical components
2. Each MUST include:
   - Damage scenario details
   - Realistic cyber losses (integrity/confidentiality/availability)
   - Plausible impact ratings (Major/Moderate/Minor)
3. Use EXACTLY this structure:
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
"""

        response = model.generate_content(prompt)
        raw_output = response.text.strip()
        cleaned = re.sub(r"```[a-z]*", "", raw_output).strip("` \n")
        scenarios = json.loads(cleaned)

        scenarios["model_id"] = model_id

        for i, detail in enumerate(scenarios.get("Details", []), start=1):
            detail["_id"] = detail.get("_id", str(uuid.uuid4()))
            detail["key"] = detail.get("key", i)

            for loss in detail.get("cyberLosses", []):
                loss["id"] = loss.get("id", str(uuid.uuid4()))
                loss["isSelected"] = loss.get("isSelected", True)

        # ✅ Only store damage scenarios
        damage_result = db.Damage_scenarios.insert_one(scenarios)

        # ❌ Do not store threat scenarios here

        result = {
            "message": "Damage scenarios created successfully",
            "scenario_id": str(damage_result.inserted_id),
            "model_id": model_id,
            "scenarios": scenarios
        }

        if standalone:
            return result
        return jsonify(result), 201

    except json.JSONDecodeError:
        error = "Invalid response format from AI"
        if standalone:
            raise ValueError(error)
        return jsonify({"error": error}), 500
    except Exception as e:
        if standalone:
            raise
        return jsonify({"error": str(e)}), 500
    
# threat scenario creation
@modelprompt.route('/v1/generate/threat-scenarios', methods=['POST'])
def create_threat_scenarios(model_id):
    # print("model_id",model_id)
    # model_id = request.form.get('modelId')
    """Create threat scenarios from existing damage scenarios"""
    try:
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        # 🔍 Fetch related damage scenarios
        damage_doc = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})
        # print("damage_doc",damage_doc)
        if not damage_doc or "Details" not in damage_doc:
            return jsonify({"error": "No damage scenarios found for this model_id"}), 404

        threat_details = []

        for i, damage in enumerate(damage_doc["Details"], start=1):
            threat_detail = {
                "damage_key": damage["key"],
                "damage_name": damage["Name"],
                "id": f"DS{str(i).zfill(3)}",
                "rowId": str(uuid.uuid4()),
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

        # 📦 Wrap in final structure
        threat_scenario_doc = {
            "model_id": model_id,
            "type": "derived",
            "Details": threat_details
        }

      # 💾 Insert into DB
        result = db.Threat_scenarios.insert_one(threat_scenario_doc)

        # Convert ObjectId to string for JSON response
        threat_scenario_doc["_id"] = str(result.inserted_id)

        return jsonify({
            "message": "Threat scenarios created successfully",
            "model_id": model_id,
            "scenarios": threat_scenario_doc
        }), 201
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


def generate_derived_threat_scenarios(model_id, threat_ids, name="", description=""):
    details = []

    # Manual override (single scenario)
    if name or description:
        derived = {
            "name": name or "Unnamed Derived Threat",
            "description": description or "",
            "id": str(uuid.uuid4()),
            "threat_ids": threat_ids  # ✅ Attach provided threat_ids directly
        }
        details.append(derived)
    else:
        grouped = group_threats_by_node(threat_ids)
        for group in grouped.values():
            result = generate_single_derived_scenario(group)
            derived = {
                "name": result.get("name", "Unnamed Derived Threat"),
                "description": result.get("description", ""),
                "id": str(uuid.uuid4()),
                "threat_ids": group  # ✅ Attach the group used to generate this scenario
            }
            details.append(derived)

    if details:
        document = {
            "model_id": model_id,
            "type": "User-defined",
            "Details": details
        }
        insert_result = db.Threat_scenarios.insert_one(document)

        document["_id"] = str(insert_result.inserted_id)
        return document

    return {}

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

        results = generate_derived_threat_scenarios(model_id, threat_ids, name, description)
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
- nodeId: the component's unique ID
- type: for the nodes use "Event".The first node must be the threat scenario and type default 
- rowId: unique scenario identifier.

RULES FOR ATTACK TREE GENERATION:
1. Every attack tree MUST have at least one gate (OR Gate or AND Gate)..
2. The root node should be the threat scenario (type: "default")
3. Events must be connected through gates - never directly to other events
4. Include realistic attack steps that would lead to the threat scenario

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
        "nodes": [
          {{
            "id": "node1",
            "name": "Root Threat",
            "type": "default",
            "threat_id": "rowId"
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
        # print("Gemini Output:", gemini_response)
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

        # 5. Save all scenes into a single document in DB
        try:
            raw_scenes = attack_tree_data.get("scenes", [])
            scenes = []

            for scene in raw_scenes:
                structured_templates = structure_attack_tree_templates(scene.get("templates", {}))

                scenes.append({
                    "ID": scene.get("ID"),
                    "Name": scene.get("Name"),
                    "threat_id": scene.get("threat_id"),
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
        return jsonify({"error": str(e)}), 500

# Cybersecurity creation
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
    gemini_response = model.generate_content(prompt)
    content_text = (
        gemini_response.text
        if hasattr(gemini_response, 'text')
        else gemini_response.candidates[0].content.parts[0].text
    )
    print(f"Gemini Output for {artifact_type}:", content_text)  # Debug log
    cleaned = re.sub(r"[a-z]*", "", content_text).strip().strip("`")
    cleaned = extract_json_block(cleaned)
    print("Gemini Output (cleaned):", cleaned)
    try:
        return json.loads(cleaned)
    except Exception as e:
        print("Gemini Output (cleaned):", cleaned)
        # Return the raw output in the error for easier debugging
        raise ValueError(f"Failed to parse Gemini {artifact_type} response: {str(e)} | Raw: {cleaned}")

@modelprompt.route('/v1/generate/cybersecurity-artifacts', methods=['POST'])
def generate_cybersecurity_artifacts():
    """
    Generate and save cybersecurity requirements, controls, goals, and claims
    for a given modelId and systemName, each stored as a document in db.Cybersecurity.
    """
    try:
        model_id = request.form.get('modelId', '')
        system_name = request.form.get('systemName', '')

        if not model_id or not system_name:
            return jsonify({"error": "Missing modelId or systemName"}), 400

        prompt = f"""
            Generate cybersecurity_requirements, cybersecurity_controls, cybersecurity_goals and cybersecurity_claims for the system '{system_name}'.
            Return ONLY valid JSON in the following format (no explanation or extra text):

            {{
            "cybersecurity_requirements": {{
                "scenes": [{{"ID": "<uuid>", "Name": "<requirement name>", "Description": "<description>", "threat_id": null}}]
            }},
            "cybersecurity_controls": {{
                "scenes": [{{"ID": "<uuid>", "Name": "<control name>", "Description": "<description>", "threat_id": null}}]
            }},
            "cybersecurity_claims": {{
                "scenes": [{{"ID": "<uuid>", "Name": "<claim name>", "Description": "<description>", "threat_id": null}}]
            }},
            "cybersecurity_goals": {{
                "scenes": [{{"ID": "<uuid>", "Name": "<goal name>", "Description": "<description>", "threat_id": null}}]
            }}
            }}

            - Each section must have a "scenes" array as shown.
            - Do NOT include any explanation or extra text.
        """

        gemini_response = model.generate_content(prompt)
        content_text = (
            gemini_response.text
            if hasattr(gemini_response, 'text')
            else gemini_response.candidates[0].content.parts[0].text
        )

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
        return jsonify({"error": str(e)}), 500
    
@modelprompt.route("/v1/generate/model", methods=["POST"])
def generate_reactflow_template_route():
    """Standalone endpoint for template generation"""
    return generate_reactflow_template()

@modelprompt.route('/v1/generate/damage-scenarios', methods=['POST'])
def create_damage_scenarios_route():
    """Route handler for damage scenario generation"""
    response = create_damage_scenarios(standalone=True, request_data=request)

    # Automatically call threat scenario generation
    model_id = request.form.get('modelId')
    threat_response = create_threat_scenarios(model_id)

    return jsonify({
        "damage_scenarios": response,
        "threat_scenarios": threat_response[0].json
    }), 201

@modelprompt.route('/v1/generate/full-model', methods=['POST'])
def generate_full_model():
    try:
        # Generate template
        template_response = generate_reactflow_template(standalone=True, request_data=request)

        scenario_request = {
            'modelId': template_response['model_id'],
            'systemName': template_response['system_name'],
            'template': json.dumps(template_response['template'])
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
            threat_ids=threat_ids
        )

        # Generate attack trees via Flask route
        with current_app.test_request_context(method='POST', data={'modelId': template_response['model_id']}):
            attack_response = generate_attack_tree()
            attack_data = attack_response.get_json() if hasattr(attack_response, 'get_json') else {}

        # Generate cybersecurity artifacts via test request context
        with current_app.test_request_context(
            method='POST',
            data={
                'modelId': template_response['model_id'],
                'systemName': template_response['system_name']
            }
        ):
            cyber_response = generate_cybersecurity_artifacts()
            cyber_data = cyber_response.get_json() if hasattr(cyber_response, 'get_json') else {}

        return current_app.response_class(
            response=json.dumps({
                "model": template_response,
                "damage_scenarios": scenarios_data,
                "threat_scenarios": threat_data,
                "derived_threat_scenarios": derived_data,
                "attack_trees": attack_data,
                "cybersecurity_artifacts": cyber_data  # ✅ Add this
            }, cls=JSONEncoder),
            status=201,
            mimetype='application/json'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
