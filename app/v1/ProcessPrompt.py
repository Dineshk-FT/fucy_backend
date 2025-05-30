from flask import Blueprint, request, jsonify,json
from config import Config
import uuid
from db import db

import google.generativeai as genai

app = Blueprint("prompt", __name__)

GENAI_API_KEY = Config.GENAI_API_KEY

# =================Gemini============================
genai.configure(api_key=GENAI_API_KEY)

def create_attack_tree(attack_data):
    attack_tree = {

        "nodes": [],
        "edges": []
    }
    
    root_id = str(uuid.uuid4())
    root_node = {
        "width": 150,
        "height": 50,
        "id": root_id,
        # "label": attack_data["root"],
        "key": attack_data["root"],
        "type": "default",
        "position": {"x": 500, "y": 100},
        "data": {
            "connections": [],
            "label": f"{attack_data['Attack']}",
            "nodeId": root_id,
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
                "height": 50,
                "textAlign": "center",
                "textDecoration": "none",
                "width": 150
            },
        }
    }
    attack_tree["nodes"].append(root_node)
    
    or_gate_root_id = str(uuid.uuid4())
    attack_tree["nodes"].append({
        "id": or_gate_root_id,
        "label": "OR Gate",
        "type": "OR Gate",
        "position": {"x": 500, "y": 200},
        "data": {
            "connections": [],
            "label": "OR Gate",
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
                "height": 100,
                "textAlign": "center",
                "textDecoration": "none",
                "width": 150
            }
        }
    })
    # attack_tree["edges"].append({"source": root_id, "target": or_gate_root_id, "type": "step"})
    attack_tree["edges"].append({
                "id": str(uuid.uuid4()),
                "markerEnd": {
                    "color": "black",
                    "height": 10,
                    "type": "arrowclosed",
                    "width": 10
                },
                "markerStart": {
                    "color": "black",
                    "height": 20,
                    "type": "arrowclosed",
                    "width": 20
                },
                "points": [],
                "animated": False,
                "data": {"label": "edge"},
                "source": root_id,
                "target": or_gate_root_id,
                "type": "step",
                "style": {"stroke": "gray"}
            })
    
    x_offset = 100
    for index, attack in enumerate(attack_data["AttackData"]):
        sub_attack_name = list(attack.values())[0]
        sub_attack_id = str(uuid.uuid4())
        attack_tree["nodes"].append({
            "width": 150,
            "height": 50,
            "damageId": str(uuid.uuid4()),
            "id": sub_attack_id,
            # "label": sub_attack_name,
            "key": sub_attack_name,
            "type": "Event",
            "position": {"x": 200 + index * x_offset, "y": 300},
            "data": {
                "connections": [],
                "label": f"{sub_attack_name}",
                "nodeId": sub_attack_id,
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
                    "height": 50,
                    "textAlign": "center",
                    "textDecoration": "none",
                    "width": 150
                }
            }
        })
        # attack_tree["edges"].append({"source": or_gate_root_id, "target": sub_attack_id, "type": "step"})
        attack_tree["edges"].append({
                "id": str(uuid.uuid4()),
                "markerEnd": {
                    "color": "black",
                    "height": 10,
                    "type": "arrowclosed",
                    "width": 10
                },
                "points": [],
                # "data": {"label": "edge"},
                "source": or_gate_root_id,
                "target": sub_attack_id,
                "type": "step",
                # "style": {"stroke": "gray"}
            })

        
        or_gate_sub_attack_id = str(uuid.uuid4())
        attack_tree["nodes"].append({
            "id": or_gate_sub_attack_id,
            "label": "OR Gate",
            "type": "OR Gate",
            "position": {"x": 200 + index * x_offset, "y": 400},
            "data": {
            "connections": [],
            "label": "OR Gate",
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
                "height": 100,
                "textAlign": "center",
                "textDecoration": "none",
                "width": 150
            }
        }
        })
        # attack_tree["edges"].append({"source": sub_attack_id, "target": or_gate_sub_attack_id, "type": "step"})
        attack_tree["edges"].append({
                "id": str(uuid.uuid4()),
                "markerEnd": {
                    "color": "black",
                    "height": 10,
                    "type": "arrowclosed",
                    "width": 10
                },
                "points": [],
                # "data": {"label": "edge"},
                "source": sub_attack_id,
                "target": or_gate_sub_attack_id,
                "type": "step",
                # "style": {"stroke": "gray"}
            })

        
        for child_index, child in enumerate(attack.get("children", [])):
            child_id = str(uuid.uuid4())
            attack_tree["nodes"].append({
                "width": 150,
                "height": 50,
                "id": child_id,
                # "label": child["name"],
                "key": child["name"],
                "type": "Event",
                "damageId": str(uuid.uuid4()),
                "position": {"x": 150 + index * x_offset + child_index * 50, "y": 500},
                "data": {
                    "connections": [],
                    "label": child["name"],
                    "nodeId": sub_attack_id,
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
                        "height": 50,
                        "textAlign": "center",
                        "textDecoration": "none",
                        "width": 150
                    }
                }
            })
            # attack_tree["edges"].append({"source": or_gate_sub_attack_id, "target": child_id, "type": "step"})
            attack_tree["edges"].append({
                "id": str(uuid.uuid4()),
                "markerEnd": {
                    "color": "black",
                    "height": 10,
                    "type": "arrowclosed",
                    "width": 10
                },
                "points": [],
                # "data": {"label": "edge"},
                "source": or_gate_sub_attack_id,
                "target": child_id,
                "type": "step",
                # "style": {"stroke": "gray"}
            })

    
    return attack_tree

@app.route('/v1/generateAndStoreAttack', methods=['POST'])
def generate_and_store_attack():
    try:
        prompt_key = request.form.get("promptKey").upper()
        model_id = request.form.get("modelId")
        attack_type = "attack_trees"

        if not prompt_key or not model_id:
            return jsonify({"error": "Both promptKey and modelId are required"}), 400

        # Check if attack_data already exists in geminiAttackTree collection
        existing_attack_data = db.geminiAttackTree.find_one({"promptKey": prompt_key})

        if existing_attack_data:
            attack_data = existing_attack_data["attack_data"]
        else:
            prompt = f"""
                    Generate an attack tree diagram for the {prompt_key} in an automotive system, and provide the output in a JSON format. 
                    The root node must represent a successful attack on the {prompt_key}. 
                    The first level of branches should include the main attack. The output JSON must adhere to the following general structure, where the values of all fields can be modified:
                    {{
                        "Attack": "String value for the overall attack name",
                        "description": "String value describing the attack tree",
                        "root": "String value representing the root attack",
                        "AttackData": [
                            {{
                                "SubAttack1": "String value for the first level sub-attack category",
                                "children": [
                                    {{
                                        "name": "String value for the specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }},
                                    {{
                                        "name": "String value for another specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }}
                                ]
                            }},
                            {{
                                "SubAttack2": "String value for a second level sub-attack category name",
                                "children": [
                                    {{
                                        "name": "String value for a specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }},
                                    {{
                                        "name": "String value for another specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }}
                                ]
                            }},
                            {{
                                "SubAttack3": "String value for a third level sub-attack category name",
                                "children": [
                                    {{
                                        "name": "String value for a specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }},
                                    {{
                                        "name": "String value for another specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }}
                                ]
                            }},
                            {{
                                "SubAttack4": "String value for a fourth level sub-attack category name",
                                "children": [
                                    {{
                                        "name": "String value for a specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }},
                                    {{
                                        "name": "String value for another specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }}
                                ]
                            }},
                            {{
                                "SubAttack5": "String value for a fifth level sub-attack category name",
                                "children": [
                                    {{
                                        "name": "String value for a specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }},
                                    {{
                                        "name": "String value for another specific attack technique",
                                        "impact": "String value describing the security impact",
                                        "description": "String value explaining the attack technique"
                                    }}
                                ]
                            }}
                        ]
                    }}
                    Ensure the generated JSON is valid and conforms to this generalized structure. Do not include any additional text or explanations outside of the requested JSON format.
                    """

            # Generate attack tree using Gemini AI
            generation_config = {
                "temperature": 0,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 8192,
                "response_mime_type": "application/json"
            }
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            ]

            model = genai.GenerativeModel(
                model_name="gemini-2.0-flash",
                generation_config=generation_config,
                safety_settings=safety_settings
            )
            chat_session = model.start_chat(history=[])
            response = chat_session.send_message(prompt)

            try:
                attack_data = json.loads(response.text)
            except json.JSONDecodeError:
                return jsonify({"error": "Failed to decode JSON from Gemini response"}), 500

            scene = {
                "ID": str(uuid.uuid4()),
                "promptKey": prompt_key,
                "Name": attack_data.get("Attack"),
                "type": attack_type,
                "templates": create_attack_tree(attack_data)
            }

            # Save the new attack_data in geminiAttackTree collection
            db.geminiAttackTree.insert_one({
                "promptKey": prompt_key,
                "type": attack_type,
                "threat_id": str(uuid.uuid4()),
                "attack_data": attack_data,
                "scenes": [scene]
            })

        # Create new scene for this model
        new_scene = {
            "ID": str(uuid.uuid4()),
            "Name": attack_data.get("Attack"),
            "threat_id": str(uuid.uuid4()),
            "templates": create_attack_tree(attack_data)
        }

        # Check for duplicate attack tree name before inserting
        existing_doc = db.Attacks.find_one({"model_id": model_id, "type": attack_type})

        if existing_doc:
            for scene in existing_doc.get("scenes", []):
                if scene.get("Name") == new_scene["Name"]:
                    return jsonify({"error": f"Attack tree with name '{new_scene['Name']}' already exists"}), 400

            db.Attacks.update_one(
                {"model_id": model_id, "type": attack_type},
                {"$push": {"scenes": new_scene}}
            )
        else:
            db.Attacks.insert_one({
                "model_id": model_id,
                "type": attack_type,
                "scenes": [new_scene]
            })

        return jsonify({"message": "Attack tree stored successfully", "scene": new_scene}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

