from flask import Blueprint, request, jsonify
import json
from json import JSONDecodeError
import uuid
from db import db
import os
import time
from datetime import datetime, timedelta
import google.generativeai as genai


app = Blueprint("prompt", __name__)


GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
# =================Gemini============================
genai.configure(api_key=GOOGLE_API_KEY)

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
            # "nodeId": root_id,
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
                # "nodeId": sub_attack_id,
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
                    # "nodeId": sub_attack_id,
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

        # Check if attack_data already exists in geminiAttackTree collection with recent timestamp
        existing_attack_data = db.geminiAttackTree.find_one({
            "promptKey": prompt_key,
            "created_at": {"$gte": datetime.now() - timedelta(days=1)}
        })

        if existing_attack_data:
            attack_data = existing_attack_data["attack_data"]
            db.geminiAttackTree.update_one(
                {"_id": existing_attack_data["_id"]},
                {"$set": {"last_accessed": datetime.now()}}
            )
        else:
            # Add longer delay for free tier
            time.sleep(5)  # Increased to 5 seconds
            
            # OPTIMIZED PROMPT - Reduced by ~70% tokens
            prompt = f"""Generate an attack tree diagram for {prompt_key} in automotive systems. 
            Output must be valid JSON with this exact structure:
            
            {{
                "Attack": "Attack name",
                "description": "Brief description",
                "root": "Root attack objective",
                "AttackData": [
                    {{
                        "SubAttack1": "Category name",
                        "children": [
                            {{"name": "Technique 1", "impact": "Impact", "description": "Description"}},
                            {{"name": "Technique 2", "impact": "Impact", "description": "Description"}}
                        ]
                    }},
                    {{
                        "SubAttack2": "Category name", 
                        "children": [
                            {{"name": "Technique 1", "impact": "Impact", "description": "Description"}},
                            {{"name": "Technique 2", "impact": "Impact", "description": "Description"}}
                        ]
                    }},
                    {{
                        "SubAttack3": "Category name",
                        "children": [
                            {{"name": "Technique 1", "impact": "Impact", "description": "Description"}},
                            {{"name": "Technique 2", "impact": "Impact", "description": "Description"}}
                        ]
                    }},
                    {{
                        "SubAttack4": "Category name",
                        "children": [
                            {{"name": "Technique 1", "impact": "Impact", "description": "Description"}},
                            {{"name": "Technique 2", "impact": "Impact", "description": "Description"}}
                        ]
                    }},
                    {{
                        "SubAttack5": "Category name",
                        "children": [
                            {{"name": "Technique 1", "impact": "Impact", "description": "Description"}},
                            {{"name": "Technique 2", "impact": "Impact", "description": "Description"}}
                        ]
                    }}
                ]
            }}
            
            Requirements:
            1. Root node: Successful attack on {prompt_key}
            2. First level: Main attack categories
            3. Each category has 2 attack techniques
            4. Focus on automotive system security
            5. Output ONLY JSON, no other text"""
            
            # Also reduce max_output_tokens
            generation_config = {
                "temperature": 0,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 2048,  # Reduced from 8192
                "response_mime_type": "application/json"
            }
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            ]

            model = genai.GenerativeModel(
                model_name="gemini-2.5-flash",  # Try 1.5-flash instead of 2.0 (might have different limits)
                generation_config=generation_config,
                safety_settings=safety_settings
            )
            
            # Add longer retry delays
            max_retries = 2  # Reduced retries
            retry_delay = 10  # Increased to 10 seconds
            
            response = None
            for attempt in range(max_retries):
                try:
                    chat_session = model.start_chat(history=[])
                    response = chat_session.send_message(prompt)
                    break
                except Exception as e:
                    if any(keyword in str(e).lower() for keyword in ["429", "quota", "rate limit"]):
                        if attempt < max_retries - 1:
                            wait_time = retry_delay * (attempt + 1)
                            time.sleep(wait_time)
                            continue
                        else:
                            # Return cached generic attack if available
                            generic_data = get_generic_attack_data(prompt_key)
                            if generic_data:
                                attack_data = generic_data
                                break
                            raise
                    else:
                        raise
            
            if response:
                try:
                    attack_data = json.loads(response.text)
                except JSONDecodeError:
                    attack_data = get_generic_attack_data(prompt_key) or {
                        "Attack": f"Attack on {prompt_key}",
                        "description": f"Security attack tree for {prompt_key}",
                        "root": f"Compromise {prompt_key}",
                        "AttackData": []
                    }

            else:
                # Use fallback data
                attack_data = get_generic_attack_data(prompt_key) or {
                    "Attack": f"Attack on {prompt_key}",
                    "description": f"Security attack tree for {prompt_key}",
                    "root": f"Compromise {prompt_key}",
                    "AttackData": []
                }

            scene = {
                "ID": str(uuid.uuid4()),
                "promptKey": prompt_key,
                "Name": attack_data.get("Attack"),
                "type": attack_type,
                "templates": create_attack_tree(attack_data)
            }

            db.geminiAttackTree.insert_one({
                "promptKey": prompt_key,
                "type": attack_type,
                "threat_id": str(uuid.uuid4()),
                "attack_data": attack_data,
                "scenes": [scene],
                "created_at": datetime.now(),
                "last_accessed": datetime.now(),
                "is_generated": response is not None  # Track if AI-generated or fallback
            })

        # Create new scene for this model
        new_scene = {
            "ID": str(uuid.uuid4()),
            "Name": attack_data.get("Attack"),
            "threat_id": str(uuid.uuid4()),
            "templates": create_attack_tree(attack_data)
        }

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

        return jsonify({
            "message": "Attack tree stored successfully", 
            "scene": new_scene,
            "ai_generated": attack_data.get("is_generated", True)
        }), 200

    except Exception as e:
        if any(keyword in str(e).lower() for keyword in ["429", "quota", "rate limit"]):
            return jsonify({
                "error": "API rate limit reached. Using cached data if available.",
                "suggestion": "Try again in 1 hour or use previously generated attack trees."
            }), 429
        return jsonify({"error": str(e)}), 500


def get_generic_attack_data(prompt_key):
    """Fallback function to provide generic attack data when API fails"""
    generic_attacks = {
        "ECU": {
            "Attack": "ECU Compromise Attack",
            "description": "Electronic Control Unit security vulnerabilities",
            "root": "Unauthorized ECU Access",
            "AttackData": [
                {
                    "SubAttack1": "Physical Access",
                    "children": [
                        {"name": "JTAG Debugging", "impact": "High", "description": "Physical debug interface exploitation"},
                        {"name": "Chip Cloning", "impact": "Critical", "description": "Hardware replication attack"}
                    ]
                },
                {
                    "SubAttack2": "Network Attacks",
                    "children": [
                        {"name": "CAN Bus Injection", "impact": "High", "description": "Inject malicious CAN messages"},
                        {"name": "DoS Attack", "impact": "Medium", "description": "Flood ECU with requests"}
                    ]
                }
            ]
        },
        "CAN": {
            "Attack": "CAN Bus Network Attack",
            "description": "Controller Area Network security threats",
            "root": "CAN Network Compromise",
            "AttackData": [
                {
                    "SubAttack1": "Message Spoofing",
                    "children": [
                        {"name": "Replay Attack", "impact": "High", "description": "Capture and replay valid messages"},
                        {"name": "Fake ECU Impersonation", "impact": "Critical", "description": "Impersonate legitimate ECU"}
                    ]
                },
                {
                    "SubAttack2": "Bus Flooding",
                    "children": [
                        {"name": "Priority Flood", "impact": "Medium", "description": "Flood with high priority messages"},
                        {"name": "Broadcast Storm", "impact": "High", "description": "Overwhelm network capacity"}
                    ]
                }
            ]
        }
    }
    
    return generic_attacks.get(prompt_key, None)