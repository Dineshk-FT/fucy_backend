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



def validate_and_fix_attack_data(attack_data, prompt_key):
    """Ensure attack_data has the complete structure"""
    
    # Set defaults for missing top-level fields
    if "Attack" not in attack_data or not attack_data["Attack"]:
        attack_data["Attack"] = f"Attack on {prompt_key}"
    
    if "description" not in attack_data:
        attack_data["description"] = f"Security attack tree for {prompt_key}"
    
    if "root" not in attack_data:
        attack_data["root"] = f"Compromise {prompt_key}"
    
    # Ensure AttackData exists and has at least 3 items
    if "AttackData" not in attack_data or not attack_data["AttackData"] or len(attack_data["AttackData"]) < 3:
        # Create default AttackData with 3-5 sub-attacks
        default_categories = [
            f"{prompt_key} Category 1: Physical Access",
            f"{prompt_key} Category 2: Network Attacks", 
            f"{prompt_key} Category 3: Software Exploitation",
            f"{prompt_key} Category 4: Side Channel Attacks",
            f"{prompt_key} Category 5: Supply Chain Attacks"
        ]
        
        attack_data["AttackData"] = []
        for i, category in enumerate(default_categories[:5], 1):
            attack_data["AttackData"].append({
                f"SubAttack{i}": category,
                "children": [
                    {"name": f"Technique {i}.1", "impact": "Medium", "description": f"Description for technique {i}.1"},
                    {"name": f"Technique {i}.2", "impact": "High", "description": f"Description for technique {i}.2"}
                ]
            })
    
    # Ensure each sub-attack has children
    for sub_attack in attack_data["AttackData"]:
        if "children" not in sub_attack or not sub_attack["children"] or len(sub_attack["children"]) < 2:
            # Get the sub-attack name
            sub_key = [k for k in sub_attack.keys() if k.startswith("SubAttack")][0] if any(k.startswith("SubAttack") for k in sub_attack.keys()) else "SubAttack"
            sub_name = sub_attack.get(sub_key, "Unknown Category")
            
            sub_attack["children"] = [
                {"name": f"Primary {sub_name} Technique", "impact": "High", "description": f"Primary attack vector for {sub_name}"},
                {"name": f"Secondary {sub_name} Technique", "impact": "Medium", "description": f"Alternative attack vector for {sub_name}"}
            ]
    
    return attack_data

def get_generic_attack_data(prompt_key):
    """Fallback function to provide generic attack data when API fails"""
    generic_attacks = {
        "ECU": {
            "Attack": "ECU Compromise Attack",
            "description": "Electronic Control Unit security vulnerabilities and attack vectors",
            "root": "Unauthorized ECU Access and Control",
            "AttackData": [
                {
                    "SubAttack1": "Physical Access Attacks",
                    "children": [
                        {"name": "JTAG Debugging Exploitation", "impact": "Critical", "description": "Using debug interfaces to extract firmware and modify code"},
                        {"name": "Chip Cloning and Replacement", "impact": "High", "description": "Hardware replication to bypass security measures"}
                    ]
                },
                {
                    "SubAttack2": "Network-Based Attacks",
                    "children": [
                        {"name": "CAN Bus Injection", "impact": "High", "description": "Injecting malicious CAN messages to control vehicle functions"},
                        {"name": "DoS Resource Exhaustion", "impact": "Medium", "description": "Flooding ECU with requests to cause denial of service"}
                    ]
                },
                {
                    "SubAttack3": "Software Exploitation",
                    "children": [
                        {"name": "Firmware Reverse Engineering", "impact": "High", "description": "Analyzing firmware to find vulnerabilities"},
                        {"name": "Memory Corruption Attacks", "impact": "Critical", "description": "Buffer overflows and memory safety violations"}
                    ]
                },
                {
                    "SubAttack4": "Side Channel Attacks",
                    "children": [
                        {"name": "Timing Analysis", "impact": "Medium", "description": "Analyzing execution timing to extract secrets"},
                        {"name": "Power Analysis", "impact": "Medium", "description": "Monitoring power consumption to infer operations"}
                    ]
                },
                {
                    "SubAttack5": "Update Mechanism Attacks",
                    "children": [
                        {"name": "Malicious Firmware Update", "impact": "Critical", "description": "Installing compromised firmware via update process"},
                        {"name": "Rollback Attack", "impact": "High", "description": "Reverting to vulnerable firmware version"}
                    ]
                }
            ]
        },
        "CAN": {
            "Attack": "CAN Bus Network Attack",
            "description": "Controller Area Network security threats and attack surfaces",
            "root": "Complete CAN Network Compromise",
            "AttackData": [
                {
                    "SubAttack1": "Message Spoofing Attacks",
                    "children": [
                        {"name": "Replay Attack", "impact": "High", "description": "Capturing and replaying legitimate CAN messages"},
                        {"name": "Fake ECU Impersonation", "impact": "Critical", "description": "Impersonating legitimate ECUs to send malicious commands"}
                    ]
                },
                {
                    "SubAttack2": "Bus Flooding Attacks",
                    "children": [
                        {"name": "Priority Message Flood", "impact": "Medium", "description": "Flooding bus with high priority messages"},
                        {"name": "Broadcast Storm Attack", "impact": "High", "description": "Overwhelming network capacity with broadcast messages"}
                    ]
                },
                {
                    "SubAttack3": "Protocol Exploitation",
                    "children": [
                        {"name": "Missing Authentication Exploit", "impact": "Critical", "description": "Exploiting lack of authentication in CAN protocol"},
                        {"name": "Arbitration Manipulation", "impact": "High", "description": "Manipulating message priority arbitration"}
                    ]
                },
                {
                    "SubAttack4": "Diagnostic Interface Attacks",
                    "children": [
                        {"name": "OBD-II Port Exploitation", "impact": "High", "description": "Using diagnostic port to inject malicious messages"},
                        {"name": "UDS Command Injection", "impact": "Critical", "description": "Injecting malicious Unified Diagnostic Services commands"}
                    ]
                },
                {
                    "SubAttack5": "Gateway Bypass Attacks",
                    "children": [
                        {"name": "Security Gateway Evasion", "impact": "High", "description": "Bypassing security gateway restrictions"},
                        {"name": "Routing Table Manipulation", "impact": "Medium", "description": "Modifying routing tables to redirect traffic"}
                    ]
                }
            ]
        },
        "IVI": {
            "Attack": "In-Vehicle Infotainment System Attack",
            "description": "Security vulnerabilities in infotainment systems",
            "root": "IVI System Compromise",
            "AttackData": [
                {
                    "SubAttack1": "Application Attacks",
                    "children": [
                        {"name": "Malicious App Installation", "impact": "High", "description": "Installing unauthorized applications"},
                        {"name": "App Sandbox Escape", "impact": "Critical", "description": "Breaking out of application isolation"}
                    ]
                },
                {
                    "SubAttack2": "Connectivity Attacks",
                    "children": [
                        {"name": "Bluetooth Exploitation", "impact": "High", "description": "Exploiting Bluetooth stack vulnerabilities"},
                        {"name": "Wi-Fi Man-in-the-Middle", "impact": "High", "description": "Intercepting Wi-Fi communications"}
                    ]
                },
                {
                    "SubAttack3": "Media Attacks",
                    "children": [
                        {"name": "Malicious USB Device", "impact": "High", "description": "Using USB devices to execute code"},
                        {"name": "Media File Exploitation", "impact": "Medium", "description": "Crafting malicious media files"}
                    ]
                }
            ]
        }
    }
    
    # Try exact match first
    if prompt_key in generic_attacks:
        return generic_attacks[prompt_key]
    
    # Try case-insensitive partial match
    for key in generic_attacks:
        if key.lower() in prompt_key.lower() or prompt_key.lower() in key.lower():
            return generic_attacks[key]
    
    # Return a generic template for unknown keys
    return {
        "Attack": f"{prompt_key} Security Attack Tree",
        "description": f"Comprehensive attack tree for {prompt_key} in automotive systems",
        "root": f"Compromise {prompt_key} System",
        "AttackData": [
            {
                "SubAttack1": f"Physical Access to {prompt_key}",
                "children": [
                    {"name": "Hardware Tampering", "impact": "High", "description": "Physical manipulation of hardware"},
                    {"name": "Debug Interface Exploitation", "impact": "Critical", "description": "Using debugging ports for access"}
                ]
            },
            {
                "SubAttack2": f"Network Attacks on {prompt_key}",
                "children": [
                    {"name": "Network Sniffing", "impact": "Medium", "description": "Capturing network traffic"},
                    {"name": "Packet Injection", "impact": "High", "description": "Injecting malicious packets"}
                ]
            },
            {
                "SubAttack3": f"Software Vulnerabilities in {prompt_key}",
                "children": [
                    {"name": "Buffer Overflow", "impact": "High", "description": "Memory corruption exploitation"},
                    {"name": "Code Injection", "impact": "Critical", "description": "Injecting and executing arbitrary code"}
                ]
            }
        ]
    }

def create_attack_tree(attack_data):
    """Create attack tree visualization data from attack_data"""
    attack_tree = {
        "nodes": [],
        "edges": []
    }
    
    # Create root node
    root_id = str(uuid.uuid4())
    root_node = {
        "width": 150,
        "height": 50,
        "id": root_id,
        "key": attack_data.get("Attack", "Attack Tree"),
        "type": "default",
        "position": {"x": 500, "y": 50},
        "data": {
            "connections": [],
            "label": f"{attack_data.get('Attack', 'Attack Tree')}",
            "style": {
                "backgroundColor": "#4CAF50",
                "borderColor": "#2E7D32",
                "borderStyle": "solid",
                "borderWidth": "2px",
                "color": "white",
                "fontFamily": "Inter",
                "fontSize": "16px",
                "fontStyle": "normal",
                "fontWeight": 600,
                "height": 50,
                "textAlign": "center",
                "textDecoration": "none",
                "width": 200
            },
        }
    }
    attack_tree["nodes"].append(root_node)
    
    # Create OR gate under root
    or_gate_root_id = str(uuid.uuid4())
    attack_tree["nodes"].append({
        "id": or_gate_root_id,
        "label": "OR",
        "type": "OR Gate",
        "position": {"x": 500, "y": 150},
        "data": {
            "connections": [],
            "label": "OR",
            "style": {
                "backgroundColor": "#FF9800",
                "borderColor": "#E65100",
                "borderStyle": "solid",
                "borderWidth": "2px",
                "color": "white",
                "fontFamily": "Inter",
                "fontSize": "20px",
                "fontStyle": "normal",
                "fontWeight": "bold",
                "height": 60,
                "textAlign": "center",
                "textDecoration": "none",
                "width": 60,
                "borderRadius": "50%"
            }
        }
    })
    
    attack_tree["edges"].append({
        "id": str(uuid.uuid4()),
        "markerEnd": {
            "color": "#666",
            "height": 10,
            "type": "arrowclosed",
            "width": 10
        },
        "points": [],
        "animated": False,
        "data": {"label": ""},
        "source": root_id,
        "target": or_gate_root_id,
        "type": "step",
        "style": {"stroke": "#666", "strokeWidth": 2}
    })
    
    # Calculate layout
    attack_data_list = attack_data.get("AttackData", [])
    num_attacks = len(attack_data_list)
    
    # Limit to 5 sub-attacks for better visualization
    if num_attacks > 5:
        attack_data_list = attack_data_list[:5]
        num_attacks = 5
    
    # Dynamic spacing based on number of items
    if num_attacks == 1:
        x_positions = [500]
    else:
        spacing = 300
        start_x = 500 - (spacing * (num_attacks - 1)) / 2
        x_positions = [start_x + i * spacing for i in range(num_attacks)]
    
    # Process each sub-attack
    for index, attack in enumerate(attack_data_list):
        # Get the sub-attack name (handles different key names)
        sub_attack_name = None
        for key in attack.keys():
            if key.startswith("SubAttack"):
                sub_attack_name = attack[key]
                break
        if not sub_attack_name:
            sub_attack_name = f"Attack Vector {index + 1}"
        
        sub_attack_id = str(uuid.uuid4())
        attack_tree["nodes"].append({
            "width": 180,
            "height": 50,
            "damageId": str(uuid.uuid4()),
            "id": sub_attack_id,
            "key": sub_attack_name,
            "type": "Event",
            "position": {"x": x_positions[index], "y": 250},
            "data": {
                "connections": [],
                "label": sub_attack_name[:30] + ("..." if len(sub_attack_name) > 30 else ""),
                "style": {
                    "backgroundColor": "#2196F3",
                    "borderColor": "#0D47A1",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "color": "white",
                    "fontFamily": "Inter",
                    "fontSize": "14px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "height": 50,
                    "textAlign": "center",
                    "textDecoration": "none",
                    "width": 180
                }
            }
        })
        
        attack_tree["edges"].append({
            "id": str(uuid.uuid4()),
            "markerEnd": {
                "color": "#666",
                "height": 10,
                "type": "arrowclosed",
                "width": 10
            },
            "points": [],
            "data": {"label": ""},
            "source": or_gate_root_id,
            "target": sub_attack_id,
            "type": "step",
            "style": {"stroke": "#666", "strokeWidth": 2}
        })
        
        # Create OR gate for this sub-attack's children
        or_gate_sub_attack_id = str(uuid.uuid4())
        attack_tree["nodes"].append({
            "id": or_gate_sub_attack_id,
            "label": "OR",
            "type": "OR Gate",
            "position": {"x": x_positions[index], "y": 350},
            "data": {
                "connections": [],
                "label": "OR",
                "style": {
                    "backgroundColor": "#FF9800",
                    "borderColor": "#E65100",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "color": "white",
                    "fontFamily": "Inter",
                    "fontSize": "20px",
                    "fontStyle": "normal",
                    "fontWeight": "bold",
                    "height": 50,
                    "textAlign": "center",
                    "textDecoration": "none",
                    "width": 50,
                    "borderRadius": "50%"
                }
            }
        })
        
        attack_tree["edges"].append({
            "id": str(uuid.uuid4()),
            "markerEnd": {
                "color": "#666",
                "height": 10,
                "type": "arrowclosed",
                "width": 10
            },
            "points": [],
            "data": {"label": ""},
            "source": sub_attack_id,
            "target": or_gate_sub_attack_id,
            "type": "step",
            "style": {"stroke": "#666", "strokeWidth": 2}
        })
        
        # Process children
        children = attack.get("children", [])
        if children:
            # Limit to 2 children per sub-attack for cleaner display
            if len(children) > 2:
                children = children[:2]
            
            num_children = len(children)
            if num_children == 1:
                child_x = x_positions[index]
            else:
                child_spacing = 150
                child_x_start = x_positions[index] - (child_spacing * (num_children - 1)) / 2
                child_x_positions = [child_x_start + i * child_spacing for i in range(num_children)]
            
            for child_index, child in enumerate(children):
                child_name = child.get("name", f"Attack Technique {child_index + 1}")
                child_id = str(uuid.uuid4())
                
                attack_tree["nodes"].append({
                    "width": 180,
                    "height": 60,
                    "id": child_id,
                    "key": child_name,
                    "type": "Event",
                    "damageId": str(uuid.uuid4()),
                    "position": {
                        "x": child_x_positions[child_index] if num_children > 1 else x_positions[index],
                        "y": 450
                    },
                    "data": {
                        "connections": [],
                        "label": child_name[:30] + ("..." if len(child_name) > 30 else ""),
                        "impact": child.get("impact", "Medium"),
                        "description": child.get("description", ""),
                        "style": {
                            "backgroundColor": "#F44336",
                            "borderColor": "#B71C1C",
                            "borderStyle": "solid",
                            "borderWidth": "2px",
                            "color": "white",
                            "fontFamily": "Inter",
                            "fontSize": "13px",
                            "fontStyle": "normal",
                            "fontWeight": 500,
                            "height": 60,
                            "textAlign": "center",
                            "textDecoration": "none",
                            "width": 180
                        }
                    }
                })
                
                attack_tree["edges"].append({
                    "id": str(uuid.uuid4()),
                    "markerEnd": {
                        "color": "#666",
                        "height": 10,
                        "type": "arrowclosed",
                        "width": 10
                    },
                    "points": [],
                    "data": {"label": ""},
                    "source": or_gate_sub_attack_id,
                    "target": child_id,
                    "type": "step",
                    "style": {"stroke": "#666", "strokeWidth": 2}
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
            print(f"Using cached attack data for {prompt_key}")
        else:
            # Add delay for API rate limiting
            time.sleep(2)
            
            # OPTIMIZED PROMPT with explicit requirements
            prompt = f"""Generate a comprehensive attack tree JSON for automotive {prompt_key} security.

CRITICAL REQUIREMENTS - MUST FOLLOW EXACTLY:
1. Generate EXACTLY 5 attack categories in AttackData array
2. Each category MUST have EXACTLY 2 attack techniques in children array
3. All techniques must be realistic and specific to automotive {prompt_key} systems

Required JSON structure:
{{
    "Attack": "Specific attack goal for {prompt_key}",
    "description": "Detailed description of the attack scenario",
    "root": "Ultimate attacker objective",
    "AttackData": [
        {{
            "SubAttack1": "First attack category name",
            "children": [
                {{"name": "Specific technique 1", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}},
                {{"name": "Specific technique 2", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}}
            ]
        }},
        {{
            "SubAttack2": "Second attack category name",
            "children": [
                {{"name": "Specific technique 1", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}},
                {{"name": "Specific technique 2", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}}
            ]
        }},
        {{
            "SubAttack3": "Third attack category name",
            "children": [
                {{"name": "Specific technique 1", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}},
                {{"name": "Specific technique 2", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}}
            ]
        }},
        {{
            "SubAttack4": "Fourth attack category name",
            "children": [
                {{"name": "Specific technique 1", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}},
                {{"name": "Specific technique 2", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}}
            ]
        }},
        {{
            "SubAttack5": "Fifth attack category name",
            "children": [
                {{"name": "Specific technique 1", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}},
                {{"name": "Specific technique 2", "impact": "Critical/High/Medium/Low", "description": "How this attack works"}}
            ]
        }}
    ]
}}

Generate ONLY valid JSON, no other text or explanation. Make it specific to automotive {prompt_key} security."""
            
            generation_config = {
                "temperature": 0.7,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 4096,
                "response_mime_type": "application/json"
            }
            
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            ]

            # Try different models for better results
            models_to_try = ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"]
            attack_data = None
            
            for model_name in models_to_try:
                try:
                    print(f"Trying model: {model_name}")
                    model = genai.GenerativeModel(
                        model_name=model_name,
                        generation_config=generation_config,
                        safety_settings=safety_settings
                    )
                    
                    max_retries = 3
                    retry_delay = 5
                    
                    for attempt in range(max_retries):
                        try:
                            chat_session = model.start_chat(history=[])
                            response = chat_session.send_message(prompt)
                            
                            if response and response.text:
                                attack_data = json.loads(response.text)
                                print(f"Success with {model_name}")
                                break
                        except Exception as e:
                            if attempt < max_retries - 1:
                                print(f"Attempt {attempt + 1} failed with {model_name}: {e}")
                                time.sleep(retry_delay)
                                continue
                            else:
                                raise e
                    
                    if attack_data:
                        break
                        
                except Exception as e:
                    print(f"Model {model_name} failed: {e}")
                    continue
            
            if attack_data:
                # Log what we received
                print(f"Received attack data with {len(attack_data.get('AttackData', []))} sub-attacks")
                
                # Validate and fix the structure
                attack_data = validate_and_fix_attack_data(attack_data, prompt_key)
                
                print(f"After validation: {len(attack_data.get('AttackData', []))} sub-attacks")
            else:
                print("All models failed, using fallback data")
                attack_data = get_generic_attack_data(prompt_key)
                if not attack_data:
                    attack_data = {
                        "Attack": f"Attack on {prompt_key}",
                        "description": f"Security attack tree for {prompt_key}",
                        "root": f"Compromise {prompt_key}",
                        "AttackData": []
                    }
                attack_data = validate_and_fix_attack_data(attack_data, prompt_key)

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
                "is_generated": attack_data is not None
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
            # Check for duplicate scene names
            for scene in existing_doc.get("scenes", []):
                if scene.get("Name") == new_scene["Name"]:
                    # Instead of error, return the existing scene
                    return jsonify({
                        "message": "Attack tree already exists",
                        "scene": scene,
                        "ai_generated": True
                    }), 200

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

        # Verify the tree has sufficient nodes
        node_count = len(new_scene["templates"]["nodes"])
        edge_count = len(new_scene["templates"]["edges"])
        print(f"Generated tree with {node_count} nodes and {edge_count} edges")
        
        if node_count < 5:
            print(f"WARNING: Only {node_count} nodes generated, expected more")

        return jsonify({
            "message": "Attack tree stored successfully", 
            "scene": new_scene,
            "stats": {
                "nodes": node_count,
                "edges": edge_count,
                "sub_attacks": len(attack_data.get("AttackData", []))
            }
        }), 200

    except Exception as e:
        error_msg = str(e)
        print(f"Error in generate_and_store_attack: {error_msg}")
        
        if any(keyword in error_msg.lower() for keyword in ["429", "quota", "rate limit"]):
            return jsonify({
                "error": "API rate limit reached. Using cached data if available.",
                "suggestion": "Try again in 1 hour or use previously generated attack trees."
            }), 429
        return jsonify({"error": error_msg}), 500