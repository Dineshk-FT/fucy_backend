from flask import current_app as app
from flask import request, jsonify, json
from flask import Blueprint
from bson import ObjectId
from db import db
import uuid
from app.Methods.helpers import get_highest_rating

app = Blueprint("attacks", __name__)


# For getting attacks ===============================
@app.route("/v1/get_details/attacks", methods=["POST"])
def get_attack_scene():
    try:
        model_id = request.form.get("model-id")
        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        # Find all documents with the specified model_id
        data_cursor = db.Attacks.find({"model_id": model_id})
        data_list = []

        # Convert each document to a dictionary and format the "_id" field
        for data in data_cursor:
            data["_id"] = str(data["_id"])  # Convert ObjectId to string
            data_list.append(data)

        if data_list:
            return jsonify(data_list), 200
        else:
            return (
                jsonify({"error": "No documents found for the specified modelId"}),
                404,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# For Add======================
@app.route("/v1/add/attacks", methods=["POST"])
def add_attack():
    try:
        model_id = request.form.get("modelId")
        attack_type = request.form.get("type")
        threat_id = request.form.get("threatId")
        name = request.form.get("name")
        attack_id = request.form.get("attackId")

        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        if not attack_type:
            return jsonify({"error": "type is required"}), 400

        if not name:
            return jsonify({"error": "name is required"}), 400
        existing_name = db.Attacks.find_one(
            {"model_id": model_id, "type": attack_type, "scenes.Name": name}
        )
        if existing_name:
            return (
                jsonify({"error": f"{attack_type} with same name cannot be added"}),
                401,
            )
        # Construct the new scene based on the attack_type
        if attack_type == "attack":
            new_scene = {
                "Approach": "",
                "Attack Feasibilities Rating": "",
                "Elapsed Time": "",
                "Equipment": "",
                "Expertise": "",
                "ID": attack_id if attack_id else str(uuid.uuid4()),
                "Knowledge of the Item": "",
                "Name": name,
                "Window of Opportunity": "",
            }
        elif attack_type == "attack_trees":
            new_scene = {
                "ID": str(uuid.uuid4()),
                "Name": name,
                "threat_id": threat_id if threat_id else None,
                "templates": {"nodes": [], "edges": []},
            }
        else:
            return jsonify({"error": "Invalid type"}), 400

        # Check if a document with the given model_id and attack_type exists
        existing_record = db.Attacks.find_one(
            {"model_id": model_id, "type": attack_type}
        )

        if existing_record:
            # If exists, push the new scene to the scenes array
            db.Attacks.update_one(
                {"_id": existing_record["_id"]}, {"$push": {"scenes": new_scene}}
            )
            return jsonify({"message": "Scene added to existing attack"}), 200
        else:
            # If not exists, create a new object
            data = {
                "model_id": model_id,
                "type": attack_type,
                "scenes": [new_scene],
            }
            result = db.Attacks.insert_one(data)
            return (
                jsonify(
                    {
                        "message": "New attack created",
                        "model_id": str(result.inserted_id),
                    }
                ),
                201,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# For update==========================
@app.route("/v1/update/attacks", methods=["POST"])
def update_attack():
    try:
        model_id = request.form.get("modelId")
        attack_type = request.form.get("type")
        scene_id = request.form.get("id")
        threat_id = request.form.get("threatId")
        damage_id = request.form.get("damageId")
        threat_key = request.form.get("key")

        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        if not attack_type:
            return jsonify({"error": "type is required"}), 400

        if not scene_id:
            return jsonify({"error": "scene_id is required"}), 400

        if attack_type == "attack":
            update_data = {
                key: value
                for key, value in {
                    "Approach": request.form.get("Approach"),
                    "Attack Feasibilities Rating": request.form.get(
                        "Attack Feasibilities Rating"
                    ),
                    "Elapsed Time": request.form.get("Elapsed Time"),
                    "Equipment": request.form.get("Equipment"),
                    "Expertise": request.form.get("Expertise"),
                    "Knowledge of the Item": request.form.get("Knowledge of the Item"),
                    "Window of Opportunity": request.form.get("Window of Opportunity"),
                }.items()
                if value is not None
            }
        elif attack_type == "attack_trees":
            templates_str = request.form.get("templates", "")

            try:
                templates = json.loads(templates_str) if templates_str else {}
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON format for templates"}), 400

            ratings = []
            nodes = templates.get("nodes", [])

            # Fetch relevant documents from the database
            attack = db.Attacks.find_one({"model_id": model_id, "type": "attack"})
            cybersecurity = db.Cybersecurity.find_one(
                {"model_id": model_id, "type": "cybersecurity_requirements"}
            )

            # if not attack and not cybersecurity:
            #     return (
            #         jsonify(
            #             {"error": "No matching attack or cybersecurity document found"}    # if attack oe cyber requirement is necessary then remove this condition
            #         ),
            #         404,
            #     )

            scenes = attack.get("scenes", []) if attack else []
            require_scenes = cybersecurity.get("scenes", []) if cybersecurity else []

            for node in nodes:
                if node.get("type") == "Event":
                    rating = node.get("data", {}).get("rating")
                    if rating:
                        ratings.append(rating.lower())

                    # Match and update scene
                    for scene in scenes:
                        if scene.get("ID") == node.get("id") or scene.get(
                            "ID"
                        ) == node.get("data", {}).get("nodeId"):
                            scene["Name"] = node["data"]["label"]
                            break
                    for require in require_scenes:
                        if require.get("ID") == node.get("id") or require.get(
                            "ID"
                        ) == node.get("data", {}).get("nodeId"):
                            require["Name"] = node["data"]["label"]
                            break

            # Save updated scenes to the database if entries exist
            if attack:
                db.Attacks.update_one(
                    {"model_id": model_id, "type": "attack"},
                    {"$set": {"scenes": scenes}},
                )
            if cybersecurity:
                db.Cybersecurity.update_one(
                    {"model_id": model_id, "type": "cybersecurity_requirements"},
                    {"$set": {"scenes": require_scenes}},
                )

            highest_rating = get_highest_rating(ratings)
            update_data = {
                "ID": scene_id,
                "templates": templates,
                "threat_id": threat_id,
                "damage_id": damage_id,
                "threat_key": threat_key,
                "overall_rating": highest_rating if highest_rating else "",
            }
        else:
            return jsonify({"error": "Invalid attack type"}), 400

        # Find the attack document by model_id and type
        attack = db.Attacks.find_one({"model_id": model_id, "type": attack_type})

        if not attack:
            return jsonify({"error": "Attack not found"}), 404

        scenes = attack.get("scenes", [])
        scene_found = False

        # Check if a scene with the specified ID exists
        for scene in scenes:
            if scene["ID"] == scene_id:
                scene.update(update_data)  # Update the existing scene
                scene_found = True
                break

        # If no scene with the ID was found, append a new scene
        if not scene_found:
            new_scene = {"ID": scene_id, **update_data}
            scenes.append(new_scene)

        # Update the database
        db.Attacks.update_one(
            {"model_id": model_id, "type": attack_type}, {"$set": {"scenes": scenes}}
        )
        updated_scene = next((s for s in scenes if s["ID"] == scene_id), None)

        return jsonify({"message": "Attack updated successfully",  "scene": updated_scene}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# for removing attacks in checkbox
@app.route("/v1/remove/attacks", methods=["DELETE"])
def remove_attacks():
    try:
        attack_id = request.form.get("id")
        rowIds = request.form.getlist("rowId")

        if not ObjectId.is_valid(attack_id):
            return jsonify({"error": "Invalid id format"}), 400

        if not rowIds:
            return jsonify({"error": "At least one rowId is required"}), 400

        model = db.Attacks.find_one({"_id": ObjectId(attack_id)})
        if not model:
            return jsonify({"error": "Model not found"}), 404

        result = db.Attacks.update_one(
            {"_id": model["_id"]}, {"$pull": {"scenes": {"ID": {"$in": rowIds}}}}
        )

        if result.modified_count == 0:
            return jsonify({"error": "No matching rowIds found to delete"}), 404

        return (
            jsonify({"message": f"Successfully deleted rows"}),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# For Deletion-------------------------------------------------
# For Deletion-------------------------------------------------
@app.route('/v1/delete/attacks', methods=['POST'])
def delete():
    try:
        model_id = request.form.get('model-id')
        type = request.form.get('type')
        id = request.form.get('id')
        
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400
        
        if not type:
            return jsonify({"error": "type is required"}), 400
        
        if not id:
            return jsonify({"error": "id is required"}), 400
        
        if type== "attack":       
            result = db.Attacks.update_one(
                {
                    "model_id": model_id,
                    "type": type,
                    "scenes": {"$elemMatch": {"ID": id}}
                },
                {"$pull": {"scenes": {"ID": id}}} 
            )
            
            # if result.modified_count == 0:
            #     return jsonify({"error": "No matching scene found"}), 404
            # attack_trees = db.Attacks.find_one(
            #     {
            #         "model_id": model_id,
            #         "type": "attack_trees"
            #     }
            # )

            # if attack_trees:
            #     for scene in attack_trees.get("scenes", []):
            #         if "templates" in scene:
            #             for template in scene["templates"]:
            #                 if "nodes" in template:
            #                     result_nodes = db.Attacks.update_one(
            #                         {
            #                             "model_id": model_id,
            #                             "type": "attack_trees",  
            #                             "scenes.templates.nodes": {
            #                                 "$elemMatch": {
            #                                     "ID": id,
            #                                     "type": "Event"  
            #                                 }
            #                             }
            #                         },
            #                         {"$pull": {"scenes.$.templates.$.nodes": {"ID": id, "type": "Event"}}}
            #                     )
            #                     if result_nodes.modified_count > 0:
            #                         break

        if type== "attack_trees":
            result = db.Attacks.update_one(
                {
                    "model_id": model_id,
                    "type": "attack_trees",
                    "scenes": {"$elemMatch": {"ID": id}}
                },
                {"$pull": {"scenes": {"ID": id}}} 
            )
        return jsonify({"message": f"Scene and nodes with ID: {id} deleted successfully"}), 200
        
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route("/v1/add/AiAttack", methods=["POST"])
def addAiAttack():
    try:
        data = request.json  
        model_id = data.get("model_id")
        attack_type = data.get("type")
        name = data.get("Attack")  

        if not model_id or not attack_type or not name:
            return jsonify({"error": "Missing required fields"}), 400

        existing_name = db.Attacks.find_one(
            {"model_id": model_id, "type": attack_type, "scenes.Name": name}
        )
        if existing_name:
            return jsonify({"error": f"{attack_type} with the same name exists"}), 401

        new_scene = {
            "ID": str(uuid.uuid4()),
            "Name": name,
            "templates": {"nodes": [], "edges": []},
        }

        def process_attack(node, parent_id=None):
            node_id = str(uuid.uuid4())
            label = node.get("name") or node.get("SubAttack1") or node.get("SubAttack2") or node.get("SubAttack3") or node.get("SubAttack4")
            
            attack_node = {
                "id": node_id,
                "label": label,
                "type": "AttackNode",
                "data": {
                    "impact": node.get("impact", "Unknown"),
                    "description": node.get("description", "No description"),
                },
            }
            new_scene["templates"]["nodes"].append(attack_node)
            
            if parent_id:
                new_scene["templates"]["edges"].append({
                    "source": parent_id,
                    "target": node_id,
                    "type": "connection",
                })

            children_keys = ["children", "SubAttack1", "SubAttack2", "SubAttack3", "SubAttack4"]
            for key in children_keys:
                if key in node:
                    for child in node[key]:
                        process_attack(child, node_id)

        root_node = {"name": name, "SubAttack1": data.get("Attack1", [])}
        process_attack(root_node)

        db.Attacks.insert_one({
            "model_id": model_id,
            "type": attack_type,
            "scenes": [new_scene],
        })

        return jsonify({"message": "Attack tree added successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route("/v1/get/globalAttackTrees", methods=["POST"])
def getGlobalAiAttacks():
    try:
        attackTrees = db.geminiAttackTree.find()
        allAttacksTrees=[]
        for data in attackTrees:
            attack_info = {
                "id": str(data['_id']),
                "attackTreeName": data["scenes"][0]['Name'],
                "templates":data["scenes"][0]['templates']
            }
            allAttacksTrees.append(attack_info)

        if attackTrees:
            return jsonify(allAttacksTrees), 200
        else:
            return jsonify({"error": "No Attack Trees found"}), 404

    except Exception as e:
        return jsonify({"error":str(e)}),500 
    
@app.route("/v1/delete/globalAttackTree", methods=["DELETE"])
def deleteGlobalAiAttack():
        try:
            attack_tree_id = request.form.get("attack-id")
            if not attack_tree_id:
                  return jsonify({"error": "Attack Tree ID is required"}), 400
        
            result = db.geminiAttackTree.delete_one({"_id": ObjectId(attack_tree_id)})
            if result.deleted_count > 0:
                return jsonify({"message": "Attack Tree deleted successfully"}), 200
            else:
                return jsonify({"error": "Attack Tree not found"}), 404
        
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
@app.route('/v1/add/aiAttackTrees', methods=['POST'])
def generate_and_store_attack():
    try:
        attackId = request.form.get("aiAttackId")
        model_id = request.form.get("modelId")
        attack_type = "attack_trees"

        if not attackId or not model_id:
            return jsonify({"error": "Both attackId and modelId are required"}), 400
        
        try:
            attackId = ObjectId(attackId)
        except Exception:
            return jsonify({"error": "Invalid attackId format"}), 400

        attackTree = db.geminiAttackTree.find_one({"_id": attackId})
        
        if not attackTree:
            return jsonify({"error": "Attack Tree Not Found"}), 400

        scenes = attackTree.get("scenes", [])
        if not scenes:
            return jsonify({"error": "No scenes found in attack tree"}), 400

        scene_id = str(uuid.uuid4())  # Generate a unique scene ID

        # Attach the generated scene_id to each scene
        for scene in scenes:
            scene["ID"] = scene_id

        data = db.Attacks.find_one({"model_id": model_id, "type": attack_type})
        if data:
            db.Attacks.update_one(
                {"model_id": model_id, "type": attack_type},
                {"$push": {"scenes": {"$each": scenes}}}
            )
        else:
            return jsonify({"error": "Failed to Store Attack Tree"}), 400

        return jsonify({
            "message": "Attack tree stored successfully",
            "scene": scenes
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
