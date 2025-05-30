from flask import current_app as app
from flask import request, jsonify, json
from flask import Blueprint
from bson import ObjectId
from db import db
import uuid

app = Blueprint("cybersecurity", __name__)


@app.route("/v1/get_details/cybersecurity", methods=["POST"])
def get_cybersecurity():
    try:
        model_id = request.form.get("model-id")
        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        # Find all documents with the specified model_id
        data_cursor = db.Cybersecurity.find({"model_id": model_id})
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


@app.route("/v1/add/cybersecurity", methods=["POST"])
def add_cybersecurity():
    try:
        model_id = request.form.get("modelId")
        cyber_type = request.form.get("type")
        name = request.form.get("name")
        description = request.form.get("description")
        cyber_id = request.form.get("id")
        threat_id = request.form.get("threatId")
        threat_key = request.form.get("threatKey")
        attack_scene_id = request.form.get("attackSceneId")
        attack_scene_name = request.form.get("attackSceneName")

        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        if not cyber_type:
            return jsonify({"error": "type is required"}), 400

        if not name:
            return jsonify({"error": "name is required"}), 400
        existing_name = db.Cybersecurity.find_one(
            {"model_id": model_id, "type": cyber_type, "scenes.Name": name}
        )
        if existing_name:
            return (
                jsonify({"error": f"{cyber_type} with same name cannot be added"}),
                401,
            )
        # Construct the new scene based on the attack_type
        new_scene = {
            "ID": cyber_id if cyber_id else str(uuid.uuid4()),
            "Name": name,
            "Description": description if description else None,
            "threat_id": threat_id if threat_id else None,
            "threat_key": threat_key if threat_key else None,
            "attack_scene_id":attack_scene_id if attack_scene_id else None,
            "attack_scene_name":attack_scene_name if attack_scene_name else None
        }

        # Check if a document with the given model_id and attack_type exists
        existing_record = db.Cybersecurity.find_one(
            {"model_id": model_id, "type": cyber_type}
        )

        if existing_record:
            # If exists, push the new scene to the scenes array
            db.Cybersecurity.update_one(
                {"_id": existing_record["_id"]}, {"$push": {"scenes": new_scene}}
            )
            return jsonify({"message": "Scene added successfully"}), 200
        else:
            # If not exists, create a new object
            data = {
                "model_id": model_id,
                "type": cyber_type,
                "scenes": [new_scene],
            }
            result = db.Cybersecurity.insert_one(data)
            return (
                jsonify(
                    {
                        "message": "Added successfully",
                        "model_id": str(result.inserted_id),
                    }
                ),
                201,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update/cybersecurity_name&desc", methods=["PATCH"])
def update_name_desc():
    try:
        # Retrieve input data from the request
        scenario_id = request.form.get("id")
        scene_id = request.form.get("sceneId")
        name = request.form.get("Name")
        description = request.form.get("Description")

        # Basic validation before JSON parsing
        if not scenario_id or not scene_id:
            return jsonify({"error": "Scenario ID and Detail ID are required"}), 400

        # Ensure MongoDB index on 'scenes._id'
        db.Cybersecurity.create_index("scenes._id", background=True)

        # Check for duplicate Name in the 'scenes' array
        if name:
            query = {
                "_id": ObjectId(scenario_id),
                "scenes": {
                    "$elemMatch": {
                        "ID": {"$ne": scene_id},  # Exclude the current detail
                        "Name": name,  # Check for duplicate name
                    }
                },
            }
            duplicate_check = db.Cybersecurity.find_one(query)

            if duplicate_check:
                return jsonify({"error": "Name already present in scenes"}), 409

        # Prepare update data
        update_data = {}
        if name:
            update_data["scenes.$[elem].Name"] = name
        if description:
            update_data["scenes.$[elem].Description"] = description

        # Update Cybersecurity collection
        result = db.Cybersecurity.update_one(
            {"_id": ObjectId(scenario_id)},
            {"$set": update_data},
            array_filters=[{"elem.ID": scene_id}],
        )

        if result.matched_count == 0:
            return jsonify({"error": "No matching Damage_scenario found"}), 404

        return jsonify({"message": "Updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/v1/delete/cybersecurity", methods=["DELETE"])
def delete_cybersecurity():
    try:
        cyber_id = request.form.get("id")
        raw_detail_ids = request.form.get("rowId", "")
        rowIds = [s.strip() for s in raw_detail_ids.split(",") if s.strip()]

        if not ObjectId.is_valid(cyber_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        if not rowIds:
            return jsonify({"error": "At least one rowId is required"}), 400

        model = db.Cybersecurity.find_one({"_id": ObjectId(cyber_id)})
        if not model:
            return jsonify({"error": "Model not found"}), 404

        result = db.Cybersecurity.update_one(
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
