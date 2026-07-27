from flask import current_app as app
from flask import request, jsonify, json
from bson import ObjectId
from db import db
from app.Methods.auth_helpers import get_user_id
from datetime import datetime
from flask import Blueprint
import re
from bson import ObjectId

app = Blueprint("models", __name__)


@app.route("/", methods=["GET"])
def hello():
    return "WORKING SUCCESSFULLY"


@app.route("/v1/get_details/models", methods=["POST"])
def get_Models():
    try:
        user_id = get_user_id()
        model_type = request.form.get("type")  # Optional: 'library' or 'model'
         
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        if model_type == "library":
            query = {
                "user_id": user_id,
                "status": 1,
                "type": "library"
            }
        else:
            # Default case: get models with type 'model' or no type at all
            query = {
                "user_id": user_id,
                "status": 1,
                "$or": [
                    {"type": {"$exists": False}},
                    {"type": "model"}
                ]
            }

        data = list(db.Models.find(query))

        for item in data:
            item["_id"] = str(item["_id"])

        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/get_details/sub_systems", methods=["POST"])
def get_sub_systems():
    try:
        user_id = get_user_id()
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        data = list(db.sub_systems.find({"user_id": user_id, "status": 1}))

        for item in data:
            item["_id"] = str(item["_id"])

        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/get_details/model", methods=["POST"])
def get_unique_model():
    try:
        model_id = request.form.get("model-id")

        if not model_id or not re.match(r"^[0-9a-fA-F]{24}$", model_id):
            return jsonify({"error": "Invalid or missing model ID"}), 400

        # ---- Find master model ----
        master_model = db.Models.find_one({"_id": ObjectId(model_id)})

        if not master_model:
            master_model = db.Libraries.find_one({"_id": ObjectId(model_id)})
            if not master_model:
                return jsonify({"error": "Model not found in Models or Libraries"}), 404

        master_model["_id"] = str(master_model["_id"])

        # ---- Master model report_info ----
        master_report = db.ReportsContent.find_one({"model_id": model_id})
        master_model["report_info"] = (
            {
                "purpose": master_report.get("purpose"),
                "intro": master_report.get("intro"),
                "scope": master_report.get("scope"),
            }
            if master_report
            else {}
        )

        # ---- Sub-models ----
        sub_system_ids = master_model.get("sub_systems", [])
        object_ids = [
            ObjectId(sid)
            for sid in sub_system_ids
            if re.match(r"^[0-9a-fA-F]{24}$", sid)
        ]

        sub_models_cursor = db.Models.find({"_id": {"$in": object_ids}})
        sub_models = []

        for model in sub_models_cursor:
            sub_model_id = str(model["_id"])

            # ---- Sub-model report_info (OWN model_id) ----
            sub_report = db.ReportsContent.find_one({"model_id": sub_model_id})
            sub_report_info = (
                {
                    "purpose": sub_report.get("purpose"),
                    "intro": sub_report.get("intro"),
                    "scope": sub_report.get("scope"),
                }
                if sub_report
                else {}
            )

            filtered_model = {
                "_id": sub_model_id,
                "Created_at": model.get("Created_at"),
                "created_by": model.get("created_by"),
                "last_updated": model.get("last_updated"),
                "name": model.get("name"),
                "user_id": model.get("user_id"),
                "report_info": sub_report_info,
            }

            # ---- Assets ----
            assets_cursor = db.Assets.find(
                {"model_id": sub_model_id},
                {"_id": 1, "model_id": 1, "template": 1},
            )

            filtered_model["assets"] = [
                {
                    "_id": str(asset["_id"]),
                    "model_id": asset["model_id"],
                    "template": asset.get("template", []),
                }
                for asset in assets_cursor
            ]

            sub_models.append(filtered_model)

        master_model["sub_models"] = sub_models

        return jsonify(master_model), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/v1/update/model-name", methods=["POST"])
def update_model_name():
    try:
        model_id = request.form.get("model-id")

        if not model_id or not re.match(r"^[0-9a-fA-F]{24}$", model_id):
            return jsonify({"error": "Invalid or missing model ID"}), 400

        # -------- Update Model Name (optional) --------
        name = request.form.get("name")
        if name:
            db.Models.update_one(
                {"_id": ObjectId(model_id)},
                {"$set": {"name": name}}
            )

        # -------- Update Report Info (optional) --------
        report_updates = {}

        purpose = request.form.get("purpose")
        intro = request.form.get("intro")
        scope = request.form.get("scope")

        if purpose is not None:
            report_updates["purpose"] = purpose
        if intro is not None:
            report_updates["intro"] = intro
        if scope is not None:
            report_updates["scope"] = scope

        if report_updates:
            db.ReportsContent.update_one(
                {"model_id": model_id},
                {
                    "$set": report_updates,
                    "$setOnInsert": {"model_id": model_id}
                },
                upsert=True
            )

        return jsonify({"success": "Model updated successfully"}), 202

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/add/models", methods=["POST"])
def add_Model_or_Library():
    try:
        user_id = get_user_id()
        current = datetime.now()
        created_by = request.form.get("createdBy")
        name = request.form.get("name")
        model_type = request.form.get("type", "model").lower()  # Default to "model" if not provided

        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        if not created_by:
            return jsonify({"error": "Created user details required"}), 400

        if not name:
            return jsonify({"error": "Model name is required"}), 400

        # Check if model with same name and type already exists for this user
        existing_model = db.Models.find_one({
            "user_id": user_id,
            "name": name,
            "type": model_type
        })
        if existing_model:
            return jsonify({"error": f"{model_type.capitalize()} with the same name already exists"}), 409

        data = {
            "user_id": user_id,
            "name": name,
            "template": [],
            "created_by": created_by,
            "Created_at": current,
            "last_updated": current,
            "status": 1,
            "type": model_type  # Either 'model' or 'library'
        }

        result = db.Models.insert_one(data)

        return jsonify({"model_id": str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/v1/convert_model_type", methods=["POST"])
def convert_model_type():
    try:
        model_id = request.form.get("model-id")
        new_type = request.form.get("type", "").strip().lower()  # Normalize input

        if not model_id or not new_type:
            return jsonify({"error": "model_id and type are required"}), 400

        # Only allow "model" or "library"
        allowed_types = {"model", "library"}
        if new_type not in allowed_types:
            return jsonify({"error": "Invalid type. Allowed values: 'model' or 'library'"}), 400

        result = db.Models.update_one(
            {"_id": ObjectId(model_id)},
            {"$set": {"type": new_type, "last_updated": datetime.now()}}
        )

        if result.matched_count == 0:
            return jsonify({"error": "No model found with the given ID"}), 404

        return jsonify({"message": f"Successfully converted to type '{new_type}'"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/delete/models", methods=["DELETE"])
def delete_model():
    try:
        model_ids = request.form.get("model-ids")
        user_id = request.form.get("user-id")  # Fetch user_id from request

        if not model_ids or not user_id:
            return jsonify({"error": "model-ids and user-id are required"}), 400

        model_ids = model_ids.split(",")
        object_ids = [ObjectId(model_id.strip()) for model_id in model_ids]

        models = list(db.Models.find({"_id": {"$in": object_ids}}))
        if len(models) != len(object_ids):
            return jsonify({"error": "One or more models not found"}), 404

        # Fetch all model IDs for the given user where status = 1, sorted by _id
        all_models = list(
            db.Models.find({"user_id": user_id, "status": 1}, {"_id": 1}).sort("_id", 1)
        )
        all_model_ids = [str(model["_id"]) for model in all_models]

        # Find the next or previous model ID
        next_model_id = None
        if all_model_ids:
            deleted_indexes = [
                all_model_ids.index(mid) for mid in model_ids if mid in all_model_ids
            ]
            if deleted_indexes:
                min_index = min(deleted_indexes)
                max_index = max(deleted_indexes)

                # Check next model
                if max_index + 1 < len(all_model_ids):
                    next_model_id = all_model_ids[max_index + 1]
                # Check previous model if next not found
                elif min_index > 0:
                    next_model_id = all_model_ids[min_index - 1]

        # Set status to 0 instead of deleting
        db.Models.update_many(
            {"_id": {"$in": object_ids}},
            {"$set": {"status": 0}},
        )

        # db.Models.delete_many({'_id': {'$in': object_ids}})  # Uncomment if actual deletion is needed

        return (
            jsonify(
                {
                    "message": f"{len(object_ids)} models deleted successfully",
                    "next_model_id": next_model_id,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Collections to clear
collections_to_clear = [
    "Assets",
    "Damage_scenarios",
    "Threat_scenrios",
    "Cybersecurity",
    "Attacks",
    "Risk_treatment"
]


@app.route("/v1/clear_model_data", methods=["POST"])
def clear_model_data():
    try:
        model_id = request.form.get("modelId")
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        deleted_counts = {}

        # Go through each collection and delete docs with model_id
        for collection in collections_to_clear:
            result = db[collection].delete_many({"model_id": model_id})
            deleted_counts[collection] = result.deleted_count

        return jsonify({
            "message": f"Data cleared for model_id {model_id}",
            "deleted_counts": deleted_counts
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route("/v1/delete_model_data", methods=["POST"])
def delete_model_data():
    try:
        model_id = request.form.get("modelId")
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        deleted_counts = {}

        # Handle Models collection separately (using _id)
        try:
            from bson.objectid import ObjectId
            models_result = db["Models"].delete_one({"_id": ObjectId(model_id)})
            deleted_counts["Models"] = models_result.deleted_count
        except Exception as e:
            # If model_id is not a valid ObjectId format
            deleted_counts["Models"] = 0
            # Optionally log the error

        # Go through other collections and delete docs with model_id field
        for collection in collections_to_clear:

            result = db[collection].delete_many({"model_id": model_id})
            deleted_counts[collection] = result.deleted_count

        return jsonify({
            "message": f"Data cleared for model_id {model_id}",
            "deleted_counts": deleted_counts
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
     
tara_data = {}

@app.route("/v1/taraModel/store", methods=["POST"])
def store_tara_data():
    try:
        # Extract form data
        model_id = request.form.get('modelId')
        vehicle_tara_edges = request.form.get('vehicleTaraEdges')
        vehicle_tara_nodes = request.form.get('vehicleTaraNodes')
        vehicle_tara_viewport = request.form.get('vehicleTaraViewport')

        # Validate inputs
        if not all([model_id, vehicle_tara_edges, vehicle_tara_nodes, vehicle_tara_viewport]):
            return jsonify({"error": "All fields (modelId, vehicleTaraEdges, vehicleTaraNodes, vehicleTaraViewport) are required"}), 400

        # Check if modelId already exists
        existing_model = db.tara_data.find_one({"model_id": model_id})
        if existing_model:
            return jsonify({"error": "Data for this modelId already exists. Use the update endpoint."}), 400

        # Prepare the data to store
        tara_data = {
            "model_id": model_id,
            "vehicle_tara_edges": vehicle_tara_edges,
            "vehicle_tara_nodes": vehicle_tara_nodes,
            "vehicle_tara_viewport": vehicle_tara_viewport
        }

        # Insert into MongoDB
        db.tara_data.insert_one(tara_data)

        return jsonify({"message": "Data stored successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/taraModel/fetch", methods=["POST"])
def fetch_tara_data():
    try:
        # Get the modelId from the form data
        model_id = request.form.get('modelId')

        # Check if modelId is provided
        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        # Fetch the data for the given modelId from MongoDB
        data = db.tara_data.find_one({"model_id": model_id})

        # If data is not found, return error
        if not data:
            return jsonify({"error": "Model not found"}), 404

        # Convert string fields into JSON objects using json.loads()
        vehicle_tara_edges = json.loads(data["vehicle_tara_edges"]) if data["vehicle_tara_edges"] else []
        vehicle_tara_nodes = json.loads(data["vehicle_tara_nodes"]) if data["vehicle_tara_nodes"] else []
        vehicle_tara_viewport = json.loads(data["vehicle_tara_viewport"]) if data["vehicle_tara_viewport"] else {}

        # Return the data, ensuring fields are in proper JSON format
        return jsonify({
            "modelId": data["model_id"],
            "vehicleTaraEdges": vehicle_tara_edges,
            "vehicleTaraNodes": vehicle_tara_nodes,
            "vehicleTaraViewport": vehicle_tara_viewport
        }), 200

    except Exception as e:
        # In case of any errors, return an error message
        return jsonify({"error": str(e)}), 500


@app.route("/v1/taraModel/update", methods=["POST"])
def update_tara_data():
    try:
        # Extract form data
        model_id = request.form.get('modelId')
        vehicle_tara_edges = request.form.get('vehicleTaraEdges')
        vehicle_tara_nodes = request.form.get('vehicleTaraNodes')
        vehicle_tara_viewport = request.form.get('vehicleTaraViewport')

        # Validate inputs
        if not all([model_id, vehicle_tara_edges, vehicle_tara_nodes, vehicle_tara_viewport]):
            return jsonify({"error": "All fields (modelId, vehicleTaraEdges, vehicleTaraNodes, vehicleTaraViewport) are required"}), 400

        # Check if the modelId exists
        existing_model = db.tara_data.find_one({"model_id": model_id})

        if not existing_model:
            return jsonify({"error": "Model not found. Please use the store endpoint to add new data."}), 404

        # Update the data in MongoDB
        db.tara_data.update_one(
            {"model_id": model_id},
            {"$set": {
                "vehicle_tara_edges": vehicle_tara_edges,
                "vehicle_tara_nodes": vehicle_tara_nodes,
                "vehicle_tara_viewport": vehicle_tara_viewport
            }}
        )

        return jsonify({"message": "Data updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
