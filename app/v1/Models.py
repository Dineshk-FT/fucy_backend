from flask import current_app as app
from flask import request, jsonify, json
from bson import ObjectId
from db import db
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
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        data = list(db.Models.find({"user_id": user_id, "status": 1}))

        for item in data:
            item["_id"] = str(item["_id"])

        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/get_details/sub_systems", methods=["POST"])
def get_sub_systems():
    try:
        user_id = request.headers.get("user-id")
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

        master_model = db.Models.find_one({"_id": ObjectId(model_id)})
        if not master_model:
            return jsonify({"error": "model not found"}), 404

        master_model["_id"] = str(master_model["_id"])

        sub_system_ids = master_model.get("sub_systems", [])
        object_ids = [
            ObjectId(sid)
            for sid in sub_system_ids
            if re.match(r"^[0-9a-fA-F]{24}$", sid)
        ]

        sub_models_cursor = db.Models.find({"_id": {"$in": object_ids}})
        sub_models = []

        for model in sub_models_cursor:
            model_id_str = str(model["_id"])

            # Pick only required fields from model
            filtered_model = {
                "_id": model_id_str,
                "Created_at": model.get("Created_at"),
                "created_by": model.get("created_by"),
                "last_updated": model.get("last_updated"),
                "name": model.get("name"),
                "user_id": model.get("user_id"),
            }

            # Get only required asset fields
            assets_cursor = db.Assets.find(
                {"model_id": model_id_str}, {"_id": 1, "model_id": 1, "template": 1}
            )
            filtered_assets = []
            for asset in assets_cursor:
                filtered_assets.append(
                    {
                        "_id": str(asset["_id"]),
                        "model_id": asset["model_id"],
                        "template": asset.get("template", []),
                    }
                )

            filtered_model["assets"] = filtered_assets
            sub_models.append(filtered_model)

        master_model["sub_models"] = sub_models

        return jsonify(master_model), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# @app.route("/v1/get_details/model", methods=["POST"])
# def get_unique_model():
#     try:
#         model_id = request.form.get("model-id")

#         if not model_id or not re.match(r"^[0-9a-fA-F]{24}$", model_id):
#             return jsonify({"error": "Invalid or missing model ID"}), 400

#         model = db.Models.find_one({"_id": ObjectId(model_id)})
#         if model:
#             model["_id"] = str(model["_id"])
#             return jsonify(model), 200
#         else:
#             return jsonify({"error": "model not found"}), 404
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route("/v1/update/model-name", methods=["POST"])
def update_model_name():
    try:
        model_id = request.form.get("model-id")
        name = request.form.get("name")
        if not model_id or not re.match(r"^[0-9a-fA-F]{24}$", model_id):
            return jsonify({"error": "Invalid or missing model ID"}), 400

        db.Models.update_one({"_id": ObjectId(model_id)}, {"$set": {"name": name}})
        return jsonify({"success": "model name changed"}), 202
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/add/models", methods=["POST"], endpoint="add_Models")
def add_Models():
    try:
        user_id = request.headers.get("user-id")
        current = datetime.now()
        created_by = request.form.get("createdBy")

        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        name = request.form.get("name")
        if not created_by:
            return jsonify({"error": "Created user details required"}), 400

        if not name:
            return jsonify({"error": "Model name is required"}), 400

        # Check if model with same name already exists for this user
        existing_model = db.Models.find_one({"user_id": user_id, "name": name})
        if existing_model:
            return jsonify({"error": "Model with the same name already exists"}), 409

        data = {
            "user_id": user_id,
            "name": name,
            "template": [],
            "created_by": created_by,
            "Created_at": current,
            "last_updated": current,
            "status": 1,
            # "config_id": ""
        }

        result = db.Models.insert_one(data)

        return (
            jsonify({"model_id": str(result.inserted_id)}),
            201,
        )

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
