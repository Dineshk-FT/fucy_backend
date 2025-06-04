from flask import current_app as app
from flask import request, jsonify, json
from bson import ObjectId
from db import db
from flask import Blueprint
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
import base64

app = Blueprint("assets", __name__)


@app.route("/v1/get_details/assets", methods=["POST"], endpoint="get_asset")
def get_asset():
    try:
        model_id = request.form.get("model-id")

        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        data = db.Assets.find_one({"model_id": model_id})
        if data:
            data["_id"] = str(data["_id"])
            if "image" in data and isinstance(data["image"], bytes):
                data["image"] = base64.b64encode(data["image"]).decode("utf-8")
            return jsonify(data), 200
        else:
            return jsonify({"error": "Model not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update/assets", methods=["POST"])
def add_assets():
    try:
        user_id = request.headers.get("user-id")
        model_id = request.form.get("model-id")
        template = request.form.get("template")
        asset_name = request.form.get("assetName")
        asset_properties = request.form.get("assetProperties")
        image_file = request.files.get("image")
        image = None
        if image_file:
            image = image_file.read()

        if not user_id:
            return jsonify({"error": "user_id is required"}), 400
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        asset_id = request.form.get("assetId")

        if asset_id:
            if isinstance(template, str):
                try:
                    template = json.loads(template)
                except json.JSONDecodeError:
                    return jsonify({"error": "template must be valid JSON"}), 400

            if not template:
                return jsonify({"error": "template is required for updates"}), 400

            try:
                existing_scenario = db.Damage_scenarios.find_one(
                    {"model_id": model_id, "type": "Derived"}
                )

                existing_derivations = (
                    {
                        derivation["id"]: derivation.get("is_checked")
                        for derivation in existing_scenario.get("Derivations", [])
                    }
                    if existing_scenario
                    else {}
                )

                existing_details = (
                    {
                        detail["nodeId"]: {
                            prop["name"]: prop["id"] for prop in detail.get("props", [])
                        }
                        for detail in existing_scenario.get("Details", [])
                    }
                    if existing_scenario
                    else {}
                )

                Derivations, Details = getDerivationsAndDetails(
                    template, existing_details
                )

                for derivation in Derivations:
                    if derivation["id"] in existing_derivations:
                        derivation["is_checked"] = existing_derivations[
                            derivation["id"]
                        ]

                result = db.Assets.update_one(
                    {"_id": ObjectId(asset_id)},
                    {
                        "$set": {
                            "template": template,
                            "Details": Details,
                            "image": image,
                        }
                    },
                )
                if result.matched_count == 0:
                    return jsonify({"error": "Asset not found"}), 404

                db.Damage_scenarios.update_one(
                    {"model_id": model_id, "type": "Derived"},
                    {"$set": {"Derivations": Derivations, "Details": Details}},
                    upsert=True,
                )

                return jsonify({"message": "Asset updated successfully"}), 200
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        try:
            template = json.loads(template) if isinstance(template, str) else template
        except json.JSONDecodeError:
            return jsonify({"error": "template must be valid JSON"}), 400

        existing_asset = db.Assets.find_one(
            {"user_id": user_id, "model_id": model_id, "asset_name": asset_name}
        )

        if existing_asset:
            return (
                jsonify(
                    {
                        "error": "An asset with the same name already exists for this user and model"
                    }
                ),
                409,
            )

        Derivations, Details = getDerivationsAndDetails(template, {})

        data = {
            "user_id": user_id,
            "model_id": model_id,
            "template": template,
            "asset_name": asset_name,
            "asset_properties": asset_properties,
            "Details": Details,
        }

        db.Assets.insert_one(data)

        db.Damage_scenarios.update_one(
            {"model_id": model_id, "type": "Derived"},
            {
                "$set": {
                    "model_id": model_id,
                    "user_id": user_id,
                    "type": "Derived",
                    "Derivations": Derivations,
                    "Details": Details,
                }
            },
            upsert=True,
        )

        return jsonify({"message": "Asset added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/delete-node/assets", methods=["DELETE"], endpoint="delete_asset_node")
def delete_asset_node():
    try:
        # Get assetId and nodeId from request
        asset_id = request.form.get("assetId")
        asset_id = ObjectId(asset_id)
        node_id = request.form.get("nodeId")

        if not asset_id or not node_id:
            return jsonify({"error": "assetId and nodeId are required"}), 400

        # Find the asset in the collection
        asset = db.Assets.find_one({"_id": asset_id})
        if not asset:
            return jsonify({"error": "Asset not found"}), 404

        # Remove the node from template.nodes
        updated_nodes = [
            node for node in asset["template"]["nodes"] if node["id"] != node_id
        ]

        # Remove edges where node_id is in source or target
        updated_edges = [
            edge
            for edge in asset["template"]["edges"]
            if edge["source"] != node_id and edge["target"] != node_id
        ]

        # Ensure existing_details is a dictionary, not a list
        details_list = asset.get("Details", [])
        existing_details = {
            d["nodeId"]: {prop["name"]: prop["id"] for prop in d.get("props", [])}
            for d in details_list
            if isinstance(d, dict)
        }

        # Update the asset in the database
        template = {"nodes": updated_nodes, "edges": updated_edges}
        Derivations, Details = getDerivationsAndDetails(template, existing_details)

        result = db.Assets.update_one(
            {"_id": asset_id},
            {
                "$set": {
                    "template.nodes": updated_nodes,
                    "template.edges": updated_edges,
                    "Details": Details,
                }
            },
        )

        if result.modified_count == 0:
            return jsonify({"error": "Failed to update asset"}), 500

        return jsonify({"message": "Node and related edges deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# seperate Update case -----------------------------------------------------------------------(Not required)
# @app.route('/v1/update/assets', methods=['POST'], endpoint='update_assets')
# def update_assets():
#     try:
#         asset_id = request.form.get('assetId')
#         template = request.form.get('template')

#         try:
#             template = json.loads(template) if isinstance(template, str) else template
#         except json.JSONDecodeError:
#             return jsonify({"error": "Template must be valid JSON"}), 400

# result = db.Assets.update_one(
#     {"_id": ObjectId(asset_id)},
#     {"$set": {"template": template}}
# )

#         if result.matched_count == 0:
#             return jsonify({"error": "Asset not found"}), 404

#         Derivations, Details = updateScenarios(template)

#         return jsonify({"message": "Asset updated successfully"}), 200
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
