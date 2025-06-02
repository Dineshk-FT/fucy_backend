from flask import current_app as app
from flask import request, jsonify
import json
from bson import ObjectId
from db import db
from flask import Blueprint
import uuid

app = Blueprint("treath_scr", __name__)


def uid():
    return str(uuid.uuid4())


def convert_objectid_to_str(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    return obj


@app.route(
    "/v1/get_details/threat_scenarios", methods=["POST"], endpoint="get_threat_scene"
)
def get_threat_scene():
    try:
        model_id = request.form.get("model-id")
        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        # Find all documents with the specified model_id
        data_cursor = db.Threat_scenarios.find({"model_id": model_id})
        data_list = []

        # First collect all derived scenarios for reference
        derived_scenarios = []

        # Initialize a global key counter for props
        global_key_counter = 1

        # Convert each document to a dictionary and format the "_id" field
        for data in data_cursor:
            data["_id"] = str(data["_id"])  # Convert ObjectId to string

            # Keep track of derived scenarios for threat_ids processing
            if data.get("type") == "derived":
                derived_scenarios.append(data)

            # Process Details array (existing functionality)
            for detail in data.get("Details", []):
                row_id = detail.get("rowId")
                damage_ids = detail.get("damage_ids", [])

                # If damage_ids exist, fetch the corresponding details from Damage_scenarios
                if damage_ids:
                    damage_details = []

                    # Query Damage_scenarios for matching _id and model_id/type
                    damage_scenarios = db.Damage_scenarios.find(
                        {
                            "model_id": model_id,
                            "type": "User-defined",
                            "Details._id": {"$in": damage_ids},
                        }
                    )

                    # Iterate through matching damage_scenarios and extract relevant fields
                    for damage_scenario in damage_scenarios:
                        for damage_detail in damage_scenario.get("Details", []):
                            if damage_detail.get("_id") in damage_ids:
                                damage_details.append(
                                    {
                                        "name": damage_detail.get("Name"),
                                        "description": damage_detail.get("Description"),
                                        "key": damage_detail.get("key"),
                                        "cyberLosses": damage_detail.get(
                                            "cyberLosses", []
                                        ),
                                    }
                                )

                    # Add the extracted damage details to the corresponding detail
                    if damage_details:
                        detail["damage_details"] = damage_details

                # Existing logic for rowId processing, adding damage_name and damage_key
                if row_id:
                    # Query Damage_scenarios for matching _id
                    damage_scenario = db.Damage_scenarios.find_one(
                        {
                            "model_id": model_id,
                            "type": "User-defined",
                            "Details": {"$elemMatch": {"_id": row_id}},
                        }
                    )
                    if damage_scenario:
                        # Extract name and key from Damage_scenarios and add to detail
                        damage_detail = next(
                            (
                                item
                                for item in damage_scenario["Details"]
                                if str(item["_id"]) == row_id
                            ),
                            None,
                        )
                        if damage_detail:
                            detail["damage_name"] = damage_detail.get("Name")
                            detail["damage_key"] = damage_detail.get("key")

            data_list.append(data)

        # Now assign global prop keys to **all props** across all layers
        for data in data_list:
            for detail in data.get("Details", []):
                # Assign to top-level detail props
                if "props" in detail:
                    for prop in detail["props"]:
                        prop["key"] = global_key_counter
                        global_key_counter += 1

                # Check nested Details (like second layer)
                for second_layer in detail.get("Details", []):
                    if "props" in second_layer:
                        for prop in second_layer["props"]:
                            prop["key"] = global_key_counter
                            global_key_counter += 1

        # Now process threat_ids in User-defined scenarios (new functionality)
        for data in data_list:
            if data.get("type") == "User-defined":
                for detail in data.get("Details", []):
                    if "threat_ids" in detail:
                        # Process each threat_id in the array
                        for threat in detail["threat_ids"]:
                            row_id = threat.get("rowId")
                            node_id = threat.get("nodeId")
                            prop_id = threat.get("propId")

                            # Find matching derived scenario
                            for derived in derived_scenarios:
                                if derived["model_id"] == model_id:
                                    for derived_detail in derived.get("Details", []):
                                        if str(derived_detail.get("rowId")) == str(
                                            row_id
                                        ):
                                            for second_layer in derived_detail.get(
                                                "Details", []
                                            ):
                                                if str(
                                                    second_layer.get("nodeId")
                                                ) == str(node_id):
                                                    for prop in second_layer.get(
                                                        "props", []
                                                    ):
                                                        if str(prop.get("id")) == str(
                                                            prop_id
                                                        ):
                                                            threat["prop_key"] = (
                                                                prop.get("key")
                                                            )
                                                            threat["prop_name"] = (
                                                                prop.get("name")
                                                            )
                                                            threat["damage_scene"] = (
                                                                second_layer.get("name")
                                                            )
                                                            threat["node_name"] = (
                                                                second_layer.get("node")
                                                            )
                                                            threat["damage_id"] = (
                                                                derived_detail["id"]
                                                            )
                                                            break
                                            break

        if data_list:
            return jsonify(data_list), 200
        else:
            return (
                jsonify({"error": "No documents found for the specified model_id"}),
                404,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/add/threat_scenarios", methods=["POST"], endpoint="add_threat_scene")
def add_threat_scene():
    try:
        # Get form data
        model_id = request.form.get("model-id")
        name = request.form.get("name")
        description = request.form.get("Description")

        # Get the threat IDs as a JSON string
        threat_ids_str = request.form.get("threatIds")

        print("Raw threat_ids:", threat_ids_str)  # Debug print

        # Parse the JSON string into a Python list
        try:
            threat_ids = json.loads(threat_ids_str) if threat_ids_str else []
            if not isinstance(threat_ids, list):
                return jsonify({"error": "threatIds must be a JSON array"}), 400
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format for threatIds"}), 400

        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        if not name:
            return jsonify({"error": "name is required"}), 400

        new_data = {
            "name": name,
            "description": description,
            "id": uid(),
            "threat_ids": threat_ids,  # Store the parsed list
        }

        existing_document = db.Threat_scenarios.find_one(
            {"model_id": model_id, "type": "User-defined"}
        )

        if existing_document:
            # Check for duplicate name
            for detail in existing_document.get("Details", []):
                if detail.get("name") == name:
                    return (
                        jsonify(
                            {
                                "error": f"A derived threat scenario with name '{name}' already exists"
                            }
                        ),
                        400,
                    )

            db.Threat_scenarios.update_one(
                {"model_id": model_id, "type": "User-defined"},
                {"$push": {"Details": new_data}},
            )
            response_message = "Data added to Threat_scenarios Details"
        else:
            db.Threat_scenarios.insert_one(
                {"model_id": model_id, "type": "User-defined", "Details": [new_data]}
            )
            response_message = "New Threat_scenarios document created and data added"

        return jsonify({"message": response_message}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update/derved_threat_scene", methods=["PUT", "PATCH"])
def update_threat_scene():
    try:
        # Get form data
        model_id = request.form.get("model-id")
        scene_id = request.form.get("scene-id")  # ID of the threat scenario to update
        name = request.form.get("name", None)  # Optional: Update name if provided
        description = request.form.get(
            "description", None
        )  # Optional: Update description
        threat_ids_str = request.form.get(
            "threatIds", None
        )  # Optional: Update threat IDs

        # Validate required fields
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400
        if not scene_id:
            return jsonify({"error": "scene_id is required"}), 400

        # Parse threat_ids if provided
        threat_ids = None
        if threat_ids_str is not None:
            try:
                threat_ids = json.loads(threat_ids_str) if threat_ids_str else []
                if not isinstance(threat_ids, list):
                    return jsonify({"error": "threatIds must be a JSON array"}), 400
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON format for threatIds"}), 400

        # Build update fields dynamically (only update provided fields)
        update_fields = {}
        if name is not None:
            update_fields["Details.$.name"] = name
        if description is not None:
            update_fields["Details.$.description"] = description
        if threat_ids is not None:
            update_fields["Details.$.threat_ids"] = threat_ids

        if not update_fields:  # No fields to update
            return jsonify({"error": "No valid fields provided for update"}), 400

        # Update the specific threat scenario
        result = db.Threat_scenarios.update_one(
            {"model_id": model_id, "type": "User-defined", "Details.id": scene_id},
            {"$set": update_fields},
        )

        if result.modified_count == 0:
            return (
                jsonify({"error": "Threat scenario not found or no changes made"}),
                404,
            )
        else:
            return jsonify({"message": "Threat scenario updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update/threat_scenario", methods=["PATCH"])
def update_threat_scenario():
    try:
        # Get input values
        threat_id = request.form.get("id")
        detail_id = request.form.get("detailId")  # Used to identify the "id" in Details
        damage_ids_str = request.form.get(
            "damageIds"
        )  # Stringified JSON array of damage ids

        # Validate required inputs
        if not threat_id or not detail_id or not damage_ids_str:
            return (
                jsonify({"error": "Threat ID, detailId, and damage_ids are required"}),
                400,
            )

        # Parse the stringified JSON array into a Python object
        try:
            damage_ids = json.loads(damage_ids_str)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format for damage_ids"}), 400

        # Convert threat_id to ObjectId
        threat_id = ObjectId(threat_id)

        # Query the database
        threat_scene = db.Threat_scenarios.find_one({"_id": threat_id})

        if not threat_scene:
            return jsonify({"error": "Threat scenario not found"}), 404

        # Search for matching detailId
        for detail in threat_scene.get("Details", []):
            if detail.get("id") == detail_id:  # Matching the "id" in Details
                # Store the damage_ids in the detail's "damage_ids" field
                detail["damage_ids"] = damage_ids

                # Save the updated document back to the database
                db.Threat_scenarios.update_one(
                    {"_id": threat_id},
                    {"$set": {"Details": threat_scene["Details"]}},
                )

                return jsonify({"message": "Damage IDs updated successfully"}), 200

        return jsonify({"error": "Matching detailId not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update/threat_scenerio_name&desc", methods=["PATCH"])
def update_name_desc():
    try:
        # Retrieve input data from the request
        threat_id = request.form.get("id")
        node_id = request.form.get("nodeId")
        row_id = request.form.get("rowId")
        prop_id = request.form.get("propId")
        updated_field = request.form.get("field")  # Either "Name" or "Description"
        updated_value = request.form.get("value")  # New value
        type = request.form.get("type")

        # Basic validation
        if not threat_id or not updated_field:
            return jsonify({"error": "Threat ID and field are required"}), 400

        # Normalize field name to match MongoDB structure
        updated_field = updated_field.lower()
        if updated_field not in ["name", "description"]:
            return jsonify({"error": "Invalid field to update"}), 400

        # Define query and update paths based on the 'type'
        if type == "derived":
            if not node_id or not row_id or not prop_id:
                return (
                    jsonify(
                        {
                            "error": "Node ID, Row ID, and Prop ID are required for derived updates"
                        }
                    ),
                    400,
                )

            query = {
                "_id": ObjectId(threat_id),
                "Details": {
                    "$elemMatch": {
                        "rowId": row_id,
                        "Details": {
                            "$elemMatch": {
                                "nodeId": node_id,
                                "props": {"$elemMatch": {"id": prop_id}},
                            }
                        },
                    }
                },
            }

            update_data = {
                f"Details.$[outer].Details.$[inner].props.$[prop].{updated_field}": updated_value
            }
            array_filters = [
                {"outer.rowId": row_id},
                {"inner.nodeId": node_id},
                {"prop.id": prop_id},
            ]
        elif type == "User-defined":
            if not prop_id:
                return (
                    jsonify({"error": "Prop ID is required for user-defined updates"}),
                    400,
                )

            query = {
                "_id": ObjectId(threat_id),
                "Details.id": prop_id,
            }
            update_data = {f"Details.$.{updated_field}": updated_value}
            array_filters = None
        else:
            return jsonify({"error": "Invalid type specified"}), 400

        # Perform the update
        update_operation = {"$set": update_data}
        if array_filters:
            result = db.Threat_scenarios.update_one(
                query, update_operation, array_filters=array_filters
            )
        else:
            result = db.Threat_scenarios.update_one(query, update_operation)

        if result.matched_count == 0:
            return jsonify({"error": "No matching record found"}), 404

        return jsonify({"message": "Updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/v1/delete/threat_scenarios", methods=["DELETE"])
def delete_threat_scenario():
    try:
        model_id = request.form.get("model-id")
        row_details_raw = request.form.get("rowDetails")  # Get raw JSON string

        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        if not row_details_raw:
            return jsonify({"error": "rowDetails is required"}), 400

        try:
            row_details = json.loads(row_details_raw)  # Parse JSON into Python objects
        except json.JSONDecodeError:
            return jsonify({"error": "rowDetails must be valid JSON"}), 400

        if not isinstance(row_details, list):
            return jsonify({"error": "rowDetails must be a list"}), 400

        for detail in row_details:
            if not isinstance(detail, dict):
                return jsonify({"error": "Each rowDetail must be a dictionary"}), 400

            detail_type = detail.get("type")
            row_id = detail.get("rowId")
            node_id = detail.get("nodeId")
            prop_id = detail.get("propId")  # Adjusted for payload structure

            if detail_type == "derived":
                # Step 1: Remove from Threat_scenarios
                result = db.Threat_scenarios.update_one(
                    {"model_id": model_id, "type": "derived"},
                    {
                        "$pull": {
                            "Details.$[outer].Details.$[inner].props": {"id": prop_id}
                        }
                    },
                    array_filters=[{"outer.rowId": row_id}, {"inner.nodeId": node_id}],
                )

                if result.modified_count == 0:
                    return (
                        jsonify(
                            {
                                "error": f"No matching props found for propId {prop_id} in Threat_scenarios"
                            }
                        ),
                        404,
                    )

                # Step 2: Remove from Damage_scenarios
                result = db.Damage_scenarios.update_one(
                    {"model_id": model_id, "type": "User-defined"},
                    {"$pull": {"Details.$[detail].cyberLosses": {"id": prop_id}}},
                    array_filters=[{"detail._id": row_id}],
                )

                if result.modified_count == 0:
                    return (
                        jsonify(
                            {
                                "error": f"No matching cyberLosses found for propId {prop_id} in Damage_scenarios"
                            }
                        ),
                        404,
                    )

                # Step 3: Remove from Risk_treatment
                result = db.Risk_treatment.update_one(
                    {"model_id": model_id},
                    {"$pull": {"Details": {"threat_id": prop_id}}},
                )

                # if result.modified_count == 0:
                #     return (
                #         jsonify({"error": "No matching risk treatment found"}),
                #         404,
                #     )

            elif detail_type == "User-defined":
                # For type "User-defined", delete the entire Details object by id
                result = db.Threat_scenarios.update_one(
                    {"model_id": model_id, "type": "User-defined"},
                    {"$pull": {"Details": {"id": prop_id}}},
                )

                if result.modified_count == 0:
                    return (
                        jsonify(
                            {
                                "error": f"No matching entry found for propId {prop_id} in User-defined"
                            }
                        ),
                        404,
                    )

            else:
                return jsonify({"error": f"Unknown type: {detail_type}"}), 400

        return jsonify({"message": "Successfully deleted specified details"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
