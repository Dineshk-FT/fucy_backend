from annotated_types import doc
from flask import current_app as app
from flask import request, jsonify, Flask
from flask import Blueprint
from bson import ObjectId
from app.Methods.helpers import calculate_average_impacts
from db import db
import json
import uuid
from bson.json_util import dumps
import logging
from pymongo.errors import PyMongoError
from copy import deepcopy

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)

app = Blueprint("riskDetAndTreat", __name__)

def convert_object_id(data):
    """Recursively convert ObjectId to string in a dictionary or list."""
    if isinstance(data, list):
        return [convert_object_id(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_object_id(value) for key, value in data.items()}
    elif isinstance(data, ObjectId):
        return str(data)
    return data


@app.route("/v1/get/riskDetAndTreat", methods=["POST"])
def get_risk_treatment():
    try:
        model_id = request.form.get("model-id")

        if not model_id:
            return jsonify({"error": "Missing modelId"}), 400

        risk_treatment = db.Risk_treatment.find_one({"model_id": model_id})

        if not risk_treatment:
            return jsonify({"error": "No risk treatments found"}), 404

        results = []
        details = risk_treatment.get("Details", [])

        for risk in details:
            threat_id = risk.get("threat_id")
            node_id = risk.get("node_id")
            damage_id = risk.get("damage_id")
            label = risk.get("label")
            threat_key = risk.get("threat_key")
            goal_ids = risk.get("cybersecurity", {}).get("cybersecurity_goals", [])
            claim_ids = risk.get("cybersecurity", {}).get("cybersecurity_claims", [])
            id = risk.get("id")
            catalogs = risk.get("catalogs")
            risk_treatment_options = risk.get("risk_treatment_options")
            is_derived = risk.get("isDerived", False)

            # ==========================================================
            # 🔥 DERIVED (USER-DEFINED) HANDLING
            # ==========================================================
            if is_derived:
                # Get cybersecurity goals and claims for the parent derived scene
                matching_goals = []
                matching_claims = []
                
                # Process goals for the parent scene
                goal_ids_list = []
                if goal_ids:
                    if isinstance(goal_ids, list):
                        goal_ids_list = [
                            item.strip()
                            for item in goal_ids
                            if isinstance(item, str) and item.strip()
                        ]
                    elif isinstance(goal_ids, str):
                        goal_ids_list = [
                            item.strip() for item in goal_ids.split(",") if item.strip()
                        ]

                    goals = db.Cybersecurity.find_one(
                        {"model_id": model_id, "type": "cybersecurity_goals"}
                    )
                    if goals:
                        scenes = goals.get("scenes", [])
                        matching_goals = [
                            scene for scene in scenes
                            if scene.get("ID") in goal_ids_list
                        ]

                # Process claims for the parent scene
                claim_ids_list = []
                if claim_ids:
                    if isinstance(claim_ids, list):
                        claim_ids_list = [
                            item.strip()
                            for item in claim_ids
                            if isinstance(item, str) and item.strip()
                        ]
                    elif isinstance(claim_ids, str):
                        claim_ids_list = [
                            item.strip() for item in claim_ids.split(",") if item.strip()
                        ]

                    claims = db.Cybersecurity.find_one(
                        {"model_id": model_id, "type": "cybersecurity_claims"}
                    )
                    if claims:
                        scenes = claims.get("scenes", [])
                        matching_claims = [
                            scene for scene in scenes
                            if scene.get("ID") in claim_ids_list
                        ]

                user_defined_threat = db.Threat_scenarios.find_one(
                    {"model_id": model_id, "type": "User-defined"}
                )

                derived_threat_ids = []

                if user_defined_threat:
                    for detail in user_defined_threat.get("Details", []):
                        if detail.get("id") == threat_id:
                            derived_threat_ids = detail.get("threat_ids", [])
                            break

                derived_results = []
                all_cyber_requirements = []  # Store all requirements for average calculation if needed

                for threat_ref in derived_threat_ids:
                    single_row_id = threat_ref.get("rowId")
                    single_node_id = threat_ref.get("nodeId")
                    single_prop_id = threat_ref.get("propId")

                    attack_scene = None
                    threat_scene = None
                    impacts = {}

                    # DAMAGE SCENARIO
                    damage_scenario = db.Damage_scenarios.find_one(
                        {
                            "model_id": model_id,
                            "type": "User-defined",
                            "Details._id": single_row_id,
                        }
                    )

                    # ATTACK TREE
                    attack_details = db.Attacks.find_one(
                        {
                            "model_id": model_id,
                            "type": "attack_trees",
                            "scenes.threat_id": single_prop_id,
                        },
                        {"scenes.$": 1},
                    )

                    if attack_details:
                        matched_scene = next(
                            (
                                scene
                                for scene in attack_details.get("scenes", [])
                                if scene.get("threat_id") == single_prop_id
                            ),
                            None,
                        )
                        if matched_scene:
                            attack_scene = {
                                "threat_id": matched_scene.get("threat_id"),
                                "Name": matched_scene.get("Name"),
                                "overall_rating": matched_scene.get("overall_rating"),
                            }

                    # DERIVED THREAT LOOKUP
                    threat_scenario = db.Threat_scenarios.find_one(
                        {"model_id": model_id, "type": "derived"}
                    )

                    if threat_scenario:
                        for threat in threat_scenario.get("Details", []):

                            if threat.get("rowId") != single_row_id:
                                continue

                            for inner_detail in threat.get("Details", []):

                                if inner_detail.get("nodeId") != single_node_id:
                                    continue

                                matching_props = [
                                    prop
                                    for prop in inner_detail.get("props", [])
                                    if prop.get("id") == single_prop_id
                                ]

                                if damage_scenario:
                                    damage_detail = next(
                                        (
                                            item
                                            for item in damage_scenario["Details"]
                                            if str(item["_id"]) == single_row_id
                                        ),
                                        None,
                                    )

                                    if damage_detail and matching_props:
                                        threat_scene = {
                                            "detail": {
                                                **inner_detail,
                                                "props": matching_props,
                                            },
                                            "damage_id": single_row_id,
                                            "damage_name": damage_detail.get("Name"),
                                            "damage_key": damage_detail.get("key", 0),
                                        }

                                        impacts = damage_detail.get("impacts")

                    # ⚠️ UPDATED: CYBER REQUIREMENTS - Fetch using both threat_id and threat_key
                    cyber_requirements_scenes = []
                    
                    # Try to fetch requirements using threat_id
                    cyber_requirements_by_id = db.Cybersecurity.find(
                        {
                            "model_id": model_id,
                            "type": "cybersecurity_requirements",
                            "scenes.threat_id": single_prop_id,
                        },
                        {"scenes": 1, "_id": 0},
                    )

                    for item in cyber_requirements_by_id:
                        for scene in item.get("scenes", []):
                            if scene.get("threat_id") == single_prop_id:
                                cyber_requirements_scenes.append(scene)
                                all_cyber_requirements.append(scene)

                    # Also try to fetch requirements using threat_key if available
                    if threat_scene and threat_scene.get("threat_key"):
                        cyber_requirements_by_key = db.Cybersecurity.find(
                            {
                                "model_id": model_id,
                                "type": "cybersecurity_requirements",
                                "scenes.threat_key": threat_scene.get("threat_key"),
                            },
                            {"scenes": 1, "_id": 0},
                        )

                        for item in cyber_requirements_by_key:
                            for scene in item.get("scenes", []):
                                if scene.get("threat_key") == threat_scene.get("threat_key"):
                                    # Avoid duplicates
                                    if scene not in cyber_requirements_scenes:
                                        cyber_requirements_scenes.append(scene)
                                        all_cyber_requirements.append(scene)

                    derived_results.append(
                        {
                            "threat_id": single_prop_id,
                            "threat_key": threat_scene.get("threat_key") if threat_scene else None,
                            "node_id": single_node_id,
                            "threat_scene": threat_scene,
                            "attack_scene": attack_scene,
                            "impacts": impacts,
                            "cybersecurity": {
                                "cybersecurity_requirements": cyber_requirements_scenes,
                                # Goals and claims removed from individual threats
                            },
                        }
                    )
                
                average_impacts = calculate_average_impacts(derived_results)
                results.append(
                    {
                        "id": id,
                        "threat_id": threat_id,
                        "threat_key": threat_key,
                        "label": label,
                        "impacts": average_impacts,
                        "isDerived": True,
                        "derived_threats": derived_results,
                        "catalogs": catalogs if catalogs else [],
                        "risk_treatment_options": risk_treatment_options if risk_treatment_options else [],
                        "cybersecurity": {
                            "cybersecurity_goals": matching_goals,
                            "cybersecurity_claims": matching_claims,
                            "cybersecurity_requirements": all_cyber_requirements,  # Add combined requirements at parent level if needed
                        },
                    }
                )

                continue


            # ==========================================================
            # 🟢 ORIGINAL SINGLE THREAT FLOW (UPDATED)
            # ==========================================================

            matching_goals = []
            matching_claims = []

            damage_scenario = db.Damage_scenarios.find_one(
                {
                    "model_id": model_id,
                    "type": "User-defined",
                    "Details": {"$elemMatch": {"_id": damage_id}},
                }
            )

            goal_ids_list = []
            if goal_ids:
                if isinstance(goal_ids, list):
                    goal_ids_list = [
                        item.strip()
                        for item in goal_ids
                        if isinstance(item, str) and item.strip()
                    ]
                elif isinstance(goal_ids, str):
                    goal_ids_list = [
                        item.strip() for item in goal_ids.split(",") if item.strip()
                    ]

                goals = db.Cybersecurity.find_one(
                    {"model_id": model_id, "type": "cybersecurity_goals"}
                )
                if goals:
                    scenes = goals.get("scenes", [])
                    matching_goals = [
                        scene for scene in scenes if scene.get("ID") in goal_ids_list
                    ]

            claim_ids_list = []
            if claim_ids:
                if isinstance(claim_ids, list):
                    claim_ids_list = [
                        item.strip()
                        for item in claim_ids
                        if isinstance(item, str) and item.strip()
                    ]
                elif isinstance(claim_ids, str):
                    claim_ids_list = [
                        item.strip() for item in claim_ids.split(",") if item.strip()
                    ]

                claims = db.Cybersecurity.find_one(
                    {"model_id": model_id, "type": "cybersecurity_claims"}
                )
                if claims:
                    scenes = claims.get("scenes", [])
                    matching_claims = [
                        scene for scene in scenes if scene.get("ID") in claim_ids_list
                    ]

            attack_scene = None
            attack_details = db.Attacks.find_one(
                {
                    "model_id": model_id,
                    "type": "attack_trees",
                    "scenes.threat_key": threat_key,
                },
                {"scenes.$": 1},
            )

            if attack_details:
                matched_scene = next(
                    (
                        scene
                        for scene in attack_details.get("scenes", [])
                        if scene.get("threat_key") == threat_key
                    ),
                    None,
                )
                if matched_scene:
                    attack_scene = {
                        "threat_id": matched_scene.get("threat_id"),
                        "Name": matched_scene.get("Name"),
                        "overall_rating": matched_scene.get("overall_rating"),
                    }

            threat_scenario = db.Threat_scenarios.find_one(
                {"model_id": model_id, "type": "derived"}
            )

            threat_scene = None
            impacts = {}
            threat_details = threat_scenario.get("Details", []) if threat_scenario else []

            for threat in threat_details:
                for inner_detail in threat.get("Details", []):

                    if inner_detail.get("nodeId") != node_id:
                        continue

                    matching_props = [
                        prop
                        for prop in inner_detail.get("props", [])
                        if prop.get("id") == threat_id
                    ]

                    if damage_scenario:
                        damage_detail = next(
                            (
                                item
                                for item in damage_scenario["Details"]
                                if str(item["_id"]) == damage_id
                            ),
                            None,
                        )

                        if damage_detail:
                            threat_scene = {
                                "detail": {
                                    **inner_detail,
                                    "props": matching_props,
                                },
                                "damage_id": damage_id,
                                "damage_name": damage_detail.get("Name"),
                                "damage_key": damage_detail.get("key", 0),
                            }

                            impacts = damage_detail.get("impacts")

            # ⚠️ UPDATED: Fetch cybersecurity requirements for single threat using both threat_id and threat_key
            cyber_requirements_scenes = []

            # Try to fetch requirements using threat_id
            cyber_requirements_by_id = db.Cybersecurity.find(
                {
                    "model_id": model_id,
                    "type": "cybersecurity_requirements",
                    "scenes.threat_id": threat_id,
                },
                {"scenes": 1, "_id": 0},
            )

            for item in cyber_requirements_by_id:
                for scene in item.get("scenes", []):
                    if scene.get("threat_id") == threat_id:
                        cyber_requirements_scenes.append(scene)

            # Also try to fetch requirements using threat_key
            if threat_key:
                cyber_requirements_by_key = db.Cybersecurity.find(
                    {
                        "model_id": model_id,
                        "type": "cybersecurity_requirements",
                        "scenes.threat_key": threat_key,
                    },
                    {"scenes": 1, "_id": 0},
                )

                for item in cyber_requirements_by_key:
                    for scene in item.get("scenes", []):
                        if scene.get("threat_key") == threat_key:
                            # Avoid duplicates
                            if scene not in cyber_requirements_scenes:
                                cyber_requirements_scenes.append(scene)

            results.append(
                {
                    "id": id,
                    "threat_id": threat_id,
                    "node_id": node_id,
                    "label": label,
                    "threat_scene": threat_scene,
                    "threat_key": threat_key,
                    "attack_scene": attack_scene,
                    "impacts": impacts,
                    "cybersecurity": {
                        "cybersecurity_requirements": cyber_requirements_scenes,  # Updated
                        "cybersecurity_goals": matching_goals,
                        "cybersecurity_claims": matching_claims,
                    },
                    "catalogs": catalogs if catalogs else [],
                    "risk_treatment_options": risk_treatment_options if risk_treatment_options else [],
                }
            )

        if not results:
            return jsonify({"error": "No matching scenarios found"}), 404

        return jsonify(results), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/add/riskDetAndTreat", methods=["POST"])
def add_risk_treatment():
    try:
        node_id = request.form.get("nodeId")
        threat_id = request.form.get("threatId")
        model_id = request.form.get("modelId")
        label = request.form.get("label")
        damage_id = request.form.get("damageId")
        threat_key = request.form.get("key")
        isDerived = request.form.get("isDerived", "false")
        
        print(f"Received parameters - nodeId: {node_id}, threatId: {threat_id}, modelId: {model_id}, label: {label}, damageId: {damage_id}, key: {threat_key}, isDerived: {isDerived}")
        if not (node_id and threat_id and model_id):
            return jsonify({"error": "Missing nodeId, threatId, or modelId"}), 400

        # Build the detail object dynamically, ignoring undefined values
        detail = {
            "id": str(uuid.uuid4()),
            "threat_id": threat_id,
            "node_id": node_id,
        }
        
        # Only add fields that are not None/undefined
        if label:
            detail["label"] = label
        if damage_id:
            detail["damage_id"] = damage_id
        if threat_key:
            detail["threat_key"] = threat_key
        if isDerived and isDerived.lower() == "true":
            detail["isDerived"] = True

        # Check if the model_id already exists in the collection
        existing_entry = db.Risk_treatment.find_one({"model_id": model_id})

        if not existing_entry:
            # If model_id does not exist, create a new entry
            db.Risk_treatment.insert_one(
                {
                    "model_id": model_id,
                    "Details": [detail]
                }
            )
            return jsonify({"message": "Risk treatment added successfully"}), 200

        # Check if both threat_id and threat_key are already present in the Details array
        detail_exists = any(
            detail.get("threat_id") == threat_id
            and detail.get("threat_key") == threat_key
            for detail in existing_entry["Details"]
        )

        if detail_exists:
            return (
                jsonify({"error": "Risk already exists"}),
                400,
            )

        # Add the new details to the Details array
        db.Risk_treatment.update_one(
            {"model_id": model_id},
            {
                "$push": {
                    "Details": detail
                }
            },
        )

        return jsonify({"message": "Risk treatment added successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/v1/update/riskDetAndTreat", methods=["PATCH"])
def update_risk_treatment():
    try:
        # Identify the request type based on provided parameters
        detail_id = request.form.get("detailId")
        catalogs = request.form.get("catalogs")
        model_id = request.form.get("model-id")
        
        # Updated parameter for risk treatment options - now single select
        risk_treatment_option = request.form.get("risk_treatment_options")  # Expecting a single value or empty string for null

        threat_key = request.form.get("threatKey") 
        cyber_details = request.form.get("cyberDetails")  # Comma-separated string
        type = request.form.get("type")  # Key for the cybersecurity document type

        # Ensure `model_id` is always provided
        if not model_id:
            return jsonify({"error": "Missing 'model_id' parameter"}), 400

        # Handle `detail_id` and `catalogs` update
        if detail_id and catalogs:
            catalogs_list = json.loads(catalogs)  # Parse catalogs into a list
            query = {"model_id": model_id}
            update = {"$set": {f"Details.$[detail].catalogs": catalogs_list}}
            array_filters = [{"detail.id": detail_id}]

            result_catalog_update = db.Risk_treatment.update_one(
                query, update, array_filters=array_filters
            )

            if result_catalog_update.matched_count == 0:
                return (
                    jsonify(
                        {"error": "No matching document found for catalogs update"}
                    ),
                    404,
                )

            return jsonify({"message": "Catalogs updated successfully"}), 200

        # Handle `risk_treatment_option` update - SINGLE SELECT
        elif detail_id and risk_treatment_option is not None:
            # For single select, store as string or null
            risk_treatment_value = risk_treatment_option.strip() if risk_treatment_option.strip() else None
            
            query = {"model_id": model_id}
            update = {"$set": {f"Details.$[detail].risk_treatment_options": risk_treatment_value}}
            array_filters = [{"detail.id": detail_id}]

            result_risk_treatment_update = db.Risk_treatment.update_one(
                query, update, array_filters=array_filters
            )

            if result_risk_treatment_update.matched_count == 0:
                return (
                    jsonify(
                        {"error": "No matching document found for risk treatment option update"}
                    ),
                    404,
                )

            return jsonify({"message": "Risk treatment option updated successfully"}), 200

        # Handle `cyber_details`, `threat_key`, and `type` update
        elif cyber_details and threat_key and type:
            # Convert comma-separated string to a list
            cyber_details_list = [
                item.strip() for item in cyber_details.split(",") if item.strip()
            ]
            if not cyber_details_list:
                return (
                    jsonify(
                        {"error": "'cyberDetails' must contain at least one value"}
                    ),
                    400,
                )

            # Query the cybersecurity document
            cybersecurity_doc = db.Cybersecurity.find_one(
                {"model_id": model_id, "type": type}
            )
            if not cybersecurity_doc:
                return jsonify({"error": "Cybersecurity document not found"}), 404

            # Update scenes in the document
            updated_scenes = []
            for scene in cybersecurity_doc.get("scenes", []):
                if scene.get("ID") in cyber_details_list:
                    if "threat_key" not in scene or not isinstance(
                        scene["threat_key"], list
                    ):
                        scene["threat_key"] = []
                    if threat_key not in scene["threat_key"]:
                        scene["threat_key"].append(threat_key)
                else:
                    if "threat_key" in scene and isinstance(scene["threat_key"], list):
                        scene["threat_key"] = [
                            key for key in scene["threat_key"] if key != threat_key
                        ]

                updated_scenes.append(scene)

            # Perform the update in the cybersecurity collection
            db.Cybersecurity.update_one(
                {"_id": cybersecurity_doc["_id"]}, {"$set": {"scenes": updated_scenes}}
            )

            # Update `Risk_treatment` collection for `cyber_details`
            query = {"model_id": model_id}
            update = {
                "$set": {f"Details.$[detail].cybersecurity.{type}": cyber_details_list}
            }
            array_filters = [{"detail.threat_key": threat_key}]

            result_cyber_update = db.Risk_treatment.update_one(
                query, update, array_filters=array_filters
            )

            if result_cyber_update.matched_count == 0:
                return (
                    jsonify(
                        {"error": "No matching document found for cyberDetails update"}
                    ),
                    404,
                )

            return jsonify({"message": "CyberDetails updated successfully"}), 200

        # If neither valid request type is provided
        return (
            jsonify(
                {
                    "error": "Invalid request. Provide either:\n1. 'detailId' and 'catalogs'\n2. 'detailId' and 'risk_treatment_option'\n3. 'cyberDetails', 'threatKey', and 'type'."
                }
            ),
            400,
        )

    except PyMongoError as db_error:
        logging.error(f"Database error: {str(db_error)}")
        return (
            jsonify({"error": "Database error occurred. Please try again later."}),
            500,
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/v1/delete/risktreatment", methods=["DELETE"])
def delete_risk_treatment():
    try:
        model_id = request.form.get("model-id")
        rowIds_raw = request.form.get("rowIds", "")
        threat_keys_raw = request.form.get("threatKeys", "")

        rowIds = [rid.strip() for rid in rowIds_raw.split(",") if rid.strip()]
        threat_keys = [tk.strip() for tk in threat_keys_raw.split(",") if tk.strip()]

        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        if not rowIds:
            return jsonify({"error": "At least one rowId is required"}), 400

        # Check if model exists in Risk_treatment
        model = db.Risk_treatment.find_one({"model_id": model_id})
        if not model:
            return jsonify({"error": "Model not found"}), 404

        # Remove matching rows from Risk_treatment
        result = db.Risk_treatment.update_one(
            {"_id": model["_id"]},
            {"$pull": {"Details": {"id": {"$in": rowIds}}}}
        )

        if result.modified_count == 0:
            return jsonify({"error": "No matching rowIds found to delete"}), 404

        # Now manually remove threat_keys from Cybersecurity collection
        types = ["cybersecurity_goals", "cybersecurity_claims"]
        modified_docs = []

        for doc in db.Cybersecurity.find({
            "model_id": model_id,
            "type": {"$in": types}
        }):
            updated_scenes = []
            modified = False

            for scene in doc.get("scenes", []):
                if isinstance(scene.get("threat_key"), list):
                    original_len = len(scene["threat_key"])
                    scene["threat_key"] = [
                        key for key in scene["threat_key"] if key not in threat_keys
                    ]
                    if len(scene["threat_key"]) != original_len:
                        modified = True
                updated_scenes.append(scene)

            if modified:
                db.Cybersecurity.update_one(
                    {"_id": doc["_id"]},
                    {"$set": {"scenes": updated_scenes}}
                )
                modified_docs.append(doc["type"])

        # Build response message
        messages = ["Successfully deleted rows"]
        if "cybersecurity_goals" in modified_docs:
            messages.append("Updated cybersecurity goals")
        if "cybersecurity_claims" in modified_docs:
            messages.append("Updated cybersecurity claims")
        if not modified_docs:
            messages.append("No matching threat keys found in cybersecurity collections")

        return jsonify({"message": " and ".join(messages)}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/get/catalog", methods=["POST"])
def catalog():
    try:
        catalog = db.catalog.find_one({}, {"_id": 0})

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        return jsonify(catalog), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
