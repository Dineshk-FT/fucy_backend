import os
from flask import current_app as app
from flask import request, jsonify, json, Response
from flask_cors import cross_origin
import uuid
from bson import ObjectId
from pymongo import ASCENDING
from app.v1.RAG_Damage_scene import  damage_pipeline
from db import db
from flask import Blueprint
from bson.json_util import dumps
import traceback
import re
import json
from typing import Dict, List, Any

# from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails


app = Blueprint("dmg_scr", __name__)
damage_scenarios = db["Damage_scenarios"]

current_file_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.dirname(current_file_dir)
methods_dir = os.path.join(app_dir, "Methods")
BMS_PATH = os.path.join(methods_dir, "bms.json") 
# Ensure the index for optimal query performance
db.Damage_scenarios.create_index(
    [("model_id", ASCENDING), ("status", ASCENDING)], background=True
)


@app.route("/v1/get_details/damage_scenarios", methods=["POST"])
def get_damage_scene():
    try:
        model_id = request.form.get("model-id")

        # Validate model_id
        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        # Query the database for Damage Scenarios
        data_cursor = (
            db.Damage_scenarios.find(
                {"model_id": model_id},
                {
                    "_id": 1,
                    "type": 1,
                    "Details": 1,
                    "Derivations": 1,
                },
            )
            .limit(2)
            .batch_size(2)
        )

        # Convert results into a list
        data_list = [{**data, "_id": str(data["_id"])} for data in data_cursor]

        # Fetch Risk_treatment document
        risk_treatment = db.Risk_treatment.find_one({"model_id": model_id})

        # Extract threat_id set from Risk_treatment Details
        risk_threat_ids = set()
        if risk_treatment and "Details" in risk_treatment:
            risk_threat_ids = {
                detail["threat_id"] for detail in risk_treatment["Details"]
            }

        # Process only "Derived" types
        for item in data_list:
            if item.get("type") == "Derived" and "Details" in item:
                for detail in item["Details"]:
                    for prop in detail["props"]:
                        prop["is_risk_added"] = prop["id"] in risk_threat_ids

        # Return results or error message if no documents are found
        if data_list:
            return jsonify(data_list), 200
        else:
            return (
                jsonify({"error": "No documents found for the specified model_id"}),
                404,
            )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/add/damage_scenario", methods=["POST"], endpoint="add_damage_scenario")
def add_damage_scenario():
    try:
        model_id = request.form.get("model-id")
        Description = request.form.get("Description")
        Name = request.form.get("Name")

        data = {}
        existing_scenario = db.Damage_scenarios.find_one(
            {"model_id": model_id, "type": "User-defined"}
        )

        if existing_scenario:
            # Ensure Details array exists and handle missing "key" field
            details = existing_scenario.get("Details", [])
            last_key = 0
            if details:
                last_item = details[-1]
                last_key = last_item.get("key", 0)  # Default to 0 if "key" is missing

            data = {
                "Description": Description,
                "Name": Name,
                "cyberLosses": [],
                "impacts": {},
                "key": last_key + 1,
                "_id": str(uuid.uuid4()),
            }

            db.Damage_scenarios.update_one(
                {"_id": existing_scenario["_id"]}, {"$push": {"Details": data}}
            )
            message = "Added to existing scenario"
        else:
            data = {
                "Description": Description,
                "Name": Name,
                "cyberLosses": [],
                "impacts": {},
                "key": 1,
                "_id": str(uuid.uuid4()),
            }
            new_scenario = {
                "model_id": model_id,
                "type": "User-defined",
                "Details": [data],
            }
            db.Damage_scenarios.insert_one(new_scenario)
            message = "New scenario added successfully"

        return jsonify({"message": message}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update/derived_damage_scenario", methods=["PATCH"])
@cross_origin()
def update_derived_damage_scenario():
    if request.method == "OPTIONS":
        return "", 204
    try:
        obj_id = request.form.get("id")
        detail_id = request.form.get("detail-id")
        is_checked = request.form.get("isChecked")
        is_all_checked = request.form.get("isAllChecked")
        is_asset_evaluated = request.form.get("isAssetEvaluated")
        is_cybersecurity_evaluated = request.form.get("isCybersecurityEvaluated")

        if not ObjectId.is_valid(obj_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        if not obj_id:
            return jsonify({"error": "id is required"}), 400

        query = {"_id": ObjectId(obj_id)}
        document = damage_scenarios.find_one(query)

        if not document:
            return jsonify({"error": "Document not found"}), 404

        # If is_all_checked is provided, update all elements in the Derivations array
        if is_all_checked is not None:
            damage_scenarios.update_one(
                query, {"$set": {"Derivations.$[].is_checked": is_all_checked}}
            )
        # Otherwise, update a single element based on detail_id
        elif is_checked is not None and detail_id:
            damage_scenarios.update_one(
                query,
                {"$set": {"Derivations.$[elem].is_checked": is_checked}},
                array_filters=[{"elem.id": detail_id}],
            )

        # Update Details array if necessary
        if is_asset_evaluated is not None or is_cybersecurity_evaluated is not None:
            update_fields = {}
            if is_asset_evaluated is not None:
                update_fields["Details.$[elem].is_asset_evaluated"] = is_asset_evaluated
            if is_cybersecurity_evaluated is not None:
                update_fields["Details.$[elem].is_cybersecurity_evaluated"] = (
                    is_cybersecurity_evaluated
                )

            damage_scenarios.update_one(
                query, {"$set": update_fields}, array_filters=[{"elem._id": detail_id}]
            )

        return jsonify({"message": "Update successful"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route(
    "/v1/update/damage_scenario",
    methods=["OPTIONS", "POST"],
    endpoint="update_damage_scenario",
)
def update_damage_scenario():
    if request.method == "OPTIONS":
        # Handle preflight request
        return "", 204
    try:
        scenario_id = request.form.get("id")
        detail_id = request.form.get("detailId")
        model_id = request.form.get("model-id")
        new_cyber_losses = request.form.get("cyberLosses")
        new_impacts = request.form.get("impacts", {})
        new_threat = json.loads(
            request.form.get("threats", "{}")
        )  # Single threat object

        if not scenario_id:
            return jsonify({"error": "ID is required to identify the scenario"}), 400
        if not detail_id:
            return jsonify({"error": "detail_id is required"}), 400

        try:
            new_cyber_losses = json.loads(new_cyber_losses) if new_cyber_losses else []
            new_impacts = json.loads(new_impacts) if new_impacts else {}
        except json.JSONDecodeError:
            return (
                jsonify({"error": "Invalid JSON format for cyberLosses or impacts"}),
                400,
            )

        # Update Damage_scenarios collection
        update_data = {}
        if new_cyber_losses:
            update_data["Details.$[elem].cyberLosses"] = new_cyber_losses
        if new_impacts:
            update_data["Details.$[elem].impacts"] = new_impacts

        result = db.Damage_scenarios.update_one(
            {"_id": ObjectId(scenario_id)},
            {"$set": update_data},
            array_filters=[{"elem._id": detail_id}],
        )

        if result.matched_count == 0:
            return jsonify({"error": "No matching Damage_scenario found"}), 404

        # Check rowId and update Threat_scenarios only if cyberLosses are received
        if new_cyber_losses:
            row_id = new_threat.get("rowId")
            if not row_id:
                return (
                    jsonify(
                        {
                            "error": "rowId is required in threats when updating cyberLosses"
                        }
                    ),
                    400,
                )

            # Check if Threat_scenarios document with model_id exists
            threat_scenario = db.Threat_scenarios.find_one({"model_id": model_id})

            if threat_scenario:
                # Check if entry with rowId exists in Details array
                existing_entry = db.Threat_scenarios.find_one(
                    {"model_id": model_id, "Details.rowId": row_id}
                )

                if existing_entry:
                    # Update the existing entry with matching rowId in Details array
                    db.Threat_scenarios.update_one(
                        {"model_id": model_id, "Details.rowId": row_id},
                        {"$set": {"Details.$[detail]": new_threat}},
                        array_filters=[{"detail.rowId": row_id}],
                    )
                else:
                    # Add new entry to Details if no matching rowId found
                    db.Threat_scenarios.update_one(
                        {"model_id": model_id}, {"$push": {"Details": new_threat}}
                    )
            else:
                # Create a new Threat_scenarios document if none exists with model_id
                db.Threat_scenarios.insert_one(
                    {
                        "model_id": model_id,
                        "type": "derived",
                        "Details": [
                            new_threat
                        ],  # Initialize Details array with the new threat
                    }
                )

        return jsonify({"message": "Updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/update-impacts/damage_scenerio", methods=["PATCH"])
def update_impacts():
    try:
        # Retrieve input data from the request
        scenario_id = request.form.get("id")
        detail_id = request.form.get("detailId")
        new_impacts = request.form.get("impacts", "{}")

        # Basic validation before JSON parsing
        if not scenario_id or not detail_id:
            return jsonify({"error": "Scenario ID and Detail ID are required"}), 400

        # Parse impacts as JSON
        try:
            new_impacts = json.loads(new_impacts) if new_impacts else {}
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON format for impacts"}), 400

        if not isinstance(new_impacts, dict):
            return jsonify({"error": "Impacts must be a valid JSON object"}), 400

        # Ensure MongoDB index on 'Details._id'
        db.Damage_scenarios.create_index("Details._id", background=True)

        # Update Damage_scenarios collection
        update_data = {"Details.$[elem].impacts": new_impacts}

        result = db.Damage_scenarios.update_one(
            {"_id": ObjectId(scenario_id)},
            {"$set": update_data},
            array_filters=[{"elem._id": detail_id}],
        )

        if result.matched_count == 0:
            return jsonify({"error": "No matching Damage_scenario found"}), 404

        return jsonify({"message": "Impacts updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/v1/update/damage_scenerio_name&desc", methods=["PATCH"])
def update_name_desc():
    try:
        # Retrieve input data from the request
        scenario_id = request.form.get("id")
        detail_id = request.form.get("detailId")
        name = request.form.get("Name")
        description = request.form.get("Description")
        justification = request.form.get("justification")

        # Basic validation before JSON parsing
        if not scenario_id or not detail_id:
            return jsonify({"error": "Scenario ID and Detail ID are required"}), 400

        # Ensure MongoDB index on 'Details._id'
        db.Damage_scenarios.create_index("Details._id", background=True)

        # Check for duplicate Name in the 'Details' array
        if name:
            query = {
                "_id": ObjectId(scenario_id),
                "Details": {
                    "$elemMatch": {
                        "_id": {"$ne": detail_id},  # Exclude the current detail
                        "Name": name,  # Check for duplicate name
                    }
                },
            }
            duplicate_check = db.Damage_scenarios.find_one(query)

            if duplicate_check:
                return jsonify({"error": "Name already present in Details"}), 409

        # Prepare update data
        update_data = {}
        if name:
            update_data["Details.$[elem].Name"] = name
        if description:
            update_data["Details.$[elem].Description"] = description
        if justification:
            update_data["Details.$[elem].impact_justification"] = justification  

        # Update Damage_scenarios collection
        result = db.Damage_scenarios.update_one(
            {"_id": ObjectId(scenario_id)},
            {"$set": update_data},
            array_filters=[{"elem._id": detail_id}],
        )

        if result.matched_count == 0:
            return jsonify({"error": "No matching Damage_scenario found"}), 404

        return jsonify({"message": "Updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/v1/delete/damage_scenario", methods=["DELETE"])
def delete_damage_scenario():
    try:
        # Get input parameters
        model_id = request.form.get("model-id")
        id = request.form.get("id")
        raw_detail_ids = request.form.get("detailId", "")
        detail_ids = [s.strip() for s in raw_detail_ids.split(",") if s.strip()]

        if not id:
            return jsonify({"error": "id is required"}), 400
        if not model_id:
            return jsonify({"error": "model_id is required"}), 400

        # Filter out invalid UUIDs (silently skip them)
        valid_detail_ids = []
        for detail_id in detail_ids:
            try:
                valid_detail_ids.append(str(uuid.UUID(detail_id)))
            except ValueError:
                continue

        # If no valid detail IDs, skip deletion
        if not valid_detail_ids:
            return jsonify({"message": "No valid detailIds provided. Nothing deleted."}), 200

        # Convert damage scenario id to ObjectId
        try:
            object_id = ObjectId(id)
        except Exception:
            return jsonify({"error": "Invalid id format"}), 400

        # Check that the damage scenario exists
        damage_scenario = db.Damage_scenarios.find_one(
            {"_id": object_id, "type": "User-defined"}
        )
        if not damage_scenario:
            return jsonify({"error": "Damage scenario not found"}), 404

        # Delete details from Damage_scenarios
        damage_result = db.Damage_scenarios.update_one(
            {"_id": object_id},
            {"$pull": {"Details": {"_id": {"$in": valid_detail_ids}}}}
        )

        # Delete details from Threat_scenarios
        threat_result = db.Threat_scenarios.update_one(
            {"model_id": model_id, "type": "derived"},
            {"$pull": {"Details": {"rowId": {"$in": valid_detail_ids}}}}
        )

        # Delete details from Risk_treatment
        risk_result = db.Risk_treatment.update_one(
            {"model_id": model_id},
            {"$pull": {"Details": {"damage_id": {"$in": valid_detail_ids}}}}
        )

        # Build response message
        response_message = {
            "message": "Details deletion attempted",
            "details_deleted_from_damage": damage_result.modified_count,
            "details_deleted_from_threat": threat_result.modified_count,
            "details_deleted_from_risk": risk_result.modified_count,
        }

        return jsonify(response_message), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def parse_damage_scenarios(markdown_text: str) -> List[Dict[str, Any]]:
    """
    Parse markdown-formatted damage scenarios into structured data.
    
    Supports both formats:
    1. Old format: **Safety Impact:** Severe
    2. New format: **Safety Impact:** S3 - Major (or S3/Major)
    """
    scenarios = []
    
    # Split by scenario headers and capture the headers
    # Pattern: ## Damage Scenario X followed by content until next ## or end
    # Enhanced to handle multi-line headers
    pattern = r'## (Damage Scenario \d+)\s*\n([^#]*)'
    
    # Find all matches
    matches = re.finditer(pattern, markdown_text, re.DOTALL | re.MULTILINE)
    
    for match in matches:
        scenario = {}
        scenario_name = match.group(1).strip()  # "Damage Scenario 1"
        content = match.group(2)  # Everything after until next ##
        
        scenario['name'] = scenario_name
        
        # Extract description - handle both single and multi-line descriptions
        desc_patterns = [
            r'\*\*Description:\*\*\s*(.+?)(?=\n\*\*|\Z)',  # Standard format
            r'\*\*Description:\*\*\s*\n(.+?)(?=\n\*\*|\Z)',  # Multi-line format
            r'Description:\s*(.+?)(?=\n\*\*|\n##|\Z)'  # Alternative format
        ]
        
        description = None
        for pattern in desc_patterns:
            desc_match = re.search(pattern, content, re.DOTALL)
            if desc_match:
                description = desc_match.group(1).strip()
                break
        
        if description:
            scenario['description'] = description
        
        # Enhanced impact extraction that handles both formats
        impact_fields = {
            'safety_impact': [
                r'\*\*Safety Impact:\*\*\s*(.+?)(?=\n\*\*|\Z)',
                r'Safety Impact:\s*(.+?)(?=\n\*\*|\n##|\Z)',
                r'Safety.*?[Ii]mpact:\s*(.+?)(?=\n|$)'
            ],
            'operational_impact': [
                r'\*\*Operational Impact:\*\*\s*(.+?)(?=\n\*\*|\Z)',
                r'Operational Impact:\s*(.+?)(?=\n\*\*|\n##|\Z)',
                r'Operational.*?[Ii]mpact:\s*(.+?)(?=\n|$)'
            ],
            'financial_impact': [
                r'\*\*Financial Impact:\*\*\s*(.+?)(?=\n\*\*|\Z)',
                r'Financial Impact:\s*(.+?)(?=\n\*\*|\n##|\Z)',
                r'Financial.*?[Ii]mpact:\s*(.+?)(?=\n|$)'
            ],
            'privacy_impact': [
                r'\*\*Privacy Impact:\*\*\s*(.+?)(?=\n\*\*|\Z)',
                r'Privacy Impact:\s*(.+?)(?=\n\*\*|\n##|\Z)',
                r'Privacy.*?[Ii]mpact:\s*(.+?)(?=\n|$)'
            ],
            'regulatory_impact': [
                r'\*\*Regulatory Impact:\*\*\s*(.+?)(?=\n\*\*|\Z)',
                r'Regulatory Impact:\s*(.+?)(?=\n\*\*|\n##|\Z)',
                r'Regulatory.*?[Ii]mpact:\s*(.+?)(?=\n|$)'
            ],
            'overall_impact': [
                r'\*\*Overall Impact:\*\*\s*(.+?)(?=\n\*\*|\Z)',
                r'Overall Impact:\s*(.+?)(?=\n\*\*|\n##|\Z)',
                r'Overall.*?[Ii]mpact:\s*(.+?)(?=\n|$)'
            ]
        }
        
        for field, patterns in impact_fields.items():
            impact_value = None
            for pattern in patterns:
                field_match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
                if field_match:
                    impact_value = field_match.group(1).strip()
                    break
            
            if impact_value:
                # Clean up the impact value
                scenario[field] = impact_value
        
        # Only add scenario if we have at least a description
        if 'description' in scenario:
            scenarios.append(scenario)
    
    # If no scenarios found with the header pattern, try alternative parsing
    if not scenarios:
        # Try to find scenario blocks by looking for numbered scenarios
        scenario_blocks = re.split(r'(?i)##?\s*(?:Damage\s+)?Scenario\s+\d+', markdown_text)
        
        for i, block in enumerate(scenario_blocks[1:], 1):  # Start from 1, skip first
            scenario = {'name': f'Damage Scenario {i}'}
            
            # Try to extract description
            desc_match = re.search(r'(?i)description[:\*]*\s*(.+?)(?=\n\s*\*\*|\n\s*[A-Z]|\Z)', block, re.DOTALL)
            if desc_match:
                scenario['description'] = desc_match.group(1).strip()
            
            # Try to extract impacts with more flexible patterns
            for field, field_name in [
                ('safety_impact', 'Safety'),
                ('operational_impact', 'Operational'),
                ('financial_impact', 'Financial'),
                ('privacy_impact', 'Privacy'),
                ('regulatory_impact', 'Regulatory'),
                ('overall_impact', 'Overall')
            ]:
                pattern = rf'(?i){field_name}[^:\n]*[:\*]+\s*(.+?)(?=\n\s*\*\*|\n\s*[A-Z]|\Z)'
                impact_match = re.search(pattern, block, re.DOTALL)
                if impact_match:
                    scenario[field] = impact_match.group(1).strip()
            
            if 'description' in scenario:
                scenarios.append(scenario)
    
    # If still no scenarios, try to extract any structured information
    if not scenarios:
        # Look for any bullet points or structured content
        lines = markdown_text.split('\n')
        current_scenario = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('## Damage Scenario') or line.startswith('## Scenario'):
                if current_scenario:
                    scenarios.append(current_scenario)
                    current_scenario = {}
                current_scenario['name'] = line.strip('# ')
            elif ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace('**', '')
                    value = parts[1].strip().replace('**', '')
                    
                    if 'description' in key:
                        current_scenario['description'] = value
                    elif 'safety' in key:
                        current_scenario['safety_impact'] = value
                    elif 'operational' in key:
                        current_scenario['operational_impact'] = value
                    elif 'financial' in key:
                        current_scenario['financial_impact'] = value
                    elif 'privacy' in key:
                        current_scenario['privacy_impact'] = value
                    elif 'regulatory' in key:
                        current_scenario['regulatory_impact'] = value
                    elif 'overall' in key:
                        current_scenario['overall_impact'] = value
        
        if current_scenario and 'description' in current_scenario:
            scenarios.append(current_scenario)
    
    return scenarios

def generate_damage_scenarios_from_json():
    """
    Reads bms.json automatically and generates damage scenarios 
    for all assets defined in the system.
    """
    if not os.path.exists(BMS_PATH):
        return jsonify({"error": f"bms.json not found at {BMS_PATH}"}), 404

    try:
        # 1. Load the assets from bms.json
        with open(BMS_PATH, "r", encoding="utf-8") as f:
            bms_data = json.load(f)
        
        # Extract assets from the Details section
        assets_to_process = bms_data.get("Assets", [{}])[0].get("Details", [])
        
        all_results = []

        # 2. Iterate through assets and run the RAG pipeline
        # Note: In a production environment with many assets, you might want to 
        # limit this or use a background task to avoid timeouts.
        for asset in assets_to_process:
            asset_name = asset.get("name")
            if not asset_name or asset.get("type") == "group":
                continue

            # Contextual query for the RAG
            query_text = f"Damage scenarios for {asset_name} in the Battery Management System"
            
            result = damage_pipeline.run({
                "text_embedder": {
                    "text": query_text
                },
                "prompt_builder": {
                    "question": asset_name,
                }
            })
            
            raw_reply = result["llm"]["replies"][0]
            
            all_results.append({
                "asset_name": asset_name,
                "generated_content": raw_reply
            })

        return jsonify({
            "model_id": bms_data["Models"][0]["_id"],
            "system_name": bms_data["Models"][0]["name"],
            "results": all_results
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Updated Route
@app.route("/v1/rag-generate/bms-damage-scenarios", methods=["GET", "POST"])
def damage_scenarios_endpoint():
    # Now this doesn't require an "item" in the body; it uses the file.
    return generate_damage_scenarios_from_json()