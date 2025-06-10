from flask import current_app as app
from flask import Blueprint, request, jsonify,send_file
from bson import ObjectId
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Image
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer
from reportlab.lib import colors
from db import db
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from app.Methods.helpers import get_highest_impact,get_threat_type,resize_image,generate_sas_url,getImpactBgcolour,getFesRateBgColor
import datetime
from azure.storage.blob import BlobServiceClient, ContentSettings
import os
import io
from config import Config
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, PageBreak


app = Blueprint("doc", __name__)
max_width = 1000  # adjust to fit your frame size
max_height = 1000


def fit_image(original_width, original_height, max_width, max_height):
    ratio = min(max_width / original_width, max_height / original_height)
    return original_width * ratio, original_height * ratio


@app.route("/v1/generate/doc", methods=["POST"])
def generate_doc():
    try:
        model_id = request.form.get("model-id")

         # Get image file from request
        image_file = request.files.get('image')  # 'image' is the name of the file input in the frontend
        if image_file:
            # Read the image file into a BytesIO stream
            image_stream = io.BytesIO(image_file.read())
            img = Image(image_stream)
            img.drawWidth, img.drawHeight = fit_image(
                img.imageWidth, img.imageHeight, max_width, max_height
            )
        else:
            image_stream = None

        if 'damageScenariosTable' in request.form and int(request.form['damageScenariosTable']) == 1:
            damage_scenarios_table = 1
        else:
            damage_scenarios_table = 0
        if 'threatScenariosTable' in request.form and int(request.form['threatScenariosTable']) == 1:
            threat_scenarios_table = 1
        else:
            threat_scenarios_table = 0
            
        if 'attackTreatScenariosTable' in request.form and int(request.form['attackTreatScenariosTable']) == 1:
            attack_trees_table = 1
        else:
            attack_trees_table = 0

        if 'riskTreatmentTable' in request.form and int(request.form['riskTreatmentTable']) == 1:
            risk_treatment = 1
        else:
            risk_treatment = 0 
            
        if 'cyberSecurityGoals' in request.form and int(request.form['cyberSecurityGoals']) == 1:
            cyber_security_goals = 1
        else:            
            cyber_security_goals = 0
        
        if 'cyberSecurityRequirements' in request.form and int(request.form['cyberSecurityRequirements']) == 1:
            cyber_security_requirements = 1
        else:            
            cyber_security_requirements = 0
            
        if 'cyberSecurityControls' in request.form and int(request.form['cyberSecurityControls']) == 1:
            cyber_security_controls = 1
        else:            
            cyber_security_controls = 0
            
        if 'cyberSecurityClaims' in request.form and int(request.form['cyberSecurityClaims']) == 1:
            cyber_security_claims = 1
        else:            
            cyber_security_claims = 0

        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400
        
        def wrap_content(content,text_color='black',bg_color=None):
            styles = getSampleStyleSheet()
            cell_style = styles['Normal']
            cell_style.textColor = colors.toColor(text_color)

            paragraph = Paragraph(str(content), cell_style) if content else ""

            if bg_color:
                table_data = [[paragraph]]  

                table = Table(table_data)

                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.toColor(bg_color)),  # Background for the whole cell
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.toColor(text_color)),  # Text color
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Center the text horizontally
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Center the text vertically
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),  # Optional: Add padding to make it more spacious
                    ('TOPPADDING', (0, 0), (-1, -1), 5),  # Optional: Add padding to make it more spacious
                ]))

                return table
            else:
                return paragraph     

# =========================================================================================================================        

# ======================= Damage Scenario Table ===========================================================================
        if damage_scenarios_table == 1:
            damage_record = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})

            valid_columns = [
                "ID", "Name", "Description/Scalability", 
                "Losses of Cybersecurity Properties", "Assets", 
                "Safety Impact", "Financial Impact", "Operational Impact", 
                "Privacy Impact", "Impact Justification", "Associated Threat Scenarios", 
                "Overall Impact"
            ]

            dmg_columns = request.form.get('dmgScenTblClms', '').split(',')   

            if not dmg_columns or dmg_columns == ['']:
                dmg_columns = valid_columns

            dmg_columns = [col for col in dmg_columns if col in valid_columns]

            if not dmg_columns:
                damage_scenario_data = [["No valid columns provided"]]
            else:
                if damage_record:
                    damage_details = damage_record.get("Details", [])

                    damage_headers = []
                    for col in dmg_columns:
                        if col == "ID":
                            damage_headers.append(wrap_content("ID", 'white'))
                        elif col == "Name":
                            damage_headers.append(wrap_content("Name", 'white'))
                        # # elif col == "Damage Scenario":
                        #     damage_headers.append(wrap_content("Damage Scenario", 'white'))
                        elif col == "Description/Scalability":
                            damage_headers.append(wrap_content("Description/Scalability", 'white'))
                        elif col == "Losses of Cybersecurity Properties":
                            damage_headers.append(wrap_content("Losses of Cybersecurity Properties", 'white'))
                        elif col == "Assets":
                            damage_headers.append(wrap_content("Assets", 'white'))
                        # elif col == "Component/Message":
                        #     damage_headers.append(wrap_content("Component/Message", 'white'))
                        elif col == "Safety Impact":
                            damage_headers.append(wrap_content("Safety Impact", 'white'))
                        elif col == "Financial Impact":
                            damage_headers.append(wrap_content("Financial Impact", 'white'))
                        elif col == "Operational Impact":
                            damage_headers.append(wrap_content("Operational Impact", 'white'))
                        elif col == "Privacy Impact":
                            damage_headers.append(wrap_content("Privacy Impact", 'white'))
                        elif col == "Impact Justification":
                            damage_headers.append(wrap_content("Impact Justification", 'white'))
                        elif col == "Associated Threat Scenarios":
                            damage_headers.append(wrap_content("Associated Threat Scenarios", 'white'))
                        elif col == "Overall Impact":
                            damage_headers.append(wrap_content("Overall Impact", 'white'))
                        # elif col == "Asset is Evaluated":
                        #     damage_headers.append(wrap_content("Asset is Evaluated", 'white'))
                        # elif col == "Cybersecurity Properties are Evaluated":
                        #     damage_headers.append(wrap_content("Cybersecurity Properties are Evaluated", 'white'))
                        # elif col == "Unevaluated Cybersecurity Properties":
                        #     damage_headers.append(wrap_content("Unevaluated Cybersecurity Properties", 'white'))

                    damage_scenario_data = [damage_headers]

                    for index, detail in enumerate(damage_details):
                        cyber_losses = "\n".join(["Loss of " + loss["name"] for loss in detail.get("cyberLosses", [])])
                        assets = "\n".join(sorted({loss["node"] for loss in detail.get("cyberLosses", [])}))
                        impacts = detail.get("impacts", {})
                        row = []
                        bg_color=''

                        for col in dmg_columns:
                            if col == "ID":
                                row.append(wrap_content(f"DS{index + 1:03}", 'black'))  # Auto-generated ID
                            elif col == "Name":
                                row.append(wrap_content(detail.get("Name", ""), 'black'))  # Name
                            # elif col == "Damage Scenario":
                            #     row.append(wrap_content("")) 
                            elif col == "Description/Scalability":
                                row.append(wrap_content(detail.get("Description", ""), 'black'))  # Description
                            elif col == "Losses of Cybersecurity Properties":
                                row.append(cyber_losses)  # Losses of Cybersecurity Properties
                            elif col == "Assets":
                                row.append(assets)  # Assets
                            elif col == "Component/Message":
                                row.append(wrap_content("")) 
                            elif col == "Safety Impact":
                                safety_impact = impacts.get("Safety Impact", "")
                                bg_color = getImpactBgcolour(safety_impact)
                                row.append(wrap_content(safety_impact, 'black', bg_color))   # Safety Impact
                            elif col == "Financial Impact":
                                financial_impact = impacts.get("Financial Impact", "")
                                bg_color = getImpactBgcolour(financial_impact)
                                row.append(wrap_content(financial_impact, 'black', bg_color))  # Financial Impact
                            elif col == "Operational Impact":
                                operational_impact = impacts.get("Operational Impact", "")
                                bg_color = getImpactBgcolour(operational_impact)
                                row.append(wrap_content(operational_impact, 'black', bg_color))  # Operational Impact
                            elif col == "Privacy Impact":
                                privacy_impact = impacts.get("Privacy Impact", "")
                                bg_color = getImpactBgcolour(privacy_impact)
                                row.append(wrap_content(privacy_impact, 'black', bg_color)) # Privacy Impact
                            elif col == "Impact Justification":
                                row.append(wrap_content(""))  
                            elif col == "Associated Threat Scenarios":
                                row.append(wrap_content("")) 
                            elif col == "Overall Impact":
                                overall_impact = get_highest_impact(impacts)
                                bg_color = getImpactBgcolour(overall_impact)
                                row.append(wrap_content(overall_impact, 'black',bg_color))  # Overall Impact
                            elif col == "Asset is Evaluated":
                                row.append(wrap_content("")) 
                            elif col == "Cybersecurity Properties are Evaluated":
                                row.append(wrap_content("")) 
                            elif col == "Unevaluated Cybersecurity Properties":
                                row.append(wrap_content("")) 
                        damage_scenario_data.append(row)
                # else:
                #     damage_scenario_data = [["No Damage Scenario Data Found"]]

# ==========================================================================================================================

# ========================= Threat Scenario Table ==========================================================================
        if threat_scenarios_table == 1:
            threat_record = db.Threat_scenarios.find_one({"model_id": model_id, "type": "derived"})

            valid_columns = [
                "SNo", "Name", "Category", "Description", 
                "Damage Scenarios", "Related Threats from Catalog", "Losses of Cybersecurity Properties", 
                "Assets", "Related Attack Trees", "Related Attack Path Models"
            ]

            threat_columns_raw = request.form.get('threatScenTblClms', '')

            if threat_columns_raw:
                if isinstance(threat_columns_raw, str):
                    threat_columns = threat_columns_raw.split(',')
                else:
                    threat_columns = threat_columns_raw
            else:
                threat_columns = valid_columns

            # Validate columns: filter out any invalid columns
            threat_columns = [col for col in threat_columns if col in valid_columns]

            if not threat_columns:
                threat_scenario_data = [["No valid columns provided"]]
            else:
                if threat_record:
                    threat_details = threat_record.get("Details", [])

                    threat_headers = []
                    for col in threat_columns:
                        if col == "SNo":
                            threat_headers.append(wrap_content("SNo", 'white'))
                        elif col == "Name":
                            threat_headers.append(wrap_content("Name", 'white'))
                        elif col == "Category":
                            threat_headers.append(wrap_content("Category", 'white'))
                        elif col == "Description":
                            threat_headers.append(wrap_content("Description", 'white'))
                        elif col == "Damage Scenarios":
                            threat_headers.append(wrap_content("Damage Scenarios", 'white'))
                        elif col == "Related Threats from Catalog":
                            threat_headers.append(wrap_content("Related Threats from Catalog", 'white'))
                        elif col == "Losses of Cybersecurity Properties":
                            threat_headers.append(wrap_content("Losses of Cybersecurity Properties", 'white'))
                        elif col == "Assets":
                            threat_headers.append(wrap_content("Assets", 'white'))
                        elif col == "Related Attack Trees":
                            threat_headers.append(wrap_content("Related Attack Trees", 'white'))
                        elif col == "Related Attack Path Models":
                            threat_headers.append(wrap_content("Related Attack Path Models", 'white'))

                    threat_scenario_data = [threat_headers]
                    sno_counter=1
                    for index, detail in enumerate(threat_details):
                        row_id = detail.get("rowId", "")
                        detail_name = detail.get("id", "")
                        detail_description = detail.get("Description", "")
                        detail_nodes = detail.get("Details", [])

                        for node_detail in detail_nodes:
                            node = node_detail.get("node", "")
                            node_props = node_detail.get("props", [])
                            damage_scenarios = node_detail.get("name", [])
                            for props in node_props:
                                name = f"{get_threat_type(props['name'])} {props['name']} of {node}"
                                description = f"{get_threat_type(props['name'])} occurred due to {props['name']} in {node}"
                                
                                # # Multiple approaches to get damage scenarios
                                # damage_scenarios = ""
                                
                                # # 1. Check if there's a threat_key that can be used to look up related damage scenarios
                                # threat_key = props.get("threat_key")
                                # if threat_key:
                                #     # Search for damage scenarios linked to this threat key
                                #     dmg_records = db.Damage_scenarios.find({"model_id": model_id, "Details.threat_key": threat_key})
                                #     dmg_names = []
                                #     for dmg_rec in dmg_records:
                                #         for dmg_detail in dmg_rec.get("Details", []):
                                #             if dmg_detail.get("threat_key") == threat_key:
                                #                 dmg_names.append(dmg_detail.get("Name", ""))
                                #     if dmg_names:
                                #         damage_scenarios = "\n".join(dmg_names)
                                
                                # # 2. Try with damage_id if threat_key didn't work
                                # if not damage_scenarios:
                                #     damage_id = props.get("damage_id")
                                #     if damage_id:
                                #         dmg_data = db.Damage_scenarios.find_one({
                                #             "model_id": model_id, 
                                #             "Details._id": damage_id
                                #         }, {"Details.$": 1})
                                        
                                #         if dmg_data and "Details" in dmg_data and len(dmg_data["Details"]) > 0:
                                #             damage_scenarios = dmg_data["Details"][0].get("Name", "")
                                
                                # # 3. Check if there are embedded damage_scenes
                                # if not damage_scenarios and props.get("damage_scenes"):
                                #     damage_scenarios = "\n".join([scene.get("Name", "") for scene in props.get("damage_scenes", [])])
                                    
                                # # 4. Look for a mapping between this props and damage scenarios
                                # if not damage_scenarios:
                                #     # Debug - First log what fields are available in props for debugging
                                #     # print(f"Props keys: {props.keys()}")
                                    
                                #     # Try to find any field that might relate to damage scenarios
                                #     for key in props:
                                #         if "damage" in key.lower() and props[key]:
                                #             # This could be a damage scenario ID or reference
                                #             dmg_data = db.Damage_scenarios.find_one({
                                #                 "model_id": model_id, 
                                #                 "Details._id": props[key]
                                #             })
                                #             if dmg_data:
                                #                 for dmg_detail in dmg_data.get("Details", []):
                                #                     if dmg_detail.get("_id") == props[key]:
                                #                         damage_scenarios = dmg_detail.get("Name", "")
                                #                         break
                                #             break
                                
                                losses = f"Losses of {props['name']}"

                                row = []

                                for col in threat_columns:
                                    if col == "SNo":
                                        row.append(f"TS{sno_counter:03}")
                                        sno_counter += 1  # Auto-generated ID
                                    elif col == "Name":
                                        row.append(wrap_content(name, 'black'))  # Name
                                    elif col == "Category":
                                        row.append(wrap_content(""))  # Category (empty for now)
                                    elif col == "Description":
                                        row.append(wrap_content(description, 'black'))  # Description
                                    elif col == "Damage Scenarios":
                                        row.append(wrap_content(damage_scenarios, 'black'))  # Damage Scenarios
                                    elif col == "Related Threats from Catalog":
                                        row.append(wrap_content("")) 
                                    elif col == "Losses of Cybersecurity Properties":
                                        row.append(wrap_content(losses, 'black'))  # Losses of Cybersecurity Properties
                                    elif col == "Assets":
                                        assets = node  # Assuming the node itself is the asset, adjust as needed
                                        row.append(wrap_content(assets, 'black'))
                                    elif col == "Related Attack Trees":
                                        row.append(wrap_content("")) 
                                    elif col == "Related Attack Path Models":
                                        row.append(wrap_content("")) 

                                threat_scenario_data.append(row)

                else:
                    threat_scenario_data = [["No Threat Scenarios Data Found"]]

# ==========================================================================================================================

# ========================= Attack Tree Table ==============================================================================
        if attack_trees_table == 1:
            attack_record = db.Attacks.find_one({"model_id": model_id, "type": "attack"})
            
            valid_columns = [
                "SNo", "Name", "Category", "Description", "Elapsed Time", "Expertise", 
                "Knowledge of the Item", "Window of Opportunity", "Equipment", "Attack Vector", 
                "Attack Complexity", "Privileges Required", "User Interaction", "Scope", 
                "Determination Criteria", "Attack Feasibilities Rating", "Attack Feasibility Rating Justification"
            ]

            attack_columns_raw = request.form.get('attackTreeTblClms', '')

            if attack_columns_raw:
                if isinstance(attack_columns_raw, str):
                    attack_columns = attack_columns_raw.split(',')
                else:
                    attack_columns = attack_columns_raw
            else:
                attack_columns = valid_columns

            # Validate columns: filter out any invalid columns
            attack_columns = [col for col in attack_columns if col in valid_columns]

            if not attack_columns:
                attack_tree_data = [["No valid columns provided"]]
            else:
                if attack_record:
                    scenes = attack_record.get("scenes", [])

                    attack_headers = []
                    for col in attack_columns:
                        if col == "SNo":
                            attack_headers.append(wrap_content("SNo", 'white'))
                        elif col == "Name":
                            attack_headers.append(wrap_content("Name", 'white'))
                        elif col == "Category":
                            attack_headers.append(wrap_content("Category", 'white'))
                        elif col == "Description":
                            attack_headers.append(wrap_content("Description", 'white'))
                        # elif col == "Approach":
                        #     attack_headers.append(wrap_content("Approach", 'white'))
                        elif col == "Elapsed Time":
                            attack_headers.append(wrap_content("Elapsed Time", 'white'))
                        elif col == "Expertise":
                            attack_headers.append(wrap_content("Expertise", 'white'))
                        elif col == "Knowledge of the Item":
                            attack_headers.append(wrap_content("Knowledge of the Item", 'white'))
                        elif col == "Window of Opportunity":
                            attack_headers.append(wrap_content("Window of Opportunity", 'white'))
                        elif col == "Equipment":
                            attack_headers.append(wrap_content("Equipment", 'white'))
                        elif col == "Attack Vector":
                            attack_headers.append(wrap_content("Attack Vector", 'white'))
                        elif col == "Attack Complexity":
                            attack_headers.append(wrap_content("Attack Complexity", 'white'))
                        elif col == "Privileges Required":
                            attack_headers.append(wrap_content("Privileges Required", 'white'))               
                        elif col == "User Interaction":
                            attack_headers.append(wrap_content("User Interaction", 'white'))               
                        elif col == "Scope":
                            attack_headers.append(wrap_content("Scope", 'white'))               
                        elif col == "Determination Criteria":
                            attack_headers.append(wrap_content("Determination Criteria", 'white'))               
                        elif col == "Attack Feasibilities Rating":
                            attack_headers.append(wrap_content("Attack Feasibilities Rating", 'white'))
                        elif col == "Attack Feasibility Rating Justification":
                            attack_headers.append(wrap_content("Attack Feasibility Rating Justification", 'white'))
    

                    attack_tree_data = [attack_headers]

                    for index, scene in enumerate(scenes):
                        row = []
                       
                        for col in attack_columns:
                            if col == "SNo":
                                row.append(f"AT{index + 1:03}")  # Auto-generated SNo
                            elif col == "Name":
                                row.append(wrap_content(scene.get("Name", ""), 'black'))  # Name
                            elif col == "Category":
                                row.append(wrap_content(""))  # Category (empty for now)
                            elif col == "Description":
                                row.append(wrap_content(f"This is description for {scene.get('Name', '')}", 'black'))  # Description
                            elif col == "Approach":
                                row.append(wrap_content(scene.get("Approach", ""), 'black'))  # Approach
                            elif col == "Elapsed Time":
                                row.append(wrap_content(scene.get("Elapsed Time", ""), 'black'))  # Elapsed Time
                            elif col == "Expertise":
                                row.append(wrap_content(scene.get("Expertise", ""), 'black'))  # Expertise
                            elif col == "Knowledge of the Item":
                                row.append(wrap_content(scene.get("Knowledge of the Item", ""), 'black'))  # Knowledge of the Item
                            elif col == "Window of Opportunity":
                                row.append(wrap_content(scene.get("Window of Opportunity", ""), 'black'))  # Window of Opportunity
                            elif col == "Equipment":
                                row.append(wrap_content(scene.get("Equipment", "")))  # Equipment
                            elif col == "Attack Vector":
                                row.append(wrap_content(scene.get("Attack Vector", ""), 'black'))
                            elif col == "Attack Complexity":
                                row.append(wrap_content(scene.get("Attack Complexity", ""), 'black'))
                            elif col == "Privileges Required":
                                row.append(wrap_content(scene.get("Privileges Required", ""), 'black'))
                            elif col == "User Interaction":
                                row.append(wrap_content(scene.get("User Interaction", ""), 'black'))
                            elif col == "Scope":
                                row.append(wrap_content(scene.get("Scope", ""), 'black'))
                            elif col == "Determination Criteria":
                                row.append(wrap_content(scene.get("Determination Criteria", ""), 'black')) 
                            elif col == "Attack Feasibilities Rating":
                                attack_rating = scene.get("Attack Feasibilities Rating", "")
                                bg_color = getFesRateBgColor(attack_rating)
                                row.append(wrap_content(attack_rating, 'black', bg_color))
                            elif col == "Attack Feasibility Rating Justification":
                                row.append(wrap_content(scene.get("Attack Feasibility Rating Justification", ""), 'black'))

                        attack_tree_data.append(row)
                # else:
                #     # If no attack record found
                #     attack_tree_data = [["No Attack Tree Data Found"]]
# =========================================================================================================================

# ========================= Risk Treatment Table ==========================================================================
        if risk_treatment == 1:
            risk_treatment_record = db.Risk_treatment.find_one({"model_id": model_id})
            cyberSecurity_record = db.Cybersecurity.find_one({"model_id": model_id, "type": "cybersecurity_requirements"})
            
            # Predefined set of valid columns for Risk Treatment Table
            valid_columns = [
                "SNo", "Threat Scenario", "Assets", "Damage Scenarios", "Related UNECE Threats or Vulns", "Safety Impact",
                "Financial Impact", "Operational Impact", "Privacy Impact", "Attack Tree or Attack Path(s)", "Attack Path Name",
                "Attack Path Details", "Attack Feasibility Rating", "Mitigated Attack Feasibility", "Acceptence Level",
                "Safety Risk", "Financial Risk", "Operational Risk", "Privacy Risk", "Residual Safety Risk", "Residual Financial Risk",
                "Residual Operational Risk", "Residual Privacy Risk", "Risk Treatment Options", "Risk Treatment Justification",
                "Applied Measures", "Detailed / Combined Threat Scenarios", "Cybersecurity Goals", "Contributing Requirements", 
                "CyberSecurity Claims"
            ]
            risk_treatment_columns_raw = request.form.get('riskTreatmentTblClms', '')
            if risk_treatment_columns_raw:
                if isinstance(risk_treatment_columns_raw, str):
                    risk_treatment_columns = risk_treatment_columns_raw.split(',')
                else:
                    risk_treatment_columns = risk_treatment_columns_raw
            else:
                risk_treatment_columns = valid_columns
            # Validate columns: filter out any invalid columns
            risk_treatment_columns = [col for col in risk_treatment_columns if col in valid_columns]
            if not risk_treatment_columns:
                risk_trtmnt_data = [["No valid columns provided"]]
            else:
                risk_trtmnt_headers = []
                for col in risk_treatment_columns:
                    if col == "SNo":
                        risk_trtmnt_headers.append(wrap_content("SNo", 'white'))
                    elif col == "Threat Scenario":
                        risk_trtmnt_headers.append(wrap_content("Threat Scenario", 'white'))
                    elif col == "Assets":
                        risk_trtmnt_headers.append(wrap_content("Assets", 'white'))
                    elif col == "Damage Scenarios":
                        risk_trtmnt_headers.append(wrap_content("Damage Scenarios", 'white'))
                    elif col == "Related UNECE Threats or Vulns":
                        risk_trtmnt_headers.append(wrap_content("Related UNECE Threats or Vulns", 'white'))
                    elif col == "Safety Impact":
                        risk_trtmnt_headers.append(wrap_content("Safety Impact", 'white'))
                    elif col == "Financial Impact":
                        risk_trtmnt_headers.append(wrap_content("Financial Impact", 'white'))
                    elif col == "Operational Impact":
                        risk_trtmnt_headers.append(wrap_content("Operational Impact", 'white'))
                    elif col == "Privacy Impact":
                        risk_trtmnt_headers.append(wrap_content("Privacy Impact", 'white'))
                    elif col == "Attack Tree or Attack Path(s)":
                        risk_trtmnt_headers.append(wrap_content("Attack Tree or Attack Path(s)", 'white'))
                    elif col == "Attack Path Name":
                        risk_trtmnt_headers.append(wrap_content("Attack Path Name", 'white'))
                    elif col == "Attack Path Details":
                        risk_trtmnt_headers.append(wrap_content("Attack Path Details", 'white'))
                    elif col == "Attack Feasibility Rating":
                        risk_trtmnt_headers.append(wrap_content("Attack Feasibility Rating", 'white'))
                    elif col == "Mitigated Attack Feasibility":
                        risk_trtmnt_headers.append(wrap_content("Mitigated Attack Feasibility", 'white'))
                    elif col == "Acceptence Level":
                        risk_trtmnt_headers.append(wrap_content("Acceptence Level", 'white'))
                    elif col == "Safety Risk":
                        risk_trtmnt_headers.append(wrap_content("Safety Risk", 'white'))
                    elif col == "Financial Risk":
                        risk_trtmnt_headers.append(wrap_content("Financial Risk", 'white'))
                    elif col == "Operational Risk":
                        risk_trtmnt_headers.append(wrap_content("Operational Risk", 'white'))
                    elif col == "Privacy Risk":
                        risk_trtmnt_headers.append(wrap_content("Privacy Risk", 'white'))
                    elif col == "Residual Safety Risk":
                        risk_trtmnt_headers.append(wrap_content("Residual Safety Risk", 'white'))
                    elif col == "Residual Financial Risk":
                        risk_trtmnt_headers.append(wrap_content("Residual Financial Risk", 'white'))
                    elif col == "Residual Operational Risk":
                        risk_trtmnt_headers.append(wrap_content("Residual Operational Risk", 'white'))
                    elif col == "Residual Privacy Risk":
                        risk_trtmnt_headers.append(wrap_content("Residual Privacy Risk", 'white'))
                    elif col == "Risk Treatment Options":
                        risk_trtmnt_headers.append(wrap_content("Risk Treatment Options", 'white'))
                    elif col == "Risk Treatment Justification":
                        risk_trtmnt_headers.append(wrap_content("Risk Treatment Justification", 'white'))
                    elif col == "Applied Measures":
                        risk_trtmnt_headers.append(wrap_content("Applied Measures", 'white'))
                    elif col == "Detailed / Combined Threat Scenarios":
                        risk_trtmnt_headers.append(wrap_content("Detailed / Combined Threat Scenarios", 'white'))
                    elif col == "Cybersecurity Goals":
                        risk_trtmnt_headers.append(wrap_content("Cybersecurity Goals", 'white'))
                    elif col == "Contributing Requirements":
                        risk_trtmnt_headers.append(wrap_content("Contributing Requirements", 'white'))
                    elif col == "CyberSecurity Claims":
                        risk_trtmnt_headers.append(wrap_content("CyberSecurity Claims", 'white'))
                risk_trtmnt_data = [risk_trtmnt_headers]
                if risk_treatment_record:
                    for index, rsk_tmt in enumerate(risk_treatment_record["Details"]):
                        threat_key = rsk_tmt.get("threat_key")
                        attack_name = ''
                        attack_overall_rating = ''  # Added for Attack Feasibility Rating
                        goal_names = []
                        calims_names = []
                        cyber_goals = ""
                        cyber_claims = ""
                        if threat_key:
                            # attack = db.Attacks.find_one({"model_id": model_id, "scenes.threat_key": rsk_tmt.get("threat_key")})
                            attack = db.Attacks.find_one({"model_id": model_id,"scenes.threat_key": {"$exists": True, "$eq": rsk_tmt.get("threat_key")}})
                            if attack:
                                for scene in attack['scenes']:
                                    if scene['threat_key'] == rsk_tmt.get("threat_key"):
                                        attack_name = scene['Name'] if scene['Name'] != '' else scene['Name']
                                        # Get the overall_rating from attack_scene, similar to frontend
                                        attack_overall_rating = scene.get('overall_rating', '')
                        
                        # Cyber Security Goals
                        cybersecurity = rsk_tmt.get("cybersecurity")
                        if cybersecurity and cybersecurity.get('cybersecurity_goals'):
                            for id in cybersecurity['cybersecurity_goals']:
                                cybersecurity_goals_record = db.Cybersecurity.find_one({"model_id": model_id,"type":"cybersecurity_goals","scenes.ID": id})
                                
                                if cybersecurity_goals_record:
                                    for scene in cybersecurity_goals_record['scenes']:
                                        if scene.get('ID') == id:
                                            goal_names.append(scene.get('Name'))
                            cyber_goals = ', '.join(goal_names)
                        if cybersecurity and cybersecurity.get('cybersecurity_claims'):
                            for id in cybersecurity['cybersecurity_claims']:
                                cybersecurity_claims_record = db.Cybersecurity.find_one({"model_id": model_id,"type":"cybersecurity_claims","scenes.ID": id})
                                
                                if cybersecurity_claims_record:
                                    for scene in cybersecurity_claims_record['scenes']:
                                        if scene.get('ID') == id:
                                            calims_names.append(scene.get('Name'))
                            cyber_claims = ', '.join(calims_names)
                        contrRequNames = []
                        if cyberSecurity_record and threat_key:
                            contrRequNames = [cyber_record['Name'] for cyber_record in cyberSecurity_record['scenes'] if cyber_record['threat_key'] == rsk_tmt.get("threat_key")]
                        dmg_data = db.Damage_scenarios.find_one({
                            "model_id": model_id, 
                            "Details._id": rsk_tmt['damage_id']
                        }, {"Details.$": 1})
                        if dmg_data and "Details" in dmg_data and len(dmg_data["Details"]) > 0:
                            dmg = dmg_data["Details"][0]
                            row = []
                            for col in risk_treatment_columns:
                                if col == "SNo":
                                    row.append(f"RT{index + 1:03}")
                                elif col == "Threat Scenario":
                                    row.append(wrap_content(rsk_tmt.get("label", ""), 'black'))
                                elif col == "Assets":
                                    row.append(wrap_content(""))  # Assets (empty for now)
                                elif col == "Damage Scenarios":
                                    row.append(wrap_content(dmg.get("Name", ""), 'black'))
                                elif col == "Related UNECE Threats or Vulns":
                                    row.append(wrap_content(",".join(rsk_tmt.get("catalogs", "")), 'black'))
                                elif col == "Safety Impact":
                                    safety_impact = dmg['impacts'].get("Safety Impact", "")
                                    bg_color = getImpactBgcolour(safety_impact)
                                    row.append(wrap_content(safety_impact, 'black', bg_color))   # Safety Impact
                                elif col == "Financial Impact":
                                    financial_impact = dmg['impacts'].get("Financial Impact", "")
                                    bg_color = getImpactBgcolour(financial_impact)
                                    row.append(wrap_content(financial_impact, 'black', bg_color))  # Financial Impact
                                elif col == "Operational Impact":
                                    operational_impact = dmg['impacts'].get("Operational Impact", "")
                                    bg_color = getImpactBgcolour(operational_impact)
                                    row.append(wrap_content(operational_impact, 'black', bg_color))  # Operational Impact
                                elif col == "Privacy Impact":
                                    privacy_impact = dmg['impacts'].get("Privacy Impact", "")
                                    bg_color = getImpactBgcolour(privacy_impact)
                                    row.append(wrap_content(privacy_impact, 'black', bg_color)) # Privacy Impact
                                elif col == "Attack Tree or Attack Path(s)":
                                    row.append(wrap_content(attack_name))
                                elif col == "Attack Path Name":
                                    row.append(wrap_content(""))
                                elif col == "Attack Path Details":
                                    row.append(wrap_content(""))
                                elif col == "Attack Feasibility Rating":
                                    # Apply background color based on rating, similar to frontend RatingColor function
                                    bg_color = getFesRateBgColor(attack_overall_rating)
                                    row.append(wrap_content(attack_overall_rating, 'black', bg_color))
                                elif col == "Mitigated Attack Feasibility":
                                    row.append(wrap_content(""))
                                elif col == "Acceptence Level":
                                    row.append(wrap_content(""))
                                elif col == "Safety Risk":
                                    row.append(wrap_content(""))
                                elif col == "Financial Risk":
                                    row.append(wrap_content(""))
                                elif col == "Operational Risk":
                                    row.append(wrap_content(""))
                                elif col == "Privacy Risk":
                                    row.append(wrap_content(""))
                                elif col == "Residual Safety Risk":
                                    row.append(wrap_content(""))
                                elif col == "Residual Financial Risk":
                                    row.append(wrap_content(""))
                                elif col == "Residual Operational Risk":
                                    row.append(wrap_content(""))
                                elif col == "Residual Privacy Risk":
                                    row.append(wrap_content(""))
                                elif col == "Risk Treatment Options":
                                    row.append(wrap_content(""))
                                elif col == "Risk Treatment Justification":
                                    row.append(wrap_content(""))
                                elif col == "Applied Measures":
                                    row.append(wrap_content(""))
                                elif col == "Detailed / Combined Threat Scenarios":
                                    row.append(wrap_content(""))
                                elif col == "Cybersecurity Goals":
                                    row.append(wrap_content(cyber_goals,'black'))
                                elif col == "Contributing Requirements":
                                    row.append(wrap_content(", ".join(contrRequNames), 'black'))
                                elif col == "CyberSecurity Claims":
                                    row.append(wrap_content(cyber_claims,'black'))
                            risk_trtmnt_data.append(row)
                        else:
                            risk_trtmnt_data.append(["No matching Damage Scenario found"] * len(risk_trtmnt_headers))
                    # else:
                    #     risk_trtmnt_data = [["No Risk Treatment Data Found"]]

# =========================================================================================================================        
       
# =========================Cyber Security Goals ===========================================================================
        if cyber_security_goals == 1:
            # Step 1: Fetch record from DB
            cybersecurity_record = db.Cybersecurity.find_one({
                "model_id": model_id,
                "type": "cybersecurity_goals"
            })

            # Step 2: Define valid columns
            valid_columns = [
                "SNo", "Name", "Description", "CAL",
                "Related Threat Scenario", "Related Cybersecurity Requirements",
                "Related Cybersecurity Controls"
            ]

            # Step 3: Get columns requested from form and apply filtering
            cyber_columns_raw = request.form.get('cyberGoalTblClms', '')

            if cyber_columns_raw:
                if isinstance(cyber_columns_raw, str):
                    cyber_columns = cyber_columns_raw.split(',')
                else:
                    cyber_columns = cyber_columns_raw
            else:
                cyber_columns = valid_columns

            # Filter out any invalid columns
            cyber_columns = [col.strip() for col in cyber_columns if col.strip() in valid_columns]

            # Step 4: Fallback if no valid columns
            if not cyber_columns:
                cybersecurity_goals_data = [["No valid columns provided"]]
            else:
                if cybersecurity_record:
                    cybersecurity_details = cybersecurity_record.get("scenes", [])

                    # Step 5: Build header row
                    cyber_headers = []
                    for col in cyber_columns:
                        cyber_headers.append(wrap_content(col, 'white'))
                    cybersecurity_goals_data = [cyber_headers]

                    # Step 6: Build data rows
                    for index, detail in enumerate(cybersecurity_details):
                        row = []
                        related_threats = detail.get("threat_key", [])
                        related_reqs = detail.get("requirements", [])
                        related_controls = detail.get("controls", [])

                        for col in cyber_columns:
                            if col == "SNo":
                                row.append(wrap_content(f"CG{index + 1:03}", 'black'))
                            elif col == "Name":
                                row.append(wrap_content(detail.get("Name", ""), 'black'))
                            elif col == "Description":
                                row.append(wrap_content(detail.get("Description", ""), 'black'))
                            elif col == "CAL":
                                row.append(wrap_content(detail.get("CAL", "") or "-", 'black'))
                            elif col == "Related Threat Scenario":
                                if related_threats:
                                    threats = [f"🔒 {threat}" for threat in sorted(related_threats)]
                                    row.append(wrap_content("\n".join(threats), 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))
                            elif col == "Related Cybersecurity Requirements":
                                if related_reqs:
                                    row.append(wrap_content("\n".join(sorted(related_reqs)), 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))
                            elif col == "Related Cybersecurity Controls":
                                if related_controls:
                                    row.append(wrap_content("\n".join(sorted(related_controls)), 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))

                        cybersecurity_goals_data.append(row)

# =========================================================================================================================        

# =========================Cyber Security Requirements ====================================================================
        if cyber_security_requirements == 1:
            # Step 1: Fetch record from DB
            cybersecurity_record = db.Cybersecurity.find_one({
                "model_id": model_id,
                "type": "cybersecurity_requirements"
            })

            # Step 2: Define valid columns
            valid_columns = [
                "SNo", "Name", "Description",
                "Related Cybersecurity Goals", "Related Cybersecurity Controls"
            ]

            # Step 3: Get columns from form
            cyber_columns_raw = request.form.get('cyberReqTblClms', '')

            if cyber_columns_raw:
                if isinstance(cyber_columns_raw, str):
                    cyber_columns = cyber_columns_raw.split(',')
                else:
                    cyber_columns = cyber_columns_raw
            else:
                cyber_columns = valid_columns

            # Filter out invalid columns
            cyber_columns = [col.strip() for col in cyber_columns if col.strip() in valid_columns]

            # Step 4: Fallback if no valid columns
            if not cyber_columns:
                cybersecurity_requirements_data = [["No valid columns provided"]]
            else:
                # Step 5: Check for DB data
                if cybersecurity_record:
                    cybersecurity_details = cybersecurity_record.get("scenes", [])

                    # Step 6: Build table headers
                    cyber_headers = [wrap_content(col, 'white') for col in cyber_columns]
                    cybersecurity_requirements_data = [cyber_headers]

                    # Step 7: Build rows for each scene
                    for index, detail in enumerate(cybersecurity_details):
                        row = []
                        related_goals = detail.get("goals", [])
                        related_controls = detail.get("controls", [])

                        for col in cyber_columns:
                            if col == "SNo":
                                row.append(wrap_content(f"CR{index + 1:03}", 'black'))
                            elif col == "Name":
                                row.append(wrap_content(detail.get("Name", ""), 'black'))
                            elif col == "Description":
                                desc = detail.get("Description") or detail.get("description") or f"description for {detail.get('Name', 'Unnamed')}"
                                row.append(wrap_content(desc, 'black'))
                            elif col == "Related Cybersecurity Goals":
                                if related_goals:
                                    row.append(wrap_content("\n".join(sorted(related_goals)), 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))
                            elif col == "Related Cybersecurity Controls":
                                if related_controls:
                                    row.append(wrap_content("\n".join(sorted(related_controls)), 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))

                        cybersecurity_requirements_data.append(row)

# =========================================================================================================================                                

# =========================Cyber Security Controls ========================================================================
        if cyber_security_controls == 1:
            # Step 1: Fetch record from DB
            cybersecurity_record = db.Cybersecurity.find_one({
                "model_id": model_id,
                "type": "cybersecurity_controls"
            })

            # Step 2: Define valid columns
            valid_columns = [
                "SNo", "Name", "Description",
                "Related Cybersecurity Goals", "Related Cybersecurity Requirements"
            ]

            # Step 3: Get columns requested from form and apply filtering
            raw_column_input = request.form.get('cyberCtrlTblClms', '')

            if raw_column_input:
                if isinstance(raw_column_input, str):
                    cyber_columns = raw_column_input.split(',')
                else:
                    cyber_columns = raw_column_input
            else:
                cyber_columns = valid_columns

            # Filter only valid columns
            cyber_columns = [col.strip() for col in cyber_columns if col.strip() in valid_columns]

            # Step 4: Fallback if no valid columns
            if not cyber_columns:
                cybersecurity_controls_data = [["No valid columns provided"]]
            else:
                # Step 5: Check if data exists in DB
                if cybersecurity_record:
                    cybersecurity_details = cybersecurity_record.get("scenes", [])

                    # Step 6: Create table headers
                    cyber_headers = []
                    for col in cyber_columns:
                        if col == "SNo":
                            cyber_headers.append(wrap_content("SNo", 'white'))
                        elif col == "Name":
                            cyber_headers.append(wrap_content("Name", 'white'))
                        elif col == "Description":
                            cyber_headers.append(wrap_content("Description", 'white'))
                        elif col == "Related Cybersecurity Goals":
                            cyber_headers.append(wrap_content("Related Cybersecurity Goals", 'white'))
                        elif col == "Related Cybersecurity Requirements":
                            cyber_headers.append(wrap_content("Related Cybersecurity Requirements", 'white'))

                    cybersecurity_controls_data = [cyber_headers]

                    # Step 7: Fill table rows
                    for index, detail in enumerate(cybersecurity_details):
                        row = []
                        related_goals = detail.get("goals", [])
                        related_reqs = detail.get("requirements", [])

                        for col in cyber_columns:
                            if col == "SNo":
                                row.append(wrap_content(f"CC{index + 1:03}", 'black'))
                            elif col == "Name":
                                row.append(wrap_content(detail.get("Name", ""), 'black'))
                            elif col == "Description":
                                description = (
                                    detail.get("Description")
                                    or detail.get("description")
                                    or f"description for {detail.get('Name', 'Unnamed')}"
                                )
                                row.append(wrap_content(description, 'black'))
                            elif col == "Related Cybersecurity Goals":
                                if related_goals:
                                    goals_content = "\n".join(sorted(related_goals))
                                    row.append(wrap_content(goals_content, 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))
                            elif col == "Related Cybersecurity Requirements":
                                if related_reqs:
                                    reqs_content = "\n".join(sorted(related_reqs))
                                    row.append(wrap_content(reqs_content, 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))

                        cybersecurity_controls_data.append(row)

# ========================================================================================================================        

# =========================Cyber Security Claims ==========================================================================        
        if cyber_security_claims == 1:
            # Step 1: Fetch record from DB
            cybersecurity_record = db.Cybersecurity.find_one({
                "model_id": model_id,
                "type": "cybersecurity_claims"
            })

            # Step 2: Define valid columns
            valid_columns = [
                "SNo", "Name", "Description",
                "Condition for Re-Evaluation", "Related Threat Scenario"
            ]

            # Step 3: Get columns requested from form and apply filtering
            raw_column_input = request.form.get('cyberClaimTblClms', '')

            if raw_column_input:
                if isinstance(raw_column_input, str):
                    cyber_columns = raw_column_input.split(',')
                else:
                    cyber_columns = raw_column_input
            else:
                cyber_columns = valid_columns

            # Filter columns to only valid ones
            cyber_columns = [col.strip() for col in cyber_columns if col.strip() in valid_columns]

            # Step 4: Fallback if no valid columns
            if not cyber_columns:
                cybersecurity_claims_data = [["No valid columns provided"]]
            else:
                # Step 5: Check if data exists in DB
                if cybersecurity_record:
                    cybersecurity_details = cybersecurity_record.get("scenes", [])

                    # Step 6: Create headers based on selected columns
                    cyber_headers = []
                    for col in cyber_columns:
                        if col == "SNo":
                            cyber_headers.append(wrap_content("SNo", 'white'))
                        elif col == "Name":
                            cyber_headers.append(wrap_content("Name", 'white'))
                        elif col == "Description":
                            cyber_headers.append(wrap_content("Description", 'white'))
                        elif col == "Condition for Re-Evaluation":
                            cyber_headers.append(wrap_content("Condition for Re-Evaluation", 'white'))
                        elif col == "Related Threat Scenario":
                            cyber_headers.append(wrap_content("Related Threat Scenario", 'white'))

                    cybersecurity_claims_data = [cyber_headers]

                    # Step 7: Iterate through scenes and build rows
                    for index, detail in enumerate(cybersecurity_details):
                        row = []
                        related_threats = detail.get("threat_key", [])

                        for col in cyber_columns:
                            if col == "SNo":
                                row.append(wrap_content(f"CL{index + 1:03}", 'black'))
                            elif col == "Name":
                                row.append(wrap_content(detail.get("Name", ""), 'black'))
                            elif col == "Description":
                                desc = (
                                    detail.get("Description")
                                    or detail.get("description")
                                    or f"description for {detail.get('Name', 'Unnamed')}"
                                )
                                row.append(wrap_content(desc, 'black'))
                            elif col == "Condition for Re-Evaluation":
                                condition = detail.get("Condition_for_Re_Evaluation", "") or "-"
                                row.append(wrap_content(condition, 'black'))
                            elif col == "Related Threat Scenario":
                                if related_threats:
                                    threat_entries = [f"🔒 {threat}" for threat in sorted(related_threats)]
                                    threat_content = "\n".join(threat_entries)
                                    row.append(wrap_content(threat_content, 'black'))
                                else:
                                    row.append(wrap_content("-", 'black'))

                        cybersecurity_claims_data.append(row)

# ==========================================================================================================================
                        
# =========================== PDF Generation ===============================================================================
        mode_record = db.Models.find_one({"_id": ObjectId(model_id)})
        current_datetime = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        # pdf_file_name = f"{mode_record['name']}({current_datetime})"
        pdf_file_name = "Myfile"
        column_widths_damage = [50] + [130] * 16  
        column_widths_threat = [50] + [120] * 13  
        column_widths_attack = [50] + [100] * 10  
        column_widths_risk_trtmnt = [50] + [100] * 26  

        table_width_damage = sum(column_widths_damage)
        table_width_threat = sum(column_widths_threat)
        table_width_attack = sum(column_widths_attack)
        column_width_risk_trtmnt = sum(column_widths_risk_trtmnt)

        
        page_size = (max(table_width_damage,table_width_threat,table_width_attack,column_width_risk_trtmnt) + 360, 11 * 72)  # Adjust width; height is letter size

        # Specify the path for the Documents folder
        documents_folder = 'Documents'
        if not os.path.exists(documents_folder):
            os.makedirs(documents_folder)  # Create the folder if it doesn't exist

        # Define the full file path to save the PDF
        pdf_path = os.path.join(documents_folder, pdf_file_name + ".pdf")
        
        pdf = SimpleDocTemplate(pdf_path, pagesize=page_size)
        elements = []

        # Add Image to the PDF if provided
        if image_stream:
            elements.append(Table([["Model Image"]], colWidths=[500], style=[
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 14),
                # ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ],hAlign='LEFT'))
            elements.append(Spacer(1, 12))  # Add spacing (1 unit wide, 12 points tall)
            img = resize_image(image_stream, max_width=800, max_height=800)  # Adjust max size as needed
            img.hAlign = 'LEFT'
            elements.append(img)
            elements.append(PageBreak())

        if damage_scenarios_table == 1:
            if damage_record:
                # Damage Scenario TITLE---------------------
                elements.append(Table([["Damage Scenario Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                    # ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ],hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing (1 unit wide, 12 points tall)

                # Damage Scenario Table------------------
                damage_table = Table(damage_scenario_data, colWidths=column_widths_damage,hAlign='LEFT')
                damage_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    # ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(damage_table)

                # Add spacing between tables
                elements.append(PageBreak())

        if threat_scenarios_table == 1:
            if threat_record:
                # Threat tree TITLE---------------------
                elements.append(Table([["Threat Scenarios Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                    # ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ],hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing (1 unit wide, 12 points tall)
                # Threat Scenario Table------------------
                threat_table = Table(threat_scenario_data, colWidths=column_widths_threat,hAlign='LEFT')
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    # ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(threat_table)

                # Add spacing between tables
                elements.append(PageBreak())  # Spacer for more significant gap

        if attack_trees_table == 1:
            if attack_record:
                # Attack tree TITLE---------------------
                elements.append(Table([["Attack Tree Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                    # ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ],hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing (1 unit wide, 12 points tall)
                # Attack Tree Table------------------
                attack_table = Table(attack_tree_data, colWidths=column_widths_attack,hAlign='LEFT')
                attack_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    # ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ],hAlign='LEFT'))
                elements.append(attack_table)

                # Add spacing between tables
                elements.append(PageBreak())  # Spacer for more significant gap

        if cyber_security_goals == 1:
            if 'cybersecurity_goals_data' in locals() and cybersecurity_goals_data:
                # Cybersecurity Goals TITLE
                elements.append(Table([["Cybersecurity Goals Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                ], hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing
                
                # Calculate column widths based on number of columns
                num_columns = len(cybersecurity_goals_data[0]) if cybersecurity_goals_data else 0
                column_widths_cyber = [50] + [100] * (num_columns - 1)  # Adjust as needed
                
                # Cybersecurity Goals Table
                cyber_goals_table = Table(cybersecurity_goals_data, colWidths=column_widths_cyber, hAlign='LEFT')
                cyber_goals_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(cyber_goals_table)

                elements.append(PageBreak())

          # Cybersecurity Requirements Table
        if cyber_security_requirements == 1:
            if 'cybersecurity_requirements_data' in locals() and cybersecurity_requirements_data:
                # Cybersecurity Requirements TITLE
                elements.append(Table([["Cybersecurity Requirements Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                ], hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing
                
                # Calculate column widths based on number of columns
                num_columns = len(cybersecurity_requirements_data[0]) if cybersecurity_requirements_data else 0
                column_widths_cyber = [50] + [100] * (num_columns - 1)  # Adjust as needed
                
                # Cybersecurity Requirements Table
                cyber_req_table = Table(cybersecurity_requirements_data, colWidths=column_widths_cyber, hAlign='LEFT')
                cyber_req_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(cyber_req_table)
                elements.append(PageBreak())  # Spacer for more significant gap
                
        # Cybersecurity Controls Table
        if cyber_security_controls == 1:
            if 'cybersecurity_controls_data' in locals() and cybersecurity_controls_data:
                # Cybersecurity Controls TITLE
                elements.append(Table([["Cybersecurity Controls Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                ], hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing
                
                # Calculate column widths based on number of columns
                num_columns = len(cybersecurity_controls_data[0]) if cybersecurity_controls_data else 0
                column_widths_cyber = [50] + [100] * (num_columns - 1)  # Adjust as needed
                
                # Cybersecurity Controls Table
                cyber_ctrl_table = Table(cybersecurity_controls_data, colWidths=column_widths_cyber, hAlign='LEFT')
                cyber_ctrl_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(cyber_ctrl_table)
                elements.append(PageBreak())  # Spacer for more significant gap
                
        # Cybersecurity Claims Table
        if cyber_security_claims == 1:
            if 'cybersecurity_claims_data' in locals() and cybersecurity_claims_data:
                # Cybersecurity Claims TITLE
                elements.append(Table([["Cybersecurity Claims Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                ], hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing
                
                # Calculate column widths based on number of columns
                num_columns = len(cybersecurity_claims_data[0]) if cybersecurity_claims_data else 0
                column_widths_cyber = [50] + [100] * (num_columns - 1)  # Adjust as needed
                
                # Cybersecurity Claims Table
                cyber_claims_table = Table(cybersecurity_claims_data, colWidths=column_widths_cyber, hAlign='LEFT')
                cyber_claims_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(cyber_claims_table)
                elements.append(PageBreak())

        if risk_treatment == 1:
            if risk_treatment_record:
                # Risk Treatment TITLE---------------------
                elements.append(Table([["Risk Treatment Table"]], colWidths=[500], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 14),
                    # ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ],hAlign='LEFT'))
                elements.append(Spacer(1, 12))  # Add spacing (1 unit wide, 12 points tall)
                # Risk Treatment Table------------------
                risk_trtmnt_table = Table(risk_trtmnt_data, colWidths=column_widths_risk_trtmnt,hAlign='LEFT')
                risk_trtmnt_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    # ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(risk_trtmnt_table)
        
                        
        # Add spacing after the table
        # Build PDF
        pdf.build(elements)

# FOr azure==================================================================================================================
        azure_connection_string = Config.AZURE_CONNECTION_STRING
        azure_container_name = Config.AZURE_CONTAINER_NAME

#         # Upload PDF to Azure Blob Storage
        blob_service_client = BlobServiceClient.from_connection_string(azure_connection_string)
        blob_client = blob_service_client.get_blob_client(container=azure_container_name, blob=pdf_file_name + ".pdf")

#         # Open the generated PDF and upload it
        with open(pdf_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True, content_settings=ContentSettings(content_type="application/pdf"))

#         # Generate a URL for the uploaded file with SAS token using the new method
        file_url = generate_sas_url(blob_service_client, pdf_file_name + ".pdf")

#         # this is used to delete once the file is upload in azure blob
#         # if file_url and os.path.exists(pdf_path):
#             # os.remove(pdf_path)

#         # Delete the local file after upload (optional)
        os.remove(pdf_path)
# FOr azure==================================================================================================================

        return jsonify({
            "message": "PDF generated and uploaded successfully.",
            "download_url": file_url
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

