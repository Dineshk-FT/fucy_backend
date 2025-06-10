from flask import Blueprint, request, jsonify
import os
from config import Config
from db import db
from azure.storage.blob import BlobServiceClient, ContentSettings
import xml.etree.ElementTree as ET
from datetime import datetime
import uuid
import json
from app.Methods.helpers import generate_sas_url

app = Blueprint("reqif", __name__)
EXPORT_DIR = './exports/'

if not os.path.exists(EXPORT_DIR):
    os.makedirs(EXPORT_DIR)

@app.route('/v1/exportCyberSecData', methods=['POST'])
def export_cyber_sec_data():
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form  # handles form-data as key-value pairs

        model_id = data.get("modelId")
        types = data.get("types", [])

        if not model_id:
            return jsonify({"error": "modelId is required"}), 400
        if not types or not isinstance(types, list):
            return jsonify({"error": "A list of types is required"}), 400

        # Start building ReqIF structure
        reqif = ET.Element("REQ-IF", xmlns="http://www.omg.org/spec/ReqIF/20110401/reqif.xsd")
        core_content = ET.SubElement(reqif, "CORE-CONTENT")
        spec_objects = ET.SubElement(core_content, "SPEC-OBJECTS")

        # Collect and add all scenes for all types
        for export_type in types:
            data_entries = list(db.Cybersecurity.find({"model_id": model_id, "type": export_type}))

            for entry in data_entries:
                scenes = entry.get("scenes", [])
                for scene in scenes:
                    spec_object = ET.SubElement(spec_objects, "SPEC-OBJECT")
                    ET.SubElement(spec_object, "DESC").text = f"Cybersecurity {export_type.capitalize()}"
                    values = ET.SubElement(spec_object, "VALUES")

                    for key, value in scene.items():
                        if value is None:
                            value = "null"
                        elif isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        else:
                            value = str(value)

                        ET.SubElement(values, "ATTRIBUTE-VALUE").text = f"{key}: {value}"

        # Save to single file
        file_name = f"Cybersecurity_Export_{uuid.uuid4().hex}.reqif"
        file_path = os.path.join(EXPORT_DIR, file_name)
        tree = ET.ElementTree(reqif)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)

        # Upload to Azure
        blob_service_client = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(container=Config.AZURE_CONTAINER_NAME, blob=file_name)

        with open(file_path, "rb") as data_file:
            blob_client.upload_blob(
                data_file,
                overwrite=True,
                content_settings=ContentSettings(
                    content_type='application/xml',
                    content_disposition=f'attachment; filename="{file_name}"'
                )
            )

        sas_url = generate_sas_url(blob_service_client, file_name)

        result = {
            "fileName": file_name,
            "url": sas_url
        }

        return jsonify({"message": "Export completed successfully", "export": result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
