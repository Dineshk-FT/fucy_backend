from flask import Blueprint, jsonify
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta
from config import Config
import re
import json
from db import db
from app.auth import require_auth  # <--- IMPORT THE DECORATOR HERE

guides = Blueprint("guides", __name__)
AZURE_CONNECTION_STRING = Config.AZURE_CONNECTION_STRING
CONTAINER_NAME = "assets"
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)

RAG_CONTAINER_NAME = "rag"
FILE_NAME = "dataecu.json"

@guides.route('/v1/guides/videos', methods=['GET'])
@require_auth  # <--- ADD THIS LINE
def get_all_video_urls():
    try:
        account_key_match = re.search(r"AccountKey=([^;]+)", AZURE_CONNECTION_STRING)
        account_key = account_key_match.group(1) if account_key_match else None
        if not account_key:
            raise ValueError("AccountKey not found in AZURE_CONNECTION_STRING")

        blob_list = blob_service_client.get_container_client(CONTAINER_NAME).list_blobs()
        video_urls = []
        for blob in blob_list:
            sas_token = generate_blob_sas(
                account_name=blob_service_client.account_name,
                container_name=CONTAINER_NAME,
                blob_name=blob.name,
                account_key=account_key,
                permission=BlobSasPermissions(read=True),
                expiry=datetime.utcnow() + timedelta(hours=12)
            )
            url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{CONTAINER_NAME}/{blob.name}?{sas_token}"
            video_urls.append({"name": blob.name, "url": url})

        return jsonify(video_urls)
    except Exception as e:
        return jsonify({"error": f"Failed to fetch videos: {str(e)}"}), 500


@guides.route('/v1/guides/rag', methods=['GET'])
@require_auth  # <--- ADD THIS LINE
def get_rag_data():
    try:
        blob_client = blob_service_client.get_blob_client(
            container=RAG_CONTAINER_NAME, 
            blob=FILE_NAME
        )
        download_stream = blob_client.download_blob()
        file_content = download_stream.readall()
        data = json.loads(file_content)
        ecus_array = data.get("ecus", [])
        return jsonify({"ecus": ecus_array})
    except Exception as e:
        return jsonify({"error": f"Failed to fetch ECU data: {str(e)}"}), 500


@guides.route('/v1/sharing_ecu', methods=['GET'])
@require_auth  # <--- ADD THIS LINE
def sharing_ecu():
    try:
        cursor = db.sharing_ecu.find()
        res = []
        for doc in cursor:
            doc['_id'] = str(doc['_id'])
            res.append(doc)
        return jsonify(res), 200    
    except Exception as e:    
        return jsonify({"error": str(e)}), 500