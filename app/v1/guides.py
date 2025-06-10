from flask import Flask,Blueprint, jsonify, redirect, request
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta
import os
from config import Config
import re

guides = Blueprint("guides", __name__)
AZURE_CONNECTION_STRING = Config.AZURE_CONNECTION_STRING
CONTAINER_NAME = "assets"
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)

@guides.route('/v1/guides/videos', methods=['GET'])
def get_all_video_urls():
    try:
        # Extract account key from connection string
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
                expiry=datetime.utcnow() + timedelta(minutes=15)
            )
            url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{CONTAINER_NAME}/{blob.name}?{sas_token}"
            video_urls.append({"name": blob.name, "url": url})

        return jsonify(video_urls)
    except Exception as e:
        # print(f"Error: {e}")
        return jsonify({"error": f"Failed to fetch videos: {str(e)}"}), 500
