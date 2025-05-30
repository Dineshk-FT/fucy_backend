from flask import Flask, jsonify, redirect, request
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from datetime import datetime, timedelta
import os
import config

app = Flask(__name__)
AZURE_CONNECTION_STRING = config.AZURE_CONNECTION_STRING
CONTAINER_NAME = "assets"
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)

@app.route('/v1/api/videos/all', methods=['GET'])
def get_all_video_urls():
    try:
        blob_list = blob_service_client.get_container_client(CONTAINER_NAME).list_blobs()
        video_urls = []
        print("blob_list",blob_list)
        for blob in blob_list:
            sas_token = generate_blob_sas(
                account_name=blob_service_client.account_name,
                container_name=CONTAINER_NAME,
                blob_name=blob.name,
                account_key=blob_service_client.credential.account_key,
                permission=BlobSasPermissions(read=True),
                expiry=datetime.utcnow() + timedelta(minutes=15)
            )
            url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{CONTAINER_NAME}/{blob.name}?{sas_token}"
            video_urls.append({"name": blob.name, "url": url})

        return jsonify(video_urls)
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to fetch videos"}), 500
