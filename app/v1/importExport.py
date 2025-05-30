from flask import Flask, request, jsonify
import json
import os
from bson.json_util import dumps, loads
from flask import Blueprint, request, jsonify,json
from config import Config
import uuid
from db import db
from bson import ObjectId
from app.Methods.helpers import generate_sas_url
from azure.storage.blob import BlobServiceClient, ContentSettings
import bson

app = Blueprint("impexp", __name__)

EXPORT_DIR = './exports/'

if not os.path.exists(EXPORT_DIR):
    os.makedirs(EXPORT_DIR)
    
    
# ===========================With Url json==================================
# @app.route('/v1/export', methods=['POST'])
# def export_data():
#     try:
#         collections = [
#             "Models", "Assets", "Attacks", "Cybersecurity",
#             "Damage_scenarios", "Risk_treatment", "Threat_scenarios"
#         ]

#         model_id = "67d1aee47595acc7354a4d7c"
#         model_id_object = ObjectId(model_id)

#         all_data = {}

#         for collection_name in collections:
#             collection = db[collection_name]

#             if collection_name == "Models":
#                 data = collection.find({"_id": model_id_object})
#             else:
#                 data = collection.find({"model_id": model_id})

#             data_list = [doc for doc in data]

#             if data_list:
#                 all_data[collection_name] = data_list

#         if not all_data:
#             return jsonify({'message': 'No data found in the database'}), 404

#         # Save to JSON file locally
#         export_filename = f'export_{model_id}.json'
#         export_file_path = os.path.join(EXPORT_DIR, export_filename)

#         with open(export_file_path, 'w') as export_file:
#             json.dump(all_data, export_file, default=str)

#         # Upload to Azure Blob Storage
#         blob_service_client = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
#         blob_client = blob_service_client.get_blob_client(
#             container=Config.AZURE_CONTAINER_NAME,
#             blob=export_filename
#         )

#         with open(export_file_path, "rb") as data:
#             blob_client.upload_blob(
#                 data,
#                 overwrite=True,
#                 content_settings=ContentSettings(
#                     content_type="application/json",
#                     content_disposition=f'attachment; filename={export_filename}'
#                 )
#             )

#         file_url = generate_sas_url(blob_service_client, export_filename)

#         os.remove(export_file_path)

#         return jsonify({
#             'message': 'Data exported and uploaded to Azure successfully.',
#             'download_url': file_url
#         }), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
    
    
# @app.route('/v1/import', methods=['POST'])
# def import_data():
#     try:
#         # user_id = request.form.get('user_id')
#         # user_id='67ac89e45fe2e23463c9c328'
#         user_id='66cc2e509e49d50985d14a2a'
#         file = request.files.get('file')

#         if not user_id or not file:
#             return jsonify({'error': 'User ID and file are required'}), 400

#         file_content = file.read().decode('utf-8')
#         all_data = json.loads(file_content)
        
#         print(all_data)

#         new_model_id = str(ObjectId())

#         for collection_name, items in all_data.items():
#             collection = db[collection_name]

#             for item in items:
#                 item.pop('_id', None)

#                 item['user_id'] = user_id

#                 if collection_name == "Models":
#                     item['_id'] = ObjectId(new_model_id)
#                     model_name = item.get('name')
#                 else:
#                     item['model_id'] = new_model_id

#                 collection.insert_one(item)

#         return jsonify({
#                 'message': 'All data successfully imported to new user',
#                 'new_model_id': new_model_id,
#                 'model_name': model_name
#             }), 200

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
    
    
    
# ===========================Export With bson==========================================
@app.route('/v1/export', methods=['POST'])
def export_data():
    try:
        collections = [
            "Models", "Assets", "Attacks", "Cybersecurity",
            "Damage_scenarios", "Risk_treatment", "Threat_scenarios"
        ]

        model_id = request.form.get('modelId')
        # model_id = "67d1aee47595acc7354a4d7c"
        model_id_object = ObjectId(model_id)

        all_data = {}

        for collection_name in collections:
            collection = db[collection_name]

            if collection_name == "Models":
                data = collection.find({"_id": model_id_object})
            else:
                data = collection.find({"model_id": model_id})

            data_list = [doc for doc in data]

            if data_list:
                all_data[collection_name] = data_list

        if not all_data:
            return jsonify({'message': 'No data found in the database'}), 404

        export_filename = f'export_{model_id}.bson'
        export_file_path = os.path.join(EXPORT_DIR, export_filename)

        with open(export_file_path, 'wb') as export_file:
            export_file.write(bson.BSON.encode(all_data))  # Write BSON data

        # Upload to Azure Blob Storage
        blob_service_client = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(
            container=Config.AZURE_CONTAINER_NAME,
            blob=export_filename
        )

        with open(export_file_path, "rb") as data:
            blob_client.upload_blob(
                data,
                overwrite=True,
                content_settings=ContentSettings(
                    content_type="application/bson",  # Set content type for BSON
                    content_disposition=f'attachment; filename={export_filename}'
                )
            )

        file_url = generate_sas_url(blob_service_client, export_filename)

        os.remove(export_file_path)

        return jsonify({
            'message': 'Data exported and uploaded to Azure successfully.',
            'download_url': file_url
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/v1/import', methods=['POST'])
def import_data():
    try:
        user_id = request.form.get('userId')
        # user_id = '66cc2e509e49d50985d14a2a'
        file = request.files.get('file')

        if not user_id or not file:
            return jsonify({'error': 'User ID and file are required'}), 400

        file_content = file.read()  
        all_data = bson.BSON.decode(file_content)   # Decode BSON data into Python objects

        new_model_id = str(ObjectId())

        for collection_name, items in all_data.items():
            collection = db[collection_name]

            for item in items:
                item.pop('_id', None)

                item['user_id'] = user_id

                if collection_name == "Models":
                    item['_id'] = ObjectId(new_model_id)
                    model_name = item.get('name')
                else:
                    item['model_id'] = new_model_id

                collection.insert_one(item)

        return jsonify({
                'message': 'All data successfully imported to new user',
                'new_model_id': new_model_id,
                'model_name': model_name
            }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


