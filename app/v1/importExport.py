from flask import Flask, request, jsonify
import json
import os
from bson.json_util import dumps, loads
from flask import Blueprint, request, jsonify, json
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


# ===========================Export (BSON + JSON)==================================
@app.route('/v1/export', methods=['POST'])
def export_data():
    try:
        collections = [
            "Models", "Assets", "Attacks", "Cybersecurity",
            "Damage_scenarios", "Risk_treatment", "Threat_scenarios"
        ]

        model_id = request.form.get('modelId')
        export_format = request.form.get('format', 'bson').lower()  # 'bson' or 'json'

        if export_format not in ('bson', 'json'):
            return jsonify({'error': 'Invalid format. Must be "bson" or "json"'}), 400

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

        # ── Write file ──────────────────────────────────────────────────────────
        if export_format == 'bson':
            export_filename = f'export_{model_id}.bson'
            export_file_path = os.path.join(EXPORT_DIR, export_filename)
            with open(export_file_path, 'wb') as export_file:
                export_file.write(bson.BSON.encode(all_data))
            content_type = 'application/bson'
        else:
            export_filename = f'export_{model_id}.json'
            export_file_path = os.path.join(EXPORT_DIR, export_filename)
            # bson.json_util.dumps handles ObjectId / datetime serialisation
            with open(export_file_path, 'w') as export_file:
                export_file.write(dumps(all_data, indent=2))
            content_type = 'application/json'

        # ── Upload to Azure Blob Storage ────────────────────────────────────────
        blob_service_client = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(
            container=Config.AZURE_CONTAINER_NAME,
            blob=export_filename
        )

        with open(export_file_path, 'rb') as data:
            blob_client.upload_blob(
                data,
                overwrite=True,
                content_settings=ContentSettings(
                    content_type=content_type,
                    content_disposition=f'attachment; filename={export_filename}'
                )
            )

        file_url = generate_sas_url(blob_service_client, export_filename)
        os.remove(export_file_path)

        return jsonify({
            'message': 'Data exported and uploaded to Azure successfully.',
            'format': export_format,
            'download_url': file_url
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================Import (BSON + JSON)==================================
@app.route('/v1/import', methods=['POST'])
def import_data():
    try:
        user_id = request.form.get('userId')
        file = request.files.get('file')

        if not user_id or not file:
            return jsonify({'error': 'User ID and file are required'}), 400

        filename = file.filename or ''
        file_content = file.read()

        # ── Detect format from file extension ──────────────────────────────────
        if filename.endswith('.json'):
            try:
                # loads() from bson.json_util correctly restores ObjectId / datetime
                all_data = loads(file_content.decode('utf-8'))
            except (ValueError, UnicodeDecodeError) as e:
                return jsonify({'error': f'Invalid JSON file: {str(e)}'}), 400
        elif filename.endswith('.bson'):
            try:
                all_data = bson.BSON.decode(file_content)
            except Exception as e:
                return jsonify({'error': f'Invalid BSON file: {str(e)}'}), 400
        else:
            return jsonify({'error': 'Unsupported file type. Upload a .json or .bson file'}), 400

        # ── Insert documents ────────────────────────────────────────────────────
        new_model_id = str(ObjectId())
        model_name = None

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


# ===========================Clone Model or Library================================
@app.route('/v1/cloneModelOrLibrary', methods=['POST'])
def clone_model_or_library():
    try:
        key_id = request.form.get('keyId')
        source = request.form.get('source')
        user_id = request.form.get('userId')
        category = request.form.get('category', '')

        if not key_id or not source:
            return jsonify({'error': 'keyId and source are required'}), 400

        source = source.lower()
        if source not in ['model', 'library']:
            return jsonify({'error': 'Invalid source value: must be "model" or "library"'}), 400

        if source == 'library' and not user_id:
            return jsonify({'error': 'userId is required when copying from library to model'}), 400

        source_collection = 'Models' if source == 'model' else 'Libraries'
        target_collection = 'Libraries' if source == 'model' else 'Models'

        related_collections = [
            'Assets', 'Attacks', 'Cybersecurity',
            'Damage_scenarios', 'Risk_treatment', 'Threat_scenarios'
        ]

        model_id_object = ObjectId(key_id)
        new_root_id = str(ObjectId())

        root_doc = db[source_collection].find_one({'_id': model_id_object})
        if not root_doc:
            return jsonify({'error': f'No document found in {source_collection} with given ID'}), 404

        root_doc.pop('_id', None)
        root_doc['_id'] = ObjectId(new_root_id)
        if target_collection == 'Models':
            root_doc['user_id'] = user_id
            root_doc['category'] = category if category else root_doc.get('category', '')
        elif target_collection == 'Libraries':
            root_doc['category'] = category if category else root_doc.get('category', '')

        model_name = root_doc.get('name')
        db[target_collection].insert_one(root_doc)

        for collection_name in related_collections:
            related_docs = db[collection_name].find({'model_id': key_id})
            for doc in related_docs:
                doc.pop('_id', None)
                doc['model_id'] = new_root_id
                if target_collection == 'Models':
                    doc['user_id'] = user_id
                db[collection_name].insert_one(doc)

        return jsonify({
            'message': f'Successfully copied from {source_collection} to {target_collection}',
            'new_id': new_root_id,
            'name': model_name,
            'target': target_collection
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================List Libraries========================================
@app.route('/v1/listLibraries', methods=['GET'])
def list_libraries():
    try:
        libraries = list(db['Libraries'].find({}, {'_id': 1, 'name': 1, 'category': 1}))
        for lib in libraries:
            lib['_id'] = str(lib['_id'])
        return jsonify(libraries), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ===========================Clone Model Data to Existing Model====================
@app.route('/v1/cloneModelDataToExistingModel', methods=['POST'])
def clone_model_data_to_existing_model():
    try:
        source_model_id = request.form.get('sourceModelId')
        target_model_id = request.form.get('targetModelId')
        user_id = request.form.get('userId')

        if not source_model_id or not target_model_id or not user_id:
            return jsonify({'error': 'sourceModelId, targetModelId, and userId are required'}), 400

        related_collections = [
            'Assets', 'Attacks', 'Cybersecurity',
            'Damage_scenarios', 'Risk_treatment', 'Threat_scenarios'
        ]

        target_model_exists = db['Models'].find_one({
            '_id': ObjectId(target_model_id),
            'user_id': user_id
        })
        if not target_model_exists:
            return jsonify({'error': 'Target model does not exist or does not belong to provided userId'}), 404

        for collection_name in related_collections:
            db[collection_name].delete_many({'model_id': target_model_id})

            related_docs = db[collection_name].find({'model_id': source_model_id})
            for doc in related_docs:
                doc.pop('_id', None)
                doc['model_id'] = target_model_id
                db[collection_name].insert_one(doc)

        source_report = db['ReportsContent'].find_one(
            {'model_id': source_model_id},
            {'purpose': 1, 'intro': 1, 'scope': 1}
        )

        if source_report:
            new_report = {
                'model_id': target_model_id,
                'purpose': source_report.get('purpose'),
                'intro': source_report.get('intro'),
                'scope': source_report.get('scope')
            }
            db['ReportsContent'].insert_one(new_report)

        return jsonify({
            'message': 'Successfully cloned data from source model to target model (overwritten)',
            'source_model_id': source_model_id,
            'target_model_id': target_model_id
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500