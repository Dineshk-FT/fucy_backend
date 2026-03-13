from flask import current_app as app
from flask import request, jsonify, json
from bson import ObjectId
from db import db
import os
from datetime import datetime
from dotenv import load_dotenv

# import jwt,secrets
# app.config['SECRET_KEY'] = secrets.token_hex(16)
from flask import Blueprint


app = Blueprint("routes", __name__)

load_dotenv()


# For Fetching--------------------------------------------------------------------------------------------
@app.route("/get_details/sidebarNode", methods=["POST"])
def sideBarNode():
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        projection = {"name": 1, "nodes": 1, "scenarios": 1}
        data = list(db.side_bar_nodes.find({"user_id": user_id}, projection))
        for item in data:
            item["_id"] = str(item["_id"])

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_details/templates", methods=["POST"])
def templates():
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        data = list(db.templates.find({"user_id": user_id}))

        for item in data:
            item["_id"] = str(item["_id"])
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_details/models", methods=["POST"])
def models():
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        data = list(db.models.find({"user_id": user_id}))

        for item in data:
            item["_id"] = str(item["_id"])

        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_details/models/<model_id>", methods=["POST"])
def get_model_by_id(model_id):
    try:
        model_id = ObjectId(model_id)
    except Exception as e:
        return jsonify({"error": "Invalid ID format"}), 400

    data = db.models.find_one({"_id": model_id})
    if data:
        data["_id"] = str(data["_id"])
        return jsonify(data)
    else:
        return jsonify({"error": "Model not found"}), 404


@app.route("/get_details/templates/<template_id>", methods=["GET"])
def get_template_by_id(template_id):
    try:
        template_id = ObjectId(template_id)
    except Exception as e:
        return jsonify({"error": "Invalid ID format"}), 400

    data = db.templates.find_one({"_id": template_id})
    if data:
        # Convert ObjectId to string
        data["_id"] = str(data["_id"])
        return jsonify(data)
    else:
        return jsonify({"error": "Model not found"}), 404


# For Adding---------------------------------------------------------------------------------------------
@app.route("/add/sidebarNode", methods=["POST"])
def addSideBarNode():
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        name = request.form.get("name")
        if not name:
            return jsonify({"error": "name is required"}), 400
        data = [{"user_id": user_id, "name": name, "nodes": []}]
        db.side_bar_nodes.insert_many(data)
        return jsonify({"message": "Side Bar Node inserted successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/add/node", methods=["POST"])
def addNode():
    try:
        node_id = request.form.get("id")
        new_node = request.form.get("new_node")

        if not node_id:
            return jsonify({"error": "Id is required"}), 400

        if not new_node:
            return jsonify({"error": "New_node is required"}), 400

        try:
            new_node = json.loads(new_node)
        except ValueError:
            return jsonify({"error": "Invalid new_node format"}), 400

        object_id = ObjectId(node_id)
        data = db.side_bar_nodes.find_one({"_id": object_id})

        if data is None:
            return jsonify({"error": "Node not found"}), 404

        if "nodes" not in data or not isinstance(data["nodes"], list):
            data["nodes"] = []

        data["nodes"].append(new_node)
        db.side_bar_nodes.update_one(
            {"_id": object_id}, {"$set": {"nodes": data["nodes"]}}
        )

        return (
            jsonify({"message": "Node inserted successfully!", "new_node": new_node}),
            201,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/add/templates", methods=["POST"])
def addTemplets():
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        data = request.form.get("templates")

        templates = json.loads(data)
        for template in templates:
            template["user_d"] = user_id

        db.templates.insert_many(templates)
        return jsonify({"message": "Templates inserted successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/add/models", methods=["POST"])
def addModels():
    try:
        user_id = request.headers.get("user-id")

        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        scenarios = request.form.get("scenarios")

        if not scenarios:
            return jsonify({"error": "scenarios is required"}), 400

        name = request.form.get("name")
        if not name:
            return jsonify({"error": "Model name is required"}), 400

        data = {
            "user_id": user_id,
            "name": name,
            "scenarios": json.loads(scenarios),
            "templets": [],
        }
        result = db.models.insert_one(data)

        return (
            jsonify(
                {
                    "model_id": str(result.inserted_id),
                    "data": data["scenarios"],
                }
            ),
            201,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# For Updating----------------------------------------------------------------------------------------------------
@app.route("/update_model/<model_id>", methods=["PUT"])
def update_model(model_id):
    try:
        model_id = ObjectId(model_id)
    except Exception as e:
        return jsonify({"error": "Invalid ID format"}), 400

    updated_data = request.json

    if "_id" in updated_data:
        del updated_data["_id"]

    result = db.models.update_one({"_id": model_id}, {"$set": updated_data})

    if result.matched_count > 0:
        if result.modified_count > 0:
            return jsonify({"message": "Model updated successfully"})
        else:
            return jsonify({"message": "No changes made to the model"}), 304
    else:
        return jsonify({"error": "Model not found"}), 404


@app.route("/add/modeltemplate", methods=["POST"])
def addModelTemplate():
    try:
        model_id = request.form.get("id")
        if not model_id:
            return jsonify({"error": "Id is required"}), 400

        template_data = request.form.get("template")

        if not template_data:
            return jsonify({"error": "Template is required"}), 400
        object_id = ObjectId(model_id)

        model = db.models.find_one({"_id": object_id})
        if model is None:
            return jsonify({"error": "Model not found"}), 404

        template = json.loads(template_data)

        if "templets" not in model or not isinstance(model["templets"], list):
            model["templets"] = []

        db.models.update_one({"_id": object_id}, {"$set": {"templets": template}})

        updated_model = db.models.find_one({"_id": object_id})
        updated_model["_id"] = str(updated_model["_id"])

        return jsonify(updated_model), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# For Deleting----------------------------------------------------------------------------------------------------
@app.route("/delete/model", methods=["POST"])
def delete_model():
    try:
        model_ids = request.form.get("model_ids")

        if not model_ids:
            return jsonify({"error": "model_id is required"}), 400

        model_ids = model_ids.split(",")

        object_ids = [ObjectId(model_id.strip()) for model_id in model_ids]

        models = list(db.models.find({"_id": {"$in": object_ids}}))
        if len(models) != len(object_ids):
            return jsonify({"error": "One or more models not found"}), 404

        db.models.delete_many({"_id": {"$in": object_ids}})

        return (
            jsonify({"message": f"{len(object_ids)} models deleted successfully"}),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# NEW RAG ROUTES - Add these at the end of your routes.py file
# ============================================================================

# Global variables for RAG
rag_pipeline = None
document_store = None
doc_embedder = None
query_history = []
last_result = None

@app.route("/rag/init", methods=["POST"])
def rag_init():
    """Initialize RAG pipeline"""
    global rag_pipeline, document_store, doc_embedder
    
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        api_key = os.getenv('GOOGLE_API_KEY')
        if not api_key:
            return jsonify({"error": "GOOGLE_API_KEY not found in environment"}), 500
        
        # Fixed import - using full path from app
        from app.v1.rag.pipeline import setup_pipeline
        rag_pipeline, document_store, doc_embedder = setup_pipeline(api_key)
        
        return jsonify({
            "message": "RAG pipeline initialized successfully",
            "status": "ready"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/load-data", methods=["POST"])
def rag_load_data():
    """Load JSON data into document store"""
    global doc_embedder, document_store
    
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        if not document_store or not doc_embedder:
            return jsonify({"error": "RAG pipeline not initialized. Call /rag/init first"}), 400

        data = request.get_json()
        file_path = data.get('file_path') if data else None
        
        if not file_path:
            return jsonify({"error": "file_path is required"}), 400

        if not os.path.exists(file_path):
            return jsonify({"error": f"File not found: {file_path}"}), 404

        # Fixed import - using full path from app
        from app.v1.rag.data_ingestion import load_json_to_store
        count = load_json_to_store(file_path, doc_embedder, document_store)
        
        return jsonify({
            "message": f"Successfully loaded {count} documents",
            "document_count": count
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/query", methods=["POST"])
def rag_query():
    """Process a natural language query"""
    global rag_pipeline, query_history, last_result
    
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user = db.accounts.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "No such user found"}), 404

        if not rag_pipeline:
            return jsonify({"error": "RAG pipeline not initialized. Call /rag/init first"}), 400

        data = request.get_json()
        query_text = data.get('query') if data else None
        top_k = data.get('top_k', 75) if data else 75
        
        if not query_text:
            return jsonify({"error": "query is required"}), 400

        # Fixed import - using full path from app
        from app.v1.rag.query_handler import process_query as process
        result = process(query_text, rag_pipeline, top_k=top_k)
        
        history_entry = {
            "query": query_text,
            "result": result,
            "user_id": user_id,
            "timestamp": str(datetime.now())
        }
        query_history.append(history_entry)
        last_result = result
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/history", methods=["GET"])
def rag_history():
    """Get query history"""
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user_history = [
            {"query": h["query"], "timestamp": h.get("timestamp")} 
            for h in query_history 
            if h.get("user_id") == user_id
        ]
        
        return jsonify({
            "history": user_history,
            "count": len(user_history)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/history/<int:index>", methods=["GET"])
def rag_history_item(index):
    """Get specific history item"""
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user_history = [h for h in query_history if h.get("user_id") == user_id]
        
        if index < 1 or index > len(user_history):
            return jsonify({"error": "Invalid history index"}), 404
        
        return jsonify(user_history[index-1]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/download/last", methods=["GET"])
def rag_download_last():
    """Download last result as JSON file"""
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        global last_result
        
        if not last_result:
            return jsonify({"error": "No result available"}), 404
        
        filename = f"rag_result_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Fixed import - using full path from app
        from app.v1.rag.utils import save_result_to_file
        saved_path = save_result_to_file(last_result, filename)
        
        return jsonify({
            "message": "Result saved successfully",
            "filename": filename,
            "path": saved_path
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/download/<int:index>", methods=["GET"])
def rag_download_history(index):
    """Download specific history result as JSON file"""
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        user_history = [h for h in query_history if h.get("user_id") == user_id]
        
        if index < 1 or index > len(user_history):
            return jsonify({"error": "Invalid history index"}), 404
        
        filename = f"rag_result_{user_id}_{index}_{datetime.now().strftime('%Y%m%d')}.json"
        
        # Fixed import - using full path from app
        from app.v1.rag.utils import save_result_to_file
        saved_path = save_result_to_file(user_history[index-1]["result"], filename)
        
        return jsonify({
            "message": f"Result #{index} saved successfully",
            "filename": filename,
            "path": saved_path
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rag/status", methods=["GET"])
def rag_status():
    """Get RAG pipeline status"""
    try:
        user_id = request.headers.get("user-id")
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        doc_count = 0
        if document_store:
            try:
                doc_count = len(document_store.filter_documents())
            except:
                pass
        
        return jsonify({
            "initialized": rag_pipeline is not None,
            "document_count": doc_count,
            "history_count": len([h for h in query_history if h.get("user_id") == user_id])
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500