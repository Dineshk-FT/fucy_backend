from flask import Blueprint, request, jsonify, current_app
import os
from .rag.pipeline import setup_pipeline, get_pipeline, get_document_store
from .rag.data_ingestion import load_json_to_store
from .rag.query_handler import process_query
from .rag.utils import save_result_to_file

rag_bp = Blueprint('rag', __name__, url_prefix='/api/v1/rag')

# Store history in memory (use database in production)
query_history = []
last_result = None

@rag_bp.route('/init', methods=['POST'])
def init_rag():
    """Initialize RAG pipeline"""
    try:
        api_key = os.getenv('GOOGLE_API_KEY')
        if not api_key:
            return jsonify({"error": "GOOGLE_API_KEY not found in environment"}), 500
        
        pipeline, store = setup_pipeline(api_key)
        return jsonify({"message": "RAG pipeline initialized successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@rag_bp.route('/load-data', methods=['POST'])
def load_data():
    """Load JSON data into document store"""
    data = request.get_json()
    file_path = data.get('file_path')
    
    if not file_path:
        return jsonify({"error": "file_path required"}), 400
    
    try:
        count = load_json_to_store(file_path)
        return jsonify({"message": f"Loaded {count} documents"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@rag_bp.route('/query', methods=['POST'])
def query():
    """Process a query"""
    global last_result
    
    data = request.get_json()
    query_text = data.get('query')
    
    if not query_text:
        return jsonify({"error": "query required"}), 400
    
    try:
        result = process_query(query_text)
        
        # Store in history
        query_history.append({
            "query": query_text,
            "result": result
        })
        last_result = result
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@rag_bp.route('/history', methods=['GET'])
def get_history():
    """Get query history"""
    return jsonify({
        "history": [
            {"query": h["query"]} for h in query_history
        ]
    }), 200

@rag_bp.route('/history/<int:index>', methods=['GET'])
def get_history_item(index):
    """Get specific history item"""
    if index < 1 or index > len(query_history):
        return jsonify({"error": "Invalid index"}), 404
    
    return jsonify(query_history[index-1]), 200

@rag_bp.route('/download/last', methods=['GET'])
def download_last():
    """Download last result"""
    global last_result
    
    if not last_result:
        return jsonify({"error": "No result available"}), 404
    
    filename = save_result_to_file(last_result, f"uploaded_results/last_result.json")
    return jsonify({"filename": filename}), 200

@rag_bp.route('/download/<int:index>', methods=['GET'])
def download_history(index):
    """Download specific history result"""
    if index < 1 or index > len(query_history):
        return jsonify({"error": "Invalid index"}), 404
    
    filename = save_result_to_file(
        query_history[index-1]["result"],
        f"uploaded_results/result_{index}.json"
    )
    return jsonify({"filename": filename}), 200

@rag_bp.route('/status', methods=['GET'])
def get_status():
    """Get RAG pipeline status"""
    try:
        store = get_document_store()
        doc_count = len(store.filter_documents())
        return jsonify({
            "initialized": True,
            "document_count": doc_count,
            "history_count": len(query_history)
        }), 200
    except:
        return jsonify({
            "initialized": False,
            "document_count": 0,
            "history_count": len(query_history)
        }), 200