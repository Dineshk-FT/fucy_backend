from flask import Blueprint, request, jsonify, current_app
import json
import os
from db import db
from bson import ObjectId
from bson.json_util import dumps
from azure.storage.blob import BlobServiceClient, ContentSettings
from app.Methods.helpers import generate_sas_url
from app.v1.gemini.main import GeminiClient
from config import Config
from datetime import datetime
import re
import concurrent.futures

from app.v1.rag.components import resolve_ecu, build_enriched_query

from dotenv import load_dotenv

load_dotenv(override=True)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Blueprint("testcasegen", __name__)

gemini_client = GeminiClient(GOOGLE_API_KEY, os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))

EXPORT_DIR = './exports/'
if not os.path.exists(EXPORT_DIR):
    os.makedirs(EXPORT_DIR)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def _safe_json_parse(raw: str):
    """Strip markdown fences and parse JSON; return None on failure."""
    cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()
  # Extract first JSON array or object
    match = re.search(r"(\[.*\]|\{.*\})", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(1)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _build_test_case_prompt(asset: str, interface: str, threat: str,
                             attack_path: str, risk: str,
                             user_prompt: str | None,
                             rag_context: str | None = None) -> str:
    """
    Build the Gemini prompt for security test case generation.
    Always returns a JSON array so _safe_json_parse can handle it.
    """
    
    # Inject the Caring Caribou persona directly into the base context
    base_context = f"""
You are an automotive cybersecurity engineer following ISO/SAE 21434 and UNECE WP.29 standards.
You specialize in using the 'caringcaribou' (cc.py) tool for CAN bus fuzzing, diagnostic (UDS) exploitation, and network mapping.

Given the following TARA input:
  Asset        : {asset}
  Interface    : {interface}
  Threat       : {threat}
  Attack Path  : {attack_path}
  Risk Level   : {risk}
"""

    rag_section = ""
    if rag_context:
        rag_section = f"""
System Reference Data (RAG Context):
Use the following documentation to find exact ECU IDs, original CAN IDs, and hex codes.
{rag_context}
"""

    custom_section = f"\nAdditional instructions from user:\n{user_prompt}\n" if user_prompt else ""

    # Explicitly instruct the AI to use Caring Caribou syntax in the schema
    schema = """
Generate a JSON array of security test specifications. Each object MUST include:
  - "threat"          : (string) the threat name
  - "test_objective"  : (string) what the test aims to verify
  - "protocol"        : (string) communication protocol under test (e.g. UDS, CAN, Ethernet)
  - "service"         : (string) protocol service identifier (e.g. 0x27, 0x2E, N/A)
  - "technique"       : (string) test technique name (e.g. Diagnostic Fuzzing, Bruteforce Security Access)
  - "preconditions"   : (array of strings) setup steps required before the test (e.g., 'Ensure CAN interface is up', 'Identify target ECU RX/TX IDs')
  - "steps"           : (array of strings) ordered test execution steps. CRITICAL: For CAN or UDS testing, you MUST output exact command-line executions using 'caringcaribou' syntax (e.g., `cc.py uds ...`, `cc.py fuzzer ...`, `cc.py dcm ...`). You MUST incorporate exact CAN IDs / hex codes extracted from the System Reference Data as arguments in these commands.
  - "expected_result" : (string) what a PASS looks like (e.g., 'The fuzzer causes no unexpected ECU resets' or 'Security access is denied')
  - "severity"        : (string) one of Critical / High / Medium / Low

Output ONLY valid JSON array — no markdown fences, no explanation, no extra text.
"""

    return base_context + rag_section + custom_section + schema

# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/testcases/generate
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/v1/testcases/generate", methods=["POST"])
def generate_test_cases():
    """
    Generate AI-powered security test cases by fetching model threats directly.
    Uses multithreading to avoid HTTP timeouts when generating multiple scenarios.
    """
    try:
        # ── 1. Parse Request ──────────────────────────────────────────────────
        if request.is_json:
            model_id = request.json.get("modelId")
            user_prompt = request.json.get("userPrompt") # Optional
        else:
            model_id = request.form.get("modelId")
            user_prompt = request.form.get("userPrompt") # Optional

        if not model_id:
            return jsonify({"error": "Missing required field: modelId"}), 400

        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        # ── 2. Verify model exists ────────────────────────────────────────────
        model_doc = db["Models"].find_one({"_id": ObjectId(model_id)})
        if not model_doc:
            return jsonify({"error": f"No model found with id {model_id}"}), 404

        # ── 3. Extract Threat Scenarios ───────────────────────────────────────
        # Fetch all threat scenario documents for this model
        threat_cursor = db.Threat_scenarios.find({"model_id": str(model_id)})
        
        threat_details = []
        for doc in threat_cursor:
            # Extract the Details array from each document and add it to our master list
            details = doc.get("Details", [])
            threat_details.extend(details)

        if not threat_details:
            return jsonify({"error": "No threat scenarios found in the specified model."}), 400

        # ── 4. RAG Context Retrieval ──────────────────────────────────────────
        rag_context = ""
        system_name = model_doc.get("name", "System")
        try:
            ecu_entry = resolve_ecu(system_name)
            if ecu_entry:
                rag_context = build_enriched_query(system_name, ecu_entry)
        except Exception as e:
            print(f"Warning: RAG context retrieval failed for {system_name}: {e}")

        # ── 5. Worker Function for Multithreading ─────────────────────────────
        def process_scenario(scenario):
            # Map the properties from the Threat scenario details
            asset       = model_doc.get("name", "System Asset")
            interface   = "CAN/UDS" # Defaulting, or extract if defined in scenario
            threat      = scenario.get("Name", "Unknown Threat")
            attack_path = "External -> Network -> ECU" # Defaulting
            risk        = scenario.get("overall_rating", "High")
            
            prompt = _build_test_case_prompt(
                asset, interface, threat, attack_path, risk, user_prompt, rag_context
            )
            
            try:
                # Call Gemini API
                response = gemini_client.generate_content(prompt)
                raw_text = gemini_client.get_text(response).strip()

                test_cases = _safe_json_parse(raw_text)
                if not test_cases:
                    return []

                # Ensure it's a list
                if isinstance(test_cases, dict):
                    test_cases = [test_cases]

                enriched = []
                for tc in test_cases:
                    tc.update({
                        "model_id"   : str(model_id),
                        "asset"      : asset,
                        "interface"  : interface,
                        "attack_path": attack_path,
                        "risk"       : risk,
                        "created_at" : datetime.utcnow().isoformat(),
                    })
                    enriched.append(tc)
                return enriched
            except Exception as e:
                print(f"Error processing {threat}: {e}")
                return []

        # ── 6. Process All Threats in Parallel ────────────────────────────────
        all_enriched_test_cases = []
        
        # Using ThreadPoolExecutor to run API calls concurrently
        # max_workers=5 keeps it fast but prevents 429 Too Many Requests errors from Google
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Map the scenarios to the worker function
            results = list(executor.map(process_scenario, threat_details))
            
        # Flatten the nested lists returned by the threads
        for result_list in results:
            if result_list:
                all_enriched_test_cases.extend(result_list)

        if not all_enriched_test_cases:
            return jsonify({"error": "Failed to parse valid test cases from AI response."}), 500

        # ── 7. Persist to MongoDB (Bulk Insert) ───────────────────────────────
        result     = db["TestCases"].insert_many(all_enriched_test_cases)
        inserted   = [str(oid) for oid in result.inserted_ids]

        # Attach the string _id back so the frontend can read it
        for tc, oid in zip(all_enriched_test_cases, inserted):
            tc["_id"] = oid

        return jsonify({
            "message"       : f"Generated and saved {len(inserted)} test cases.",
            "model_id"      : str(model_id),
            "test_cases"    : all_enriched_test_cases,
            "inserted_count": len(inserted),
        }), 201

    except Exception as e:
        print(f"Internal Error in generate_test_cases: {e}")
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────────────────────
# GET /v1/testcases/<model_id>
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/v1/testcases/<model_id>", methods=["GET"])
def get_test_cases(model_id: str):
    """
    Retrieve all test cases for a given modelId.

    Query params (all optional):
      threat    – filter by threat name
      risk      – filter by risk level
      interface – filter by interface
    """
    try:
        query: dict = {"model_id": model_id}

        for field in ("threat", "risk", "interface"):
            val = request.args.get(field)
            if val:
                query[field] = val

        docs = list(db["TestCases"].find(query))
        for doc in docs:
            doc["_id"] = str(doc["_id"])

        return jsonify({
            "model_id"  : model_id,
            "count"     : len(docs),
            "test_cases": docs,
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# POST /v1/testcases/export
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/v1/testcases/export", methods=["POST"])
def export_test_cases():
    """
    Export test cases for a model to JSON (mirrors importExport.py pattern)
    and upload to Azure Blob Storage.

    Form fields:
      modelId – required
      format  – 'json' (default) or 'bson'  [bson not supported for test cases]
    """
    try:
        model_id      = request.form.get("modelId")
        export_format = request.form.get("format", "json").lower()

        if not model_id:
            return jsonify({"error": "modelId is required"}), 400

        if export_format != "json":
            return jsonify({"error": "Only 'json' format is supported for test-case export"}), 400

        # ── Fetch test cases ──────────────────────────────────────────────────
        docs = list(db["TestCases"].find({"model_id": model_id}))
        if not docs:
            return jsonify({"message": "No test cases found for this model"}), 404

        for doc in docs:
            doc["_id"] = str(doc["_id"])

        payload = {
            "model_id"   : model_id,
            "exported_at": datetime.utcnow().isoformat(),
            "count"      : len(docs),
            "test_cases" : docs,
        }

        # ── Write local file ──────────────────────────────────────────────────
        export_filename  = f"testcases_{model_id}.json"
        export_file_path = os.path.join(EXPORT_DIR, export_filename)

        with open(export_file_path, "w") as f:
            json.dump(payload, f, indent=2, cls=JSONEncoder)

        # ── Upload to Azure Blob Storage ──────────────────────────────────────
        blob_service_client = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
        blob_client = blob_service_client.get_blob_client(
            container=Config.AZURE_CONTAINER_NAME,
            blob=export_filename,
        )

        with open(export_file_path, "rb") as f:
            blob_client.upload_blob(
                f,
                overwrite=True,
                content_settings=ContentSettings(
                    content_type="application/json",
                    content_disposition=f"attachment; filename={export_filename}",
                ),
            )

        file_url = generate_sas_url(blob_service_client, export_filename)
        os.remove(export_file_path)

        return jsonify({
            "message"     : "Test cases exported and uploaded successfully",
            "model_id"    : model_id,
            "count"       : len(docs),
            "download_url": file_url,
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /v1/testcases/<model_id>
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/v1/testcases/<model_id>", methods=["DELETE"])
def delete_test_cases(model_id: str):
    """Delete all test cases for a model (useful before re-generation)."""
    try:
        result = db["TestCases"].delete_many({"model_id": model_id})
        return jsonify({
            "message"      : "Test cases deleted",
            "model_id"     : model_id,
            "deleted_count": result.deleted_count,
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500