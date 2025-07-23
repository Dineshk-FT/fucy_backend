from flask import Blueprint, request, jsonify
import google.generativeai as genai
from config import Config
import ast
import json
import re

modelprompt = Blueprint("modelprompt", __name__)

genai.configure(api_key=Config.GOOGLE_API_KEY)

@modelprompt.route('/v1/create-model', methods=['POST'])
def generate_reactflow_template():
    try:
        system_name = request.form.get('systemName', 'Test System')

        model = genai.GenerativeModel('gemini-2.5-flash')

        prompt = f"""
Return only valid JSON for a React Flow diagram for: {system_name}.

Include:
    - Realistic nodes for main components.
    - Group nodes with parent-child if needed.
    - Each node must have: unique id, position, label, style, width, height, properties list.
    - Add edges with source/target, handles, labels, marker arrows, example properties.
    Return only valid JSON. Do not include explanation text.
    
Example format:
{{
  "templates": {{
    "nodes": [
      {{
        "id": "1",
        "type": "default",
        "position": {{"x": 100, "y": 100}},
        "data": {{"label": "Node 1"}}
      }},
      {{
        "id": "2",
        "type": "group",
        "position": {{"x": 200, "y": 200}},
        "data": {{"label": "Group Node"}}
      }}
    ],
    "edges": [
      {{
        "id": "e1-2",
        "source": "1",
        "target": "2",
        "type": "step"
      }}
    ]
  }}
}}

Return only valid JSON. No explanations.
"""
        response = model.generate_content(prompt)
        output = response.text.strip()

        # print("=== RAW GEMINI OUTPUT ===")
        # print(output)

        # Remove code fences if they appear anyway
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")

        # Try JSON first
        try:
            data = json.loads(cleaned)
            # print("✅ Parsed with JSON")
        except json.JSONDecodeError as je:
            print(f"❌ JSON failed: {je}")
            # Try ast fallback
            try:
                data = ast.literal_eval(cleaned)
                # print("✅ Parsed with ast.literal_eval")
            except Exception as ae:
                print(f"❌ ast.literal_eval failed: {ae}")
                raise ValueError("Both JSON and ast failed.")

        return jsonify(data), 200

    except Exception as e:
        print(f"!! Final exception: {e}")
        return jsonify({"error": str(e)}), 500
