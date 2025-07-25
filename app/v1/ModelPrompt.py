from flask import Blueprint, request, jsonify
import google.generativeai as genai
from config import Config
import ast
import json
import re
from app.Methods.getDerivationsAndDetails import getDerivationsAndDetails
from app.Methods.helpers import build_full_edge, build_basic_node,calculate_node_positions

modelprompt = Blueprint("modelprompt", __name__)

genai.configure(api_key=Config.GOOGLE_API_KEY)

@modelprompt.route('/v1/create-model', methods=['POST'])

def generate_reactflow_template():
    try:
        # 🔹 1️⃣ Get inputs
        system_name = request.form.get('systemName', 'Test System')
        algorithms = request.form.get('algorithms', '["Algorithm 1", "Algorithm 2"]')
        communication_interfaces = request.form.get('communicationInterfaces', '["Interface 1", "Interface 2"]')
        cell_chemistry = request.form.get('cellChemistry', '["Chemistry 1", "Chemistry 2"]')

        # 🔹 2️⃣ Setup Gemini
        model = genai.GenerativeModel('gemini-2.5-flash')

        prompt = f"""
Return ONLY valid JSON for a React Flow diagram for the system below:

System Name: {system_name}
Algorithms: {algorithms}
Communication Interfaces: {communication_interfaces}
Cell Chemistry: {cell_chemistry}

Include:
  - Nodes must have: id, type ("default" or "group"), data.label, properties.
  - Edges must have: id, type ("step"), source, target, sourceHandle, targetHandle, data.label, properties.

Constraints:
  - If multiple related nodes exist, create at least one group node to contain them.
  - Do not include position information - positions will be calculated automatically.
  - Specify parent-child relationships using parentId where applicable.

Example:
{{
  "templates": {{
    "nodes": [
      {{
        "id": "1",
        "type": "default",
        "data": {{"label": "BMU"}},
        "properties": ["Confidentiality"]
      }},
      {{
        "id": "group-1",
        "type": "group",
        "data": {{"label": "Algorithms Group"}},
        "properties": []
      }},
      {{
        "id": "algo-1",
        "type": "default",
        "parentId": "group-1",
        "data": {{"label": "Algorithm 1"}},
        "properties": ["Integrity"]
      }}
    ],
    "edges": [
      {{
        "id": "e1-2",
        "type": "step",
        "source": "1",
        "target": "algo-1",
        "sourceHandle": "bottom",
        "targetHandle": "top",
        "data": {{"label": "CAN"}},
        "properties": ["Integrity"]
      }}
    ]
  }}
}}
"""

        # 🔹 3️⃣ Call Gemini
        response = model.generate_content(prompt)
        output = response.text.strip()
        cleaned = re.sub(r"```[a-z]*", "", output).strip().strip("`")

        # 🔹 4️⃣ Parse minimal JSON
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            data = ast.literal_eval(cleaned)

        minimal_nodes = data["templates"]["nodes"]
        minimal_edges = data["templates"]["edges"]

        # Build full nodes first without positions
        full_nodes = [build_basic_node(n) for n in minimal_nodes]
        
        # Then calculate all positions carefully
        positioned_nodes = calculate_node_positions(full_nodes)
        
        full_edges = [build_full_edge(e) for e in minimal_edges]

        final_result = {
            "templates": {
                "nodes": positioned_nodes,
                "edges": full_edges
            }
        }

        return jsonify(final_result), 200

    except Exception as e:
        print(f"!! Final exception: {e}")
        return jsonify({"error": str(e)}), 500