"""
PHASE 2: Attack Tree Enricher
==============================
Standalone script — completely independent of the LangGraph pipeline.

Usage:
    python add_attack_trees.py --query "Camera Sensor System"
    python add_attack_trees.py --query "ABS Braking System"

How it works:
    1. Reads the existing TARA JSON from outputs/Results/
    2. For each threat_scenario that has NO attack_tree yet → generates one (1 API call)
    3. Caches each tree individually → on next run, skips already-done trees
    4. Writes the enriched JSON back to the same file

This means you can run it in batches:
    - Run 1: Generates trees for TS001-TS005 (uses quota, stops)
    - Run 2: Skips TS001-TS005, generates TS006-TS010
    - Final: All trees complete!
"""

import os
import re
import json
import time
import uuid
import argparse
import hashlib

import google.generativeai as genai
from config import GEMINI_MODEL
from export_report import generate_pdf

# ── Config ──────────────────────────────────────────────────────────────────
RESULTS_DIR  = os.path.join("outputs", "Results")
TREE_CACHE_DIR = os.path.join("cache", "attack_trees")
WAIT_BETWEEN_CALLS = 65   # seconds — safe for Gemini free tier
MAX_TREES_PER_RUN  = 5    # Process this many trees per run (prevents quota drain)

# ── Setup ────────────────────────────────────────────────────────────────────
API_KEY = os.environ.get("GOOGLE_API_KEY")
if not API_KEY:
    raise SystemExit("[Error] GOOGLE_API_KEY not set. Run: $env:GOOGLE_API_KEY='your_key'")

genai.configure(api_key=API_KEY)
model = genai.GenerativeModel(GEMINI_MODEL)

os.makedirs(TREE_CACHE_DIR, exist_ok=True)

# ── Cache helpers ─────────────────────────────────────────────────────────────
def _tree_cache_path(ts_id: str, ts_name: str) -> str:
    """Unique cache file per threat scenario."""
    key = hashlib.md5(f"{ts_id}:{ts_name}".encode()).hexdigest()[:10]
    return os.path.join(TREE_CACHE_DIR, f"{key}.json")

def load_tree_cache(ts_id: str, ts_name: str):
    path = _tree_cache_path(ts_id, ts_name)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def save_tree_cache(ts_id: str, ts_name: str, tree: dict):
    path = _tree_cache_path(ts_id, ts_name)
    with open(path, "w") as f:
        json.dump(tree, f, indent=2)

def log_prompt(node_name: str, prompt: str, response: str):
    """Logs prompts for transparency in outputs/prompts/"""
    log_dir = os.path.join("outputs", "prompts")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = str(int(time.time()))
    filepath = os.path.join(log_dir, f"{timestamp}_{node_name}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== {node_name.upper()} LOG ===\n\n--- PROMPT ---\n{prompt}\n\n--- RESPONSE ---\n{response}\n")

# ── Attack Tree Generator ─────────────────────────────────────────────────────
def generate_tree(ts: dict, system_name: str, architecture: dict) -> dict:
    """
    Generates a 2-level attack tree using ONE API call.
    Uses the architecture context to produce system-specific vectors.
    """
    goal     = ts.get("name", "Unknown Threat")
    asset    = ts.get("asset", "System Component")
    category = ts.get("category", "Security Threat")

    # Build component list from architecture for context
    nodes = architecture.get("nodes", [])
    components = ", ".join([n.get("name", "") for n in nodes]) if nodes else system_name

    prompt = f"""
You are a Red-Team automotive cybersecurity expert performing a TARA analysis.

System: {system_name}
Key Components: {components}

Generate a 2-level Attack Tree for this THREAT SCENARIO:
Goal: "{goal}"
Category: {category}
Target Asset: {asset}

REQUIREMENTS:
- Use OR-Gate logic (any one path can achieve the goal)
- Level 1: 3 specific Attack Vectors targeting {system_name} components
- Level 2: 2-3 specific Technical Methods per vector
- Reference actual system components (from the list above) where possible
- Be technical and specific, not generic

Return ONLY valid JSON (no markdown, no commentary):
{{
  "goal": "{goal}",
  "gate": "OR",
  "type": "surface_goal",
  "asset": "{asset}",
  "children": [
    {{
      "goal": "Attack Vector description referencing {system_name}",
      "gate": "OR",
      "type": "attack_vector",
      "children": [
        {{"goal": "Specific technical method", "type": "method"}},
        {{"goal": "Another specific method", "type": "method"}}
      ]
    }}
  ]
}}
"""

    try:
        response = model.generate_content(prompt)
        raw = response.text.strip()
        
        # Log the activity
        log_prompt("attack_tree_generator", prompt, raw)
        
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        tree = json.loads(cleaned)

        # Stamp IDs and levels
        def stamp(node, level=0):
            node["id"] = str(uuid.uuid4())[:8]
            node["level"] = level
            for child in node.get("children", []):
                stamp(child, level + 1)

        stamp(tree)
        return tree

    except json.JSONDecodeError as e:
        print(f"    [Warning] JSON parse failed: {e}")
        return {"goal": goal, "gate": "OR", "type": "surface_goal", "children": [], "error": "parse_failed"}
    except Exception as e:
        print(f"    [Warning] API error: {e}")
        return None # Return None instead of error dict to avoid caching failures


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Phase 2: Add Attack Trees to TARA JSON")
    parser.add_argument("--query", required=True, help="ECU name (e.g. 'Camera Sensor System')")
    parser.add_argument("--max", type=int, default=MAX_TREES_PER_RUN, help="Max trees to generate per run")
    args = parser.parse_args()

    query = args.query
    max_trees = args.max

    # ── Find the TARA JSON file ──────────────────────────────────────────────
    filename = f"tara_output_{query.replace(' ', '_')}.json"
    filepath = os.path.join(RESULTS_DIR, filename)

    if not os.path.exists(filepath):
        raise SystemExit(f"[Error] TARA JSON not found: {filepath}\n   Run Phase 1 first: python main.py --query \"{query}\"")

    with open(filepath) as f:
        tara = json.load(f)

    # ── Find threat scenarios in the new nested structure ─────────────────────
    # ── Find threat scenarios in the new nested structure ─────────────────────
    assets_raw = tara.get("Assets", tara.get("item_definition", {}))
    # Handle Assets as a list or single object
    if isinstance(assets_raw, list):
        architecture = assets_raw[0] if assets_raw else {}
    else:
        architecture = assets_raw
    
    threat_scen_list  = tara.get("Threat_scenarios", [])
    
    # Flatten the nested threat scenarios for processing
    all_ts = []
    if threat_scen_list and isinstance(threat_scen_list, list):
        for entry in threat_scen_list:
            for ds_group in entry.get("Details", []):
                ds_id = ds_group.get("id", "")
                ds_row = ds_group.get("rowId", "")
                for ts in ds_group.get("Details", []):
                    # Carry parent identifiers onto each flattened entry
                    if ds_id and "id" not in ts:
                        ts["id"] = ds_id
                    if ds_row and "rowId" not in ts:
                        ts["rowId"] = ds_row
                    all_ts.append(ts)
    
    threat_scenarios = all_ts
    system_name      = architecture.get("system", architecture.get("template", {}).get("nodes", [{}])[0].get("data", {}).get("label", query))

    if not threat_scenarios:
        # Fallback for old flat format
        threat_scenarios = tara.get("threat_scenarios", [])
        if not threat_scenarios:
            raise SystemExit(f"[Error] No threat scenarios found in {filename}.\n   Run Phase 1 first to generate the base TARA report.")

    print("=" * 60)
    print(f"  PHASE 2: Attack Tree Enricher")
    print(f"  System  : {system_name}")
    print(f"  File    : {filename}")
    print(f"  Total TS: {len(threat_scenarios)}")
    print("=" * 60)

    # ── Process each threat scenario ─────────────────────────────────────────
    generated_count = 0
    skipped_count   = 0

    for ts in threat_scenarios:
        ts_id   = ts.get("id", "UNKNOWN")
        ts_name = ts.get("name", "Unknown")

        # Skip if already has a tree with children
        if ts.get("attack_tree", {}).get("children"):
            print(f"  [Skip] {ts_id}: Already has attack tree — skipping.")
            skipped_count += 1
            continue

        # Check per-tree cache
        cached = load_tree_cache(ts_id, ts_name)
        if cached:
            print(f"  [Cache] {ts_id}: Loaded from cache.")
            ts["attack_tree"] = cached
            skipped_count += 1
            continue

        # Stop if we've hit the per-run limit
        if generated_count >= max_trees:
            print(f"\n  ⏹️  Reached max trees per run ({max_trees}). Re-run to continue.")
            break

        # Generate the tree
        print(f"\n  🌳 [{generated_count+1}/{max_trees}] Generating tree for {ts_id}: {ts_name[:55]}...")
        tree = generate_tree(ts, system_name, architecture)
        
        if tree is None:
            print(f"     [Error] Generation failed — skipping cache.")
            continue
            
        ts["attack_tree"] = tree
        save_tree_cache(ts_id, ts_name, tree)
        generated_count += 1

        vectors = len(tree.get("children", []))
        print(f"     [Success] Done — {vectors} attack vectors generated.")

        # Wait between calls to respect free-tier limits
        if generated_count < max_trees:
            remaining_ts = [t for t in threat_scenarios if not t.get("attack_tree", {}).get("children") and t.get("id") != ts_id]
            if remaining_ts:
                print(f"     ⏳ Waiting {WAIT_BETWEEN_CALLS}s before next API call...")
                time.sleep(WAIT_BETWEEN_CALLS)

    # ── Populate Attacks key for bms_1.json ditto compatibility ────────────────
    def flatten_tree(tree, x=0, y=0, level_width=600):
        """Recursively flattens a tree into React Flow nodes and edges."""
        nodes = []
        edges = []
        
        node_id = tree.get("id", str(uuid.uuid4())[:8])
        gate = tree.get("gate", "OR")
        
        # Create standard node structure matching bms_1.json
        # Each node is 180px wide. With 600px level_width, we have plenty of room.
        current_node = {
            "id": node_id,
            "type": "default",
            "position": {"x": x, "y": y},
            "data": {
                "label": tree.get("goal", ""),
                "nodeId": node_id,
                "nodeType": tree.get("type", "derived"),
                "style": {
                    "backgroundColor": "transparent",
                    "borderColor": "black",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "color": "black",
                    "fontFamily": "Inter",
                    "fontSize": "14px",
                    "fontWeight": 500,
                    "height": 60,
                    "textAlign": "center",
                    "width": 180
                },
                "connections": []
            },
            "width": 180,
            "height": 60,
            "level": tree.get("level", 0)
        }
        
        nodes.append(current_node)
        
        children = tree.get("children", [])
        if children:
            child_y = y + 250 # Deep spacing for absolute clarity
            total_child_width = (len(children) - 1) * level_width
            start_x = x - (total_child_width / 2)
            
            for i, child in enumerate(children):
                child_x = start_x + (i * level_width)
                c_nodes, c_edges = flatten_tree(child, child_x, child_y, level_width / 1.5)
                
                nodes.extend(c_nodes)
                edges.extend(c_edges)
                
                # Add connection details to parent data object
                child_id = child.get("id")
                current_node["data"]["connections"].append({
                    "id": child_id,
                    "type": f"{child.get('gate', 'OR')} Gate"
                })

                # Create the professional React Flow edge
                edges.append({
                    "id": f"e-{node_id}-{child_id}",
                    "source": node_id,
                    "target": child_id,
                    "sourceHandle": "b",
                    "targetHandle": "t",
                    "type": "step",
                    "animated": True,
                    "markerEnd": {
                        "type": "arrowclosed",
                        "color": "#000000",
                        "width": 20,
                        "height": 20
                    },
                    "markerStart": {
                        "type": "arrowclosed",
                        "color": "#000000",
                        "width": 20,
                        "height": 20,
                        "orient": "auto-start-reverse"
                    },
                    "style": {
                        "strokeWidth": 2,
                        "stroke": "#000000",
                        "strokeDasharray": "0",
                        "start": True,
                        "end": True
                    }
                })
                
                # Update parent connections metadata
                current_node["data"]["connections"].append({
                    "id": child.get("id"),
                    "type": f"{gate} Gate"
                })
                
        return nodes, edges

    attacks_scenes = []
    for ts in threat_scenarios:
        tree = ts.get("attack_tree")
        if tree and tree.get("children"):
            rf_nodes, rf_edges = flatten_tree(tree)
            attacks_scenes.append({
                "ID": str(uuid.uuid4()),
                "Name": ts.get("name", "Attack Tree"),
                "threat_id": ts.get("id", ""),
                "templates": {
                    "nodes": rf_nodes,
                    "edges": rf_edges
                },
                "tree": tree # Keep nested tree for RAG/reference
            })
    
    if attacks_scenes:
        tara["Attacks"] = [{
            "type": "attack_trees",
            "_id": str(uuid.uuid4()),
            "model_id": architecture.get("model_id", ""),
            "scenes": attacks_scenes
        }]

    # ── Save enriched JSON back to file ──────────────────────────────────────
    # (No need to re-assign threat_scenarios as we modified the objects in place)
    # But just in case we are in old format:
    if "threat_scenarios" in tara:
        tara["threat_scenarios"] = threat_scenarios
        
    with open(filepath, "w") as f:
        json.dump(tara, f, indent=2)

    # ── Summary ──────────────────────────────────────────────────────────────
    total_with_trees = sum(1 for t in threat_scenarios if t.get("attack_tree", {}).get("children"))
    print(f"\n{'=' * 60}")
    print(f"  [Success] Enrichment complete!")
    print(f"  Generated this run : {generated_count} trees")
    print(f"  Skipped (cached)   : {skipped_count} trees")
    print(f"  Total with trees   : {total_with_trees}/{len(threat_scenarios)}")
    print(f"  Saved to           : {filepath}")
    
    # ── Regenerate PDF Report ──────────────────────────────────────────────
    print(f"\n[Export] Regenerating professional PDF report...")
    reports_dir = os.path.join("outputs", "Reports")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f"TARA_Report_{query.replace(' ', '_')}.pdf")
    try:
        if generate_pdf(tara, query, pdf_path):
            print(f"  [Success] Updated PDF Report -> {pdf_path}")
    except Exception as e:
        print(f"  [Error] PDF regeneration failed: {e}")

    if total_with_trees < len(threat_scenarios):
        remaining = len(threat_scenarios) - total_with_trees
        print(f"\n  ℹ️  {remaining} trees still pending. Re-run to continue:")
        print(f"     python add_attack_trees.py --query \"{query}\"")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
