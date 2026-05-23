from langgraph.graph import StateGraph
from typing import TypedDict
from collections import Counter
import jinja2
import os
import time
import json
import re
import copy
import uuid
from google.api_core.exceptions import ResourceExhausted
from app.v1.rag.cache_manager import save_cache, load_cache

from app.v1.rag.components import build_store, build_retriever, build_generator
from app.v1.rag.config import RETRIEVER_TOP_K

# ── GLOBAL CONFIGURATION ─────────────────────────────────────────────────────
MAX_NODES       = 14   
MAX_EDGES       = 11   
MAX_GROUPS      = 4    
MAX_THREATS     = 5    
MAX_SCENARIOS   = 5    

MIN_QUALITY_NODES = 3  
MIN_QUALITY_TS    = 3  
# ─────────────────────────────────────────────────────────────────────────────

class RAGState(TypedDict):
    user_query: str
    enriched_query: str
    documents: list
    architecture: dict       
    threats: list            
    damage_details: list     
    threat_scenarios: list   
    attacks: list            
    answer: str              
    retry_count: int
    full_prompt: str
    eval_score: int
    eval_details: dict

def setup(all_docs):
    store, text_embedder = build_store(all_docs)
    retriever = build_retriever(store)
    generator = build_generator()
    return retriever, generator, text_embedder

def clean_json_response(raw_text: str) -> str:
    """Aggressively extract JSON object or array from LLM response to prevent parsing crashes."""
    if not raw_text:
        return "{}"
        
    text = raw_text.strip()
    
    # Strip markdown backticks
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```$", "", text.strip())
    
    # Extract JSON boundaries
    start_obj = text.find('{')
    start_arr = text.find('[')
    
    if start_obj == -1 and start_arr == -1:
        return "{}"
        
    start_idx = start_obj if start_obj != -1 and (start_arr == -1 or start_obj < start_arr) else start_arr
    end_char = '}' if start_idx == start_obj else ']'
    end_idx = text.rfind(end_char)
    
    if end_idx != -1:
        text = text[start_idx:end_idx+1]
        
    return text.strip()

def safe_generate(prompt: str, role_name: str = "Agent"):
    max_retries = 5  
    for attempt in range(max_retries):
        try:
            return generator.run(parts=[prompt])
        except ResourceExhausted as e:
            wait_time = 90 + (attempt * 60) 
            msg = str(e)
            if "retry in" in msg:
                try:
                    match = re.search(r"retry in ([\d.]+)", msg)
                    if match:
                        wait_time = int(float(match.group(1))) + 5
                except:
                    pass
            
            print(f"  ⚠️  {role_name} Quota hit. Sleeping {wait_time}s...")
            time.sleep(wait_time)
        except Exception as e:
            print(f"  ❌ {role_name} error: {e}")
            time.sleep(10)
    return {"replies": ["Failed due to repeated quota errors."]}

def log_prompt(node_name: str, context: list, prompt: str, response: str):
    log_dir = os.path.join("outputs", "prompts")
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = str(int(time.time()))
    filename = f"{timestamp}_{node_name}.txt"
    filepath = os.path.join(log_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== {node_name.upper()} LOG ===\n")
        f.write("RAG CONTEXT (First 3 docs):\n")
        for i, doc in enumerate(context[:3]):
            content = getattr(doc, 'content', str(doc))
            f.write(f"DOC {i}: {content[:300]}...\n")
        f.write("\n--- PROMPT ---\n")
        f.write(prompt)
        f.write("\n\n--- AI RESPONSE ---\n")
        f.write(response)
        f.write("\n" + "="*50 + "\n")

def retrieve(state: RAGState):
    query = state.get("enriched_query") or state.get("user_query")
    embedding = text_embedder.run(text=query)["embedding"]
    result = retriever.run(query_embedding=embedding)
    docs = result["documents"][:RETRIEVER_TOP_K]
    return {"documents": docs}

def architect_node(state: RAGState):
    query = state.get("user_query", "") or state.get("query", "")

    from app.v1.rag.prompt import ARCHITECT_PROMPT
    from app.v1.rag.components import resolve_ecu, resolve_reference_report, build_ref_context

    ecu_entry = resolve_ecu(query)
    reference_data = resolve_reference_report(ecu_entry, query)

    ref_context, ecu_hint_context = build_ref_context(reference_data, ecu_entry)

    # Build comprehensive reference map
    ref_node_map = {}
    ref_edge_map = {}
    if reference_data:
        ref_assets = reference_data.get("Assets", [])
        if ref_assets:
            ref_asset = ref_assets[0] if isinstance(ref_assets, list) else ref_assets
            ref_template = ref_asset.get("template", {})
            
            for rn in ref_template.get("nodes", []):
                lbl = rn.get("data", {}).get("label", "").lower().strip()
                if lbl:
                    ref_node_map[lbl] = rn
                ref_node_map[rn.get("id")] = rn
                
            for re in ref_template.get("edges", []):
                s_id = re.get("source")
                t_id = re.get("target")
                s_node = ref_node_map.get(s_id)
                t_node = ref_node_map.get(t_id)
                if s_node and t_node:
                    s_lbl = s_node.get("data", {}).get("label", "").lower().strip()
                    t_lbl = t_node.get("data", {}).get("label", "").lower().strip()
                    ref_edge_map[f"{s_lbl}->{t_lbl}"] = re

    tmpl = jinja2.Template(ARCHITECT_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"],
        documents=state["documents"],
        max_nodes=MAX_NODES,
        max_edges=MAX_EDGES,
        max_groups=MAX_GROUPS,
        ref_context=ref_context,
        ecu_hint_context=ecu_hint_context,
    )
    
    result = safe_generate(prompt, "Architect")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    log_prompt("architect_node", state["documents"], prompt, raw_json)
    
    time.sleep(10)
    try:
        cleaned = clean_json_response(raw_json)
        arch_data = json.loads(cleaned)
        
        if "template" in arch_data: assets = arch_data
        elif "Assets" in arch_data: assets = arch_data["Assets"][0] if isinstance(arch_data["Assets"], list) and arch_data["Assets"] else arch_data["Assets"]
        elif "assets" in arch_data: assets = arch_data["assets"][0] if isinstance(arch_data["assets"], list) and arch_data["assets"] else arch_data["assets"]
        else: assets = arch_data
        
        template = assets.get("template", {})
        nodes = template.get("nodes", assets.get("nodes", []))

        if not nodes:
            return {"architecture": {"template": {"nodes": [], "edges": []}, "Details": []}}
        
        gen_label_to_id = {n.get("data", {}).get("label", "").lower().strip(): n.get("id") for n in nodes if n.get("id")}
        
        # 1. Restore exact Node layouts from Reference
        for node in nodes:
            node_label = node.get("data", {}).get("label", "").lower().strip()
            orig = ref_node_map.get(node_label)
            
            if orig:
                if "position" in orig: node["position"] = orig["position"]
                if "positionAbsolute" in orig: node["positionAbsolute"] = orig["positionAbsolute"]
                if "width" in orig: node["width"] = orig["width"]
                if "height" in orig: node["height"] = orig["height"]
                if "extent" in orig: node["extent"] = orig["extent"]
                if "style" in orig.get("data", {}):
                    if "data" not in node: node["data"] = {}
                    node["data"]["style"] = orig["data"]["style"]
                
                # Link Parent-Child using newly generated UUIDs to preserve structure
                orig_pid = orig.get("parentId")
                if orig_pid:
                    orig_parent_node = next((n for n in ref_node_map.values() if n.get("id") == orig_pid), None)
                    if orig_parent_node:
                        p_lbl = orig_parent_node.get("data", {}).get("label", "").lower().strip()
                        if p_lbl in gen_label_to_id:
                            node["parentId"] = gen_label_to_id[p_lbl]

                # Map security properties
                props = orig.get("properties", None)
                if props is not None:
                    node["properties"] = props
            
            elif "properties" not in node or node["properties"] is None:
                node["properties"] = ["Integrity", "Confidentiality", "Authenticity", "Authorization", "Availability", "Non-repudiation"]
        
        edges = template.get("edges", [])
        
        # 2. Restore exact Edge routing from Reference
        for edge in edges:
            s_node = next((n for n in nodes if n.get("id") == edge.get("source")), None)
            t_node = next((n for n in nodes if n.get("id") == edge.get("target")), None)
            
            if s_node and t_node:
                s_lbl = s_node.get("data", {}).get("label", "").lower().strip()
                t_lbl = t_node.get("data", {}).get("label", "").lower().strip()
                orig_e = ref_edge_map.get(f"{s_lbl}->{t_lbl}")
                
                if orig_e:
                    if "sourceHandle" in orig_e: edge["sourceHandle"] = orig_e["sourceHandle"]
                    if "targetHandle" in orig_e: edge["targetHandle"] = orig_e["targetHandle"]
                    if "data" in orig_e: edge["data"] = orig_e["data"]
                    if "style" in orig_e: edge["style"] = orig_e["style"]
                    if "properties" in orig_e: edge["properties"] = orig_e["properties"]
            
            if "properties" not in edge or edge["properties"] is None:
                edge["properties"] = ["Integrity"]
        
        template["nodes"] = nodes
        template["edges"] = [e for e in edges if e.get("source") in gen_label_to_id.values() and e.get("target") in gen_label_to_id.values()]
        assets["template"] = template

        details = assets.get("Details", [])
        if details:
            assets["Details"] = [d for d in details if d.get("nodeId") in gen_label_to_id.values()]

        return {"architecture": assets}
        
    except Exception as e:
        print(f"  ❌ Architect parsing failed Exception: {e}")
        return {"architecture": {"template": {"nodes": [], "edges": []}, "Details": []}}


def threat_analysis_node(state: RAGState):
    query = state.get("user_query", "") or state.get("query", "")
    
    cached = load_cache(query, "threats")
    if cached: return {"threats": cached}
    
    from app.v1.rag.prompt import THREAT_PROMPT
    if not state.get("architecture") or not state["architecture"].get("template", {}).get("nodes"): 
        return {"threats": []}
    
    tmpl = jinja2.Template(THREAT_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"],
        architecture=json.dumps(state["architecture"], indent=2),
        documents=state["documents"],
        max_threats=MAX_THREATS
    )
    
    result = safe_generate(prompt, "ThreatAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    log_prompt("threat_analysis_node", state["documents"], prompt, raw_json)
    
    time.sleep(10)
    try:
        cleaned = clean_json_response(raw_json)
        threat_data = json.loads(cleaned)
        
        threats = threat_data.get("Derivations", threat_data.get("threats", threat_data.get("derivations", [])))
        if not threats and isinstance(threat_data, list):
            threats = threat_data
            
        return {"threats": threats}
    except Exception as e:
        return {"threats": []}

def _match_node_label(node_name: str, valid_node_labels: dict):
    if not node_name:
        return None, None
    node_lower = node_name.lower().strip()

    if node_lower in valid_node_labels:
        return valid_node_labels[node_lower], node_lower

    for label, nid in valid_node_labels.items():
        if node_lower in label or label in node_lower:
            return nid, label

    node_words = set(node_lower.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
    best_score, best_match = 0, None
    for label, nid in valid_node_labels.items():
        label_words = set(label.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
        overlap = len(node_words & label_words)
        if overlap > best_score:
            best_score = overlap
            best_match = (nid, label)

    if best_match and best_score > 0:
        return best_match

    return None, None

def _fix_derived_row_structure(row):
    """
    Fix the data structure of a derived threat scenario row.
    Ensures 'name' field is inside each Details item, not at the top level.
    Preserves damage_key, damage_name, and id (DS00X) at the row level.

    BEFORE (wrong):
    {
        "rowId": "uuid",
        "id": "DS001",
        "Details": [
            {
                "node": "code flash",
                "nodeId": "...",
                "props": [...]
                // name is MISSING here
            }
        ],
        "name": "Thermal Runaway..."  // name at wrong level
    }

    AFTER (correct):
    {
        "rowId": "uuid",
        "id": "DS001",
        "damage_key": 1,
        "damage_name": "Thermal Runaway...",
        "Details": [
            {
                "node": "Code Flash",
                "nodeId": "...",
                "props": [...],
                "name": "Thermal Runaway..."  // name at correct level
            }
        ]
    }
    """
    if not isinstance(row, dict) or "Details" not in row:
        return row

    details_list = row.get("Details", [])
    if not isinstance(details_list, list) or len(details_list) == 0:
        return row

    # Preserve damage fields BEFORE any pop operations
    damage_key   = row.get("damage_key")
    damage_name  = row.get("damage_name")
    ds_id        = row.get("id")

    # Extract the stray top-level 'name' to push into Details items.
    # Use damage_name as fallback so Details items always get a meaningful name.
    # Do NOT pop 'damage_name' — it must stay on the row.
    row_level_name = row.pop("name", None) or damage_name

    fixed_details = []
    for item in details_list:
        if not isinstance(item, dict):
            fixed_details.append(item)
            continue

        # Ensure 'name' field exists at item level
        if "name" not in item:
            item["name"] = row_level_name or item.get("node", "Unknown Scenario")

        fixed_details.append(item)

    row["Details"] = fixed_details

    # Restore damage fields in case they were accidentally removed upstream
    if damage_key is not None:
        row["damage_key"] = damage_key
    if damage_name:
        row["damage_name"] = damage_name
    if ds_id:
        row["id"] = ds_id

    return row


def threat_scenario_agent_node(state: RAGState):
    """AGENT 4: Generates the dual Threat_scenarios structure using an LLM."""
    from app.v1.rag.prompt import THREAT_SCENARIO_PROMPT
    from app.v1.rag.components import resolve_ecu, resolve_reference_report
    import copy

    query = state.get("user_query", "") or state.get("query", "")

    if not state.get("damage_details"):
        return {"threat_scenarios": []}

    # ── Build current-architecture label→id and id→label maps ────────────
    arch = state.get("architecture", {})
    arch_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    curr_label_to_id = {}
    curr_id_to_label = {}
    for n in arch_nodes:
        if n.get("type") == "group":
            continue
        lbl = (n.get("data", {}).get("label") or "").lower().strip()
        nid = n.get("id", "")
        if lbl:
            curr_label_to_id[lbl] = nid
        if nid:
            curr_id_to_label[nid] = lbl

    def _fuzzy_match(name: str):
        if not name:
            return None, None
        nl = name.lower().strip()
        if nl in curr_label_to_id:
            return curr_label_to_id[nl], nl
        for lbl, nid in curr_label_to_id.items():
            if nl in lbl or lbl in nl:
                return nid, lbl
        nw = set(nl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
        best_score, best = 0, None
        for lbl, nid in curr_label_to_id.items():
            lw = set(lbl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
            score = len(nw & lw)
            if score > best_score:
                best_score, best = score, (nid, lbl)
        if best and best_score > 0:
            return best
        return None, None

    def _remap_to_current(node_name: str, node_id: str):
        if node_id and node_id.startswith("reactflow__edge"):
            return _fuzzy_match(node_name)
        ref_lbl = ref_id_to_label.get(node_id, "")
        if ref_lbl:
            matched_id, matched_label = _fuzzy_match(ref_lbl)
            if matched_id:
                return matched_id, matched_label
        return _fuzzy_match(node_name)

    # ── STEP 1: Load reference ────────────────────────────────────────────
    ecu_entry = resolve_ecu(query)
    reference_data = resolve_reference_report(ecu_entry, query)

    ref_id_to_label = {}
    if reference_data:
        ref_assets = reference_data.get("Assets", [])
        if ref_assets:
            ref_asset = ref_assets[0] if isinstance(ref_assets, list) else ref_assets
            for n in ref_asset.get("template", {}).get("nodes", []):
                if n.get("type") != "group":
                    ref_id_to_label[n.get("id", "")] = (
                        n.get("data", {}).get("label") or ""
                    ).lower().strip()

    # ── BUILD DAMAGE SCENARIO MAP: key → {id, damage_key, damage_name} ──────
    # Primary index: integer key (1,2,3...) from state damage_details
    damage_key_map = {}  # int key → info dict
    for dd in state.get("damage_details", []):
        if isinstance(dd, dict):
            key = dd.get("key")
            if key is not None:
                k = int(key)
                damage_key_map[k] = {
                    "id": f"DS{k:03d}",
                    "damage_key": k,
                    "damage_name": dd.get("Name", dd.get("name", "")),
                }

    # FALLBACK: Build from architecture Details if damage_details is empty or un-keyed
    if not damage_key_map:
        arch_details = state.get("architecture", {}).get("Details", [])
        if isinstance(arch_details, list):
            for idx, detail in enumerate(arch_details, start=1):
                damage_key_map[idx] = {
                    "id": f"DS{idx:03d}",
                    "damage_key": idx,
                    "damage_name": detail.get("name", f"Damage Scenario {idx}"),
                }

    # ── BUILD REFERENCE rowId → damage info lookup ────────────────────────
    # In the BMS reference JSON the Threat_scenarios derived rows carry
    # rowId values that match the _id field of User-defined Damage_scenarios.
    # The reference derived rows themselves have NO damage_key / damage_name,
    # so we must join through this link to obtain them.
    ref_rowid_to_damage_info = {}  # rowId (str) → {id, damage_key, damage_name}
    if reference_data and "Damage_scenarios" in reference_data:
        for ds_block in reference_data["Damage_scenarios"]:
            if ds_block.get("type", "").lower() not in ("user-defined", "user_defined"):
                continue
            for d in ds_block.get("Details", []):
                if not isinstance(d, dict):
                    continue
                ref_ds_id  = d.get("_id", "")
                ref_ds_key = d.get("key")
                ref_ds_name = d.get("Name", d.get("name", ""))
                if ref_ds_id and ref_ds_key is not None:
                    k = int(ref_ds_key)
                    info = {
                        "id": f"DS{k:03d}",
                        "damage_key": k,
                        "damage_name": ref_ds_name,
                    }
                    ref_rowid_to_damage_info[ref_ds_id] = info
                    # Also keep damage_key_map in sync (authoritative source)
                    if k not in damage_key_map:
                        damage_key_map[k] = info

    # ── STEP 2a: Deterministically remap DERIVED reference rows ──────────
    remapped_derived_rows = []
    covered_ds_ids = set()
    ref_prop_id_map = {}
    ref_row_id_map = {}
    ref_derived_node_id_to_label = {}

    if reference_data and "Threat_scenarios" in reference_data:
        print(f"  ✅ Found reference Threat_scenarios — remapping deterministically")
        for ts_block in reference_data["Threat_scenarios"]:
            if ts_block.get("type", "").lower() != "derived":
                continue
            for row in ts_block.get("Details", []):
                row_copy = copy.deepcopy(row)
                remapped_items = []
                all_ok = True

                # Resolve damage info:
                # 1. Try damage_key already on the row (may be absent in reference JSON)
                # 2. Fall back to rowId → User-defined DS join
                # 3. Fall back to DS id string parsing (DS001 → key 1)
                ref_damage_key = row_copy.get("damage_key")
                damage_info = damage_key_map.get(ref_damage_key) if ref_damage_key is not None else None

                if not damage_info:
                    # Join via rowId → reference Damage_scenarios._id
                    ref_rowid = row_copy.get("rowId", "")
                    damage_info = ref_rowid_to_damage_info.get(ref_rowid)

                if not damage_info:
                    # Last resort: parse the DS id string
                    ds_id_str = row_copy.get("id", "")
                    if ds_id_str.upper().startswith("DS"):
                        try:
                            parsed_key = int(ds_id_str[2:])
                            damage_info = damage_key_map.get(parsed_key)
                        except ValueError:
                            pass

                if not damage_info:
                    damage_info = {}

                for item in row_copy.get("Details", []):
                    ref_node_name = item.get("node", "")
                    ref_node_id = item.get("nodeId", "")

                    new_id, new_label = _remap_to_current(ref_node_name, ref_node_id)

                    if new_id:
                        if ref_node_id:
                            ref_derived_node_id_to_label[ref_node_id] = new_label or ref_node_name
                        item["nodeId"] = new_id
                        item["node"] = curr_id_to_label.get(new_id, ref_node_name)
                        for p in item.get("props", []):
                            old_pid = p.get("id", "")
                            new_pid = str(uuid.uuid4())
                            if old_pid:
                                ref_prop_id_map[old_pid] = new_pid
                            p["id"] = new_pid
                        remapped_items.append(item)
                    else:
                        print(f"  ⚠️  No arch match for ref node '{ref_node_name}' "
                              f"(nodeId={ref_node_id[:24]}…) — dropping item from row {row.get('id')}")
                        all_ok = False

                if remapped_items:
                    # Move stray top-level 'name' into each Details item.
                    # Prefer damage_info.damage_name as the authoritative label.
                    authoritative_name = damage_info.get("damage_name", "")
                    row_level_name = row_copy.pop("name", None) or authoritative_name
                    for item in remapped_items:
                        if "name" not in item:
                            item["name"] = authoritative_name or row_level_name or item.get("node", "Unknown")

                    row_copy["Details"] = remapped_items
                    old_row_id = row.get("rowId", "")
                    new_row_id = str(uuid.uuid4())
                    if old_row_id:
                        ref_row_id_map[old_row_id] = new_row_id
                    row_copy["rowId"] = new_row_id

                    # Set damage_key, damage_name, id from resolved damage_info
                    if damage_info:
                        row_copy["id"]          = damage_info["id"]
                        row_copy["damage_key"]  = damage_info["damage_key"]
                        row_copy["damage_name"] = damage_info["damage_name"]
                    else:
                        # Keep whatever id the reference had; zero out unfillable fields
                        if not row_copy.get("id"):
                            row_copy["id"] = f"DS{ref_damage_key:03d}" if ref_damage_key else "DS001"
                        if row_copy.get("damage_key") is None:
                            row_copy["damage_key"] = ref_damage_key
                        if not row_copy.get("damage_name"):
                            row_copy["damage_name"] = row_level_name or ""

                    remapped_derived_rows.append(row_copy)
                    covered_ds_ids.add(row_copy.get("id", ""))
                    status = "✅ full" if all_ok else "⚠️  partial"
                    print(f"      ├─ {row_copy.get('id')} (damage_key={row_copy.get('damage_key')}, "
                          f"damage_name='{row_copy.get('damage_name', '')[:40]}'): {status} remap "
                          f"({len(remapped_items)}/{len(row.get('Details',[]))} items)")
    else:
        print(f"  ℹ️  No reference threat scenarios available")

    print(f"  ✅ {len(remapped_derived_rows)} reference derived rows remapped and locked in "
          f"(covering DS IDs: {sorted(covered_ds_ids)})")

    # ── STEP 2b: Deterministically remap USER-DEFINED reference rows ──────
    remapped_user_defined = []

    if reference_data and "Threat_scenarios" in reference_data:
        for ts_block in reference_data["Threat_scenarios"]:
            if ts_block.get("type", "").lower() not in ("user-defined", "user_defined"):
                continue
            print(f"  ✅ Found reference User-defined Threat_scenarios — remapping deterministically")
            for ud_row in ts_block.get("Details", []):
                ud_copy = copy.deepcopy(ud_row)
                remapped_threat_ids = []
                all_ok = True

                for tid in ud_copy.get("threat_ids", []):
                    ref_node_id = tid.get("nodeId", "")
                    ref_prop_id = tid.get("propId", "")
                    ref_row_id = tid.get("rowId", "")

                    resolved_name = (
                        ref_derived_node_id_to_label.get(ref_node_id)
                        or ref_id_to_label.get(ref_node_id, "")
                    )
                    new_node_id, _ = _remap_to_current(resolved_name, ref_node_id)

                    new_prop_id = ref_prop_id_map.get(ref_prop_id, "")
                    new_row_id = ref_row_id_map.get(ref_row_id, "")

                    if new_node_id:
                        tid["nodeId"] = new_node_id
                    else:
                        print(f"  ⚠️  No arch match for user-defined threat_id nodeId "
                              f"'{ref_node_id[:24]}…' in scenario '{ud_row.get('name')}'")
                        all_ok = False

                    if new_prop_id:
                        tid["propId"] = new_prop_id
                    else:
                        tid["propId"] = str(uuid.uuid4())

                    if new_row_id:
                        tid["rowId"] = new_row_id
                    else:
                        tid["rowId"] = str(uuid.uuid4())

                    remapped_threat_ids.append(tid)

                ud_copy["threat_ids"] = remapped_threat_ids
                if not ud_copy.get("id"):
                    ud_copy["id"] = str(uuid.uuid4())

                remapped_user_defined.append(ud_copy)
                status = "✅ full" if all_ok else "⚠️  partial"
                print(f"      ├─ User-defined '{ud_row.get('name', 'unnamed')}': {status} remap")

    print(f"  ✅ {len(remapped_user_defined)} reference user-defined rows remapped and locked in")

    # ── STEP 3: Build prompt with existing reference data included ────────
    print("Generating context-aware Threat Scenarios for uncovered DS rows (Agent 4)...")
    tmpl = jinja2.Template(THREAT_SCENARIO_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"],
        architecture=json.dumps(state["architecture"], indent=2),
        damage_scenarios=json.dumps(state["damage_details"], indent=2),
        threats=json.dumps(state["threats"], indent=2)
    )

    if remapped_derived_rows:
        prompt += (
            "\n\n### EXISTING DERIVED THREAT SCENARIOS (DO NOT REGENERATE THESE):\n"
            + json.dumps(remapped_derived_rows, indent=2)
            + f"\n\nDo NOT regenerate these DS IDs: {sorted(covered_ds_ids)}. "
            "Only generate derived rows for DS IDs NOT in that list.\n"
        )

    if remapped_user_defined:
        existing_ud_count = len(remapped_user_defined)
        target_ud_extras = max(2, 6 - existing_ud_count)
        prompt += (
            "\n\n### EXISTING USER-DEFINED THREAT SCENARIOS (DO NOT REGENERATE THESE):\n"
            + json.dumps(remapped_user_defined, indent=2)
            + f"\n\nGenerate {target_ud_extras} EXTRA user-defined threat scenarios "
            "covering different attack vectors not already listed above.\n"
        )
    else:
        prompt += (
            "\n\nGenerate 3–5 realistic user-defined attack scenarios that reference "
            "the derived DS rows via threat_ids.\n"
        )

    result = safe_generate(prompt, "ThreatScenarioAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"

    log_prompt("threat_scenario_agent_node", state.get("documents", []), prompt, raw_json)

    time.sleep(10)

    llm_derived_rows = []
    llm_user_defined_rows = []

    try:
        cleaned = clean_json_response(raw_json)
        ts_data = json.loads(cleaned)
        threat_scenarios_llm = ts_data.get("Threat_scenarios", ts_data.get("threat_scenarios", []))

        for block in threat_scenarios_llm:
            if not isinstance(block, dict):
                continue
            btype = block.get("type", "").lower()
            if btype == "derived":
                for row in block.get("Details", []):
                    if row.get("id") not in covered_ds_ids:
                        # Resolve damage info: parse numeric key from DS id string
                        ds_id = row.get("id", "")
                        damage_info = {}
                        if ds_id.upper().startswith("DS"):
                            try:
                                parsed_key = int(ds_id[2:])
                                damage_info = damage_key_map.get(parsed_key, {})
                            except ValueError:
                                pass
                        # Fallback: linear scan by id match
                        if not damage_info:
                            for info in damage_key_map.values():
                                if info.get("id") == ds_id:
                                    damage_info = info
                                    break

                        authoritative_name = damage_info.get("damage_name", "")

                        # Move stray top-level 'name' into each Details item
                        row_level_name = row.pop("name", None) or authoritative_name
                        for item in row.get("Details", []):
                            if isinstance(item, dict):
                                if "name" not in item:
                                    item["name"] = authoritative_name or row_level_name or item.get("node", "Unknown")

                        # Always set damage_key and damage_name from resolved info
                        if damage_info:
                            row["damage_key"]  = damage_info.get("damage_key")
                            row["damage_name"] = damage_info.get("damage_name", "")
                        else:
                            # Last resort: at least set damage_key from the id string
                            if row.get("damage_key") is None and ds_id.upper().startswith("DS"):
                                try:
                                    row["damage_key"] = int(ds_id[2:])
                                except ValueError:
                                    pass
                            if not row.get("damage_name"):
                                row["damage_name"] = row_level_name or ""

                        llm_derived_rows.append(row)
            elif btype in ("user-defined", "user_defined"):
                for ud in block.get("Details", []):
                    llm_user_defined_rows.append(ud)

    except Exception as e:
        print(f"  ❌ LLM Threat Scenario parsing failed: {e}")
        import traceback
        traceback.print_exc()

    # ── STEP 4: Combine reference rows + LLM extras ───────────────────────
    final_derived_rows = remapped_derived_rows + llm_derived_rows
    final_user_defined_rows = remapped_user_defined + llm_user_defined_rows

    combined_threat_scenarios = [
        {
            "type": "derived",
            "Details": final_derived_rows,
        }
    ]
    if final_user_defined_rows:
        combined_threat_scenarios.append({
            "type": "user-defined",
            "Details": final_user_defined_rows,
        })

    print(f"  ✅ Threat Scenario Agent SUCCESS: "
          f"{len(final_derived_rows)} derived rows, {len(final_user_defined_rows)} user-defined rows")

    return {"threat_scenarios": combined_threat_scenarios}


def generate_attack_trees_node(state: RAGState):
    """Generates simplified attack trees for each threat scenario."""
    print("Generating Attack Trees (React Flow)...")
    raw_ts_data = state.get("threat_scenarios", [])
    attacks = []
    
    # Extract flat list of derived scenarios safely
    flat_ts_list = []
    for block in raw_ts_data:
        if isinstance(block, dict) and block.get("type", "").lower() == "derived":
            for ds_group in block.get("Details", []):
                for ts in ds_group.get("Details", []):
                    ts_copy = ts.copy()
                    ts_copy["rowId"] = ds_group.get("rowId", "")
                    
                    ds_str = ts.get("damage_scenario", "")
                    ts_name_str = ts.get("name", "")
                    
                    if "]" in ds_str:
                        parts = ds_str.split("]")
                        d_id = parts[0].strip("[")
                        scene_str = f"[{d_id}] {ts_name_str}"
                        ts_copy["damage_scenario"] = scene_str
                    else:
                        grp_id = ds_group.get("id", "")
                        scene_str = f"[{grp_id}] {ts_name_str}"
                        ts_copy["damage_scenario"] = scene_str
                        
                    flat_ts_list.append(ts_copy)
                    
    # Fallback to old format
    if not flat_ts_list and raw_ts_data and "type" not in raw_ts_data[0]:
        flat_ts_list = raw_ts_data
    
    def _create_node(label, name, x, y, desc="", node_type="derived", threat_ids=None):
        uid = str(uuid.uuid4())
        new_conn_id = str(uuid.uuid4())
        return {
            "id": uid,
            "nodeId": uid,
            "type": node_type,
            "nodeType": node_type,
            "label": label,
            "name": name,
            "description": desc,
            "dragged": True,
            "dragging": False,
            "selected": False,
            "height": 60,
            "width": 150,
            "position": {"x": x, "y": y},
            "positionAbsolute": {"x": x, "y": y},
            "data": {
                "label": label,
                "nodeId": uid,
                "nodeType": node_type,
                "connections": [{"id": new_conn_id, "type": "OR Gate"}],
                "style": {
                    "backgroundColor": "transparent", 
                    "borderColor": "black", 
                    "borderStyle": "solid", 
                    "borderWidth": "2px",
                    "color": "black", 
                    "fontFamily": "Inter", 
                    "fontSize": "16px", 
                    "fontStyle": "normal", 
                    "fontWeight": 500,
                    "height": 60, 
                    "textAlign": "center", 
                    "textDecoration": "none", 
                    "width": 150
                }
            },
            "threat_ids": threat_ids or []
        }

    for ts in flat_ts_list:
        nodes = []
        edges = []
        
        props_list = ts.get("props", [{}])
        prop = props_list[0] if props_list else {}
        
        # Safely parse damage_scenario string
        ds_str = ts.get("damage_scenario", "")
        if "]" in ds_str:
            d_parts = ds_str.split("]")
            d_id = d_parts[0].strip("[")
            d_scene = d_parts[1].strip() if len(d_parts) > 1 else ""
        else:
            d_id = ds_str
            d_scene = ""
            
        t_ids = [
            {
                "damage_id": d_id,
                "damage_scene": d_scene,
                "nodeId": ts.get("nodeId", ""),
                "node_name": ts.get("node", ""),
                "propId": prop.get("id", ""),
                "prop_key": prop.get("key", 1),
                "prop_name": prop.get("name", "Integrity"),
                "rowId": ts.get("rowId", "") 
            }
        ]
        
        ts_name_str = ts.get("name", "Attack")
        name_only = ts_name_str.split("]")[-1].strip() if "]" in ts_name_str else ts_name_str
        label = ts_name_str
        
        root = _create_node(label, name_only, 1184, -113, desc="Attack scenario description", node_type="derived", threat_ids=t_ids)
        nodes.append(root)
        
        attacks.append({
            "ID": str(uuid.uuid4()),
            "Name": name_only,
            "threat_id": "",
            "templates": {
                "nodes": nodes,
                "edges": edges
            }
        })
    
    return {"attacks": attacks}



def damage_scenario_node(state: RAGState):
    from app.v1.rag.prompt import DAMAGE_PROMPT
    import copy
    query = state.get("user_query", "") or state.get("query", "")

    cached = load_cache(query, "damage")
    if cached:
        return {"damage_details": cached}

    if not state.get("threats"): return {"damage_details": []}

    from app.v1.rag.components import resolve_ecu, resolve_reference_report
    ecu_entry = resolve_ecu(query)
    reference_data = resolve_reference_report(ecu_entry, query)

    arch = state.get("architecture", {})
    arch_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    arch_edges = arch.get("template", {}).get("edges", arch.get("edges", []))

    # ── Node label → id map (non-group nodes only) ──────────────────────────
    valid_node_labels = {
        n.get("data", {}).get("label", "").lower().strip(): n.get("id")
        for n in arch_nodes if n.get("type") != "group"
    }

    # ── Edge label → id map (edges carry data.label like "CAN1", "CAN2") ───
    valid_edge_labels = {}
    for e in arch_edges:
        e_data = e.get("data", {})
        e_label = (e_data.get("label", "") if isinstance(e_data, dict) else "").lower().strip()
        e_id = e.get("id", "")
        if e_label and e_id:
            valid_edge_labels[e_label] = e_id

    _fallback_label = next(iter(valid_node_labels), None)
    _fallback_id    = valid_node_labels.get(_fallback_label) if _fallback_label else None

    existing_scenarios = []
    if reference_data and "Damage_scenarios" in reference_data:
        for ds_block in reference_data["Damage_scenarios"]:
            if ds_block.get("type") == "User-defined":
                for detail in ds_block.get("Details", []):
                    detail_copy = copy.deepcopy(detail)
                    remapped_losses = []

                    for loss in detail_copy.get("cyberLosses", []):
                        node_name    = loss.get("node", "")
                        ref_node_id  = loss.get("nodeId", "")

                        # ── Strategy 1: try nodes first ──────────────────────
                        matched_nid, matched_label = _match_node_label(node_name, valid_node_labels)

                        # ── Strategy 2: if the reference nodeId is an edge ID
                        #    (reactflow__edge-…), try matching against edge labels ──
                        if not matched_nid and ref_node_id.startswith("reactflow__edge"):
                            matched_nid, matched_label = _match_node_label(node_name, valid_edge_labels)

                        if matched_nid:
                            loss["nodeId"] = matched_nid
                            loss["node"]   = matched_label
                        elif _fallback_id:
                            loss["nodeId"] = _fallback_id
                            loss["node"]   = _fallback_label

                        loss["id"] = str(uuid.uuid4())
                        remapped_losses.append(loss)

                    if remapped_losses:
                        detail_copy["cyberLosses"] = remapped_losses
                    detail_copy["_id"] = str(uuid.uuid4())
                    existing_scenarios.append(detail_copy)

    tmpl = jinja2.Template(DAMAGE_PROMPT)
    prompt = tmpl.render(
        question=state.get("user_query", "Automotive ECU System"),
        threats=json.dumps(state["threats"], indent=2),
        architecture=json.dumps(state["architecture"], indent=2)
    )

    if existing_scenarios:
        prompt += "\n\n### EXISTING SCENARIOS (DO NOT REGENERATE THESE):\n"
        prompt += json.dumps(existing_scenarios, indent=2)
        prompt += "\n\n"
        target_extras = max(3, 10 - len(existing_scenarios))
        prompt += f"Generate {target_extras} EXTRA damage scenarios covering different components. "
        prompt += "Return ONLY the new scenarios in your JSON output.\n"

    result = safe_generate(prompt, "DamageAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"

    log_prompt("damage_scenario_node", state.get("documents", []), prompt, raw_json)

    time.sleep(10)
    try:
        cleaned = clean_json_response(raw_json)
        damage_data = json.loads(cleaned)

        if "Damage_scenarios" in damage_data:
            details = damage_data["Damage_scenarios"]
        else:
            details = damage_data.get("Details", damage_data.get("details", damage_data.get("damage_details", [])))

        if not details and isinstance(damage_data, list):
            details = damage_data

        if not details:
            details = []

        combined_details = existing_scenarios + details

        save_cache(query, "damage", combined_details)
        return {"damage_details": combined_details}

    except Exception as e:
        if existing_scenarios:
            save_cache(query, "damage", existing_scenarios)
            return {"damage_details": existing_scenarios}

        return {"damage_details": []}

def attack_scenario_agent_node(state: RAGState):
    """
    AGENT 5: Generates attack scenarios and attack trees by extracting
    reference data first, then generating extras via LLM.
    
    PATTERN (mirrors damage_scenario_node and threat_scenario_agent_node):
      1. Extract existing attack scenarios from reference data (bms_1.json)
      2. Extract existing attack trees from reference data
      3. Deterministically remap nodeIds, propIds, rowIds to current architecture
      4. Generate extras for uncovered threat scenarios via LLM
      5. Combine and return all attack scenarios and trees
    """
    from app.v1.rag.prompt import ATTACK_SCENARIO_PROMPT
    from app.v1.rag.components import resolve_ecu, resolve_reference_report
    import copy
    import uuid as _uuid
    
    query = state.get("user_query", "") or state.get("query", "")
    
    if not state.get("threat_scenarios"):
        return {"attacks": []}
    
    # ── Build current-architecture maps ─────────────────────────────────
    arch = state.get("architecture", {})
    arch_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    arch_edges = arch.get("template", {}).get("edges", arch.get("edges", []))
    
    curr_label_to_id = {}
    curr_edge_label_to_id = {}
    curr_all_ids = set()
    
    for n in arch_nodes:
        if n.get("type") != "group":
            lbl = (n.get("data", {}).get("label") or "").lower().strip()
            nid = n.get("id", "")
            if lbl:
                curr_label_to_id[lbl] = nid
            if nid:
                curr_all_ids.add(nid)
    
    for e in arch_edges:
        e_data = e.get("data", {})
        e_label = (e_data.get("label", "") if isinstance(e_data, dict) else "").lower().strip()
        e_id = e.get("id", "")
        if e_label:
            curr_edge_label_to_id[e_label] = e_id
        if e_id:
            curr_all_ids.add(e_id)
    
    def _fuzzy_match(name: str):
        """Exact → substring → word-overlap matching."""
        if not name:
            return None
        nl = name.lower().strip()
        
        # Try node labels first
        if nl in curr_label_to_id:
            return curr_label_to_id[nl]
        for lbl, nid in curr_label_to_id.items():
            if nl in lbl or lbl in nl:
                return nid
        
        # Try edge labels
        if nl in curr_edge_label_to_id:
            return curr_edge_label_to_id[nl]
        for lbl, eid in curr_edge_label_to_id.items():
            if nl in lbl or lbl in nl:
                return eid
        
        # Word overlap
        nw = set(nl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
        best_score, best = 0, None
        for lbl, nid in {**curr_label_to_id, **curr_edge_label_to_id}.items():
            lw = set(lbl.replace("-", " ").replace("_", " ").split()) - {"", "the", "and", "of"}
            score = len(nw & lw)
            if score > best_score:
                best_score, best = score, nid
        if best and best_score > 0:
            return best
        return None
    
    # ── Load reference data ────────────────────────────────────────────
    ecu_entry = resolve_ecu(query)
    reference_data = resolve_reference_report(ecu_entry, query)
    
    # Build reference node ID → label map
    ref_id_to_label = {}
    if reference_data:
        ref_assets = reference_data.get("Assets", [])
        if ref_assets:
            ref_asset = ref_assets[0] if isinstance(ref_assets, list) else ref_assets
            for n in ref_asset.get("template", {}).get("nodes", []):
                if n.get("type") != "group":
                    ref_id_to_label[n.get("id", "")] = (
                        n.get("data", {}).get("label") or ""
                    ).lower().strip()
            for e in ref_asset.get("template", {}).get("edges", []):
                e_label = e.get("data", {}).get("label", "").lower().strip()
                if e_label:
                    ref_id_to_label[e.get("id", "")] = e_label
    
    # ── Extract existing attack scenarios from reference ───────────────
    existing_attacks = []
    existing_attack_trees = []
    
    if reference_data and "Attacks" in reference_data:
        print("  ✅ Found reference Attacks — extracting and remapping")
        for attack_block in reference_data["Attacks"]:
            attack_type = attack_block.get("type", "")
            
            if attack_type == "attack":
                # Process attack scenarios
                for scene in attack_block.get("scenes", []):
                    scene_copy = copy.deepcopy(scene)
                    # Remap any node references
                    if scene_copy.get("threat_id"):
                        scene_copy["_original_threat_id"] = scene_copy["threat_id"]
                        scene_copy["threat_id"] = str(_uuid.uuid4())  # Fresh ID
                    existing_attacks.append(scene_copy)
                    print(f"      ├─ Attack scene: '{scene_copy.get('Name', 'unnamed')}' extracted")
            
            elif attack_type == "attack_trees":
                # Process attack trees
                for scene in attack_block.get("scenes", []):
                    scene_copy = copy.deepcopy(scene)
                    
                    # Remap node IDs in templates
                    if "templates" in scene_copy:
                        templates = scene_copy["templates"]
                        node_id_mapping = {}
                        
                        # Create new IDs for all nodes
                        for node in templates.get("nodes", []):
                            old_id = node.get("id", "")
                            new_id = str(_uuid.uuid4())
                            node_id_mapping[old_id] = new_id
                            node["id"] = new_id
                            if "nodeId" in node:
                                node["nodeId"] = new_id
                        
                        # Update edge references
                        for edge in templates.get("edges", []):
                            old_source = edge.get("source", "")
                            old_target = edge.get("target", "")
                            if old_source in node_id_mapping:
                                edge["source"] = node_id_mapping[old_source]
                            if old_target in node_id_mapping:
                                edge["target"] = node_id_mapping[old_target]
                    
                    existing_attack_trees.append(scene_copy)
                    print(f"      ├─ Attack tree: '{scene_copy.get('Name', 'unnamed')}' extracted")
    
    print(f"  ✅ Extracted {len(existing_attacks)} attack scenarios and {len(existing_attack_trees)} attack trees from reference")
    
    # ── Collect covered threat scenarios ───────────────────────────────
    covered_threat_names = set()
    for scene in existing_attack_trees:
        scene_name = scene.get("Name", "").lower().strip()
        covered_threat_names.add(scene_name)
    
    # Get user-defined threat scenarios that need attack trees
    user_defined_ts = []
    for ts_block in state.get("threat_scenarios", []):
        if ts_block.get("type", "").lower() in ("user-defined", "user_defined"):
            for detail in ts_block.get("Details", []):
                ts_name = detail.get("name", "").strip()
                if ts_name and ts_name.lower() not in covered_threat_names:
                    user_defined_ts.append(detail)
    
    print(f"  ℹ️  {len(user_defined_ts)} user-defined threat scenarios need attack trees")

    # ── Build extra trees deterministically using flatten_tree (add_attack_trees logic) ──
    # No LLM call — avoids timeout. Each uncovered threat scenario gets a
    # skeleton tree (root node only, type='derived') so it appears in the
    # attack_trees section without being misidentified as an attack entry.
    # The add_attack_trees.py Phase-2 script can enrich these with real vectors later.
    new_attack_trees = []
    new_attacks = []

    # Semantic type → React Flow node type map (mirrors add_attack_trees.py)
    TREE_TYPE_MAP = {
        "surface_goal":  "derived",   # threat-scenario root — never an attack
        "attack_vector": "Event",
        "method":        "Event",
    }

    def _flatten_tree(tree, x=0, y=0, level_width=600):
        """Flatten a nested attack-tree dict into React Flow nodes + edges.
        Uses semantic types so threat-scenario roots are never type='default'."""
        nodes, edges = [], []
        node_id  = tree.get("id", str(_uuid.uuid4())[:8])
        gate     = tree.get("gate", "OR")
        semantic = tree.get("type", "method")
        rf_type  = TREE_TYPE_MAP.get(semantic, "Event")

        current = {
            "id":       node_id,
            "type":     rf_type,
            "nodeType": rf_type,
            "position": {"x": x, "y": y},
            "positionAbsolute": {"x": x, "y": y},
            "width": 180, "height": 60,
            "dragged": True, "dragging": False, "selected": False,
            "data": {
                "label":    tree.get("goal", tree.get("name", "")),
                "nodeId":   node_id,
                "nodeType": rf_type,
                "connections": [],
                "style": {
                    "backgroundColor": "transparent", "borderColor": "black",
                    "borderStyle": "solid", "borderWidth": "2px", "color": "black",
                    "fontFamily": "Inter", "fontSize": "14px", "fontWeight": 500,
                    "height": 60, "textAlign": "center", "width": 180,
                },
            },
        }
        nodes.append(current)

        children = tree.get("children", [])
        if children:
            child_y = y + 250
            start_x = x - ((len(children) - 1) * level_width / 2)
            for i, child in enumerate(children):
                child_x = start_x + i * level_width
                c_nodes, c_edges = _flatten_tree(child, child_x, child_y, level_width / 1.5)
                nodes.extend(c_nodes)
                edges.extend(c_edges)
                child_id = child.get("id")
                current["data"]["connections"].append({"id": child_id, "type": f"{gate} Gate"})
                edges.append({
                    "id": f"e-{node_id}-{child_id}",
                    "source": node_id, "target": child_id,
                    "sourceHandle": "b", "targetHandle": "t",
                    "type": "step", "animated": True,
                    "style": {"strokeWidth": 2, "stroke": "#000000"},
                    "markerEnd": {"type": "arrowclosed", "color": "#000000", "width": 20, "height": 20},
                })
        return nodes, edges

    def _sanitize_tree_nodes(nodes):
        """Ensure nodes with nodeType='derived' are never type='default'.
        Any stray 'default' in an attack tree becomes 'Event'."""
        for node in nodes:
            nt = (node.get("data") or {}).get("nodeType") or node.get("nodeType", "")
            if nt == "derived":
                node["type"] = "derived"
                node["nodeType"] = "derived"
                if isinstance(node.get("data"), dict):
                    node["data"]["nodeType"] = "derived"
            elif node.get("type") == "default":
                node["type"] = "Event"
                if isinstance(node.get("data"), dict):
                    node["data"]["nodeType"] = "Event"

    # Also sanitize reference trees before combining
    for scene in existing_attack_trees:
        if "templates" in scene:
            _sanitize_tree_nodes(scene["templates"].get("nodes", []))

    # ── Collect uncovered derived scenarios, cap LLM call at MAX_EXTRAS ─────
    MAX_EXTRAS = 3
    uncovered_ts = []
    for ts_block in state.get("threat_scenarios", []):
        if ts_block.get("type", "").lower() != "derived":
            continue
        for ds_group in ts_block.get("Details", []):
            for ts in ds_group.get("Details", []):
                ts_name = ts.get("name", "").strip()
                if ts_name and ts_name.lower() not in covered_threat_names:
                    uncovered_ts.append(ts)

    extras_ts = uncovered_ts[:MAX_EXTRAS]
    print(f"  ℹ️  {len(uncovered_ts)} uncovered derived scenarios — calling LLM for {len(extras_ts)}")

    if extras_ts:
        from app.v1.rag.prompt import ATTACK_SCENARIO_PROMPT
        tmpl   = jinja2.Template(ATTACK_SCENARIO_PROMPT)
        prompt = tmpl.render(
            question=state["user_query"],
            architecture=json.dumps(state["architecture"], indent=2),
            threat_scenarios=json.dumps(extras_ts, indent=2),
            existing_attacks=json.dumps(existing_attacks, indent=2),
            existing_attack_trees=json.dumps(existing_attack_trees, indent=2),
        )
        prompt += (
            f"\n\nGenerate attack trees for exactly {len(extras_ts)} threat scenario(s) listed above. "
            "Return JSON with keys: attack_trees (list) and attacks (list).\n"
        )
        try:
            result   = safe_generate(prompt, "AttackScenarioAnalyst")
            raw_json = result["replies"][0] if result["replies"] else "{}"
            log_prompt("attack_scenario_agent_node", state.get("documents", []), prompt, raw_json)
            time.sleep(5)
            cleaned     = clean_json_response(raw_json)
            attack_data = json.loads(cleaned)
            llm_trees   = attack_data.get("attack_trees", attack_data.get("Attack_Trees", []))
            llm_attacks = attack_data.get("attacks", attack_data.get("Attacks", []))
            for tree in llm_trees:
                if "templates" in tree:
                    templates       = tree["templates"]
                    node_id_mapping = {}
                    for node in templates.get("nodes", []):
                        old_id = node.get("id", "")
                        new_id = str(_uuid.uuid4())
                        node_id_mapping[old_id] = new_id
                        node["id"] = new_id
                        if "nodeId" in node:
                            node["nodeId"] = new_id
                    _sanitize_tree_nodes(templates.get("nodes", []))
                    for edge in templates.get("edges", []):
                        if edge.get("source") in node_id_mapping:
                            edge["source"] = node_id_mapping[edge["source"]]
                        if edge.get("target") in node_id_mapping:
                            edge["target"] = node_id_mapping[edge["target"]]
                tree["ID"] = str(_uuid.uuid4())
                new_attack_trees.append(tree)
                # print(f"      ├─ LLM tree added: '{tree.get('Name', 'unnamed')[:55]}'")
            for attack in llm_attacks:
                attack["ID"] = str(_uuid.uuid4())
                new_attacks.append(attack)
        except Exception as e:
            print(f"  ⚠️  LLM extras failed ({e}) — reference trees retained")

    # ── Combine all attacks ─────────────────────────────────────────────
    combined_attacks = existing_attacks + new_attacks
    combined_trees = existing_attack_trees + new_attack_trees
    
    ref_count = len(existing_attack_trees)
    new_count = len(new_attack_trees)
    
    print(f"  ✅ Attack Scenario Agent SUCCESS: "
          f"{len(combined_trees)} attack trees (ref={ref_count}, new={new_count}), "
          f"{len(combined_attacks)} attack scenarios")
    
    return {
        "attacks": [
            {
                "type": "attack_trees",
                "scenes": combined_trees,
            },
            {
                "type": "attack",
                "scenes": combined_attacks,
            }
        ]
    }

    
def evaluate(state: RAGState):
    # ── DEFENSIVE EXTRACTION of Architecture ──
    assets_data = state.get("architecture", {})
    if not assets_data:
        assets_data = {"template": {"nodes": [], "edges": []}, "Details": []}

    assets_list = []
    if isinstance(assets_data, list):
        assets_list = assets_data
    else:
        assets_list = [assets_data]

    mid = "698397514b57b8f24ed40a43"
    uid = "66ce823d95a055635c0ae0ae"

    unified_assets = []
    for asset in assets_list:
        if isinstance(asset, dict) and "Assets" in asset:
            sub = asset["Assets"]
            if isinstance(sub, list): unified_assets.extend(sub)
            else: unified_assets.append(sub)
        elif isinstance(asset, dict):
            unified_assets.append(asset)

    if not unified_assets:
        unified_assets = [{"template": {"nodes": [], "edges": []}, "Details": []}]

    for asset in unified_assets:
        if "template" not in asset or not asset["template"]:
            existing_nodes = asset.pop("nodes", [])
            existing_edges = asset.pop("edges", [])
            asset["template"] = {"nodes": existing_nodes, "edges": existing_edges}
        else:
            asset.pop("nodes", None)
            asset.pop("edges", None)

    for asset in unified_assets:
        details = asset.get("Details", [])
        if not isinstance(details, list):
            details = []

        detail_props_map = {}
        for detail in details:
            if not isinstance(detail, dict):
                continue
            nid = detail.get("nodeId")
            sec_props = detail.get("securityProperties", [])
            if not sec_props:
                props_raw = detail.get("properties", detail.get("props", []))
                sec_props = []
                for p in (props_raw if isinstance(props_raw, list) else []):
                    if isinstance(p, dict):
                        name = p.get("name", "")
                        if name: sec_props.append(name)
                    elif isinstance(p, str) and p:
                        sec_props.append(p)
            if nid and sec_props:
                detail_props_map[nid] = sec_props

        nodes = asset.get("template", {}).get("nodes", [])
        if not isinstance(nodes, list):
            nodes = []

        for node in nodes:
            if not isinstance(node, dict):
                continue
            nid = node.get("id")
            node_type = node.get("type", "default")

            if nid in detail_props_map:
                node["properties"] = detail_props_map[nid]
            elif node_type != "group":
                if "properties" not in node or not node.get("properties"):
                    node["properties"] = [
                        "Integrity", "Confidentiality", "Authenticity",
                        "Authorization", "Availability", "Non-repudiation"
                    ]

            properties = node.get("properties", [])
            if not isinstance(properties, list):
                properties = []
            clean_props = []
            for p in properties:
                if isinstance(p, dict):
                    name = p.get("name", p.get("value", "Integrity"))
                    if name: clean_props.append(name)
                elif isinstance(p, str) and p:
                    clean_props.append(p)
            node["properties"] = clean_props if clean_props else [
                "Integrity", "Confidentiality", "Authenticity",
                "Authorization", "Availability", "Non-repudiation"
            ]

    node_id_map = {}
    label_id_map = {}
    edge_id_map = {}  # Moved up here for use in _remap
    
    for asset in unified_assets:
        nodes = asset.get("template", {}).get("nodes", [])
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            old_id = node.get("id")
            node_data = node.get("data", {})
            label = node_data.get("label") if isinstance(node_data, dict) else None

            new_uuid = str(uuid.uuid4())
            if old_id:
                node_id_map[old_id] = new_uuid
            if label:
                label_id_map[label] = new_uuid
                label_id_map[label.lower()] = new_uuid
            node["id"] = new_uuid
            node["nodeId"] = new_uuid
            if "data" in node and isinstance(node["data"], dict):
                node["data"]["nodeId"] = new_uuid

    for asset in unified_assets:
        for node in asset.get("template", {}).get("nodes", []):
            if not isinstance(node, dict):
                continue
            old_pid = node.get("parentId")

            final_pid = None
            if old_pid:
                if old_pid in node_id_map:
                    final_pid = node_id_map[old_pid]
                elif old_pid in label_id_map:
                    final_pid = label_id_map[old_pid]
                elif str(old_pid).lower() in label_id_map:
                    final_pid = label_id_map[str(old_pid).lower()]
                else:
                    final_pid = old_pid

            node["parentId"] = final_pid

            valid_ids = [n.get("id") for n in asset.get("template", {}).get("nodes", []) if isinstance(n, dict)]
            if final_pid and final_pid not in valid_ids:
                node["parentId"] = None

    for asset in unified_assets:
        asset["_id"] = asset.get("_id", str(uuid.uuid4()))
        asset["user_id"] = uid
        asset["model_id"] = mid
        asset["asset_name"] = asset.get("asset_name", None)
        asset["asset_properties"] = asset.get("asset_properties", None)

        nested_details = asset.get("template", {}).pop("details", None) or asset.get("template", {}).pop("Details", None)
        if nested_details and not asset.get("Details"):
            asset["Details"] = nested_details

        nodes = asset.get("template", {}).get("nodes", [])
        if not isinstance(nodes, list):
            nodes = []

        group_ids = {n.get("id") for n in nodes if isinstance(n, dict) and n.get("type") == "group"}
        child_counters = {}

        for i, node in enumerate(nodes):
            if not isinstance(node, dict):
                continue
            if "data" not in node or not isinstance(node.get("data"), dict):
                node["data"] = {}
            ntype = node.get("type", "default")

            if ntype == "group":
                default_w, default_h = 800, 500
            elif ntype == "data":
                default_w, default_h = 100, 40
            else:
                default_w, default_h = 160, 40

            pid = node.get("parentId")

            if "position" not in node:
                if ntype == "group":
                    node["position"] = {"x": -96.0, "y": -44.0}
                elif pid and pid in group_ids:
                    ci = child_counters.get(pid, 0)
                    col = ci % 4
                    row = ci // 4
                    node["position"] = {"x": 20 + (col * 200), "y": 80 + (row * 150)}
                    node["extent"] = "parent"
                    child_counters[pid] = ci + 1
                else:
                    col = i % 3
                    node["position"] = {"x": 100 + (col * 350), "y": 100 + 300}

            node["positionAbsolute"] = node.get("positionAbsolute", node.get("position", {"x": 0, "y": 0}))
            node["dragging"] = node.get("dragging", False)
            node["resizing"] = node.get("resizing", False)
            node["selected"] = node.get("selected", False)
            node["isAsset"] = node.get("isAsset", False)

            if ntype == "group":
                node["zIndex"] = 0

            if "properties" not in node or not isinstance(node.get("properties"), list):
                node["properties"] = [
                    "Integrity", "Confidentiality", "Authenticity",
                    "Authorization", "Availability", "Non-repudiation"
                ]
            else:
                clean_props = []
                for p in node["properties"]:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", "Integrity")))
                    elif isinstance(p, str):
                        clean_props.append(p)
                node["properties"] = clean_props if clean_props else [
                    "Integrity", "Confidentiality", "Authenticity",
                    "Authorization", "Availability", "Non-repudiation"
                ]

            if "style" not in node.get("data", {}):
                bg = "#dadada" if ntype == "group" else ("#e3e896" if ntype == "data" else "#FFFFFF")
                node["data"]["style"] = {
                    "backgroundColor": bg,
                    "borderColor": "gray",
                    "borderStyle": "solid",
                    "borderWidth": "2px",
                    "color": "black",
                    "fontFamily": "Inter",
                    "fontSize": "12px",
                    "fontStyle": "normal",
                    "fontWeight": 500,
                    "height": node.get("height", default_h),
                    "textAlign": "center",
                    "textDecoration": "none",
                    "width": node.get("width", default_w)
                }

            node["data"]["style"]["height"] = node.get("height", default_h)
            node["data"]["style"]["width"] = node.get("width", default_w)
            node["height"] = node["data"]["style"]["height"]
            node["width"] = node["data"]["style"]["width"]
            node["style"] = {"height": node["height"], "width": node["width"]}

        for node in nodes:
            if isinstance(node, dict) and node.get("type") == "group":
                nid = node.get("id")
                count = child_counters.get(nid, 0)
                if count > 0:
                    cols = min(count, 4)
                    rows = (count - 1) // 4 + 1
                    min_w = 40 + (cols * 200)
                    min_h = 80 + (rows * 150)

                    node["data"]["style"]["width"] = max(node["data"]["style"].get("width", 800), min_w)
                    node["data"]["style"]["height"] = max(node["data"]["style"].get("height", 500), min_h)
                    node["width"] = node["data"]["style"]["width"]
                    node["height"] = node["data"]["style"]["height"]
                    node["style"] = {"height": node["height"], "width": node["width"]}

        edges = asset.get("template", {}).get("edges", [])
        if not isinstance(edges, list):
            edges = []

        for edge in edges:
            if not isinstance(edge, dict):
                continue

            src_raw = edge.get("source", "")
            if src_raw in node_id_map:
                src = node_id_map[src_raw]
            elif src_raw in label_id_map:
                src = label_id_map[src_raw]
            else:
                src = src_raw

            tgt_raw = edge.get("target", "")
            if tgt_raw in node_id_map:
                tgt = node_id_map[tgt_raw]
            elif tgt_raw in label_id_map:
                tgt = label_id_map[tgt_raw]
            else:
                tgt = tgt_raw

            edge["source"] = src
            edge["target"] = tgt
            edge["sourceHandle"] = edge.get("sourceHandle", "b")
            edge["targetHandle"] = edge.get("targetHandle", "right")

            sh = edge["sourceHandle"]
            th = edge["targetHandle"]

            old_edge_id = edge.get("id", "")
            new_edge_id = f"reactflow__edge-{src}{sh}-{tgt}{th}"
            edge["id"] = new_edge_id
            if old_edge_id:
                edge_id_map[old_edge_id] = new_edge_id

            edge["type"] = edge.get("type", "step")
            edge["animated"] = edge.get("animated", True)
            edge["selected"] = edge.get("selected", False)

            if "properties" not in edge or not isinstance(edge.get("properties"), list):
                edge["properties"] = ["Integrity"]
            else:
                clean_props = []
                for p in edge["properties"]:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", "Integrity")))
                    elif isinstance(p, str):
                        clean_props.append(p)
                edge["properties"] = clean_props if clean_props else ["Integrity"]

            if "data" not in edge or not isinstance(edge.get("data"), dict):
                edge["data"] = {}
            if "label" not in edge["data"]:
                edge["data"]["label"] = edge.get("label", edge.get("name", "Connection"))
            edge["data"]["offset"] = 0
            edge["data"]["t"] = 0.5
            edge["markerEnd"] = edge.get("markerEnd", {
                "color": "#64B5F6", "height": 18, "type": "arrowclosed", "width": 18
            })
            edge["markerStart"] = edge.get("markerStart", {
                "color": "#64B5F6", "height": 18, "orient": "auto-start-reverse", "type": "arrowclosed", "width": 18
            })
            edge["style"] = edge.get("style", {
                "end": True, "start": True, "stroke": "#808080",
                "strokeDasharray": "0", "strokeWidth": 2
            })

        if "Details" not in asset or not isinstance(asset.get("Details"), list) or not asset["Details"]:
            asset["Details"] = []
            for node in asset.get("template", {}).get("nodes", []):
                if not isinstance(node, dict):
                    continue
                if node.get("type") != "group":
                    props = node.get("properties", ["Integrity"])
                    if not isinstance(props, list):
                        props = ["Integrity"]

                    node_data = node.get("data", {})
                    node_label = node_data.get("label", "Unknown") if isinstance(node_data, dict) else "Unknown"
                    node_desc = node_data.get("description", None) if isinstance(node_data, dict) else None

                    asset["Details"].append({
                        "nodeId": node.get("id"),
                        "name": node_label,
                        "desc": node_desc,
                        "type": node.get("type", "default"),
                        "props": [{"name": p, "id": str(uuid.uuid4())} for p in props if isinstance(p, str)]
                    })
        else:
            for detail in asset["Details"]:
                if not isinstance(detail, dict):
                    continue

                nid_raw = detail.get("nodeId", "")
                if nid_raw in node_id_map:
                    detail["nodeId"] = node_id_map[nid_raw]
                elif nid_raw in label_id_map:
                    detail["nodeId"] = label_id_map[nid_raw]
                else:
                    detail["nodeId"] = nid_raw

                if "props" not in detail or not isinstance(detail.get("props"), list) or not detail["props"]:
                    sec_props = detail.get("securityProperties", [])
                    if isinstance(sec_props, list) and sec_props:
                        detail["props"] = [{"name": p, "id": str(uuid.uuid4())} for p in sec_props if isinstance(p, str)]
                    else:
                        detail["props"] = [{"name": "Integrity", "id": str(uuid.uuid4())}]

                for prop in detail.get("props", []):
                    if not isinstance(prop, dict):
                        continue
                    pid = str(prop.get("id", ""))
                    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', pid):
                        prop["id"] = str(uuid.uuid4())

    def _remap(old_nid):
        if not old_nid:
            return old_nid
        if isinstance(old_nid, dict):
            old_nid = old_nid.get("id", old_nid.get("nodeId", ""))

        if old_nid in node_id_map:
            return node_id_map[old_nid]
        if old_nid in label_id_map:
            return label_id_map[old_nid]
        if str(old_nid).lower() in label_id_map:
            return label_id_map[str(old_nid).lower()]
        if old_nid in edge_id_map:
            return edge_id_map[old_nid]

        return old_nid

            # ── Process threat scenarios ─────────────────────────────────────────
    raw_ts_data = state.get("threat_scenarios", [])
    
    # Extract derived and user-defined threat scenarios from agent output
    derived_ts_details = []
    user_defined_ts_details = []

    # Build a lookup: DS id string (e.g. "DS001") → {damage_key, damage_name, id}
    # Source: state["damage_details"] which holds the User-defined DS list produced
    # by damage_scenario_node. These items carry key + Name reliably.
    _ds_id_to_damage_info: dict = {}
    for _dd in state.get("damage_details", []):
        if not isinstance(_dd, dict):
            continue
        _key = _dd.get("key")
        _name = _dd.get("Name", _dd.get("name", ""))
        if _key is not None and _name:
            _k = int(_key)
            _ds_id_str = f"DS{_k:03d}"
            _ds_id_to_damage_info[_ds_id_str] = {
                "id": _ds_id_str,
                "damage_key": _k,
                "damage_name": _name,
            }

    def _resolve_damage_info(row: dict) -> dict:
        """Return {id, damage_key, damage_name} for a derived TS row.

        Resolution order (most-to-least reliable):
        1. id-string parse  → lookup in _ds_id_to_damage_info  (DS001 → key 1 → Name)
        2. existing damage_key on the row → lookup in _ds_id_to_damage_info
        3. Whatever is already on the row (partial, no-op)
        """
        ds_id = row.get("id", "")

        # 1. Parse numeric key from DS id string and look up the name
        if ds_id.upper().startswith("DS"):
            try:
                parsed_key = int(ds_id[2:])
                info = _ds_id_to_damage_info.get(f"DS{parsed_key:03d}")
                if info:
                    return info
                # Key exists but name not in map — still fill what we can
                return {"id": f"DS{parsed_key:03d}", "damage_key": parsed_key, "damage_name": ""}
            except ValueError:
                pass

        # 2. damage_key already on the row
        existing_key = row.get("damage_key")
        if existing_key is not None:
            info = _ds_id_to_damage_info.get(f"DS{int(existing_key):03d}")
            if info:
                return info

        # 3. Nothing resolved
        return {}

    if isinstance(raw_ts_data, list):
        for block in raw_ts_data:
            if not isinstance(block, dict):
                continue
            btype = block.get("type", "").lower()
            if btype == "derived":
                details = block.get("Details", [])
                if isinstance(details, list):
                    for row in details:
                        fixed_row = _fix_derived_row_structure(row)
                        if fixed_row:
                            info = _resolve_damage_info(fixed_row)
                            if info.get("damage_key") is not None:
                                fixed_row["damage_key"] = info["damage_key"]
                            if info.get("damage_name"):
                                fixed_row["damage_name"] = info["damage_name"]
                            if info.get("id"):
                                fixed_row["id"] = info["id"]
                            derived_ts_details.append(fixed_row)
            elif btype in ("user-defined", "user_defined"):
                details = block.get("Details", [])
                if isinstance(details, list):
                    user_defined_ts_details = details

    # ── FIX: Preserve the correct data structure ─────────────────────────
    # The derived_ts_details from threat_scenario_agent_node are already in the correct format:
    # [
    #   {
    #     "rowId": "uuid",
    #     "id": "DS001",
    #     "Details": [
    #       {"node": "CodeFlash", "nodeId": "...", "props": [...], "name": "..."},
    #       {"node": "DataFlash", "nodeId": "...", "props": [...], "name": "..."}
    #     ]
    #   }
    # ]
    
    # Remap nodeIds within derived threat scenarios to match current architecture
    for row in derived_ts_details:
        if not isinstance(row, dict):
            continue
        # Remap the rowId
        if "rowId" in row:
            old_row_id = row["rowId"]
            
        # Remap nodeIds in each Detail item
        if "Details" in row and isinstance(row["Details"], list):
            for item in row["Details"]:
                if isinstance(item, dict):
                    item["nodeId"] = _remap(item.get("nodeId"))
                    
                    # Remap prop IDs
                    for p in item.get("props", []):
                        if isinstance(p, dict):
                            if not re.match(r'^[0-9a-f]{8}-', str(p.get("id", ""))):
                                p["id"] = str(uuid.uuid4())
                            # Ensure ref_threat_id is set
                            if "ref_threat_id" not in p and "id" in p:
                                p["ref_threat_id"] = p.get("id")

    # Deduplicate derived scenarios
    if derived_ts_details:
        seen_rowids = set()
        dedup_derived = []
        for detail in derived_ts_details:
            rowid = detail.get("rowId")
            if not rowid or rowid not in seen_rowids:
                if rowid:
                    seen_rowids.add(rowid)
                dedup_derived.append(detail)
        derived_ts_details = dedup_derived
        print(f"  ✅ Derived threat scenarios deduplicated: {len(derived_ts_details)} unique rows")

    # Deduplicate user-defined scenarios
    if user_defined_ts_details:
        seen_ids = set()
        seen_names = set()
        dedup_user = []
        for detail in user_defined_ts_details:
            threat_id = detail.get("id", "")
            threat_name = detail.get("name", "")
            is_duplicate = (threat_id and threat_id in seen_ids) or (threat_name and threat_name in seen_names)
            if not is_duplicate:
                if threat_id:
                    seen_ids.add(threat_id)
                if threat_name:
                    seen_names.add(threat_name)
                dedup_user.append(detail)
        user_defined_ts_details = dedup_user
        print(f"  ✅ User-defined threat scenarios deduplicated: {len(user_defined_ts_details)} unique scenarios")

    # Remap user-defined threat_ids
    for dd in user_defined_ts_details:
        if "threat_ids" in dd and isinstance(dd["threat_ids"], list):
            for t_id in dd["threat_ids"]:
                if isinstance(t_id, dict):
                    t_id["nodeId"] = _remap(t_id.get("nodeId"))

    # ── Process damage details ───────────────────────────────────────────
    raw_damage_details = state.get("damage_details", [])
    if not isinstance(raw_damage_details, list):
        raw_damage_details = []

    # Remap nodeIds in damage details
    for block in raw_damage_details:
        if not isinstance(block, dict):
            continue
        if "nodeId" in block:
            block["nodeId"] = _remap(block.get("nodeId"))
        cyber_losses = block.get("cyberLosses", block.get("cyberlosses", []))
        if isinstance(cyber_losses, list):
            for cl in cyber_losses:
                if isinstance(cl, dict):
                    cl["nodeId"] = _remap(cl.get("nodeId"))
                    if not cl.get("id") or not re.match(r'^[0-9a-f]{8}-', str(cl.get("id", ""))):
                        cl["id"] = str(uuid.uuid4())

    # ── Process threats ──────────────────────────────────────────────────
    raw_threats = state.get("threats", [])
    if not isinstance(raw_threats, list):
        raw_threats = []

    for t in raw_threats:
        if isinstance(t, dict):
            t["nodeId"] = _remap(t.get("nodeId"))

    # ── Build asset details ──────────────────────────────────────────────
    first_asset = unified_assets[0] if unified_assets else {}
    if not isinstance(first_asset, dict):
        first_asset = {}

    if "Details" not in first_asset or not isinstance(first_asset.get("Details"), list) or not first_asset["Details"]:
        asset_details = []
        for node in first_asset.get("template", {}).get("nodes", []):
            if not isinstance(node, dict):
                continue
            if node.get("type") != "group":
                props = node.get("properties", ["Integrity"])
                if not isinstance(props, list):
                    props = ["Integrity"]

                node_data = node.get("data", {})
                node_label = node_data.get("label", "Unknown") if isinstance(node_data, dict) else "Unknown"

                asset_details.append({
                    "nodeId": node.get("id"),
                    "name": node_label,
                    "desc": None,
                    "type": node.get("type", "default"),
                    "props": [{"name": p, "id": str(uuid.uuid4())} for p in props if isinstance(p, str)]
                })
        for edge in first_asset.get("template", {}).get("edges", []):
            if not isinstance(edge, dict):
                continue
            props = edge.get("properties", ["Integrity"])
            if not isinstance(props, list):
                props = ["Integrity"]

            edge_data = edge.get("data", {})
            edge_label = edge_data.get("label", "Connection") if isinstance(edge_data, dict) else "Connection"

            asset_details.append({
                "nodeId": edge.get("id", ""),
                "name": edge_label,
                "desc": None,
                "type": "step",
                "props": [{"name": p, "id": str(uuid.uuid4())} for p in props if isinstance(p, str)]
            })
        first_asset["Details"] = asset_details

    # ── Build damage scenario derivations ─────────────────────────────────
    ds_derivations = []
    ds_counter = 1
    for detail in first_asset.get("Details", []):
        if not isinstance(detail, dict):
            continue
        for prop in detail.get("props", []):
            if not isinstance(prop, dict):
                continue

            prop_name = prop.get("name", "Integrity")
            detail_name = detail.get("name", "Component")

            ds_derivations.append({
                "id": f"DS{ds_counter:03}",
                "task": f"Check for DS due to the loss of {prop_name} for {detail_name}",
                "name": f"DS due to the loss of {prop_name} for {detail_name}",
                "loss": f"loss of {prop_name}",
                "asset": False,
                "damageScene": [],
                "nodeId": detail.get("nodeId", ""),
                "is_checked": None
            })
            ds_counter += 1

    # Backfill damageScene in each derivation from threat scenario rowIds
    ds_id_to_row_ids = {}
    for ts_row in derived_ts_details:
        if not isinstance(ts_row, dict):
            continue
        ds_id = ts_row.get("id", "")
        row_id = ts_row.get("rowId", "")
        if ds_id and row_id:
            ds_id_to_row_ids.setdefault(ds_id, [])
            if row_id not in ds_id_to_row_ids[ds_id]:
                ds_id_to_row_ids[ds_id].append(row_id)

    for derivation in ds_derivations:
        ds_id = derivation.get("id", "")
        row_ids = ds_id_to_row_ids.get(ds_id, [])
        if row_ids:
            derivation["damageScene"] = row_ids

    # ── Reorder assets ───────────────────────────────────────────────────
    reordered_assets = []
    for asset in unified_assets:
        if not isinstance(asset, dict):
            continue
        ordered = {
            "_id": asset.get("_id", str(uuid.uuid4())),
            "user_id": asset.get("user_id", uid),
            "model_id": asset.get("model_id", mid),
            "template": asset.get("template", {"nodes": [], "edges": []}),
            "Details": asset.get("Details", []),
            "asset_name": asset.get("asset_name", None),
            "asset_properties": asset.get("asset_properties", None)
        }
        reordered_assets.append(ordered)
    unified_assets = reordered_assets

    # ── Build user-defined damage scenarios ──────────────────────────────
    user_defined_ds_details = []
    for block in raw_damage_details:
        if isinstance(block, dict) and block.get("type") == "User-defined":
            details = block.get("Details", [])
            if isinstance(details, list):
                user_defined_ds_details = details
            break

    if not user_defined_ds_details:
        user_defined_ds_details = raw_damage_details if isinstance(raw_damage_details, list) else []

    safe_user_defined = []
    for i, dd in enumerate(user_defined_ds_details):
        if not isinstance(dd, dict):
            continue
        cyber_losses = dd.get("cyberLosses", dd.get("cyberlosses", []))
        if not isinstance(cyber_losses, list):
            cyber_losses = []

        safe_losses = []
        for cl in cyber_losses:
            if not isinstance(cl, dict):
                continue
            safe_losses.append({
                "id": cl.get("id", str(uuid.uuid4())),
                "is_risk_added": cl.get("is_risk_added", True),
                "name": cl.get("name", "Integrity"),
                "isSelected": cl.get("isSelected", True),
                "node": cl.get("node", "Component"),
                "nodeId": _remap(cl.get("nodeId", ""))
            })

        impacts = dd.get("impacts", {})
        if not isinstance(impacts, dict):
            impacts = {}

        ds_name = dd.get("Name", dd.get("name", ""))
        if not ds_name:
            ds_name = f"Damage Scenario DS{i+1:03}"

        safe_user_defined.append({
            "Description": dd.get("Description", dd.get("description", "")),
            "Name": ds_name,
            "cyberLosses": safe_losses,
            "impacts": {
                "Financial Impact": impacts.get("Financial Impact", "Severe"),
                "Safety Impact": impacts.get("Safety Impact", "Severe"),
                "Operational Impact": impacts.get("Operational Impact", "Severe"),
                "Privacy Impact": impacts.get("Privacy Impact", "Negligible")
            },
            "key": i + 1,
            "_id": dd.get("_id", str(uuid.uuid4()))
        })

    # ── BUILD FINAL OUTPUT ───────────────────────────────────────────────
    final_output = {
        "Models": [
            {
                "_id": mid,
                "user_id": uid,
                "name": state.get("user_query", "BatteryManagement"),
                "template": [],
                "created_by": "prabhu.desai@gmail.com",
                "Created_at": "2025-03-28T14:07:06.485Z",
                "last_updated": "2025-03-28T14:07:07Z",
                "status": 1
            }
        ],
        "Assets": unified_assets,
        "Damage_scenarios": [
            {
                "_id": "698397514b57b8f24ed40a4b",
                "model_id": mid,
                "type": "Derived",
                "Derivations": ds_derivations,
                "Details": first_asset.get("Details", []) if isinstance(first_asset, dict) else [],
                "user_id": uid
            },
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "User-defined",
                "Details": safe_user_defined,
                "user_id": uid
            }
        ],
        "Threat_scenarios": [
            {
                "_id": "698397514b57b8f24ed40a4e",
                "model_id": mid,
                "type": "derived",
                "Details": derived_ts_details,  # FIX: Use the already-correct format from threat_scenario_agent_node
                "user_id": uid
            },
            {
                "_id": str(uuid.uuid4()),
                "model_id": mid,
                "type": "User-defined",
                "Details": user_defined_ts_details,
                "user_id": uid
            }
        ]
    }

    # ── Link attack tree threat_ids to derived threat scenario rowIds ────
    try:
        threat_to_rowid = {}
        for block in final_output["Threat_scenarios"][0]["Details"]:
            if not isinstance(block, dict):
                continue
            for detail in block.get("Details", []):
                if not isinstance(detail, dict):
                    continue
                props = detail.get("props", [])
                p_name = props[0].get("name", "") if props and isinstance(props[0], dict) else ""
                key = f"{detail.get('nodeId', '')}_{p_name}"
                threat_to_rowid[key] = block.get("rowId", "")
    except Exception as e:
        print(f"  ⚠️  RowId linking skipped/failed: {e}")

    answer = json.dumps(final_output, indent=2)

    # ── Evaluation scoring ───────────────────────────────────────────────
    first_asset = unified_assets[0] if unified_assets else {}
    nodes = first_asset.get("template", {}).get("nodes", []) if isinstance(first_asset, dict) else []
    derivations = ds_derivations
    threats = state.get("threats", [])

    score = 20
    if nodes:       score += 30
    if derivations: score += 25
    if threats:     score += 25

    retry = state.get("retry_count", 0)
    print(f"  EVALUATION: Multi-agent score {score}% (retry {retry})")

    eval_details = {
        "final_score": score,
        "retry_attempt": retry,
        "nodes_count": len(nodes) if isinstance(nodes, list) else 0,
        "derivations_count": len(derivations) if isinstance(derivations, list) else 0,
        "threat_scenarios_count": len(derived_ts_details),
        "item_definition_details_count": len(first_asset.get("Details", [])) if isinstance(first_asset, dict) else 0,
        "passed_quality_check": score >= 50
    }

    return {"eval_score": score, "eval_details": eval_details, "answer": answer}


def build_graph(all_docs):
    global retriever, generator, text_embedder
    retriever, generator, text_embedder = setup(all_docs)

    builder = StateGraph(RAGState)

    builder.add_node("retrieve", retrieve)
    builder.add_node("architect", architect_node)
    builder.add_node("threats", threat_analysis_node)
    builder.add_node("damage", damage_scenario_node)
    builder.add_node("threat_scenarios", threat_scenario_agent_node)
    builder.add_node("attacks", generate_attack_trees_node)
    builder.add_node("evaluate", evaluate)

    builder.set_entry_point("retrieve")
    builder.add_edge("retrieve", "architect")
    builder.add_edge("architect", "threats")
    builder.add_edge("threats", "damage")
    builder.add_edge("damage", "threat_scenarios")
    builder.add_edge("threat_scenarios", "attacks")
    builder.add_edge("attacks", "evaluate")
    builder.add_edge("evaluate", "__end__")

    return builder.compile()