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
import time

from app.v1.rag.components import build_store, build_retriever, build_generator
from app.v1.rag.config import RETRIEVER_TOP_K
from app.v1.rag.prompt import TARA_PROMPT_TEMPLATE

# ── GLOBAL CONFIGURATION (Change these to adjust output depth) ───────────────
MAX_NODES       = 14   # Component nodes to generate (excluding groups)
MAX_EDGES       = 11   # Number of edges/connections
MAX_GROUPS      = 4    # Maximum number of group containers
MAX_THREATS     = 5    # Number of technical threat derivations (Agent 2)
MAX_SCENARIOS   = 5    # Number of STRIDE-mapped scenarios (Agent 3)

MIN_QUALITY_NODES = 3  # Minimum nodes required to pass quality check
MIN_QUALITY_TS    = 3  # Minimum scenarios required to pass quality check
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

# ---------------- STATE ----------------
class RAGState(TypedDict):
    user_query: str
    enriched_query: str
    documents: list
    architecture: dict       # High-quality system design
    threats: list            # Detailed threat analysis
    damage_details: list     # Impact/damage details per threat
    threat_scenarios: list   # Automated Threat Scenarios
    attacks: list            # React Flow attack trees
    answer: str              # Final Combined JSON
    retry_count: int
    full_prompt: str
    eval_score: int
    eval_details: dict

# ---------------- SETUP ----------------
def setup(all_docs):
    store, text_embedder = build_store(all_docs)
    retriever = build_retriever(store)
    generator = build_generator()
    return retriever, generator, text_embedder

def safe_generate(prompt: str, role_name: str = "Agent"):
    """Thin wrapper to handle Gemini free-tier rate limits with auto-sleep and deep retries."""
    max_retries = 5  # Increased for better persistence
    for attempt in range(max_retries):
        try:
            return generator.run(parts=[prompt])
        except ResourceExhausted as e:
            # Deep back-off for free tier
            wait_time = 90 + (attempt * 60) 
            msg = str(e)
            if "retry in" in msg:
                try:
                    match = re.search(r"retry in ([\d.]+)", msg)
                    if match:
                        wait_time = int(float(match.group(1))) + 5
                except:
                    pass
            
            print(f"  ⚠️  {role_name} Quota hit (Attempt {attempt+1}/{max_retries}). Sleeping {wait_time}s...")
            time.sleep(wait_time)
        except Exception as e:
            print(f"  ❌ {role_name} error: {e}")
            time.sleep(10) # Small cooldown on generic errors
    return {"replies": ["Failed due to repeated quota errors."]}

def log_prompt(node_name: str, context: list, prompt: str, response: str):
    """Logs everything goig from RAG to LLM in outputs/prompts"""
    log_dir = os.path.join("outputs", "prompts")
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = str(int(time.time()))
    filename = f"{timestamp}_{node_name}.txt"
    filepath = os.path.join(log_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== {node_name.upper()} LOG ===\n")
        f.write(f"RAG CONTEXT (First 3 docs):\n")
        for i, doc in enumerate(context[:3]):
            content = getattr(doc, 'content', str(doc))
            f.write(f"DOC {i}: {content[:300]}...\n")
        f.write("\n--- PROMPT ---\n")
        f.write(prompt)
        f.write("\n\n--- AI RESPONSE ---\n")
        f.write(response)
        f.write("\n" + "="*50 + "\n")

# ---------------- QUALITY-AWARE RETRY ----------------

MIN_NODES       = MIN_QUALITY_NODES
MIN_THREATS     = MIN_QUALITY_TS
MIN_DETAILS     = MIN_QUALITY_TS
MIN_SCENARIOS   = MIN_QUALITY_TS


def _score_section(state: RAGState) -> dict:
    """Per-section quality flags."""
    arch  = state.get("architecture", {})
    all_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    nodes = [n for n in all_nodes if n.get("type") != "group"]
    threats   = state.get("threats", [])
    details   = state.get("damage_details", [])
    scenarios = state.get("threat_scenarios", [])
    return {
        "arch_ok":      len(nodes)     >= MIN_NODES,
        "threats_ok":   len(threats)   >= MIN_THREATS,
        "details_ok":   len(details)   >= MIN_DETAILS,
        "scenarios_ok": len(scenarios) >= MIN_SCENARIOS,
        "node_count":      len(nodes),
        "threat_count":    len(threats),
        "detail_count":    len(details),
        "scenario_count":  len(scenarios),
    }


def _should_retry(state: RAGState) -> str:
    """Quality-aware conditional edge.
    
    Checks each section against minimum quality thresholds.
    If any section fails AND we have retries left → retry.
    On retry, only FAILING sections are cleared from cache,
    so passing sections are served from cache (no wasted tokens).
    """
    retry     = state.get("retry_count", 0)
    max_retry = 2   # up to 2 reflection passes
    qc        = _score_section(state)

    failing = [k for k, v in qc.items() if k.endswith("_ok") and not v]

    print(f"  🔍 Quality Check | nodes={qc['node_count']} threats={qc['threat_count']} "
          f"details={qc['detail_count']} scenarios={qc['scenario_count']}")

    if failing and retry < max_retry:
        print(f"  🔁 Sections below threshold: {failing} — "
              f"retrying (attempt {retry+1}/{max_retry}) [cached sections preserved]")
        return "retry"
    elif failing:
        print(f"  ⚠️  Max retries reached. Accepting output (failing: {failing}).")
        return "done"
    else:
        print(f"  ✅ All sections passed quality check!")
        return "done"


def _bump_retry(state: RAGState):
    """Selectively clear ONLY failing sections from cache.
    
    Passing sections stay cached → their nodes return instantly from cache.
    Failing sections are evicted → their nodes will call the API again.
    """
    from app.v1.rag.cache_manager import get_cache_key
    query  = state.get("user_query", "")
    retry  = state.get("retry_count", 0) + 1
    qc     = _score_section(state)

    # Map section name to: (cache_step_key, state_key_to_clear)
    section_map = {
        "arch_ok":      ("architect",  "architecture"),
        "threats_ok":   ("threats",    "threats"),
        "details_ok":   ("damage",     "damage_details"),
        "scenarios_ok": (None,         "threat_scenarios"),  # deterministic, no cache key
    }

    reset_state = {"retry_count": retry}

    for flag, (cache_step, state_key) in section_map.items():
        if not qc.get(flag, True):   # section FAILED quality check
            print(f"  🗑️  Evicting cache for failing section: {state_key}")
            if cache_step:
                cache_file = get_cache_key(query, cache_step)
                if os.path.exists(cache_file):
                    os.remove(cache_file)
            reset_state[state_key] = [] if state_key != "architecture" else {}
        else:
            print(f"  💾 Keeping cache for passing section: {state_key}")

    return reset_state

def retrieve(state: RAGState):
    """Retrieves relevant documents using the Haystack retriever."""
    query = state.get("enriched_query") or state.get("user_query")
    embedding = text_embedder.run(text=query)["embedding"]
    result = retriever.run(query_embedding=embedding)
    # Safety: ensure we don't pass massive content if context is bloated
    docs = result["documents"][:RETRIEVER_TOP_K]
    return {"documents": docs}

def architect_node(state: RAGState):
    """Deep technical discovery to build the system architecture."""
    query = state.get("user_query", "") or state.get("query", "")

    from app.v1.rag.prompt import ARCHITECT_PROMPT
    from app.v1.rag.components import resolve_ecu, resolve_reference_report, build_ref_context

    ecu_entry = resolve_ecu(query)
    if ecu_entry:
        print(f"  🔍 ECU resolved: {ecu_entry.get('name', '?')}")
    else:
        print("  ℹ️  No ECU match — proceeding without ECU hint.")

    reference_data = resolve_reference_report(ecu_entry, query)

    ref_context, ecu_hint_context = build_ref_context(reference_data, ecu_entry)

    # ── BUILD REFERENCE PROPERTIES MAP ──
    # If we have reference data, extract node properties to enforce in output
    ref_properties_map = {}
    ref_edge_properties_map = {}
    
    if reference_data:
        ref_assets = reference_data.get("Assets", [])
        if ref_assets:
            ref_asset = ref_assets[0] if isinstance(ref_assets, list) else ref_assets
            ref_template = ref_asset.get("template", {})
            ref_nodes = ref_template.get("nodes", [])
            ref_edges = ref_template.get("edges", [])
            
            # ✅ FIX: Map properties by both label AND spatial position (fingerprint)
            for node in ref_nodes:
                label = node.get("data", {}).get("label", "")
                props = node.get("properties", None)
                pos = node.get("position", {})
                pos_key = f"{pos.get('x')}_{pos.get('y')}"
                
                if props is not None:
                    if label:
                        ref_properties_map[label.lower()] = props
                    if pos_key and pos_key != "None_None":
                        ref_properties_map[pos_key] = props
                        print(f"  📋 Ref node fingerprint '{pos_key}' properties: {props}")
            
            # Build edge properties map by label
            for edge in ref_edges:
                label = edge.get("data", {}).get("label", edge.get("label", ""))
                props = edge.get("properties", None)
                if label and props is not None:
                    ref_edge_properties_map[label.lower()] = props
                    print(f"  📋 Ref edge '{label}' properties: {props}")

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
    
    # Save the architect prompt for debugging
    prompt_file = f"architect_prompt_{query.replace(' ', '_')}.txt"
    with open(prompt_file, "w", encoding="utf-8") as f:
        f.write(prompt)
    print(f"  📝 Saved architect prompt to {prompt_file}")
    
    result = safe_generate(prompt, "Architect")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_prompt("architect_node", state["documents"], prompt, raw_json)
    
    # Cooldown
    time.sleep(10)
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        arch_data = json.loads(cleaned)
        
        # Flexibly find architecture data
        if "template" in arch_data:
            assets = arch_data
        elif "Assets" in arch_data:
            a = arch_data["Assets"]
            assets = a[0] if isinstance(a, list) and a else a
        elif "assets" in arch_data:
            a = arch_data["assets"]
            assets = a[0] if isinstance(a, list) and a else a
        else:
            assets = arch_data
        
        # ── ENFORCEMENT: trim to EXACTLY MAX_NODES and MAX_EDGES ──────
        template = assets.get("template", {})
        nodes = template.get("nodes", assets.get("nodes", []))

        if not nodes:
            print(f"  ❌ Architect FAIL: No nodes found.")
            return {"architecture": {}}
        
        # ── APPLY REFERENCE PROPERTIES TO NODES ──
        for node in nodes:
            ntype = node.get("type", "default")
            if ntype == "group":
                # Groups don't need security properties
                if "properties" not in node:
                    node["properties"] = []
                continue
            
            node_label = node.get("data", {}).get("label", "")
            pos = node.get("position", {})
            pos_key = f"{pos.get('x')}_{pos.get('y')}"
            
            # ✅ FIX: Check position fingerprint first, then label fallback
            if pos_key in ref_properties_map:
                node["properties"] = ref_properties_map[pos_key]
                print(f"  📋 Applied ref properties via position to '{node_label}': {node['properties']}")
            elif node_label.lower() in ref_properties_map:
                node["properties"] = ref_properties_map[node_label.lower()]
                print(f"  📋 Applied ref properties via label to '{node_label}': {node['properties']}")
            elif "properties" not in node or node["properties"] is None:
                # No reference match and no LLM properties - use defaults
                node["properties"] = ["Integrity", "Confidentiality", "Authenticity", 
                                     "Authorization", "Availability", "Non-repudiation"]
                print(f"  ⚠️ No ref match for '{node_label}', using defaults")
        
        # ── APPLY REFERENCE PROPERTIES TO EDGES ──
        edges = template.get("edges", [])
        for edge in edges:
            edge_label = edge.get("data", {}).get("label", edge.get("label", ""))
            
            if edge_label.lower() in ref_edge_properties_map:
                ref_props = ref_edge_properties_map[edge_label.lower()]
                edge["properties"] = ref_props
                print(f"  📋 Applied ref edge properties to '{edge_label}': {ref_props}")
            elif "properties" not in edge or edge["properties"] is None:
                edge["properties"] = ["Integrity"]
        
        # Separate groups from components
        group_nodes = [n for n in nodes if n.get("type") == "group"]
        component_nodes = [n for n in nodes if n.get("type") != "group"]

        print(f"  📊 LLM generated: {len(component_nodes)} components, {len(group_nodes)} groups")
        
        # ENFORCE MAX GROUPS
        if len(group_nodes) > MAX_GROUPS:
            print(f"  ✂️  Trimming {len(group_nodes)} groups → {MAX_GROUPS} (MAX_GROUPS)")
            group_nodes = group_nodes[:MAX_GROUPS]
        
        # ENFORCE EXACT COMPONENT COUNT
        if len(component_nodes) > MAX_NODES:
            print(f"  ✂️  Trimming {len(component_nodes)} → {MAX_NODES} components")
            component_nodes = component_nodes[:MAX_NODES]
        elif len(component_nodes) < MAX_NODES:
            print(f"  ⚠️  WARNING: Only {len(component_nodes)} components (target: {MAX_NODES})")

        # Combine back
        trimmed_nodes = group_nodes + component_nodes
        kept_ids = {n["id"] for n in trimmed_nodes}

        # Process edges
        print(f"  📊 LLM generated: {len(edges)} edges")
        
        # Filter edges that reference kept nodes
        valid_edges = [
            e for e in edges
            if e.get("source") in kept_ids and e.get("target") in kept_ids
        ]
        
        print(f"  🔗 After filtering dangling edges: {len(valid_edges)} edges")
        
        # ENFORCE EXACT EDGE COUNT
        if len(valid_edges) > MAX_EDGES:
            print(f"  ✂️  Trimming {len(valid_edges)} → {MAX_EDGES} edges")
            valid_edges = valid_edges[:MAX_EDGES]
        elif len(valid_edges) < MAX_EDGES:
            print(f"  ⚠️  WARNING: Only {len(valid_edges)} edges (target: {MAX_EDGES})")

        # Write back
        template["nodes"] = trimmed_nodes
        template["edges"] = valid_edges
        assets["template"] = template

        # Trim Details to match kept nodes
        details = assets.get("Details", [])
        if details:
            original_detail_count = len(details)
            assets["Details"] = [d for d in details if d.get("nodeId") in kept_ids]
            print(f"  📋 Trimmed details: {original_detail_count} → {len(assets['Details'])}")

        # FINAL VERIFICATION
        final_comp_count = len([n for n in trimmed_nodes if n.get("type") != "group"])
        final_edge_count = len(valid_edges)
        final_group_count = len(group_nodes)
        
        print(f"  ✅ Architect FINAL: {final_comp_count} components, "
              f"{final_group_count} groups, {final_edge_count} edges.")
        
        # Save the trimmed output for debugging
        output_file = f"architect_output_{query.replace(' ', '_')}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(assets, f, indent=2)
        print(f"  📝 Saved trimmed output to {output_file}")
        
        # Only cache if it meets requirements
        if final_comp_count == MAX_NODES and final_edge_count == MAX_EDGES:
            save_cache(query, "architect", assets)
            print(f"  💾 Cached valid architecture")
        else:
            print(f"  ⚠️  NOT caching - counts don't match targets")
        
        return {"architecture": assets}
        
    except Exception as e:
        print(f"Architect parsing failed: {e}. Raw: {raw_json[:200]}")
        import traceback
        traceback.print_exc()
        return {"architecture": {}}

def threat_analysis_node(state: RAGState):
    """Deep technical threat discovery."""
    query = state.get("user_query", "") or state.get("query", "")
    
    # Check cache first
    cached = load_cache(query, "threats")
    if cached: return {"threats": cached}
    
    # Bootstrap check - scan results folder for any matching file
    # res_dir = os.path.join("outputs", "Results")
    # if os.path.exists(res_dir):
    #     for filename in os.listdir(res_dir):
    #         if query.lower().replace(" ", "") in filename.lower().replace(" ", ""):
    #             res_path = os.path.join(res_dir, filename)
    #             with open(res_path, "r") as f:
    #                 data = json.load(f)
    #                 threats = data.get("threat_scenarios", []) or data.get("damage_scenarios", {}).get("Derivations", [])
    #                 if threats: 
    #                     print(f"  ⚡ Bootstrapped Threat result from {filename}!")
    #                     save_cache(query, "threats", threats)
    #                     return {"threats": threats}

    from app.v1.rag.prompt import THREAT_PROMPT
    if not state.get("architecture"): return {"threats": []}
    
    print(f" Analyzing threats (Target: {MAX_THREATS} derivations)...")
    tmpl = jinja2.Template(THREAT_PROMPT)
    prompt = tmpl.render(
        question=state["user_query"],
        architecture=json.dumps(state["architecture"], indent=2),
        documents=state["documents"],
        max_threats=MAX_THREATS
    )
    
    result = safe_generate(prompt, "ThreatAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_prompt("threat_analysis_node", state["documents"], prompt, raw_json)
    
    # Cooldown
    time.sleep(10)
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        threat_data = json.loads(cleaned)
        
        # Flexibly find threats
        threats = threat_data.get("Derivations", threat_data.get("threats", threat_data.get("derivations", [])))
        if not threats and isinstance(threat_data, list):
            threats = threat_data
            
        if not threats:
            print(f"Threat Analyst FAIL: 0 threats. Snippet: {raw_json[:150]}")
        else:
            print(f"Threat Analyst SUCCESS: Found {len(threats)} threats.")
            
        return {"threats": threats}
    except Exception as e:
        print(f"Threat parsing failed: {e}. Raw: {raw_json[:200]}")
        return {"threats": []}


def generate_threat_scenarios_node(state: RAGState):
    """Generates Threat Scenarios from Damage Scenarios using STRIDE mapping.
    
    NEW: Also pulls existing threat scenarios from reference data and combines with derived ones.
    """
    print("Generating automated Threat Scenarios (STRIDE mapping)...")
    
    from app.v1.rag.components import resolve_ecu, resolve_reference_report
    query = state.get("user_query", "") or state.get("query", "")
    ecu_entry = resolve_ecu(query)
    reference_data = resolve_reference_report(ecu_entry, query)
    
    arch = state.get("architecture", {})
    arch_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    
    valid_node_labels = {n.get("data", {}).get("label", "").lower().strip(): n.get("id") 
                        for n in arch_nodes if n.get("type") != "group"}
    
    _fallback_label = next(iter(valid_node_labels), None)
    _fallback_id    = valid_node_labels.get(_fallback_label) if _fallback_label else None
    
    existing_threat_scenarios = []
    if reference_data and "Threat_scenarios" in reference_data:
        for ts_block in reference_data["Threat_scenarios"]:
            # Skip derived threats - they're auto-generated and often incomplete
            # Only pull from well-structured user-defined threats
            if ts_block.get("type") in ["User-defined", "user-defined"]:
                for detail in ts_block.get("Details", []):
                    if not isinstance(detail, dict):
                        continue
                    
                    # Skip if missing required fields
                    if not detail.get("name") or not detail.get("nodeId"):
                        continue
                    
                    ts_copy = copy.deepcopy(detail)
                    remapped_props = []
                    
                    for prop in ts_copy.get("props", []):
                        if not isinstance(prop, dict):
                            continue
                        
                        node_name = ts_copy.get("node", "")
                        matched_nid, matched_label = _match_node_label(node_name, valid_node_labels)
                        
                        if matched_nid:
                            prop["nodeId"] = matched_nid
                            ts_copy["nodeId"] = matched_nid
                            ts_copy["node"] = matched_label
                        elif _fallback_id:
                            prop["nodeId"] = _fallback_id
                            ts_copy["nodeId"] = _fallback_id
                            ts_copy["node"] = _fallback_label
                            print(f"  ⚠️  No match for '{node_name}' — assigned to '{_fallback_label}'")
                        
                        prop["id"] = str(uuid.uuid4())
                        remapped_props.append(prop)
                    
                    if remapped_props:
                        ts_copy["props"] = remapped_props
                    ts_copy["_id"] = str(uuid.uuid4())
                    existing_threat_scenarios.append(ts_copy)
    
    print(f"✅ Found {len(existing_threat_scenarios)} existing threat scenarios from reference.")
    
    damage_details = state.get("damage_details", [])
    derived_threat_scenarios = []
    
    stride_mapping = {
        "Integrity": "Tampering",
        "Confidentiality":"Information Disclosure",
        "Availability": "Denial",
        "Authenticity": "Spoofing",
        "Authorization": "Elevation of Privilege",
        "Non-repudiation": "Rejection",
    }
    
    ts_count = len(existing_threat_scenarios) + 1
    
    flat_scenarios = []
    if isinstance(damage_details, list):
        for block in damage_details:
            if not isinstance(block, dict): 
                flat_scenarios.append(block)
                continue
                
            btype = block.get("type", "")
            if btype == "Derived":
                flat_scenarios.extend(block.get("Derivations", []))
            elif btype == "User-defined":
                flat_scenarios.extend(block.get("Details", []))
            else:
                flat_scenarios.append(block)
    
    for ds_index, ds in enumerate(flat_scenarios):
        ds_id = ds.get("id", ds.get("Name", f"DS{ds_index+1:03}"))
        if not re.match(r"^DS\d+", str(ds_id)):
             ds_id = f"DS{ds_index+1:03}"
             
        ds_name = ds.get("Name", ds.get("name", "Unnamed Scenario"))
        
        losses = ds.get("cyberLosses", ds.get("cyberlosses", []))
        if not losses:
            text = (str(ds_name) + " " + str(ds.get("Description", ds.get("task", "")))).lower()
            inferred = []
            for prop in stride_mapping.keys():
                if prop.lower() in text:
                    inferred.append({"name": prop, "node": "System", "nodeId": ds.get("nodeId", "unknown")})
            losses = inferred if inferred else [{"name": "Integrity", "node": "System", "nodeId": ds.get("nodeId", "unknown")}]

        for loss in losses:
            loss_name = loss.get("name", loss.get("value", "Integrity"))
            asset_name = loss.get("node", loss.get("asset", "System"))
            threat_type = stride_mapping.get(loss_name, "Security Violation")
            
            ts_entry = {
                "node": asset_name,
                "nodeId": loss.get("nodeId", ""),
                "props": [
                    {
                        "id": str(uuid.uuid4()),
                        "is_risk_added": True,
                        "name": loss_name,
                        "isSelected": True,
                        "key": 1
                    }
                ],
                "name": f"[{ts_count:03}] {threat_type} of {asset_name}",
                "damage_scenario": f"[{ds_id}] {ds_name}",
                "id": f"TS{ts_count:03}",
            }
            derived_threat_scenarios.append(ts_entry)
            ts_count += 1
    
    combined_threat_scenarios = existing_threat_scenarios + derived_threat_scenarios
    
    print(f"📊 Threat Scenarios Summary:")
    print(f"   - Existing: {len(existing_threat_scenarios)}")
    print(f"   - Derived: {len(derived_threat_scenarios)}")
    print(f"   - Total: {len(combined_threat_scenarios)}")
    
    return {"threat_scenarios": combined_threat_scenarios}


def generate_attack_trees_node(state: RAGState):
    """Generates simplified attack trees for each threat scenario."""
    print("Generating Attack Trees (React Flow)...")
    ts_list = state.get("threat_scenarios", [])
    attacks = []
    
    def _create_node(label, name, x, y, desc="", node_type="default", threat_ids=None):
        uid = str(uuid.uuid4())
        return {
            "id": uid,
            "nodeId": uid,
            "type": "default",
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
                "connections": [{"id": str(uuid.uuid4()), "type": "OR Gate"}],
                "style": {
                    "backgroundColor": "transparent", "borderColor": "black", "borderStyle": "solid", "borderWidth": "2px",
                    "color": "black", "fontFamily": "Inter", "fontSize": "16px", "fontStyle": "normal", "fontWeight": 500,
                    "height": 60, "textAlign": "center", "textDecoration": "none", "width": 150
                }
            },
            "threat_ids": threat_ids or []
        }

    for ts in ts_list:
        nodes = []
        edges = []
        
        # Prepare threat_ids list
        # We need to find the rowId and other info from how Threat_scenarios was constructed
        # For now we use the info available in ts
        prop = ts.get("props", [{}])[0]
        t_ids = [
            {
                "damage_id": ts.get("damage_scenario", "").split("]")[0].strip("["),
                "damage_scene": ts.get("damage_scenario", "").split("]")[1].strip() if "]" in ts.get("damage_scenario", "") else "",
                "nodeId": ts.get("nodeId", ""),
                "node_name": ts.get("node", ""),
                "propId": prop.get("id", ""),
                "prop_key": prop.get("key", 1),
                "prop_name": prop.get("name", "Integrity"),
                "rowId": ts.get("rowId", "") # This will be injected during evaluate stage or we can pre-generate it
            }
        ]
        
        # Root Node
        name_only = ts.get("name", "Attack").split("]")[-1].strip()
        label = ts.get("name", "Attack")
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

def _match_node_label(node_name: str, valid_node_labels: dict):
    """
    Match a reference node name to a current-architecture node label.
    Tries exact → substring → word-overlap strategies in order.
    Returns (node_id, matched_label) or (None, None).
    """
    if not node_name:
        return None, None
    node_lower = node_name.lower().strip()

    # 1. Exact match
    if node_lower in valid_node_labels:
        return valid_node_labels[node_lower], node_lower

    # 2. Substring match (original behaviour)
    for label, nid in valid_node_labels.items():
        if node_lower in label or label in node_lower:
            return nid, label

    # 3. Word-level overlap — catches "Battery Pack ECU" ↔ "Battery Management"
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


def damage_scenario_node(state: RAGState):
    """AGENT 3: Focuses on Impact Ratings and Damage Scenarios."""
    from app.v1.rag.prompt import DAMAGE_PROMPT
    import copy
    query = state.get("user_query", "") or state.get("query", "")

    # Check cache first
    cached = load_cache(query, "damage")
    if cached:
        return {"damage_details": cached}

    if not state.get("threats"): return {"damage_details": []}
    
    # ✅ FIX: Fetch reference data and remap existing damage scenarios
    from app.v1.rag.components import resolve_ecu, resolve_reference_report
    ecu_entry = resolve_ecu(query)
    reference_data = resolve_reference_report(ecu_entry, query)
    
    arch = state.get("architecture", {})
    arch_nodes = arch.get("template", {}).get("nodes", arch.get("nodes", []))
    
    valid_node_labels = {n.get("data", {}).get("label", "").lower().strip(): n.get("id") 
                        for n in arch_nodes if n.get("type") != "group"}

    # Fallback: first available non-group node (used when no label match is found at all)
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
                        node_name = loss.get("node", "")
                        matched_nid, matched_label = _match_node_label(node_name, valid_node_labels)

                        if matched_nid:
                            # Best-case: found a matching architecture node
                            loss["nodeId"] = matched_nid
                            loss["node"]   = matched_label
                        elif _fallback_id:
                            # Fallback: map to the first available node so the
                            # scenario is never silently dropped
                            loss["nodeId"] = _fallback_id
                            loss["node"]   = _fallback_label
                            print(f"  ⚠️  No match for '{node_name}' — assigned to fallback '{_fallback_label}'")
                        # else: keep original node/nodeId intact (better than dropping)

                        loss["id"] = str(uuid.uuid4())
                        remapped_losses.append(loss)

                    # ✅ KEY FIX: ALWAYS include the scenario regardless of whether
                    # any loss matched. Dropping scenarios silently was the bug.
                    if remapped_losses:
                        detail_copy["cyberLosses"] = remapped_losses
                    detail_copy["_id"] = str(uuid.uuid4())
                    existing_scenarios.append(detail_copy)

    print(f"✅ Found {len(existing_scenarios)} valid existing damage scenarios from reference.")

    print("Assessing damage scenarios...")
    tmpl = jinja2.Template(DAMAGE_PROMPT)
    prompt = tmpl.render(
        question=state.get("user_query", "Automotive ECU System"),
        threats=json.dumps(state["threats"], indent=2),
        architecture=json.dumps(state["architecture"], indent=2)
    )
    
    # ✅ FIX: Tell LLM to generate extras if we have existing ones
    if existing_scenarios:
        prompt += f"\n\n### EXISTING SCENARIOS (DO NOT REGENERATE THESE):\n{json.dumps(existing_scenarios, indent=2)}\n\n"
        target_extras = max(3, 10 - len(existing_scenarios))
        prompt += f"Generate {target_extras} EXTRA damage scenarios covering different components. Return ONLY the new scenarios in your JSON output.\n"
    
    result = safe_generate(prompt, "DamageAnalyst")
    raw_json = result["replies"][0] if result["replies"] else "{}"
    
    # Log the RAG and LLM activity
    log_prompt("damage_scenario_node", state.get("documents", []), prompt, raw_json)
    
    # Cooldown
    time.sleep(10)
    try:
        cleaned = re.sub(r"^```[a-z]*\n?", "", raw_json.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"```$", "", cleaned.strip())
        damage_data = json.loads(cleaned)
        
        # Flexibly find Details or full structure
        if "Damage_scenarios" in damage_data:
            details = damage_data["Damage_scenarios"]
        else:
            details = damage_data.get("Details", damage_data.get("details", damage_data.get("damage_details", [])))
            
        if not details and isinstance(damage_data, list):
            details = damage_data
            
        if not details:
            print(f"DEBUG: Raw Damage Response: {raw_json[:300]}")
            print(f" Damage Analyst FAIL: No scenarios found in JSON.")
            details = []
        else:
            print(f"Damage Analyst SUCCESS: Found {len(details)} extra scenarios.")
            
        # ✅ FIX: Combine existing scenarios with the newly generated extras
        combined_details = existing_scenarios + details
        
        save_cache(query, "damage", combined_details)
        return {"damage_details": combined_details}
        
    except Exception as e:
        print(f"DEBUG: Parsing error: {e}")
        print(f"DEBUG: Raw Damage Response: {raw_json[:500]}")
        
        # If LLM failed but we have existing scenarios, return them anyway!
        if existing_scenarios:
            print(f"Returning {len(existing_scenarios)} existing damage scenarios despite LLM failure.")
            save_cache(query, "damage", existing_scenarios)
            return {"damage_details": existing_scenarios}
            
        return {"damage_details": []}


def evaluate(state: RAGState):
    """Combine all agent outputs into the final TARA JSON and evaluate."""
    print("  📝 Combining and evaluating...")

    # Group threat scenarios by damage scenario ID (nodeIds remapped later)
    ts_list = state.get("threat_scenarios", [])

    # Assemble final JSON
    assets_data = state.get("architecture", {})
    assets_list = []
    
    if assets_data:
        if isinstance(assets_data, list): assets_list = assets_data
        else: assets_list = [assets_data]

    # Deterministic metadata and structure fix for Assets
    mid = "698397514b57b8f24ed40a43"
    uid = "66ce823d95a055635c0ae0ae"
    
    # 1. PRE-PROCESS: Ensure all assets have a 'template' key before mapping
    unified_assets = []
    for asset in assets_list:
        if isinstance(asset, dict) and "Assets" in asset:
            sub = asset["Assets"]
            if isinstance(sub, list): unified_assets.extend(sub)
            else: unified_assets.append(sub)
        elif isinstance(asset, dict):
            unified_assets.append(asset)

    for asset in unified_assets:
        if "template" not in asset or not asset["template"]:
            existing_nodes = asset.pop("nodes", [])
            existing_edges = asset.pop("edges", [])
            asset["template"] = {"nodes": existing_nodes, "edges": existing_edges}
        else:
            asset.pop("nodes", None)
            asset.pop("edges", None)

    # ── PROPAGATE securityProperties from Details to nodes ──
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
                    node["properties"] = ["Integrity", "Confidentiality", "Authenticity", 
                                          "Authorization", "Availability", "Non-repudiation"]
            
            # Normalize properties
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
            node["properties"] = clean_props if clean_props else ["Integrity", "Confidentiality", 
                                                                   "Authenticity", "Authorization", 
                                                                   "Availability", "Non-repudiation"]
        
        print(f"  ✅ Propagated properties for {len(detail_props_map)} nodes from Details")

    # 2. Standardize Node IDs and Create Deep Mapping
    node_id_map = {}
    label_id_map = {}
    for asset in unified_assets:
        nodes = asset.get("template", {}).get("nodes", [])
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            old_id = node.get("id")
            label = node.get("data", {})
            if isinstance(label, dict):
                label = label.get("label")
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

    # 2b. Remap parentId references to new UUIDs
    for asset in unified_assets:
        for node in asset.get("template", {}).get("nodes", []):
            if not isinstance(node, dict):
                continue
            old_pid = node.get("parentId")
            if old_pid:
                node["parentId"] = node_id_map.get(
                    old_pid,
                    label_id_map.get(old_pid,
                    label_id_map.get(str(old_pid).lower(),
                    old_pid)))
            final_pid = node.get("parentId")
            valid_ids = [n.get("id") for n in asset.get("template", {}).get("nodes", []) if isinstance(n, dict)]
            if final_pid and final_pid not in valid_ids:
                node["parentId"] = None

    # 3. Final Styling and Metadata
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
                default_w, default_h = 50, 30
            else:
                default_w, default_h = 150, 60
            
            pid = node.get("parentId")
            if "position" not in node:
                if ntype == "group":
                    node["position"] = {"x": -96.0, "y": -44.0}
                elif pid and pid in group_ids:
                    ci = child_counters.get(pid, 0)
                    col = ci % 4
                    row = ci // 4
                    node["position"] = {"x": 20 + (col * 200), "y": 80 + (row * 150)}
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
            
            # Properties normalization
            if "properties" not in node or not isinstance(node.get("properties"), list):
                node["properties"] = ["Integrity", "Confidentiality", "Authenticity", 
                                      "Authorization", "Availability", "Non-repudiation"]
            else:
                clean_props = []
                for p in node["properties"]:
                    if isinstance(p, dict):
                        clean_props.append(p.get("name", p.get("value", "Integrity")))
                    elif isinstance(p, str):
                        clean_props.append(p)
                node["properties"] = clean_props if clean_props else ["Integrity", "Confidentiality", 
                                                                       "Authenticity", "Authorization", 
                                                                       "Availability", "Non-repudiation"]
            
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
        
        # Edges
        edges = asset.get("template", {}).get("edges", [])
        if not isinstance(edges, list):
            edges = []
        
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src = node_id_map.get(edge.get("source"), label_id_map.get(edge.get("source"), edge.get("source", "")))
            tgt = node_id_map.get(edge.get("target"), label_id_map.get(edge.get("target"), edge.get("target", "")))
            edge["source"] = src
            edge["target"] = tgt
            edge["sourceHandle"] = edge.get("sourceHandle", "b")
            edge["targetHandle"] = edge.get("targetHandle", "right")
            edge["id"] = f"reactflow__edge-{src}{edge['sourceHandle']}-{tgt}{edge['targetHandle']}"
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

        # Details handling
        if "Details" not in asset or not isinstance(asset.get("Details"), list) or not asset["Details"]:
            asset["Details"] = []
            for node in asset.get("template", {}).get("nodes", []):
                if not isinstance(node, dict):
                    continue
                if node.get("type") != "group":
                    props = node.get("properties", ["Integrity"])
                    if not isinstance(props, list):
                        props = ["Integrity"]
                    asset["Details"].append({
                        "nodeId": node.get("id"),
                        "name": node.get("data", {}).get("label", "Unknown") if isinstance(node.get("data"), dict) else "Unknown",
                        "desc": node.get("data", {}).get("description", None) if isinstance(node.get("data"), dict) else None,
                        "type": node.get("type", "default"),
                        "props": [{"name": p, "id": str(uuid.uuid4())} for p in props if isinstance(p, str)]
                    })
        else:
            for detail in asset["Details"]:
                if not isinstance(detail, dict):
                    continue
                detail["nodeId"] = node_id_map.get(
                    detail.get("nodeId"),
                    label_id_map.get(detail.get("nodeId"), detail.get("nodeId"))
                )
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

    # ── DATA NORMALIZATION ──
    def _remap(old_nid):
        if not old_nid:
            return old_nid
        if isinstance(old_nid, dict):
            old_nid = old_nid.get("id", old_nid.get("nodeId", ""))
        return node_id_map.get(old_nid, label_id_map.get(old_nid, label_id_map.get(str(old_nid).lower(), old_nid)))

    # Process Threats (Raw) - ADD SAFETY CHECKS
    raw_threats = state.get("threats", [])
    if not isinstance(raw_threats, list):
        raw_threats = []
    
    raw_damage_details = state.get("damage_details", [])
    if not isinstance(raw_damage_details, list):
        raw_damage_details = []
    
    for i, t in enumerate(raw_threats):
        if not isinstance(t, dict):
            continue
        t["nodeId"] = _remap(t.get("nodeId"))
        if i < len(raw_damage_details):
            dd = raw_damage_details[i]
            if isinstance(dd, dict):
                impacts = dd.get("impacts", {})
                if isinstance(impacts, dict):
                    t["financial_impact"] = impacts.get("Financial Impact", "Severe")
                    t["safety_impact"] = impacts.get("Safety Impact", "Severe")
                    t["operational_impact"] = impacts.get("Operational Impact", "Severe")
                    t["privacy_impact"] = impacts.get("Privacy Impact", "Negligible")
                if dd.get("Description"):
                    t["description"] = dd["Description"]

    # Process Damage Details (Deep)
    for block in raw_damage_details:
        if not isinstance(block, dict):
            continue
        
        nested_items = []
        if block.get("type") == "Derived":
            nested_items = block.get("Derivations", [])
        elif block.get("type") == "User-defined":
            nested_items = block.get("Details", [])
        else:
            nested_items = [block]
        
        if not isinstance(nested_items, list):
            continue
        
        for item in nested_items:
            if not isinstance(item, dict):
                continue
            if "nodeId" in item:
                item["nodeId"] = _remap(item["nodeId"])
            cyber_losses = item.get("cyberLosses", item.get("cyberlosses", []))
            if isinstance(cyber_losses, list):
                for cl in cyber_losses:
                    if isinstance(cl, dict):
                        cl["nodeId"] = _remap(cl.get("nodeId"))
                        if not cl.get("id") or not re.match(r'^[0-9a-f]{8}-', str(cl.get("id", ""))):
                            cl["id"] = str(uuid.uuid4())

    # Process Threat Scenarios
    ts_scenarios = state.get("threat_scenarios", [])
    if not isinstance(ts_scenarios, list):
        ts_scenarios = []
    
    for ts in ts_scenarios:
        if not isinstance(ts, dict):
            continue
        ts["nodeId"] = _remap(ts.get("nodeId"))
        for p in ts.get("props", []):
            if not isinstance(p, dict):
                continue
            if not p.get("id") or not re.match(r'^[0-9a-f]{8}-', str(p.get("id", ""))):
                p["id"] = str(uuid.uuid4())
    
    # ── EXTRACT User-defined Scenarios ──
    user_defined_scenarios = []
    for block in raw_damage_details:
        if isinstance(block, dict) and block.get("type") == "User-defined":
            details = block.get("Details", [])
            if isinstance(details, list):
                user_defined_scenarios = details
            break
    
    # If the user-defined wrapper wasn't returned, fallback to the raw list
    if not user_defined_scenarios:
        user_defined_scenarios = raw_damage_details if isinstance(raw_damage_details, list) else []

    # Build threat_scenarios_details
    threat_scenarios_details = []
    grouped_ts = {}
    
    for ts in ts_scenarios:
        if not isinstance(ts, dict):
            continue
        ds_ref = ts.get("damage_scenario", "")
        match = re.search(r"\[(DS\d+)\]", ds_ref)
        ds_id = match.group(1) if match else "Global"
        if ds_id not in grouped_ts:
            grouped_ts[ds_id] = []
        grouped_ts[ds_id].append(ts)
        
    for ds_id, ts_items in grouped_ts.items():
        node_grouping = {}
        ds_display_name = ""
        
        for ts in ts_items:
            if not isinstance(ts, dict):
                continue
            nid = _remap(ts.get("nodeId", ""))
            if nid == "unknown" or not nid:
                label = ts.get("node", "")
                nid = node_id_map.get(label, label_id_map.get(label, nid))
                
            node_name = ts.get("node", "Component")
            if not ds_display_name:
                ds_display_name = ts.get("name", "Threat Scenario").split(']')[-1].strip() if ']' in ts.get("name", "") else ts.get("name", "Threat Scenario")
                
            if nid not in node_grouping:
                node_grouping[nid] = {
                    "node": node_name,
                    "nodeId": nid,
                    "props": [],
                    "name": ds_display_name
                }
            
            for p in ts.get("props", []):
                if not isinstance(p, dict):
                    continue
                p_name = p.get("name", "Integrity")
                if not any(ep["name"] == p_name for ep in node_grouping[nid]["props"]):
                    pid = p.get("id", str(uuid.uuid4()))
                    if not re.match(r'^[0-9a-f]{8}-', str(pid)):
                        pid = str(uuid.uuid4())
                    node_grouping[nid]["props"].append({
                        "id": pid,
                        "is_risk_added": p.get("is_risk_added", True),
                        "name": p_name,
                        "isSelected": p.get("isSelected", True),
                        "key": len(node_grouping[nid]["props"]) + 1
                    })
        
        if node_grouping:
            threat_scenarios_details.append({
                "rowId": str(uuid.uuid4()),
                "id": ds_id,
                "Details": list(node_grouping.values())
            })

    # ── BUILD Assets[0].Details ──
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
                asset_details.append({
                    "nodeId": node.get("id"),
                    "name": node.get("data", {}).get("label", "Unknown") if isinstance(node.get("data"), dict) else "Unknown",
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
            asset_details.append({
                "nodeId": edge.get("id", ""),
                "name": edge.get("data", {}).get("label", "Connection") if isinstance(edge.get("data"), dict) else "Connection",
                "desc": None,
                "type": "step",
                "props": [{"name": p, "id": str(uuid.uuid4())} for p in props if isinstance(p, str)]
            })
        first_asset["Details"] = asset_details

    # ── BUILD Damage_scenarios.Derivations ──
    ds_derivations = []
    ds_counter = 1
    for detail in first_asset.get("Details", []):
        if not isinstance(detail, dict):
            continue
        for prop in detail.get("props", []):
            if not isinstance(prop, dict):
                continue
            ds_derivations.append({
                "id": f"DS{ds_counter:03}",
                "task": f"Check for DS due to the loss of {prop.get('name', 'Integrity')} for {detail.get('name', 'Component')}",
                "name": f"DS due to the loss of {prop.get('name', 'Integrity')} for {detail.get('name', 'Component')}",
                "loss": f"loss of {prop.get('name', 'Integrity')}",
                "asset": False,
                "damageScene": [],
                "nodeId": detail.get("nodeId", ""),
                "is_checked": None
            })
            ds_counter += 1

    # ── BUILD final output ──
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

    # ── Build safe user-defined details ──
    safe_user_defined = []
    for i, dd in enumerate(user_defined_scenarios if isinstance(user_defined_scenarios, list) else []):
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
        
        safe_user_defined.append({
            "Description": dd.get("Description", dd.get("description", "")),
            "Name": dd.get("Name", dd.get("name", f"Damage Scenario DS{i+1:03}")),
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
        "Attacks": [
            {
                "_id": "698397514b57b8f24ed40a45",
                "model_id": mid,
                "type": "attack_trees",
                "scenes": state.get("attacks", [])
            }
        ],
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
                "Details": threat_scenarios_details,
                "user_id": uid
            }
        ]
    }

    # Post-processing to link rowId in Attacks
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

        for scene in final_output["Attacks"][0].get("scenes", []):
            if not isinstance(scene, dict):
                continue
            for node in scene.get("templates", {}).get("nodes", []):
                if not isinstance(node, dict):
                    continue
                node["nodeId"] = node_id_map.get(node.get("nodeId"), label_id_map.get(node.get("nodeId"), node.get("nodeId")))
                if "data" in node and isinstance(node["data"], dict):
                    node["data"]["nodeId"] = node_id_map.get(node["data"].get("nodeId"), label_id_map.get(node["data"].get("nodeId"), node["data"].get("nodeId")))

                for t_id_ref in node.get("threat_ids", []):
                    if not isinstance(t_id_ref, dict):
                        continue
                    t_id_ref["nodeId"] = node_id_map.get(t_id_ref.get("nodeId"), label_id_map.get(t_id_ref.get("nodeId"), t_id_ref.get("nodeId")))
                    
                    key = f"{t_id_ref.get('nodeId', '')}_{t_id_ref.get('prop_name', '')}"
                    if key in threat_to_rowid:
                        t_id_ref["rowId"] = threat_to_rowid[key]
    except Exception as e:
        print(f"  ⚠️  RowId linking skipped/failed: {e}")

    answer = json.dumps(final_output, indent=2)

    first_asset = unified_assets[0] if unified_assets else {}
    nodes = first_asset.get("template", {}).get("nodes", []) if isinstance(first_asset, dict) else []
    derivations = ds_derivations
    threats = ts_list

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
        "threat_scenarios_count": len(threat_scenarios_details),
        "item_definition_details_count": len(first_asset.get("Details", [])) if isinstance(first_asset, dict) else 0,
        "passed_quality_check": score >= 50
    }

    return {"eval_score": score, "eval_details": eval_details, "answer": answer}

# ---------------- BUILD GRAPH ----------------
def build_graph(all_docs):
    global retriever, generator, text_embedder
    retriever, generator, text_embedder = setup(all_docs)

    builder = StateGraph(RAGState)

    # Register all nodes
    builder.add_node("retrieve", retrieve)
    builder.add_node("architect", architect_node)
    builder.add_node("threats", threat_analysis_node)
    builder.add_node("damage", damage_scenario_node)
    builder.add_node("threat_scenarios", generate_threat_scenarios_node)
    builder.add_node("attacks", generate_attack_trees_node)
    builder.add_node("evaluate", evaluate)

    # Clean linear graph
    builder.set_entry_point("retrieve")
    builder.add_edge("retrieve", "architect")
    builder.add_edge("architect", "threats")
    builder.add_edge("threats", "damage")
    builder.add_edge("damage", "threat_scenarios")
    builder.add_edge("threat_scenarios", "attacks")
    builder.add_edge("attacks", "evaluate")
    builder.add_edge("evaluate", "__end__")

    return builder.compile()