# =============================================================================
# postprocess.py — UUID stamping, crosslinking, and JSON parsing
# =============================================================================

import json
import re
import uuid as _uuid


def stamp_uuids(obj: dict) -> dict:
    """
    Walk the JSON tree and replace any id/_id/model_id that is empty,
    None, or a placeholder string with a fresh uuid4.
    """
    ID_KEYS = {"id", "_id", "model_id"}

    def _bad(val) -> bool:
        if not val:
            return True
        if isinstance(val, str) and (
            "PLACEHOLDER" in val or val.strip() == "" or val.startswith("<")
        ):
            return True
        return False

    def _walk(o):
        if isinstance(o, dict):
            for k, v in list(o.items()):
                if k in ID_KEYS and _bad(v):
                    o[k] = str(_uuid.uuid4())
                else:
                    _walk(v)
        elif isinstance(o, list):
            for item in o:
                _walk(item)

    _walk(obj)
    return obj


def crosslink_node_ids(obj: dict) -> dict:
    """
    After node UUIDs are stamped, propagate real nodeId values into
    Derivations[].nodeId and Details[].cyberLosses[].nodeId by label-matching.
    """
    nodes = obj.get("assets", {}).get("template", {}).get("nodes", [])
    label_to_id = {
        n.get("data", {}).get("label", "").lower(): n.get("id")
        for n in nodes if n.get("id")
    }

    for d in obj.get("damage_scenarios", {}).get("Derivations", []):
        nid = d.get("nodeId", "")
        if not nid or str(nid).startswith("<") or "PLACEHOLDER" in str(nid):
            matched   = label_to_id.get(d.get("asset", "").lower())
            d["nodeId"] = matched if matched else str(_uuid.uuid4())

    for det in obj.get("damage_scenarios", {}).get("Details", []):
        for cl in det.get("cyberLosses", []):
            nid = cl.get("nodeId", "")
            if not nid or str(nid).startswith("<") or "PLACEHOLDER" in str(nid):
                matched      = label_to_id.get(cl.get("node", "").lower())
                cl["nodeId"] = matched if matched else str(_uuid.uuid4())
            if not cl.get("id") or str(cl.get("id", "")).startswith("<"):
                cl["id"] = str(_uuid.uuid4())

    return obj


def parse_and_fix(raw_text: str) -> dict | None:
    """
    Strip markdown fences, parse JSON, apply UUID stamping and crosslinking.
    Returns fixed dict or None on parse failure.
    """
    # Strip markdown fences
    cleaned = re.sub(r"^```[a-z]*\n?", "", raw_text.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"```$", "", cleaned.strip())

    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON parse error: {e}")
        print(f"Raw output (first 500 chars):\n{cleaned[:500]}")
        return None

    obj = stamp_uuids(obj)
    obj = crosslink_node_ids(obj)
    return obj


def print_summary(tara_json: dict) -> None:
    """Print a short summary of the generated TARA JSON."""
    node_count  = len(tara_json.get("assets", {}).get("template", {}).get("nodes", []))
    edge_count  = len(tara_json.get("assets", {}).get("template", {}).get("edges", []))
    details_count = len(tara_json.get("assets", {}).get("template", {}).get("details", []))
    deriv_count = len(tara_json.get("damage_scenarios", {}).get("Derivations", []))
    ds_count    = len(tara_json.get("damage_scenarios", {}).get("Details", []))
    print(f"   Nodes          : {node_count}")
    print(f"   Edges          : {edge_count}")
    print(f"   Details        : {details_count}")
    print(f"   Derivations    : {deriv_count}")
    print(f"   Damage details : {ds_count}")
    print("   IDs            : all stamped as uuid4")
