from db import db
from reportlab.platypus import Image
import io
from PIL import Image as PILImage
from azure.storage.blob import (
    BlobServiceClient,
    BlobSasPermissions,
    generate_blob_sas,
    ContentSettings,
)
from reportlab.lib import colors
from config import Config
import datetime
import uuid
import json
import re
import math

from typing import List, Dict, Any, Optional, Tuple
from bs4 import BeautifulSoup

def get_highest_impact(impacts):
    # impact_order = ["Severe", "Major", "Moderate", "Minor", "Negligible"]
    impact_order = ["Negligible", "Minor", "Moderate", "Major", "Severe"]

    # Extract values from the impacts dictionary and map them to their rank in the impact_order list
    impact_values = [
        (impacts.get("Safety Impact", ""), "Safety Impact"),
        (impacts.get("Financial Impact", ""), "Financial Impact"),
        (impacts.get("Operational Impact", ""), "Operational Impact"),
        (impacts.get("Privacy Impact", ""), "Privacy Impact"),
    ]

    # Determine the highest impact
    overall_impact = max(
        impact_values,
        key=lambda x: impact_order.index(x[0]) if x[0] in impact_order else -1,
    )[0]

    return overall_impact


def get_threat_type(value):
    mapping = {
        "Integrity": "Tampering",
        "Confidentiality": "Information Disclosure",
        "Availability": "Denial",
        "Authenticity": "Spoofing",
        "Authorization": "Elevation of Privilege",
        "Non-repudiation": "Rejection",
    }
    return mapping.get(value, "")


def get_highest_rating(ratings):
    rating_order = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4}
    highest_rating = None

    for rating in ratings:
        normalized_rating = rating.capitalize()  # Normalize to title case
        if normalized_rating in rating_order:
            if (
                highest_rating is None
                or rating_order[normalized_rating] > rating_order[highest_rating]
            ):
                highest_rating = normalized_rating

    return highest_rating


def resize_image(image_stream, max_width=500, max_height=400):
    # Open the image using Pillow
    img_pil = PILImage.open(image_stream)
    img_width, img_height = img_pil.size  # Get the image size (width, height)

    # Calculate aspect ratio
    aspect_ratio = img_width / img_height

    # Scale the image proportionally
    if img_width > max_width or img_height > max_height:
        if img_width > img_height:
            # Scale based on width
            img_width = max_width
            img_height = img_width / aspect_ratio
        else:
            # Scale based on height
            img_height = max_height
            img_width = img_height * aspect_ratio

    # Create a BytesIO stream to save the resized image
    img_pil = img_pil.resize((int(img_width), int(img_height)))
    img_byte_arr = io.BytesIO()
    img_pil.save(
        img_byte_arr, format="PNG"
    )  # Save image as PNG into the BytesIO stream
    img_byte_arr.seek(0)  # Reset stream position to the beginning

    # Now return the Image object for reportlab
    return Image(img_byte_arr)


def generate_sas_url(blob_service_client, blob_name):
    try:
        # Generate SAS token
        sas_token = generate_blob_sas(
            account_name=blob_service_client.account_name,
            container_name=Config.AZURE_CONTAINER_NAME,
            blob_name=blob_name,
            account_key=blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.datetime.utcnow()
            + datetime.timedelta(hours=1),  # URL valid for 1 hour
        )
        # Generate the file URL with SAS token
        file_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{Config.AZURE_CONTAINER_NAME}/{blob_name}?{sas_token}"
        return file_url
    except Exception as e:
        raise Exception(f"Error generating SAS URL: {str(e)}")


def getImpactBgcolour(impact):
    impact_color = {
        "Negligible": colors.lightgreen,
        "Minor": colors.green,
        "Moderate": colors.yellow,
        "Major": colors.orange,
        "Severe": colors.red,
    }

    return impact_color.get(impact, None)

def getFesRateBgColor(rating):
    rating_color = {
        "Very low": colors.lightgreen,
        "Low": colors.green,
        "Medium": colors.yellow,
        "High": colors.red,
        "Very High": colors.red,
    }
    return rating_color.get(rating,None)

DEFAULT_NODE_WIDTH = 180
DEFAULT_NODE_HEIGHT = 60
DEFAULT_GROUP_WIDTH = 700
DEFAULT_GROUP_HEIGHT = 400
GROUP_PADDING = 60
GROUP_HORIZONTAL_SPACING = 300
GROUP_VERTICAL_SPACING = 200
NODE_SPACING_X = 100   # horizontal gap between children inside a group
NODE_SPACING_Y = 80    # vertical gap between rows inside a group
MIN_CLEARANCE = 60     # vertical clearance between groups and ungrouped section

# Ungrouped-node specific spacing (tighter than group-children spacing)
UNGROUPED_START_X = 50
UNGROUPED_NODE_SPACING_X = 30   # gap between nodes in the same ungrouped row
UNGROUPED_NODE_SPACING_Y = 30   # gap between ungrouped rows
UNGROUPED_ROW_MAX_WIDTH = 2000  # wrap to a new row after this many pixels
# Label sizing estimates
CHAR_WIDTH = 8          # Approximate pixel width per character
LINE_HEIGHT = 20        # Height of a text line
MAX_CHARS_PER_LINE = 20 # Wrap after ~20 characters
MAX_NODE_WIDTH = 400    # Cap so nodes don’t get crazy wide


def estimate_node_size(label):
    """Estimate width/height of node based on label text length with wrapping"""
    lines = max(1, math.ceil(len(label) / MAX_CHARS_PER_LINE))
    est_width = min(
        max(DEFAULT_NODE_WIDTH, min(len(label), MAX_CHARS_PER_LINE) * CHAR_WIDTH + 40),
        MAX_NODE_WIDTH,
    )
    est_height = max(DEFAULT_NODE_HEIGHT, lines * LINE_HEIGHT + 20)  # +20 padding
    return est_width, est_height


def build_basic_node(node):
    """Create node structure with adaptive sizing, preserving colors from RAG"""
    is_group = node["type"] == "group"
    
    # Get colors from node data if provided, otherwise use defaults
    node_style = node.get("data", {}).get("style", {})
    
    if not is_group:
        width, height = estimate_node_size(node["data"]["label"])
        # Use provided background color or default
        bg_color = node_style.get("backgroundColor", "#f0f0f0")
        border_color = node_style.get("borderColor", "#666")
    else:
        width, height = DEFAULT_GROUP_WIDTH, DEFAULT_GROUP_HEIGHT
        bg_color = node_style.get("backgroundColor", "rgba(200,230,255,0.2)")
        border_color = node_style.get("borderColor", "#2196F3")

    return {
        "id": node["id"],
        "type": node["type"],
        "position": {"x": 0, "y": 0},
        "data": {
            "label": node["data"]["label"],
            "style": {
                "backgroundColor": bg_color,
                "borderColor": border_color,
                "borderStyle": node_style.get("borderStyle", "solid"),
                "borderWidth": node_style.get("borderWidth", "2px"),
                "color": node_style.get("color", "#333"),
                "fontFamily": node_style.get("fontFamily", "Inter"),
                "fontSize": node_style.get("fontSize", "14px"),
                "fontWeight": node_style.get("fontWeight", 500),
                "height": height,
                "width": width,
            },
        },
        "width": width,
        "height": height,
        "parentId": node.get("parentId"),
        "properties": node.get("properties", []),
    }

def adjust_group_sizes(nodes):
    """Recalculate group sizes based on children - MINIMAL SPACING"""
    groups = [n for n in nodes if n["type"] == "group"]

    for group in groups:
        children = [n for n in nodes if n.get("parentId") == group["id"]]
        if not children:
            continue

        # Get actual child dimensions
        child_widths = [c.get("width", DEFAULT_NODE_WIDTH) for c in children]
        child_heights = [c.get("height", DEFAULT_NODE_HEIGHT) for c in children]
        
        max_child_width = max(child_widths)
        max_child_height = max(child_heights)
        
        # Calculate optimal grid - fit as many as possible
        available_width = DEFAULT_GROUP_WIDTH - 2 * GROUP_PADDING
        cols = max(1, available_width // (max_child_width + NODE_SPACING_X))
        cols = min(cols, len(children))  # Don't exceed number of children
        
        rows = math.ceil(len(children) / cols)
        
        # Calculate actual required size based on children
        if cols > 1:
            total_width = cols * max_child_width + (cols - 1) * NODE_SPACING_X
        else:
            total_width = max_child_width
            
        if rows > 1:
            total_height = rows * max_child_height + (rows - 1) * NODE_SPACING_Y
        else:
            total_height = max_child_height
        
        # Add padding
        required_width = total_width + 2 * GROUP_PADDING
        required_height = total_height + 2 * GROUP_PADDING
        
        # Update group size - use exact required size, don't add extra
        group["width"] = max(DEFAULT_GROUP_WIDTH, required_width)
        group["height"] = max(DEFAULT_GROUP_HEIGHT, required_height)
        group["data"]["style"]["width"] = group["width"]
        group["data"]["style"]["height"] = group["height"]

    return nodes


def recalculate_group_heights_from_children(nodes):
    """
    After calculate_node_positions has run, shrink each group's height to
    tightly wrap its actual children.

    Child positions are stored as absolute coordinates by calculate_node_positions,
    but ReactFlow (with parentId) treats them as relative to the parent group.
    Therefore child["position"]["y"] is effectively the relative Y inside the group,
    and we use it directly to find the bottommost content extent.
    """
    groups = [n for n in nodes if n["type"] == "group"]

    for group in groups:
        children = [n for n in nodes if n.get("parentId") == group["id"]]
        if not children:
            continue

        # child["position"]["y"] is the effective relative Y (as ReactFlow renders it)
        max_content_bottom = max(
            child["position"]["y"] + child.get("height", DEFAULT_NODE_HEIGHT)
            for child in children
        )

        # New height = bottom of last child + bottom padding
        new_height = max_content_bottom + GROUP_PADDING

        # Only shrink — never grow beyond what adjust_group_sizes already set
        if new_height < group["height"]:
            group["height"] = new_height
            group["data"]["style"]["height"] = new_height

    return nodes


def calculate_node_positions(nodes):
    """Position nodes with MINIMAL spacing and proper alignment"""
    groups = [n for n in nodes if n["type"] == "group"]
    other_nodes = [n for n in nodes if n["type"] != "group"]

    # Position groups
    current_x = 50
    current_y = 50
    
    for group in groups:
        group["position"]["x"] = current_x
        group["position"]["y"] = current_y
        current_x += group["width"] + GROUP_HORIZONTAL_SPACING

    # Position children inside groups - TIGHT packing
    for group in groups:
        children = [n for n in other_nodes if n.get("parentId") == group["id"]]
        if not children:
            continue
        
        # Calculate optimal columns based on available width
        available_width = group["width"] - 2 * GROUP_PADDING
        child_width = children[0].get("width", DEFAULT_NODE_WIDTH)
        cols = max(1, available_width // (child_width + NODE_SPACING_X))
        cols = min(cols, len(children))
        
        # Calculate actual spacing to distribute evenly
        if cols > 1:
            total_children_width = cols * child_width
            remaining_space = available_width - total_children_width
            spacing_between = remaining_space // (cols - 1) if cols > 1 else 0
            # Use minimal spacing, don't spread out too much
            actual_spacing = min(NODE_SPACING_X, spacing_between)
        else:
            actual_spacing = 0
        
        start_x = group["position"]["x"] + GROUP_PADDING
        start_y = group["position"]["y"] + GROUP_PADDING
        
        for i, child in enumerate(children):
            row = i // cols
            col = i % cols
            
            # Calculate X position
            if cols > 1:
                child_x = start_x + col * (child_width + actual_spacing)
            else:
                # Center single child
                child_x = group["position"]["x"] + (group["width"] - child_width) / 2
            
            child_y = start_y + row * (child.get("height", DEFAULT_NODE_HEIGHT) + NODE_SPACING_Y)
            
            child["position"]["x"] = child_x
            child["position"]["y"] = child_y

    return nodes


def position_ungrouped_nodes(nodes):
    """
    Position nodes that have no parentId (not inside any group).
    Must be called AFTER recalculate_group_heights_from_children so that
    group heights are already trimmed to their real content size.
    """
    groups = [n for n in nodes if n["type"] == "group"]
    ungrouped = [n for n in nodes if n["type"] != "group" and not n.get("parentId")]

    if not ungrouped:
        return nodes

    # Use the actual (post-trim) bottom of the tallest group
    lowest_group_bottom = max(
        (g["position"]["y"] + g["height"] for g in groups),
        default=0
    )

    current_x = UNGROUPED_START_X
    current_y = lowest_group_bottom + MIN_CLEARANCE
    max_height_in_row = 0

    for node in ungrouped:
        node_width = node.get("width", DEFAULT_NODE_WIDTH)
        node_height = node.get("height", DEFAULT_NODE_HEIGHT)

        # Wrap to a new row when we exceed the max row width
        if current_x + node_width > UNGROUPED_ROW_MAX_WIDTH:
            current_x = UNGROUPED_START_X
            current_y += max_height_in_row + UNGROUPED_NODE_SPACING_Y
            max_height_in_row = 0

        node["position"]["x"] = current_x
        node["position"]["y"] = current_y

        current_x += node_width + UNGROUPED_NODE_SPACING_X
        max_height_in_row = max(max_height_in_row, node_height)

    return nodes

def verify_no_overlaps(nodes):
    """Double-check that no nodes overlap"""
    for i, a in enumerate(nodes):
        for j, b in enumerate(nodes):
            if i >= j:
                continue  # Don't compare twice or with self

            a_left = a["position"]["x"]
            a_right = a_left + a["width"]
            a_top = a["position"]["y"]
            a_bottom = a_top + a["height"]

            b_left = b["position"]["x"]
            b_right = b_left + b["width"]
            b_top = b["position"]["y"]
            b_bottom = b_top + b["height"]

            # Check for overlap
            if not (a_right < b_left or a_left > b_right or
                    a_bottom < b_top or a_top > b_bottom):
                print(f"Warning: Potential overlap between {a['id']} and {b['id']}")


def build_full_edge(source_id: str, target_id: str, label: str = "", 
                    edge_type: str = "step") -> Dict:
    """
    Build a complete edge object for React Flow.
    
    Args:
        source_id: Source node ID
        target_id: Target node ID
        label: Edge label (e.g., "SPI", "CAN")
        edge_type: Type of edge
    
    Returns:
        Edge dictionary
    """
    import uuid
    
    edge = {
        "id": f"reactflow__edge-{source_id}b-{target_id}right",
        "source": source_id,
        "target": target_id,
        "sourceHandle": "b",
        "targetHandle": "right",
        "type": edge_type,
        "animated": True,
        "selected": False,
        "properties": ["Integrity"],
        "data": {
            "label": label,
            "offset": 0,
            "t": 0.5
        },
        "markerEnd": {
            "color": "#64B5F6",
            "height": 18,
            "type": "arrowclosed",
            "width": 18
        },
        "markerStart": {
            "color": "#64B5F6",
            "height": 18,
            "orient": "auto-start-reverse",
            "type": "arrowclosed",
            "width": 18
        },
        "style": {
            "end": True,
            "start": True,
            "stroke": "#808080",
            "strokeDasharray": "0",
            "strokeWidth": 2
        }
    }
    
    return edge

def threat_type(value: str) -> str:
    """
    Maps a property name to a STRIDE threat category.
    """
    type_map = {
        "Integrity": "Tampering",
        "Confidentiality": "Information Disclosure",
        "Availability": "Denial of service",
        "Authenticity": "Spoofing",
        "Authorization": "Elevation of Privilege",
        "Non-repudiation": "Rejection"
    }
    return type_map.get(value, "")

def apply_stride_prefix(name: str, props: list, node_type: str) -> str:
    """
    Adds STRIDE prefix only for 'default' node types.
    """
    if node_type not in ("default"):
        return name

    for p in props:
        mapped = threat_type(p)
        if mapped and not name.startswith(mapped):
            return f"{mapped} of {name}"
    return name

def structure_attack_tree_templates(raw_templates, processed_scenarios=None):
    """
    Structure attack tree: default -> individual OR gates -> events.
    Injects a unique gate between root and every event node.
    Adds STRIDE prefix for root and Event nodes based on processed_scenarios.
    """
    nodes = raw_templates.get("nodes", [])
    edges = raw_templates.get("edges", [])

    # Find the root node
    root_node = next((n for n in nodes if n.get("type", "").lower() == "default"), None)
    if not root_node:
        raise ValueError("No root node (type='default') found")

    # Get props for root
    root_props = []
    if processed_scenarios:
        root_props = next((s["properties"] for s in processed_scenarios if s["rowId"] == root_node.get("threat_id")), [])

    # Apply STRIDE prefix for root node
    root_label = apply_stride_prefix(
        root_node.get("label", root_node.get("name", "Root")),
        root_props,
        "default"
    )

    # Remaining nodes are events
    event_nodes = [n for n in nodes if n != root_node]

    structured_nodes = []
    structured_edges = []

    def style(width=120, height=60):
        return {
            "fontSize": "16px",
            "fontFamily": "Inter",
            "fontStyle": "normal",
            "fontWeight": 500,
            "textAlign": "center",
            "color": "black",
            "textDecoration": "none",
            "borderColor": "black",
            "borderWidth": "2px",
            "borderStyle": "solid",
            "backgroundColor": "transparent",
            "width": width,
            "height": height
        }

    # Add root node
    root_structured = {
        "id": root_node["id"],
        "position": {"x": 300, "y": 32},
        "type": "default",
        "label": root_label,
        "dragged": True,
        "nodeId": root_node.get("nodeId", ""),
        "threatId": root_node.get("threat_id", ""),
        "damageId": root_node.get("damageId", ""),
        "width": 150,
        "height": 60,
        "key": root_node.get("key", ""),
        "data": {
            "label": root_label,
            "nodeId": root_node.get("nodeId", ""),
            "style": style(150, 60),
            "connections": []
        }
    }
    structured_nodes.append(root_structured)

    # Build gate + event for each event node
    for i, event in enumerate(event_nodes):
        event_id = event["id"]
        gate_id = str(uuid.uuid4())

        gate_x = 100 + i * 250
        gate_y = 150
        event_y = 270

        # Get props for event
        event_props = []
        if processed_scenarios:
            event_props = next((s["properties"] for s in processed_scenarios if s["rowId"] == event.get("threat_id")), [])

        # Apply STRIDE prefix for Event nodes
        event_label = apply_stride_prefix(
            event.get("label", event.get("name", "Event")),
            event_props,
            "Event"
        )

        # OR Gate node
        gate_node = {
            "id": gate_id,
            "position": {"x": gate_x, "y": gate_y},
            "type": "OR Gate",
            "label": "OR Gate",
            "width": 100,
            "height": 100,
            "data": {
                "label": "OR Gate",
                "style": style(120, 60),
                "connections": [{
                    "id": event_id,
                    "type": "Event"
                }]
            },
            "selected": False,
            "dragging": False
        }
        structured_nodes.append(gate_node)

        # Event node
        event_node = {
            "id": event_id,
            "position": {"x": gate_x, "y": event_y},
            "type": "Event",
            "label": event_label,
            "width": 198,
            "height": 60,
            "data": {
                "label": event_label,
                "style": style(120, 60)
            },
            "selected": True,
            "dragging": False
        }
        structured_nodes.append(event_node)

        # Gate → Event edge
        structured_edges.append({
            "id": f"{gate_id}-{event_id}",
            "source": gate_id,
            "target": event_id,
            "type": "step",
            "markerEnd": {
                "type": "arrowclosed",
                "width": 20,
                "height": 20,
                "color": "black"
            },
            "points": []
        })

        # Root → Gate edge
        structured_edges.append({
            "id": f"{root_node['id']}-{gate_id}",
            "source": root_node["id"],
            "target": gate_id,
            "type": "step",
            "markerEnd": {
                "type": "arrowclosed",
                "width": 20,
                "height": 20,
                "color": "black"
            },
            "points": []
        })

        root_structured["data"]["connections"].append({
            "id": gate_id,
            "type": "OR Gate"
        })

    return {
        "nodes": structured_nodes,
        "edges": structured_edges
    }

# Backend version of AttackTableoptions
AttackTableoptions = {
    # "Approach": [
    #     {"value": "Attack Potential-based Approach"},
    #     {"value": "CVSS-based Approach"},
    #     {"value": "Attack Vector-based Approach"}
    # ],
    "Elapsed Time": [
        {"value": "<= 1 day", "rating": 0},
        {"value": "<= 1 week", "rating": 1},
        {"value": "<= 1 month", "rating": 4},
        {"value": "<= 6 month", "rating": 17},
        {"value": ">6 month", "rating": 19}
    ],
    "Expertise": [
        {"value": "Layman", "rating": 0},
        {"value": "Proficient", "rating": 3},
        {"value": "Expert", "rating": 6},
        {"value": "Multiple experts", "rating": 8}
    ],
    "Knowledge of the Item": [
        {"value": "Public information", "rating": 0},
        {"value": "Restricted information", "rating": 3},
        {"value": "Confidential information", "rating": 7},
        {"value": "Strictly confidential information", "rating": 11}
    ],
    "Window of Opportunity": [
        {"value": "Unlimited", "rating": 0},
        {"value": "Easy", "rating": 1},
        {"value": "Moderate", "rating": 4},
        {"value": "Difficult", "rating": 10}
    ],
    "Equipment": [
        {"value": "Standard", "rating": 0},
        {"value": "Specialized", "rating": 4},
        {"value": "Bespoke", "rating": 7},
        {"value": "Multiple bespoke", "rating": 9}
    ]
}


def safe_json_parse(content):
    # First try direct parsing
    try:
        parsed = json.loads(content)
        if isinstance(parsed, str):
            return json.loads(parsed)  # double-parsed case
        return parsed
    except json.JSONDecodeError:
        pass

    # If direct parse fails, try extracting first JSON array
    match = re.search(r"\[\s*{.*}\s*\]", content, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, str):
                return json.loads(parsed)
            return parsed
        except json.JSONDecodeError:
            pass

    return None


def html_to_reportlab(html: str) -> str:
    if not html:
        return ""

    soup = BeautifulSoup(html, "html.parser")

    def walk(node):
        output = ""

        for el in node.children:
            if isinstance(el, str):
                output += el
                continue

            tag = el.name.lower()

            # --- inline formatting ---
            if tag in ["strong", "b"]:
                output += f"<b>{walk(el)}</b>"
            elif tag in ["em", "i"]:
                output += f"<i>{walk(el)}</i>"
            elif tag == "u":
                output += f"<u>{walk(el)}</u>"
            elif tag in ["s", "strike"]:
                output += f"<strike>{walk(el)}</strike>"
            elif tag == "sub":
                output += f"<sub>{walk(el)}</sub>"
            elif tag == "sup":
                output += f"<sup>{walk(el)}</sup>"

            # --- color ---
            elif tag == "span":
                style = el.get("style", "")
                m = re.search(r"color:\s*rgb\((\d+),\s*(\d+),\s*(\d+)\)", style)
                if m:
                    r, g, b = map(int, m.groups())
                    color = f"#{r:02x}{g:02x}{b:02x}"
                    output += f'<font color="{color}">{walk(el)}</font>'
                else:
                    output += walk(el)

            # --- headings ---
            elif tag in ["h1", "h2", "h3"]:
                output += f"<b>{walk(el)}</b><br/><br/>"

            # --- paragraphs ---
            elif tag == "p":
                output += f"{walk(el)}<br/><br/>"

            # --- line breaks ---
            elif tag == "br":
                output += "<br/>"

            # --- lists ---
            elif tag == "li":
                output += f"• {walk(el)}<br/>"
            elif tag in ["ul", "ol"]:
                output += walk(el) + "<br/>"

            # --- links ---
            elif tag == "a":
                output += walk(el)  # or make clickable if needed

            # --- ignore safely ---
            else:
                output += walk(el)

        return output

    text = walk(soup)

    # Final cleanup
    text = re.sub(r'\n+', '<br/>', text)
    text = re.sub(r'<br/>\s*<br/>+', '<br/><br/>', text)

    return text.strip()

  

def resolve_user_defined_threat(
    ud_detail, model_id, derived_threat_scenario
):
    resolved_threats = []

    for threat in ud_detail.get("threat_ids", []):
        row_id = threat.get("rowId")
        node_id = threat.get("nodeId")
        prop_id = threat.get("propId")

        damage_name = None
        impacts = {}

        # ------------------------
        # DAMAGE SCENARIO LOOKUP
        # ------------------------
        damage_scenario = db.Damage_scenarios.find_one(
            {
                "model_id": model_id,
                "type": "User-defined",
                "Details": {"$elemMatch": {"_id": row_id}},
            }
        )

        if damage_scenario:
            damage_detail = next(
                (
                    d
                    for d in damage_scenario.get("Details", [])
                    if str(d.get("_id")) == str(row_id)
                ),
                None,
            )
            if damage_detail:
                damage_name = damage_detail.get("Name")
                impacts = damage_detail.get("impacts", {})

        # ------------------------
        # DERIVED THREAT LOOKUP
        # ------------------------
        node_name = None
        prop_name = None
        prop_key = None

        if derived_threat_scenario:
            for derived in derived_threat_scenario.get("Details", []):
                for inner in derived.get("Details", []):
                    if inner.get("nodeId") != node_id:
                        continue

                    node_name = inner.get("node")

                    for prop in inner.get("props", []):
                        if prop.get("id") == prop_id:
                            prop_name = prop.get("name")
                            prop_key = prop.get("key")
                            break

        resolved_threats.append(
            {
                "damage_id": row_id,
                "damage_scene": damage_name,
                "node_id": node_id,
                "node_name": node_name,
                "prop_id": prop_id,
                "prop_name": prop_name,
                "prop_key": prop_key,
                "impacts": impacts,
            }
        )

    return resolved_threats

def calculate_average_impacts(threats):
    """
    Returns averaged impacts in the SAME format as input impacts.
    Example:
    {
        "Financial Impact": "Major",
        "Operational Impact": "Severe",
        ...
    }
    """

    IMPACT_SCORE_MAP = {
        "Negligible": 1,
        "Minor": 2,
        "Moderate": 3,
        "Major": 4,
        "Severe": 5,
    }

    REVERSE_MAP = {v: k for k, v in IMPACT_SCORE_MAP.items()}

    impact_buckets = {}

    # Collect scores per impact type
    for threat in threats or []:
        impacts = threat.get("impacts", {})
        for impact_type, rating in impacts.items():
            if rating not in IMPACT_SCORE_MAP:
                continue

            impact_buckets.setdefault(impact_type, []).append(
                IMPACT_SCORE_MAP[rating]
            )

    if not impact_buckets:
        return {}

    averaged_impacts = {}

    for impact_type, scores in impact_buckets.items():
        avg_score = sum(scores) / len(scores)

        # Find nearest rating
        closest_score = min(
            REVERSE_MAP.keys(),
            key=lambda x: abs(x - avg_score)
        )

        averaged_impacts[impact_type] = REVERSE_MAP[closest_score]

    return averaged_impacts

