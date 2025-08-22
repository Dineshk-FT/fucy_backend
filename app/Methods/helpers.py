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


# Constants for layout
DEFAULT_NODE_WIDTH = 180
DEFAULT_NODE_HEIGHT = 60
DEFAULT_GROUP_WIDTH = 700
DEFAULT_GROUP_HEIGHT = 500
GROUP_PADDING = 60
GROUP_HORIZONTAL_SPACING = 600  # Space between groups
GROUP_VERTICAL_SPACING = 300    # Vertical space if we stack groups
NODE_SPACING_X = 200
NODE_SPACING_Y = 120
UNGROUPED_START_X = 100
UNGROUPED_START_Y = 800  # Start ungrouped nodes below all groups
MIN_CLEARANCE = 100      # Minimum space between any two elements

def build_basic_node(node):
    """Create node structure without positioning"""
    is_group = node["type"] == "group"
    return {
        "id": node["id"],
        "type": node["type"],
        "position": {"x": 0, "y": 0},  # Temporary
        "data": {
            "label": node["data"]["label"],
            "style": {
                "backgroundColor": "#f0f0f0" if not is_group else "rgba(200,230,255,0.2)",
                "borderColor": "#666" if not is_group else "#2196F3",
                "borderStyle": "solid",
                "borderWidth": "2px",
                "color": "#333",
                "fontFamily": "Inter",
                "fontSize": "14px",
                "fontWeight": 500,
                "height": DEFAULT_GROUP_HEIGHT if is_group else DEFAULT_NODE_HEIGHT,
                "width": DEFAULT_GROUP_WIDTH if is_group else DEFAULT_NODE_WIDTH,
            },
        },
        "width": DEFAULT_GROUP_WIDTH if is_group else DEFAULT_NODE_WIDTH,
        "height": DEFAULT_GROUP_HEIGHT if is_group else DEFAULT_NODE_HEIGHT,
        "parentId": node.get("parentId"),
        "properties": node.get("properties", []),
    }

def calculate_node_positions(nodes):
    """Carefully position all nodes with proper spacing"""
    groups = [n for n in nodes if n["type"] == "group"]
    other_nodes = [n for n in nodes if n["type"] != "group"]
    
    # Position groups in a row with spacing
    current_x = 100
    current_y = 100
    
    for group in groups:
        group["position"]["x"] = current_x
        group["position"]["y"] = current_y
        
        # Next group moves right with spacing
        current_x += group["width"] + GROUP_HORIZONTAL_SPACING
        
        # If we're running out of horizontal space, start new row
        if current_x > 2500:  # Arbitrary reasonable limit
            current_x = 100
            current_y += group["height"] + GROUP_VERTICAL_SPACING
    
    # Position child nodes within their groups
    for group in groups:
        children = [n for n in other_nodes if n.get("parentId") == group["id"]]
        
        # Calculate grid layout within group
        max_per_row = max(1, (group["width"] - 2 * GROUP_PADDING) // NODE_SPACING_X)
        
        for i, child in enumerate(children):
            row = i // max_per_row
            col = i % max_per_row
            
            child["position"]["x"] = (
                group["position"]["x"] + 
                GROUP_PADDING + 
                col * NODE_SPACING_X
            )
            child["position"]["y"] = (
                group["position"]["y"] + 
                GROUP_PADDING + 
                row * NODE_SPACING_Y
            )
    
    # Position ungrouped nodes in a separate area below
    ungrouped = [n for n in other_nodes if not n.get("parentId")]
    
    current_ungrouped_x = UNGROUPED_START_X
    current_ungrouped_y = UNGROUPED_START_Y
    max_row_width = 0
    
    for node in ungrouped:
        # If node would go off screen, move to next row
        if current_ungrouped_x + node["width"] > 2500:  # Arbitrary reasonable limit
            current_ungrouped_x = UNGROUPED_START_X
            current_ungrouped_y += node["height"] + MIN_CLEARANCE
        
        node["position"]["x"] = current_ungrouped_x
        node["position"]["y"] = current_ungrouped_y
        
        # Move right for next node
        current_ungrouped_x += node["width"] + NODE_SPACING_X
        max_row_width = max(max_row_width, current_ungrouped_x)
    
    # Ensure final layout has no overlaps
    verify_no_overlaps(nodes)
    
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
                # In a real implementation, you'd adjust positions here


def build_full_edge(edge):
    return {
        "id": f"reactflow__edge-{edge['source']}{edge['sourceHandle']}-{edge['target']}{edge['targetHandle']}",
        "type": edge["type"],
        "source": edge["source"],
        "target": edge["target"],
        "sourceHandle": edge["sourceHandle"],
        "targetHandle": edge["targetHandle"],
        "data": {
            "label": edge["data"]["label"],
        },
        "markerStart": {
            "color": "#64B5F6",
            "height": 18,
            "orient": "auto-start-reverse",
            "type": "arrowclosed",
            "width": 18,
        },
        "markerEnd": {
            "color": "#64B5F6",
            "height": 18,
            "type": "arrowclosed",
            "width": 18,
        },
        "style": {
            "stroke": "#808080",
            "strokeWidth": 2,
            "strokeDasharray": "0",
            "start": True,
            "end": True,
        },
        "properties": edge.get("properties", []),
        "animated": True,
        "selected": False,
    }



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
    