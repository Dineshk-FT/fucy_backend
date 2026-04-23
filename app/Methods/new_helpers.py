import math
import random
import colorsys
from typing import List, Dict, Any, Optional, Tuple


def generate_node_color(node_type="default"):
    """
    Generate a random background color for nodes with appropriate text color.
    Returns a dict with backgroundColor and textColor.
    """
    # Pre-defined pleasant colors for different node types
    if node_type == "group":
        # Groups get light gray with subtle tint
        hue = random.uniform(0, 1)
        saturation = random.uniform(0.05, 0.15)
        lightness = random.uniform(0.85, 0.95)
    elif node_type == "data":
        # Data nodes get soft pastel colors
        hue = random.uniform(0, 1)
        saturation = random.uniform(0.3, 0.5)
        lightness = random.uniform(0.7, 0.85)
    else:  # default
        # Default nodes get vibrant but professional colors
        hue = random.uniform(0, 1)
        saturation = random.uniform(0.4, 0.7)
        lightness = random.uniform(0.6, 0.8)
    
    # Convert HSL to RGB
    r, g, b = colorsys.hls_to_rgb(hue, lightness, saturation)
    r, g, b = int(r * 255), int(g * 255), int(b * 255)
    
    bg_color = f"#{r:02x}{g:02x}{b:02x}"
    
    # Determine if text should be black or white based on luminance
    # Using perceived luminance formula
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    text_color = "#000000" if luminance > 0.5 else "#ffffff"
    
    return {
        "backgroundColor": bg_color,
        "color": text_color,
        "borderColor": "#555555"
    }


def generate_edge_stroke():
    """
    Generate a random but professional stroke color for edges.
    Returns a hex color string.
    """
    # Professional edge colors (blues, grays, teals, purples)
    edge_colors = [
        "#4A90E2",  # Soft Blue
        "#5B6C7E",  # Slate Gray
        "#20B2AA",  # Light Sea Green
        "#7B68EE",  # Medium Slate Blue
        "#5F9EA0",  # Cadet Blue
        "#6495ED",  # Cornflower Blue
        "#6A5ACD",  # Slate Blue
        "#4682B4",  # Steel Blue
        "#808080",  # Gray
        "#2F4F4F",  # Dark Slate Gray
        "#3B82F6",  # Blue
        "#8B5CF6",  # Purple
        "#06B6D4",  # Cyan
        "#10B981",  # Emerald
        "#6366F1",  # Indigo
    ]
    return random.choice(edge_colors)


def generate_deterministic_color(seed_string: str, node_type="default"):
    """
    Generate a deterministic color based on a seed string (like node ID).
    Same seed will always produce the same color.
    """
    import hashlib
    
    # Create a hash of the seed string
    hash_obj = hashlib.md5(seed_string.encode())
    hash_int = int(hash_obj.hexdigest(), 16)
    
    # Use the hash to seed random
    random.seed(hash_int)
    
    if node_type == "group":
        hue = random.uniform(0, 1)
        saturation = random.uniform(0.05, 0.15)
        lightness = random.uniform(0.85, 0.95)
    elif node_type == "data":
        hue = random.uniform(0, 1)
        saturation = random.uniform(0.3, 0.5)
        lightness = random.uniform(0.7, 0.85)
    else:
        hue = random.uniform(0, 1)
        saturation = random.uniform(0.4, 0.7)
        lightness = random.uniform(0.6, 0.8)
    
    # Reset random seed
    random.seed()
    
    r, g, b = colorsys.hls_to_rgb(hue, lightness, saturation)
    r, g, b = int(r * 255), int(g * 255), int(b * 255)
    
    bg_color = f"#{r:02x}{g:02x}{b:02x}"
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    text_color = "#000000" if luminance > 0.5 else "#ffffff"
    
    return {
        "backgroundColor": bg_color,
        "color": text_color,
        "borderColor": "#555555"
    }


def calculate_node_positions(nodes: List[Dict], edges: List[Dict] = None) -> List[Dict]:
    """
    Calculate optimal positions for nodes to avoid overlap.
    Ensures children are properly positioned inside their parent groups.
    """
    if not nodes:
        return nodes
    
    # Make a deep copy to avoid modifying original
    import copy
    nodes = copy.deepcopy(nodes)
    
    # Separate groups from component nodes
    groups = [n for n in nodes if n.get("type") == "group"]
    components = [n for n in nodes if n.get("type") != "group"]
    
    # Build parent-child relationships
    parent_map = {}
    for node in components:
        parent_id = node.get("parentId")
        if parent_id:
            if parent_id not in parent_map:
                parent_map[parent_id] = []
            parent_map[parent_id].append(node)
    
    # Position groups first (top level)
    groups = _position_groups(groups)
    
    # Create group lookup by ID
    group_map = {g.get("id"): g for g in groups}
    
    # Position children inside their parent groups
    positioned_components = []
    
    for component in components:
        parent_id = component.get("parentId")
        
        if parent_id and parent_id in group_map:
            # This component belongs to a group - position it inside
            parent_group = group_map[parent_id]
            _position_child_in_group(component, parent_group, parent_map.get(parent_id, []))
            positioned_components.append(component)
        else:
            # This component has no parent or parent not found
            positioned_components.append(component)
    
    # Position ungrouped components outside groups
    ungrouped = [c for c in positioned_components if not c.get("parentId") or c.get("parentId") not in group_map]
    grouped = [c for c in positioned_components if c.get("parentId") and c.get("parentId") in group_map]
    
    if ungrouped:
        ungrouped = _position_ungrouped_components(ungrouped, groups)
    
    # Merge all nodes
    result = groups + grouped + ungrouped
    
    # Final pass to ensure group sizes contain all children
    result = _adjust_group_sizes_for_children(result, group_map, parent_map)
    
    return result


def _position_groups(groups: List[Dict]) -> List[Dict]:
    """Position group containers in a grid layout with increased spacing."""
    if not groups:
        return groups
    
    # Increased spacing to prevent overlap
    start_x = -96.0
    start_y = -44.0
    groups_per_row = 2
    spacing_x = 1000  # Increased from 900
    spacing_y = 700   # Increased from 600
    
    for i, group in enumerate(groups):
        row = i // groups_per_row
        col = i % groups_per_row
        
        group["position"] = {
            "x": start_x + (col * spacing_x),
            "y": start_y + (row * spacing_y)
        }
        group["positionAbsolute"] = group["position"].copy()
        
        # Default group size (increased)
        if "width" not in group:
            group["width"] = 850  # Increased from 800
        if "height" not in group:
            group["height"] = 550  # Increased from 500
        
        # Store original position for reference
        group["original_x"] = group["position"]["x"]
        group["original_y"] = group["position"]["y"]
            
    return groups


def _position_child_in_group(child: Dict, parent_group: Dict, siblings: List[Dict] = None) -> None:
    """
    Position a single child node inside its parent group.
    Uses grid layout with proper offsets from group origin and increased spacing.
    """
    if not parent_group:
        return
    
    # Get group position (origin)
    group_x = parent_group.get("position", {}).get("x", 0)
    group_y = parent_group.get("position", {}).get("y", 0)
    
    # Group internal padding (increased)
    padding = 60  # Increased from 40
    
    # Calculate grid dimensions based on siblings
    if siblings:
        num_children = len(siblings)
        cols = min(4, math.ceil(math.sqrt(num_children)))
    else:
        cols = 1
    
    # Node dimensions
    node_width = child.get("width", 150)
    node_height = child.get("height", 60)
    spacing_x = 50  # Increased horizontal spacing
    spacing_y = 80  # Increased vertical spacing
    
    # Find this child's index among siblings
    if siblings:
        try:
            child_index = siblings.index(child)
        except ValueError:
            child_index = 0
    else:
        child_index = 0
    
    # Calculate position within group
    col = child_index % cols
    row = child_index // cols
    
    # Calculate position relative to group origin (with increased spacing)
    relative_x = padding + (col * (node_width + spacing_x))
    relative_y = padding + (row * (node_height + spacing_y))
    
    # Set absolute position
    child["position"] = {
        "x": group_x + relative_x,
        "y": group_y + relative_y
    }
    child["positionAbsolute"] = child["position"].copy()
    
    # Store relative position for reference
    child["relative_x"] = relative_x
    child["relative_y"] = relative_y


def _position_ungrouped_components(components: List[Dict], groups: List[Dict]) -> List[Dict]:
    """
    Position ungrouped components OUTSIDE all groups.
    Places them in a grid below all groups with increased spacing.
    """
    if not components:
        return components
    
    # Find the lowest Y position of all groups
    max_group_bottom = -float('inf')
    for group in groups:
        group_y = group.get("position", {}).get("y", 0)
        group_height = group.get("height", 550)  # Updated default
        group_bottom = group_y + group_height
        max_group_bottom = max(max_group_bottom, group_bottom)
    
    # Start below the lowest group with extra margin
    start_y = max_group_bottom + 150 if groups else 150  # Increased from 100
    start_x = 100
    
    cols = min(3, math.ceil(math.sqrt(len(components))))
    spacing_x = 400  # Increased from 350
    spacing_y = 350  # Increased from 300
    node_width = 150
    node_height = 60
    
    for i, node in enumerate(components):
        col = i % cols
        row = i // cols
        
        node["position"] = {
            "x": start_x + (col * spacing_x),
            "y": start_y + (row * spacing_y)
        }
        node["positionAbsolute"] = node["position"].copy()
        
        # Set default dimensions if not present
        if "width" not in node:
            node["width"] = node_width
        if "height" not in node:
            node["height"] = node_height
    
    return components


def _adjust_group_sizes_for_children(nodes: List[Dict], group_map: Dict, parent_map: Dict) -> List[Dict]:
    """
    Adjust group dimensions to properly contain all child nodes.
    Expands groups if children extend beyond boundaries.
    """
    for group_id, children in parent_map.items():
        group = group_map.get(group_id)
        if not group or not children:
            continue
        
        group_x = group.get("position", {}).get("x", 0)
        group_y = group.get("position", {}).get("y", 0)
        
        # Calculate bounds of children
        min_child_x = float('inf')
        min_child_y = float('inf')
        max_child_x = float('-inf')
        max_child_y = float('-inf')
        
        for child in children:
            child_x = child.get("position", {}).get("x", 0)
            child_y = child.get("position", {}).get("y", 0)
            child_w = child.get("width", 150)
            child_h = child.get("height", 60)
            
            min_child_x = min(min_child_x, child_x)
            min_child_y = min(min_child_y, child_y)
            max_child_x = max(max_child_x, child_x + child_w)
            max_child_y = max(max_child_y, child_y + child_h)
        
        # Add extra padding (increased)
        padding = 80  # Increased from 50
        required_width = (max_child_x - min_child_x) + (2 * padding)
        required_height = (max_child_y - min_child_y) + (2 * padding)
        
        # Update group size (only expand, don't shrink)
        current_width = group.get("width", 850)
        current_height = group.get("height", 550)
        
        group["width"] = max(current_width, required_width)
        group["height"] = max(current_height, required_height)
        
        # If group expanded, reposition children to maintain relative positions
        if group["width"] > current_width or group["height"] > current_height:
            for child in children:
                # Keep relative position from group origin
                rel_x = child.get("relative_x", child["position"]["x"] - group_x)
                rel_y = child.get("relative_y", child["position"]["y"] - group_y)
                
                # Ensure within padding bounds (with extra margin)
                padding_inner = 60
                rel_x = max(padding_inner, min(rel_x, group["width"] - child.get("width", 150) - padding_inner))
                rel_y = max(padding_inner, min(rel_y, group["height"] - child.get("height", 60) - padding_inner))
                
                child["position"] = {
                    "x": group_x + rel_x,
                    "y": group_y + rel_y
                }
                child["positionAbsolute"] = child["position"].copy()
    
    return nodes


def recalculate_group_heights_from_children(nodes: List[Dict]) -> List[Dict]:
    """
    Recalculate group dimensions based on child node positions.
    This is a wrapper for the internal adjustment function.
    """
    # Separate groups and build relationships
    groups = [n for n in nodes if n.get("type") == "group"]
    group_map = {g.get("id"): g for g in groups}
    
    parent_map = {}
    for node in nodes:
        if node.get("type") != "group":
            parent_id = node.get("parentId")
            if parent_id and parent_id in group_map:
                if parent_id not in parent_map:
                    parent_map[parent_id] = []
                parent_map[parent_id].append(node)
    
    return _adjust_group_sizes_for_children(nodes, group_map, parent_map)


def adjust_group_sizes(nodes: List[Dict]) -> List[Dict]:
    """Adjust group sizes to properly contain all child nodes."""
    return recalculate_group_heights_from_children(nodes)


def position_ungrouped_nodes(nodes: List[Dict], edges: List[Dict] = None) -> List[Dict]:
    """
    Position nodes that don't belong to any group outside all groups.
    """
    groups = [n for n in nodes if n.get("type") == "group"]
    group_ids = {g.get("id") for g in groups}
    
    # Separate grouped and ungrouped nodes
    grouped_nodes = []
    ungrouped_nodes = []
    
    for node in nodes:
        if node.get("type") == "group":
            continue
        if node.get("parentId") and node.get("parentId") in group_ids:
            grouped_nodes.append(node)
        else:
            ungrouped_nodes.append(node)
    
    # Position ungrouped nodes below all groups
    if ungrouped_nodes:
        ungrouped_nodes = _position_ungrouped_components(ungrouped_nodes, groups)
    
    # Merge back
    result = [n for n in nodes if n.get("type") == "group"] + grouped_nodes + ungrouped_nodes
    
    return result


def build_basic_node(node_id: str, label: str, node_type: str = "default", 
                     position: Tuple[float, float] = (0, 0), 
                     parent_id: str = None) -> Dict:
    """Build a basic node object with random colored styling."""
    import uuid
    
    width = 850 if node_type == "group" else (50 if node_type == "data" else 150)
    height = 550 if node_type == "group" else (30 if node_type == "data" else 60)
    
    # Generate random colors based on node type
    colors = generate_node_color(node_type)
    
    node = {
        "id": node_id,
        "type": node_type,
        "position": {"x": position[0], "y": position[1]},
        "positionAbsolute": {"x": position[0], "y": position[1]},
        "width": width,
        "height": height,
        "selected": False,
        "dragging": False,
        "resizing": False,
        "isAsset": False,
        "data": {
            "label": label,
            "nodeId": node_id,
            "style": {
                "backgroundColor": colors["backgroundColor"],
                "borderColor": "#999999" if node_type == "group" else "#555555",
                "borderStyle": "dashed" if node_type == "group" else "solid",
                "borderWidth": "1px" if node_type == "group" else "2px",
                "color": colors["color"],
                "fontFamily": "Inter",
                "fontSize": "14px" if node_type == "group" else "12px",
                "fontStyle": "normal",
                "fontWeight": 600 if node_type == "group" else 500,
                "height": height,
                "textAlign": "center",
                "textDecoration": "none",
                "width": width
            }
        },
        "style": {"height": height, "width": width},
        "properties": ["Integrity", "Confidentiality", "Authenticity", "Authorization", "Availability", "Non-repudiation"]
    }
    
    if parent_id:
        node["parentId"] = parent_id
        node["zIndex"] = 1
    else:
        node["zIndex"] = 0 if node_type == "group" else 2
    
    return node


def build_full_edge(source_id: str, target_id: str, label: str = "", 
                    edge_type: str = "step") -> Dict:
    """Build a complete edge object for React Flow with random colored stroke."""
    import uuid
    
    # Generate random stroke color
    stroke_color = generate_edge_stroke()
    
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
            "color": stroke_color,
            "height": 18,
            "type": "arrowclosed",
            "width": 18
        },
        "markerStart": {
            "color": stroke_color,
            "height": 18,
            "orient": "auto-start-reverse",
            "type": "arrowclosed",
            "width": 18
        },
        "style": {
            "end": True,
            "start": True,
            "stroke": stroke_color,
            "strokeDasharray": "0",
            "strokeWidth": 2
        }
    }
    
    return edge