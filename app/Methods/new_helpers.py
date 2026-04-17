import math
from typing import List, Dict, Any, Optional, Tuple

def calculate_node_positions(nodes: List[Dict], edges: List[Dict] = None) -> List[Dict]:
    """
    Calculate optimal positions for nodes to avoid overlap.
    
    Args:
        nodes: List of node objects
        edges: List of edge objects (optional, for layout hints)
    
    Returns:
        Nodes with updated positions
    """
    if not nodes:
        return nodes
    
    # Separate groups from component nodes
    groups = [n for n in nodes if n.get("type") == "group"]
    components = [n for n in nodes if n.get("type") != "group"]
    
    # Position groups first (top level)
    groups = _position_groups(groups)
    
    # Position components inside their groups
    components = _position_components_in_groups(components, groups)
    
    # Position remaining components (ungrouped) outside all groups
    ungrouped_components = [c for c in components if not c.get("parentId")]
    grouped_components = [c for c in components if c.get("parentId")]
    
    ungrouped_components = _position_ungrouped_components(ungrouped_components, groups)
    
    # Merge back
    positioned_nodes = groups + grouped_components + ungrouped_components
    
    # Final pass to resolve any remaining overlap
    positioned_nodes = _resolve_overlap(positioned_nodes)
    
    return positioned_nodes


def _position_groups(groups: List[Dict]) -> List[Dict]:
    """Position group containers in a grid layout."""
    if not groups:
        return groups
    
    start_x = -96.0
    start_y = -44.0
    groups_per_row = 2
    spacing_x = 900
    spacing_y = 600
    
    for i, group in enumerate(groups):
        row = i // groups_per_row
        col = i % groups_per_row
        
        group["position"] = {
            "x": start_x + (col * spacing_x),
            "y": start_y + (row * spacing_y)
        }
        group["positionAbsolute"] = group["position"].copy()
        
        # Default group size if not specified
        if "width" not in group:
            group["width"] = 800
        if "height" not in group:
            group["height"] = 500
            
    return groups


def _position_components_in_groups(components: List[Dict], groups: List[Dict]) -> List[Dict]:
    """
    Position child components inside their parent groups using a grid layout.
    """
    if not components or not groups:
        return components
    
    # Build group lookup
    group_map = {g.get("id"): g for g in groups}
    
    # Separate nodes with parentId (children) from root nodes
    children = [c for c in components if c.get("parentId")]
    
    # Group children by their parent group
    children_by_parent = {}
    for child in children:
        parent_id = child.get("parentId")
        if parent_id not in children_by_parent:
            children_by_parent[parent_id] = []
        children_by_parent[parent_id].append(child)
    
    # Position children inside each group
    for parent_id, child_list in children_by_parent.items():
        parent_group = group_map.get(parent_id)
        if parent_group:
            _position_children_in_group(child_list, parent_group)
    
    return components


def _position_children_in_group(children: List[Dict], parent_group: Dict) -> None:
    """
    Position child nodes inside their parent group using a grid layout.
    Prevents overlap by calculating exact positions.
    """
    if not children:
        return
    
    group_x = parent_group.get("position", {}).get("x", 0)
    group_y = parent_group.get("position", {}).get("y", 0)
    group_width = parent_group.get("width", 800)
    group_height = parent_group.get("height", 500)
    
    # Calculate available space inside group (with padding)
    padding = 30
    available_width = group_width - (2 * padding)
    available_height = group_height - (2 * padding)
    
    # Determine optimal grid dimensions
    num_children = len(children)
    cols = min(4, math.ceil(math.sqrt(num_children)))
    rows = math.ceil(num_children / cols)
    
    # Calculate cell size (with spacing between nodes)
    node_width = 150
    node_height = 60
    spacing = 20
    
    # Calculate total grid dimensions
    total_grid_width = (cols * node_width) + ((cols - 1) * spacing)
    total_grid_height = (rows * node_height) + ((rows - 1) * spacing)
    
    # Center the grid within the group
    start_x = group_x + padding + (available_width - total_grid_width) / 2
    start_y = group_y + padding + (available_height - total_grid_height) / 2
    
    # Position each child
    for i, child in enumerate(children):
        col = i % cols
        row = i // cols
        
        # Calculate position within group
        child_x = start_x + (col * (node_width + spacing))
        child_y = start_y + (row * (node_height + spacing))
        
        # Set node dimensions
        child["width"] = node_width
        child["height"] = node_height
        child["position"] = {"x": child_x, "y": child_y}
        child["positionAbsolute"] = child["position"].copy()


def _position_ungrouped_components(components: List[Dict], groups: List[Dict]) -> List[Dict]:
    """
    Position ungrouped components OUTSIDE all groups.
    Ensures no component overlaps with any group.
    """
    if not components:
        return components
    
    # Find the bounding area of all groups
    group_bounds = _get_group_bounds(groups)
    
    # Position ungrouped components below all groups
    start_x = group_bounds["min_x"] if group_bounds else 100
    start_y = group_bounds["max_y"] + 100 if group_bounds else 100
    
    cols = min(3, math.ceil(math.sqrt(len(components))))
    spacing_x = 350
    spacing_y = 300
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
        
        # Set default dimensions
        node["width"] = node_width
        node["height"] = node_height
    
    return components


def _get_group_bounds(groups: List[Dict]) -> Dict:
    """Get the bounding box that covers all groups."""
    if not groups:
        return {}
    
    min_x = float('inf')
    min_y = float('inf')
    max_x = float('-inf')
    max_y = float('-inf')
    
    for group in groups:
        x = group.get("position", {}).get("x", 0)
        y = group.get("position", {}).get("y", 0)
        width = group.get("width", 800)
        height = group.get("height", 500)
        
        min_x = min(min_x, x)
        min_y = min(min_y, y)
        max_x = max(max_x, x + width)
        max_y = max(max_y, y + height)
    
    return {
        "min_x": min_x,
        "min_y": min_y,
        "max_x": max_x,
        "max_y": max_y
    }


def _resolve_overlap(nodes: List[Dict]) -> List[Dict]:
    """
    Detect and resolve overlapping between any nodes (groups or components).
    """
    if len(nodes) < 2:
        return nodes
    
    # Create bounding boxes for all nodes
    node_boxes = []
    for node in nodes:
        pos = node.get("position", {"x": 0, "y": 0})
        width = node.get("width", 150)
        height = node.get("height", 60)
        
        node_boxes.append({
            "node": node,
            "x": pos.get("x", 0),
            "y": pos.get("y", 0),
            "width": width,
            "height": height,
            "right": pos.get("x", 0) + width,
            "bottom": pos.get("y", 0) + height,
            "is_group": node.get("type") == "group"
        })
    
    # Resolve overlaps with multiple iterations
    margin = 30
    max_iterations = 10
    
    for iteration in range(max_iterations):
        overlaps_found = False
        
        for i in range(len(node_boxes)):
            for j in range(i + 1, len(node_boxes)):
                box1 = node_boxes[i]
                box2 = node_boxes[j]
                
                # Skip if one is a group and the other is inside it
                if _is_inside_group(box1, box2) or _is_inside_group(box2, box1):
                    continue
                
                # Check if boxes overlap (with margin)
                if (box1["x"] - margin < box2["right"] and
                    box1["right"] + margin > box2["x"] and
                    box1["y"] - margin < box2["bottom"] and
                    box1["bottom"] + margin > box2["y"]):
                    
                    overlaps_found = True
                    
                    # Calculate overlap amounts
                    overlap_x = min(box1["right"] + margin - box2["x"],
                                   box2["right"] + margin - box1["x"])
                    overlap_y = min(box1["bottom"] + margin - box2["y"],
                                   box2["bottom"] + margin - box1["y"])
                    
                    # Shift based on which is a group (groups should stay fixed)
                    if box1["is_group"] and not box2["is_group"]:
                        # Shift box2 (component) away from group
                        _shift_node_away(box2, box1, overlap_x, overlap_y)
                    elif box2["is_group"] and not box1["is_group"]:
                        # Shift box1 (component) away from group
                        _shift_node_away(box1, box2, overlap_x, overlap_y)
                    else:
                        # Both are components or both are groups - shift the one with smaller impact
                        if overlap_x < overlap_y:
                            if box1["x"] < box2["x"]:
                                _shift_node_right(box2, overlap_x + 10)
                            else:
                                _shift_node_right(box1, overlap_x + 10)
                        else:
                            if box1["y"] < box2["y"]:
                                _shift_node_down(box2, overlap_y + 10)
                            else:
                                _shift_node_down(box1, overlap_y + 10)
        
        if not overlaps_found:
            break
    
    # Apply updated positions back to nodes
    for box in node_boxes:
        box["node"]["position"] = {"x": box["x"], "y": box["y"]}
        box["node"]["positionAbsolute"] = box["node"]["position"].copy()
    
    return nodes


def _is_inside_group(child_box: Dict, group_box: Dict) -> bool:
    """Check if a node is inside a group."""
    if not group_box["is_group"]:
        return False
    
    # Check if node is completely inside the group
    return (child_box["x"] >= group_box["x"] and
            child_box["right"] <= group_box["right"] and
            child_box["y"] >= group_box["y"] and
            child_box["bottom"] <= group_box["bottom"])


def _shift_node_right(node_box: Dict, amount: float) -> None:
    """Shift a node to the right."""
    node_box["x"] += amount
    node_box["right"] += amount


def _shift_node_down(node_box: Dict, amount: float) -> None:
    """Shift a node down."""
    node_box["y"] += amount
    node_box["bottom"] += amount


def _shift_node_away(node_box: Dict, fixed_box: Dict, overlap_x: float, overlap_y: float) -> None:
    """Shift a node away from a fixed node (like a group)."""
    # Determine which direction has less overlap
    if overlap_x < overlap_y:
        # Shift horizontally
        if node_box["x"] < fixed_box["x"]:
            # Node is to the left, shift left
            node_box["x"] -= overlap_x + 10
            node_box["right"] -= overlap_x + 10
        else:
            # Node is to the right, shift right
            node_box["x"] += overlap_x + 10
            node_box["right"] += overlap_x + 10
    else:
        # Shift vertically
        if node_box["y"] < fixed_box["y"]:
            # Node is above, shift up
            node_box["y"] -= overlap_y + 10
            node_box["bottom"] -= overlap_y + 10
        else:
            # Node is below, shift down
            node_box["y"] += overlap_y + 10
            node_box["bottom"] += overlap_y + 10


def recalculate_group_heights_from_children(nodes: List[Dict], groups: List[Dict] = None) -> List[Dict]:
    """
    Calculate group dimensions based on child node positions.
    Expands groups to contain all children with proper padding.
    """
    if groups is None:
        groups = [n for n in nodes if n.get("type") == "group"]
    
    if not groups:
        return nodes
    
    group_map = {g.get("id"): g for g in groups}
    
    # Group children by parent
    children_by_parent = {}
    for node in nodes:
        parent_id = node.get("parentId")
        if parent_id and parent_id in group_map:
            if parent_id not in children_by_parent:
                children_by_parent[parent_id] = []
            children_by_parent[parent_id].append(node)
    
    # Calculate bounds for each group
    for parent_id, children in children_by_parent.items():
        group = group_map.get(parent_id)
        if not group or not children:
            continue
        
        # Get group position
        group_x = group.get("position", {}).get("x", 0)
        group_y = group.get("position", {}).get("y", 0)
        
        # Find min/max of child positions
        min_x = float('inf')
        min_y = float('inf')
        max_x = float('-inf')
        max_y = float('-inf')
        
        for child in children:
            pos = child.get("position", {"x": 0, "y": 0})
            child_x = pos.get("x", 0)
            child_y = pos.get("y", 0)
            child_width = child.get("width", 150)
            child_height = child.get("height", 60)
            
            min_x = min(min_x, child_x)
            min_y = min(min_y, child_y)
            max_x = max(max_x, child_x + child_width)
            max_y = max(max_y, child_y + child_height)
        
        # Add padding
        padding = 40
        min_x -= padding
        min_y -= padding
        max_x += padding
        max_y += padding
        
        # Calculate new dimensions
        new_width = max_x - min_x
        new_height = max_y - min_y
        
        # Only expand if needed (don't shrink)
        current_width = group.get("width", 800)
        current_height = group.get("height", 500)
        
        group["width"] = max(current_width, new_width)
        group["height"] = max(current_height, new_height)
        
        # Reposition group to contain children if needed
        if min_x < group_x:
            group["position"]["x"] = min_x
            group["positionAbsolute"]["x"] = min_x
        if min_y < group_y:
            group["position"]["y"] = min_y
            group["positionAbsolute"]["y"] = min_y
    
    return nodes


def adjust_group_sizes(nodes: List[Dict]) -> List[Dict]:
    """Adjust group sizes to properly contain all child nodes."""
    return recalculate_group_heights_from_children(nodes)


def position_ungrouped_nodes(nodes: List[Dict], edges: List[Dict] = None) -> List[Dict]:
    """Position nodes that don't belong to any group outside all groups."""
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
    """Build a basic node object with default styling."""
    import uuid
    
    width = 800 if node_type == "group" else (50 if node_type == "data" else 150)
    height = 500 if node_type == "group" else (30 if node_type == "data" else 60)
    
    bg_color = "#dadada" if node_type == "group" else ("#e3e896" if node_type == "data" else "#FFFFFF")
    
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
                "backgroundColor": bg_color,
                "borderColor": "gray",
                "borderStyle": "solid",
                "borderWidth": "2px",
                "color": "black",
                "fontFamily": "Inter",
                "fontSize": "12px" if node_type != "group" else "16px",
                "fontStyle": "normal",
                "fontWeight": 500,
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
        node["zIndex"] = 0 if node_type == "group" else 1
    
    return node


def build_full_edge(source_id: str, target_id: str, label: str = "", 
                    edge_type: str = "step") -> Dict:
    """Build a complete edge object for React Flow."""
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