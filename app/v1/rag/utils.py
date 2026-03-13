import json
from datetime import datetime

def save_result_to_file(result, filename=None):
    """Save result to JSON file"""
    if filename is None:
        filename = f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    return filename

def load_json_file(filepath):
    """Load JSON file"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)