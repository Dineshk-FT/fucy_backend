# =============================================================================
# cache_manager.py — Cache manager for LangGraph pipeline
# =============================================================================

import os
import json
import hashlib

CACHE_DIR = "cache"

def get_cache_key(query: str, step: str):
    """Generate a unique key based on the input query and the agent step."""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    hash_object = hashlib.md5(query.encode())
    query_hash = hash_object.hexdigest()[:8]
    return os.path.join(CACHE_DIR, f"{query_hash}_{step}.json")

def save_cache(query: str, step: str, data: dict):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    
    file_path = get_cache_key(query, step)
    with open(file_path, "w") as f:
        json.dump(data, f)
    print(f"  💾 Cached {step} result.")

def load_cache(query: str, step: str):
    file_path = get_cache_key(query, step)
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            print(f"  ⚡ Using Cached {step} result (Skipping API call)...")
            return json.load(f)
    return None

def clear_cache(query: str, step: str):
    """Clear a specific cache entry."""
    file_path = get_cache_key(query, step)
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"  🗑️ Cleared cache for {step}")