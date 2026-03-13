import json
from haystack import Document
from .pipeline import get_document_store
from .pipeline import rag_pipeline  # To access doc_embedder

def load_json_to_store(file_path, doc_embedder):
    """
    Load JSON file into document store with embedding
    
    Args:
        file_path: Path to JSON file
        doc_embedder: Document embedder instance from pipeline
    """
    store = get_document_store()
    docs = []
    
    with open(file_path, "r", encoding="utf-8") as f:
        full_data = json.load(f)
    
    file_name = file_path.split("/")[-1].split(".")[0]
    
    # Assets
    for asset in full_data.get("Assets", []):
        asset_id = asset.get("_id")
        
        # Full asset object
        docs.append(Document(
            content=json.dumps(asset, ensure_ascii=False),
            meta={
                "source": "full_file",
                "type": "full_asset",
                "file": file_name,
                "asset_id": asset_id
            }
        ))
        
        # Asset metadata
        docs.append(Document(
            content=json.dumps({
                "_id": asset.get("_id"),
                "user_id": asset.get("user_id"),
                "model_id": asset.get("model_id")
            }, ensure_ascii=False),
            meta={
                "source": "full_file",
                "type": "asset_metadata",
                "file": file_name,
                "asset_id": asset_id
            }
        ))
        
        template = asset.get("template", {})
        
        # Nodes
        for node in template.get("nodes", []):
            docs.append(Document(
                content=json.dumps(node, ensure_ascii=False),
                meta={
                    "source": "full_file",
                    "type": "node",
                    "file": file_name,
                    "asset_id": asset_id,
                    "node_id": node.get("id"),
                    "node_label": node.get("data", {}).get("label", "")
                }
            ))
        
        # Edges
        for edge in template.get("edges", []):
            docs.append(Document(
                content=json.dumps(edge, ensure_ascii=False),
                meta={
                    "source": "full_file",
                    "type": "edge",
                    "file": file_name,
                    "asset_id": asset_id,
                    "edge_id": edge.get("id"),
                    "source_node": edge.get("source"),
                    "target_node": edge.get("target")
                }
            ))
        
        # Asset Details
        for detail in (asset.get("Details", []) or []):
            docs.append(Document(
                content=json.dumps(detail, ensure_ascii=False),
                meta={
                    "source": "full_file",
                    "type": "asset_detail",
                    "file": file_name,
                    "asset_id": asset_id,
                    "node_id": detail.get("nodeId"),
                    "name": detail.get("Name") or detail.get("name")
                }
            ))
    
    # Damage Scenarios
    for ds in full_data.get("Damage_scenarios", []):
        ds_type = ds.get("type", "")
        ds_id = ds.get("_id")
        
        for deriv in ds.get("Derivations", []):
            docs.append(Document(
                content=json.dumps(deriv, ensure_ascii=False),
                meta={
                    "source": "full_file",
                    "type": "derivation",
                    "file": file_name,
                    "ds_type": ds_type,
                    "ds_id": ds_id,
                    "node_id": deriv.get("nodeId")
                }
            ))
        
        for detail in (ds.get("Details", []) or []):
            docs.append(Document(
                content=json.dumps(detail, ensure_ascii=False),
                meta={
                    "source": "full_file",
                    "type": "damage_detail",
                    "file": file_name,
                    "ds_type": ds_type,
                    "ds_id": ds_id,
                    "node_id": detail.get("nodeId"),
                    "name": detail.get("Name") or detail.get("name")
                }
            ))
    
    print(f"Loaded {len(docs)} documents from {file_path}")
    
    # Embed only small docs (not full_asset)
    small_docs = [d for d in docs if d.meta["type"] != "full_asset"]
    full_docs = [d for d in docs if d.meta["type"] == "full_asset"]
    
    embedded_small_docs = doc_embedder.run(documents=small_docs)["documents"]
    
    store.write_documents(embedded_small_docs + full_docs)
    print("Documents embedded and stored successfully.")
    
    return len(docs)