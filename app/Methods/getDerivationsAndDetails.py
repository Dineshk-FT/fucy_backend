from db import db
import uuid


def uid():
    return str(uuid.uuid4())

def getDerivationsAndDetails(template, existing_details):
    nodes = template.get("nodes", [])
    edges = template.get("edges", [])
    Derivations = []
    Details = []
    derivation_counter = 1

    for node in nodes:
        if node.get("type") != "group":
            for pr in node.get("properties", []):
                Derivations.append(
                    {
                        "task": f"Check for DS due to the loss of {pr} for {node.get('data', {}).get('label')}",
                        "name": f"DS due to the loss of {pr} for {node.get('data', {}).get('label')}",
                        "loss": f"loss of {pr}",
                        "asset": node.get("isAsset"),
                        "damageScene": [],
                        "id": f"DS{derivation_counter:03}",
                        "nodeId": node.get("id"),
                    }
                )
                derivation_counter += 1

            Details.append(
                {
                    "nodeId": node.get("id"),
                    "name": node.get("data", {}).get("label"),
                    "type":node.get("type"),
                    "props": [
                        {"name": pr, "id": existing_details.get(node.get("id"), {}).get(pr, uid())}
                        for pr in node.get("properties", [])
                    ],
                }
            )

    for edge in edges:
        for prop in edge.get("properties", []):
            Derivations.append(
                {
                    "task": f"Check for DS due to the loss of {prop} for {edge.get('data', {}).get('label')}",
                    "name": f"DS due to the loss of {prop} for {edge.get('data', {}).get('label')}",
                    "loss": f"loss of {prop}",
                    "asset": edge.get("isAsset"),
                    "damageScene": [],
                    "id": f"DS{derivation_counter:03}",
                    "nodeId": edge.get("id"),
                }
            )
            derivation_counter += 1

        Details.append(
            {
                "nodeId": edge.get("id"),
                "name": edge.get("data", {}).get("label"),
                "type":edge.get("type"),
                "props": [
                    {"name": prop, "id": existing_details.get(edge.get("id"), {}).get(prop, uid())}
                    for prop in edge.get("properties", [])
                ],
            }
        )

    return Derivations, Details
