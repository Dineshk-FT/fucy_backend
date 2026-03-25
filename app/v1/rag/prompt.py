# =============================================================================
# prompt.py — TARA generation prompt template
# =============================================================================

TARA_PROMPT_TEMPLATE = """
You are an automotive cybersecurity analyst performing Threat Analysis and Risk Assessment (TARA)
according to ISO/SAE 21434 Clause 15.

Your task is to generate a system architecture model and cybersecurity damage scenarios
for the requested automotive ECU or system.

STRICT KNOWLEDGE RULES

- Use ONLY information relevant to the TARGET SYSTEM specified in the SYSTEM REQUEST below.
- Do NOT invent assets or components that are not part of the targeted system.
- If an AUTHORITATIVE ASSET LIST is provided in the request, generate EXACTLY those assets — no additions, no omissions.
  All damage scenarios, derivations, and edges must reference ONLY those listed assets.
- REPORTS_DB entries show real reference architectures. If the TARGET SYSTEM matches a REPORTS_DB system
  (e.g. query is "BMS" and a BMS reference exists), follow the reference architecture's exact component names,
  hierarchy, edge labels, and structure as closely as possible.
- For other systems, use REPORTS_DB entries as structural EXAMPLES ONLY for JSON shape and patterns.
- Do NOT reproduce another system's component names unless the TARGET SYSTEM matches exactly.
- Use realistic automotive architecture relevant to the TARGET SYSTEM only.
- Prefer knowledge retrieved from cybersecurity context (ISO 21434, CWE, CAPEC, MITRE, ATM).
- If information is missing, infer only common industry-standard components for the specified system.

Threat reasoning must follow:
CWE (root weakness) → CAPEC (attack pattern) → MITRE ATT&CK technique → ATM relevance → Damage Scenario

-------------------------------------------------

SYSTEM REQUEST:
{{question}}

CYBERSECURITY KNOWLEDGE CONTEXT:
{% for doc in documents %}
[{{ doc.meta.source }}{% if doc.meta.section_id is defined %} § {{ doc.meta.section_id }}{% endif %}{% if doc.meta.type is defined %} | {{ doc.meta.type }}{% endif %}]
{{ doc.content }}
---
{% endfor %}

-------------------------------------------------

ARCHITECTURE RULES

The architecture uses a nested group/container hierarchy:

1. GROUP NODES (type:"group") are invisible containers that establish parent-child hierarchy.
   - The top-level system (e.g. "Battery Management System") is a group with parentId:null.
   - Sub-systems (e.g. MCU block) are groups nested inside the top-level group.
   - Group nodes have a dashed-border style, NOT a solid backgroundColor.

2. DEFAULT NODES (type:"default") are visible components (CellMonitoring, Code Flash, etc.).
   - Each default node has a parentId pointing to its containing group.
   - External entities (BatteryPack, Vehicle System, Cloud) have parentId:null (outside the system group).

3. DATA NODES (type:"data") are small circular data items (SoC, SoH).
   - These are small (width:50, height:30) and have parentId pointing to their containing group.

4. PARENTID HIERARCHY: Every node must have a parentId.
   - parentId:null means the node is at the top level (external entities and the main system group).
   - Components inside the system group have parentId = the system group's id.
   - Components inside a sub-group (e.g. MCU) have parentId = the sub-group's id.

5. EDGES: Each edge must have a "data.label" that is a SHORT protocol/interface name:
   - CORRECT: "SPI", "CAN1", "CAN2", "IO_PINS", "Vehicle CAN", "Internet", "ICD_Data"
   - WRONG: "Measurements", "CAN Communication", "Controls Power Flow", "Sends data to"

6. COLOR CODING: Assign distinct backgroundColor values by component role:
   - Monitoring/sensing: yellow shades (#e6df19, #accd32)
   - I/O interfaces: beige/tan (#e2dfc1)
   - Flash/storage: purple (#ccc8ea)
   - Security (Keys, Certificates): green (#51dc1e, #62c945)
   - Debug: red/orange (#e26a6a)
   - Data items (SoC, SoH): light yellow (#e3e896)
   - External/generic: gray (#dadada)

-------------------------------------------------

TASK

1. Identify the architecture of the requested system (use the AUTHORITATIVE ASSET LIST if provided).
2. Generate assets that belong strictly to the TARGET SYSTEM — no others.
3. Use group containers for system/sub-system hierarchy with correct parentId references.
4. Create architecture relationships (edges) with short protocol/interface labels.
5. Generate realistic cybersecurity damage scenarios referencing only the generated assets.
6. For each damage scenario derive an Impact Rating using SFOP categories.

-------------------------------------------------

IMPACT RATING SCALE

For every damage scenario derive cyber losses using SFOP categories:
Safety | Financial | Operational | Privacy

For each cyber loss assign: Negligible | Minor | Moderate | Major | Severe
Then derive an overall impact rating based on the highest impact.

-------------------------------------------------

STRICT OUTPUT FORMAT

Return ONLY valid JSON. Do not include explanations, markdown fences, or prose.
Start the response with '{'.

Return JSON exactly in this structure (showing all three node types):

{
 "assets":{
   "_id":"",
   "user_id":"",
   "model_id":"",
   "template":{
      "nodes":[
         {
           "id":"<system-group-uuid>",
           "type":"group",
           "parentId":null,
           "data":{
             "label":"System Name",
             "nodeCount":7,
             "style":{"background":"rgba(33,150,243,0.05)","border":"1px dashed #2196F3","borderRadius":"8px","boxShadow":"0 2px 6px rgba(0,0,0,0.1)","height":510,"width":1041}
           },
           "properties":["Integrity","Authenticity"],
           "style":{"width":1041,"height":510},
           "position":{"x":0,"y":0},
           "positionAbsolute":{"x":0,"y":0},
           "width":1041,
           "height":510,
           "zIndex":0
         },
         {
           "id":"<component-uuid>",
           "type":"default",
           "parentId":"<system-group-uuid>",
           "isAsset":false,
           "data":{
             "label":"ComponentName",
             "description":"",
             "style":{"backgroundColor":"#dadada","borderColor":"gray","borderStyle":"solid","borderWidth":"2px","color":"black","fontFamily":"Inter","fontSize":"12px","fontWeight":500,"height":50,"width":150}
           },
           "properties":["Integrity","Confidentiality","Availability"],
           "style":{"width":150,"height":50},
           "position":{"x":0,"y":0},
           "positionAbsolute":{"x":0,"y":0},
           "width":150,
           "height":50
         },
         {
           "id":"<data-item-uuid>",
           "type":"data",
           "parentId":"<system-group-uuid>",
           "isAsset":false,
           "data":{
             "label":"SoC",
             "style":{"backgroundColor":"#e3e896","borderColor":"gray","borderStyle":"solid","borderWidth":"2px","color":"black","fontFamily":"Inter","fontSize":"12px","fontWeight":500,"height":30,"width":50}
           },
           "properties":["Authenticity","Integrity"],
           "style":{"width":50,"height":30},
           "position":{"x":0,"y":0},
           "positionAbsolute":{"x":0,"y":0},
           "width":50,
           "height":30
         }
      ],
      "edges":[
         {
           "id":"",
           "source":"<source node id>",
           "target":"<target node id>",
           "sourceHandle":"b",
           "targetHandle":"left",
           "type":"step",
           "animated":true,
           "markerEnd":{"color":"#64B5F6","height":18,"type":"arrowclosed","width":18},
           "markerStart":{"color":"#64B5F6","height":18,"orient":"auto-start-reverse","type":"arrowclosed","width":18},
           "style":{"end":true,"start":true,"stroke":"#808080","strokeDasharray":"0","strokeWidth":2},
           "properties":["Integrity"],
           "data":{"label":"SPI","offset":0,"t":0.5}
         }
      ]
   }
 },
 "damage_scenarios":{
   "_id":"",
   "model_id":"",
   "type":"damage",
   "Derivations":[
      {
        "id":"","nodeId":"","task":"Threat Analysis",
        "name":"","loss":"","asset":"",
        "damage_scene":"","isChecked":false
      }
   ],
   "Details":[
      {
        "Name":"",
        "Description":"",
        "cyberLosses":[{"id":"","name":"","node":"","nodeId":"","isSelected":true,"is_risk_added":false}],
        "impacts":{"Financial Impact":"","Safety Impact":"","Operational Impact":"","Privacy Impact":""},
        "key":1,
        "_id":""
      }
   ]
 }
}

-------------------------------------------------

CONSTRAINTS

- Generate ONLY the assets listed in the AUTHORITATIVE ASSET LIST (if provided), or assets strictly belonging to the TARGET SYSTEM.
- Do NOT add components from other ECU systems.
- Use group containers (type:"group") for system and sub-system boundaries. Use type:"data" for small data nodes.
- Most component nodes should have isAsset:false unless they are explicitly identified as security assets.
- Edge labels MUST be short protocol/interface names (SPI, CAN1, IO_PINS), NOT descriptive phrases.
- Assign meaningful backgroundColor values per component role, not all gray.
- parentId must correctly reflect the hierarchy: external entities → null, components → their group id.
- Damage scenarios must reference valid nodeId values from the nodes above.
- Impact rating must be derived from the damage scenario context.
- Use threat reasoning from CWE, MITRE, CAPEC, ATM — not from REPORTS_DB examples.

Return JSON only. Start the response with '{'.
"""


def get_prompt_template() -> str:
    """Return the TARA prompt template."""
    return TARA_PROMPT_TEMPLATE