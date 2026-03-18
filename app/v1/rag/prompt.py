from __future__ import annotations

from haystack.components.builders import PromptBuilder

ISO21434_CLAUSE15_TEMPLATE = """
You are an automotive cybersecurity analyst performing Threat Analysis and Risk Assessment (TARA)
according to ISO/SAE 21434 Clause 15.

Your task is to generate a system architecture model and cybersecurity damage scenarios
for the requested automotive ECU or system.

STRICT KNOWLEDGE RULES

- Use ONLY information relevant to the TARGET SYSTEM specified in the SYSTEM REQUEST below.
- Do NOT invent assets or components that are not part of the targeted system.
- If an AUTHORITATIVE ASSET LIST is provided in the request, generate EXACTLY those assets — no additions, no omissions.
  All damage scenarios, derivations, and edges must reference ONLY those listed assets.
- REPORTS_DB entries are structural EXAMPLES ONLY. Do NOT copy their node labels, scenario names, or IDs.
  They show the expected JSON shape, security property patterns, and derivation format.
  All generated content must be derived from the TARGET SYSTEM, not from any reference system (e.g. BMS).
- Do NOT reproduce BMS, Infotainment, or any other system's component names unless the TARGET SYSTEM matches exactly.
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
{% if doc.meta.source == "REPORTS_DB" %}
[REFERENCE-PATTERN-ONLY | structural example — do NOT copy node names or scenario content]
{% else %}
[{{ doc.meta.source }}{% if doc.meta.section_id is defined %} § {{ doc.meta.section_id }}{% endif %}{% if doc.meta.type is defined %} | {{ doc.meta.type }}{% endif %}]
{% endif %}
{{ doc.content }}
---
{% endfor %}

-------------------------------------------------

TASK

1. Identify the architecture of the requested system (use the AUTHORITATIVE ASSET LIST if provided).
2. Generate assets that belong strictly to the TARGET SYSTEM — no others.
3. Create architecture relationships (edges) between those assets.
4. Generate realistic cybersecurity damage scenarios referencing only the generated assets.
5. For each damage scenario derive an Impact Rating using SFOP categories.

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

Return JSON exactly in this structure:

{
 "assets":{
   "_id":"",
   "user_id":"",
   "model_id":"",

   "template":{
      "nodes":[
         {
           "id":"",
           "type":"default",
           "parentId":"",
           "isAsset":true,
           "data":{
             "label":"",
             "description":"",
             "style":{"backgroundColor":"#dadada","borderColor":"gray","borderStyle":"solid","borderWidth":"2px","color":"black","fontFamily":"Inter","fontSize":"12px","fontWeight":500,"height":50,"width":150}
           },
           "properties":["Integrity","Confidentiality","Availability"],
           "style":{"width":150,"height":50},
           "position":{"x":0,"y":0},
           "positionAbsolute":{"x":0,"y":0},
           "width":150,
           "height":50
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
           "data":{"label":"","offset":0,"t":0.5}
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
- Damage scenarios must reference valid nodeId values from the nodes above.
- Impact rating must be derived from the damage scenario context.
- Use threat reasoning from CWE, MITRE, CAPEC, ATM — not from REPORTS_DB examples.

Return JSON only. Start the response with '{'.
"""


def create_prompt_builder(template: str = ISO21434_CLAUSE15_TEMPLATE) -> PromptBuilder:
    """Create a PromptBuilder with the specified template."""
    return PromptBuilder(
        template=template,
        required_variables=["documents", "question"],
    )