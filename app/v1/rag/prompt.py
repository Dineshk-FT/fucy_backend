from __future__ import annotations

from haystack.components.builders import PromptBuilder

ISO21434_CLAUSE15_TEMPLATE = """
You are an automotive cybersecurity analyst performing Threat Analysis and Risk Assessment (TARA)
according to ISO/SAE 21434 Clause 15.

Your task is to generate a system architecture model and cybersecurity damage scenarios
for the requested automotive ECU or system.

STRICT KNOWLEDGE RULES

- Use ONLY information relevant to the requested system.
- Do NOT invent unrelated vehicle components.
- Assets must belong to the requested ECU/system.
- Use realistic automotive architecture.
- Prefer knowledge retrieved from the provided cybersecurity context.
- If information is missing, infer only common industry-standard components.

Cybersecurity knowledge context may include:

- ISO 21434 clauses
- CWE weaknesses
- CAPEC attack patterns
- MITRE ATT&CK techniques
- Automotive Threat Matrix (ATM)

Threat reasoning must follow:

CWE (root weakness) → CAPEC (attack pattern) → MITRE ATT&CK (attack technique) → ATM relevance → Damage Scenario

-------------------------------------------------

SYSTEM REQUEST:
{{question}}

CYBERSECURITY KNOWLEDGE CONTEXT:
{{documents}}

-------------------------------------------------

TASK

1. Identify the architecture of the requested system.
2. Generate assets that belong strictly to that system.
3. Create architecture relationships between assets.
4. Generate realistic cybersecurity damage scenarios.
5. For each damage scenario derive an **Impact Rating**.

-------------------------------------------------

IMPACT RATING SCALE

For every damage scenario derive cyber losses using SFOP categories:

Safety
Financial
Operational
Privacy

For each cyber loss assign an impact rating using:

Negligible
Minor
Moderate
Major
Severe

Then derive an overall impact rating based on the highest impact.
-------------------------------------------------

STRICT OUTPUT FORMAT

Return ONLY valid JSON.

Do not include explanations.

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
           "type":"component",
           "parentId":"",
           "isAsset":true,
           "data":{
              "label":"",
              "description":""
           },
           "properties":[
              "Integrity",
              "Confidentiality",
              "Availability"
           ],
           "style":{
              "width":200,
              "height":80
           },
           "position":{
              "x":0,
              "y":0
           }
         }
      ],

      "edges":[
         {
           "id":"",
           "source":"",
           "target":"",
           "type":"smoothstep",
           "data":{
              "label":""
           }
         }
      ],

      "details":[
         {
           "nodeId":"",
           "name":"",
           "desc":"",
           "type":"",
           "props":[
             {
               "name":"",
               "id":""
             }
           ]
         }
      ]
   }
 },

 "damage_scenarios":{
   "_id":"",
   "model_id":"",
   "type":"damage",

   "derivation":[
      {
        "id":"",
        "nodeId":"",
        "task":"Threat Analysis",
        "name":"",
        "loss":"",
        "asset":"",
        "damage_scene":"",
        "isChecked":false
      }
   ],

   "details":[
  {
    "Name":"",
    "Description":"",
    "cyberLosses":[
      {
        "id":"",
        "name":"",
        "node":"",
        "nodeId":"",
        "isSelected":true,
        "is_risk_added":false
      }
    ],
    "impacts":{
      "Financial Impact":"",
      "Safety Impact":"",
      "Operational Impact":"",
      "Privacy Impact":""
    },
    "key":1,
    "_id":""
  }
]
}
]
}
}
-------------------------------------------------

CONSTRAINTS

- Generate at least 10 assets belonging to the requested system.
- Assets must match the requested ECU/system architecture.
- Do NOT generate assets unrelated to the system.
- Damage scenarios must reference valid nodeId values.
- Impact rating must be derived from the damage scenario.
- Use cybersecurity reasoning from CWE, MITRE, CAPEC and ATM.

Return JSON only.

Start the response with '{'.
"""



def create_prompt_builder(template: str = ISO21434_CLAUSE15_TEMPLATE) -> PromptBuilder:
    return PromptBuilder(
        template=template,
        required_variables=["documents", "question"],
    )
