# =============================================================================
# prompt.py — TARA generation prompt templates (Multi-Agent Pipeline)
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# REFERENCE SCHEMA (not used by any pipeline node)
# ─────────────────────────────────────────────────────────────────────────────

TARA_PROMPT_TEMPLATE = """
[REFERENCE ONLY — This template is not used by any pipeline node.]

The final assembled TARA JSON structure (built by the evaluate() node from
individual agent outputs) follows this schema:

{
  "Models":            [{ "_id": "...", "name": "SystemName" }],
  "Assets":            [{ "template": { "nodes": [...], "edges": [...] }, "Details": [...] }],
  "Damage_scenarios":  [{ "Derivations": [...], "Details": [...] }],
  "Threat_scenarios":  [{ "Details": [{ "rowId": "...", "id": "DS001", "Details": [...] }] }],
  "Attacks":           [{ "type": "attack_trees", "scenes": [...] }]
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 1. ARCHITECT AGENT
# ─────────────────────────────────────────────────────────────────────────────

ARCHITECT_PROMPT = """
You are a Principal Automotive Systems Architect specializing in ISO 21434 TARA.

SYSTEM TO ARCHITECT: {{ question }}

{% if ecu_hint_context %}
{{ ecu_hint_context }}
{% endif %}

{% if ref_context %}
{{ ref_context }}
{% endif %}

### RETRIEVED CYBERSECURITY & REFERENCE CONTEXT:
{% for doc in documents %}
[{{ doc.meta.source }}]
{{ doc.content }}
---
{% endfor %}

### CRITICAL REQUIREMENT — EXACT COUNTS:
⚠️ YOU MUST GENERATE EXACTLY {{ max_nodes }} COMPONENT NODES (type "default" or "data").
⚠️ YOU MUST GENERATE EXACTLY {{ max_edges }} EDGES (connections between nodes).
⚠️ YOU MUST GENERATE NO MORE THAN {{ max_groups }} GROUP CONTAINERS (type "group").
- Groups (type "group") DO NOT count toward the {{ max_nodes }} limit.
- Count your component nodes before outputting. Regenerate if the count is wrong.
- Count your edges before outputting. Regenerate if the count is wrong.

### YOUR TASK:
Design a professional-grade system architecture for "{{ question }}" with:
- EXACTLY {{ max_nodes }} component nodes (excluding groups)
- EXACTLY {{ max_edges }} edges
- NO MORE THAN {{ max_groups }} group containers

{% if ecu_hint_context %}
⚠️ The ECU SPECIFICATION HINT above is authoritative. Generate ONLY the assets
listed there. Do NOT invent components that are not mentioned in the hint.
{% endif %}

{% if ref_context %}
⚠️ REFERENCE ARCHITECTURE — STRICT STRUCTURAL COPY RULES:
The REFERENCE ARCHITECTURE above is the canonical source of truth for this system's
structure. You MUST follow ALL of the rules below without exception:

1. **COPY ALL EDGES VERBATIM** — Every edge that exists in the reference architecture
   MUST appear in your output. Do NOT drop, merge, or skip any edge.
   - Map source/target IDs from the reference to the corresponding IDs in your output.
   - If the reference has 20 edges, your output must have 20 edges (= {{ max_edges }}).
   - Verify edge-by-edge before outputting. A missing edge is a hard failure.

2. **COPY NODE GEOMETRY VERBATIM** — For every node from the reference, preserve its
   exact layout values:
   - `position` → copy { x, y } exactly as given in the reference
   - `width`    → copy the numeric value exactly as given
   - `height`   → copy the numeric value exactly as given
   Do NOT recalculate, estimate, or omit any of these fields.

3. **COPY NODE TYPE & DATA VERBATIM** — For every node:
   - `type`     → copy exactly ("default", "data", "group", etc.)
   - `data`     → copy the entire data object (label, style, etc.) and then
                  rename only the `label` field to match the TARGET SYSTEM component.
   - `parentId` → preserve the parent-child grouping from the reference.

4. **RENAME ONLY LABELS AND IDs** — The only changes you are allowed to make are:
   - Replace the `id` string with a new short, stable, lowercase, hyphenated ID
     derived from the TARGET SYSTEM name (e.g. `bms-mcu` for the BMS MCU).
   - Replace the `data.label` string with the corresponding TARGET SYSTEM component name.
   - Update edge `source` / `target` to use the renamed IDs.
   Everything else (geometry, style, type) must be an exact copy.

5. **EDGE PRESERVATION CHECKLIST** — Before outputting, verify:
   □ I have counted every edge in the reference architecture.
   □ My output contains exactly that many edges ({{ max_edges }}).
   □ Every source and target ID in my edges resolves to a node in my output.
   □ I have NOT dropped any edge that is in the reference.

6. **COPY NODE PROPERTIES VERBATIM** — For every component node (type "default" or "data"):
   - `properties` → copy the EXACT properties array from the corresponding reference node
   - Do NOT add, remove, or change any properties
   - If the reference node has ["Integrity", "Availability"], output EXACTLY ["Integrity", "Availability"]
   - If the reference node has all 6 properties, output all 6
   - If the reference node has an empty array [], output []
   - This is CRITICAL for correct security analysis — mismatched properties will cause failures

7. **COPY EDGE PROPERTIES VERBATIM** — For every edge:
   - `properties` → copy the EXACT properties array from the corresponding reference edge
   - Do NOT add, remove, or change any edge properties
   - If a reference edge has ["Confidentiality"], output EXACTLY ["Confidentiality"]
   - If a reference edge has ["Integrity", "Authenticity"], output EXACTLY those

{% endif %}

### ARCHITECTURE RULES:

1. **COMPONENT LIST (generate exactly {{ max_nodes }} components):**
   Base your component list on:
   a) The ECU Specification Hint above (highest priority — if provided).
   b) The Reference Architecture above (structural template — if provided).
   c) The Retrieved Context below (cybersecurity knowledge).
   d) Your own expertise in automotive ECU architecture for this system type.

2. **GROUP CONTAINERS (maximum {{ max_groups }} groups):**
   Use groups to organise components logically. Typical groupings:
   - Core processing group (MCU, memory, watchdog)
   - Communication interfaces group (CAN, LIN, Ethernet transceivers)
   - Power/analog group (power supply, sensors, ADCs)
   - External interfaces group (debug port, OBD, V2X, cloud)
   DO NOT create more than {{ max_groups }} group nodes.
   Groups should have an empty properties array: `"properties": []`

3. **NODE IDs** — Use short, stable, lowercase, hyphenated strings derived from
   the system name. Examples for an ABS ECU: `abs-mcu`, `abs-can`, `abs-flashmem`.
   WRONG: UUIDs, bare numbers, or labels with spaces.

4. **EDGES (exactly {{ max_edges }} connections):**
   Each edge must have:
   - source: valid node ID from your component list
   - target: valid node ID from your component list
   - label: short protocol name (CAN, SPI, I2C, UART, ADC, IO_PINS, Ethernet, etc.)
   - properties: copy from reference edge, or use ["Integrity"] if no reference
   Every component should have at least one connection.

5. **NODE GEOMETRY — REQUIRED FIELDS FOR EVERY NODE:**
   Every node (group, default, and data) MUST include ALL of the following fields:
   - `position`: { "x": <number>, "y": <number> }
   - `width`:    <number>   (pixel width of the node)
   - `height`:   <number>   (pixel height of the node)
   These values must come from the reference architecture when one is provided.
   If no reference is provided, choose sensible layout values (see examples below).

6. **NODE PROPERTIES — REQUIRED FIELD FOR EVERY COMPONENT NODE:**
   {% if ref_context %}
   ⚠️ COPY PROPERTIES FROM REFERENCE: For each component node, copy the exact `properties` 
   array from the matching reference node. Do NOT change, add, or remove any properties.
   {% else %}
   Every component node (type "default" or "data") MUST include a `"properties"` array
   listing ALL cybersecurity properties relevant to that component. Choose from:
   "Integrity", "Confidentiality", "Authenticity", "Authorization", "Availability", "Non-repudiation"
   
   ⚠️ CRITICAL: Include ALL 6 properties for critical components like BatteryPack, 
   Code Flash, and main ECU components. Only exclude properties that are truly not applicable.
   {% endif %}
   
   Example for a critical component:
   {
     "id": "bms-batterypack",
     "type": "default",
     "properties": ["Integrity", "Confidentiality", "Authenticity", "Authorization", "Availability", "Non-repudiation"],
     ...
   }
   
   Example for a simple component:
   {
     "id": "bms-can-transceiver",
     "type": "default",
     "properties": ["Integrity", "Availability"],
     ...
   }
   
   These must match the securityProperties listed in the Details array for the same node.

7. **DETAILS — one entry per component node:**
   Each Detail entry maps a component to its security-relevant properties
   (CIA triad, STRIDE threats, asset sensitivity). Use the nodeId of the
   component it describes.

8. **VERIFICATION CHECKLIST (complete before output):**
   □ I have exactly {{ max_nodes }} component nodes (type "default" or "data")
   □ I have exactly {{ max_edges }} edges
   □ I have {{ max_groups }} or fewer group containers
   □ Every edge source and target matches a real component node ID
   □ Groups do NOT count toward the {{ max_nodes }} limit
   □ No duplicate node IDs
   □ All components are specific to "{{ question }}" (no generic placeholders)
   □ Every node has position, width, height fields
   {% if ref_context %}
   □ Every component node's properties EXACTLY match the reference node's properties
   □ Every edge's properties EXACTLY match the reference edge's properties
   {% else %}
   □ Every component node has a "properties" array with relevant cybersecurity properties
   {% endif %}
   □ No edges from the reference architecture have been dropped

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary.

{
  "template": {
    "nodes": [
      {
        "id": "<system-prefix>-main-group",
        "type": "group",
        "parentId": null,
        "data": {
          "label": "<System Name>",
          "style": {
            "backgroundColor": "rgba(33,150,243,0.05)",
            "borderColor": "#2196F3",
            "borderStyle": "dashed",
            "borderWidth": "2px"
          }
        },
        "position": {"x": 0, "y": 0},
        "width": 1000,
        "height": 600,
        "properties": []
      },
      // Add up to {{ max_groups - 1 }} more group containers here (total ≤ {{ max_groups }})
      {
        "id": "<system-prefix>-component-node",
        "type": "default",
        "parentId": "<system-prefix>-main-group",
        "data": {
          "label": "<Component Label>",
          "style": {
            "background": "#ffffff",
            "border": "1px solid #999",
            "borderRadius": "4px",
            "fontSize": "12px"
          }
        },
        "position": {"x": 120, "y": 80},
        "width": 160,
        "height": 40,
        {% if ref_context %}
        "properties": ["Integrity", "Availability"]
        {% else %}
        "properties": ["Integrity", "Confidentiality"]
        {% endif %}
      }
      // Add remaining {{ max_nodes }} component nodes here with position/width/height AND properties ...
    ],
    "edges": [
      {
        "id": "e-<source>-<target>",
        "source": "<source-node-id>",
        "target": "<target-node-id>",
        "label": "<Protocol>",
        "type": "default",
        "properties": ["Integrity"]
      }
      // Add exactly {{ max_edges }} edges here — ALL edges from the reference must be present
    ]
  },
  "Details": [
    // Add exactly {{ max_nodes }} detail entries matching your component nodes
  ]
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 2. THREAT ANALYST AGENT
# ─────────────────────────────────────────────────────────────────────────────

THREAT_PROMPT = """
You are a Cybersecurity Threat Analyst performing ISO 21434 "Pin-Point Pinning" analysis.

TARGET SYSTEM: {{ question }}

### SYSTEM ARCHITECTURE:
{{ architecture }}

### RETRIEVED CYBERSECURITY CONTEXT:
{% for doc in documents %}
[{{ doc.meta.source }}]
{{ doc.content }}
---
{% endfor %}

### YOUR TASK:
Generate exactly {{ max_threats }} high-priority technical threats, each targeting a specific component node from the architecture above.

### THREAT DISCOVERY RULES:

1. **PIN TO NODE**: Each threat's `nodeId` MUST be the EXACT `id` value of a node from the architecture JSON above.
   Example: If a node has `"id": "abs-mcu"`, use `"nodeId": "abs-mcu"`.
   Do NOT use the label, a UUID, or any invented string.

2. **SPREAD**: Target DIFFERENT nodes. Do not cluster all threats on one component.

3. **DIVERSITY**: Include at least:
   - One PHYSICAL attack (Debug port, JTAG, hardware tampering)
   - One NETWORK attack (CAN bus injection, Ethernet replay, OTA exploit)
   - One SOFTWARE/DATA attack (Firmware corruption, calibration tampering, key extraction)

4. **LOSS TYPE**: Specify which cybersecurity property is lost using one of:
   `Integrity` | `Confidentiality` | `Authenticity` | `Authorization` | `Availability` | `Non-repudiation`

5. **REASONING**: Ground threats in real attack patterns from CWE, CAPEC, or MITRE ATT&CK
   when available from the context.

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary. Start with `{`.

{
  "Derivations": [
    {
      "id": "T-01",
      "nodeId": "<exact-node-id-from-architecture>",
      "task": "Check for DS due to the loss of Integrity for ComponentName",
      "name": "Descriptive Threat Name",
      "loss": "Integrity",
      "asset": "Component Name",
      "damage_scene": "Detailed technical description of the attack and its consequences.",
      "isChecked": false
    },
    {
      "id": "T-02",
      "nodeId": "<different-node-id>",
      "task": "Check for DS due to the loss of Availability for OtherComponent",
      "name": "Another Threat Name",
      "loss": "Availability",
      "asset": "Other Component Name",
      "damage_scene": "Detailed technical scenario for this threat.",
      "isChecked": false
    }
  ]
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 3. DAMAGE ANALYST AGENT
# ─────────────────────────────────────────────────────────────────────────────

DAMAGE_PROMPT = """
You are a Damage Assessment Specialist performing ISO 21434 impact analysis for automotive systems.

### TARGET SYSTEM:
{{ question if question is defined else "Automotive ECU System" }}

### SYSTEM ARCHITECTURE:
{{ architecture }}

### IDENTIFIED THREATS:
{{ threats }}

### YOUR TASK:
Generate detailed, realistic cybersecurity damage scenarios for the system described above.
You MUST generate 10-15 comprehensive damage scenarios.

### DAMAGE SCENARIO REQUIREMENTS:

Each damage scenario must include:
1. **Name**: A short, descriptive title (max 8 words) specific to THIS system
2. **Description**: Detailed technical explanation of the attack, its method, and consequences (2-4 sentences)
3. **cyberLosses**: Array of cybersecurity properties affected (2-4 properties per scenario)
4. **impacts**: Impact ratings for Financial, Safety, Operational, and Privacy domains

### CYBER LOSS PROPERTIES (use these exact names):
- Integrity
- Confidentiality
- Authenticity
- Authorization
- Availability
- Non-repudiation

### IMPACT RATINGS (use only these values):
`Negligible` | `Minor` | `Moderate` | `Major` | `Severe`

### IMPACT GUIDELINES (ISO 21434 Annex F):
- **Safety**: Negligible=no injury | Minor=light injury | Moderate=severe injury | Major=life-threatening | Severe=fatal
- **Financial**: Negligible=<$100 | Minor=<$1K | Moderate=<$10K | Major=<$100K | Severe=>$100K
- **Operational**: Negligible=no disruption | Minor=minor delay | Moderate=reduced capability | Major=system unusable | Severe=fleet-wide
- **Privacy**: Negligible=no PII | Minor=anonymized | Moderate=limited PII | Major=sensitive PII | Severe=mass breach

### SCENARIO DIVERSITY REQUIREMENTS:
- Cover DIFFERENT components from this specific system (use nodeIds from the architecture above)
- Include various attack types: physical, network, software, side-channel, supply chain
- Mix impact levels — include Severe, Major, Moderate scenarios
- Reference specific node IDs from the architecture above in each cyberLoss entry
- Scenario names must be specific to this system type — avoid generic names like "Damage Scenario 1"

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No extra text. Start with `{` and end with `}`.

{
  "type": "User-defined",
  "Details": [
    {
      "Name": "<Specific scenario name for this system>",
      "Description": "<Technical description of attack method and consequences.>",
      "cyberLosses": [
        {
          "name": "Integrity",
          "node": "<Component Name>",
          "nodeId": "<exact-node-id-from-architecture>"
        },
        {
          "name": "Authenticity",
          "node": "<Component Name>",
          "nodeId": "<exact-node-id-from-architecture>"
        }
      ],
      "impacts": {
        "Financial Impact": "Severe",
        "Safety Impact": "Severe",
        "Operational Impact": "Severe",
        "Privacy Impact": "Negligible"
      }
    }
  ]
}

### IMPORTANT REMINDERS:
- Generate 10-15 scenarios, not fewer
- Descriptions must be technically accurate for this specific system
- Reference actual components from the architecture using their exact nodeId
- Each scenario should have 2-4 cyberLosses on average
- Vary the impact ratings across scenarios
"""

# ─────────────────────────────────────────────────────────────────────────────
# 4. THREAT SCENARIO AGENT
# ─────────────────────────────────────────────────────────────────────────────
THREAT_SCENARIO_PROMPT = """
You are a Cybersecurity Threat Scenario Specialist performing ISO 21434 TARA threat scenario generation.

TARGET SYSTEM: {{ question }}

### SYSTEM ARCHITECTURE (for nodeId reference):
{{ architecture }}

### DAMAGE SCENARIOS (for DS mapping):
{{ damage_scenarios }}

### THREATS (for prop and nodeId cross-reference):
{{ threats }}

### YOUR TASK:
Generate a complete Threat_scenarios structure with exactly TWO objects:
  1. type: "derived"   — pin each DS entry to its affected node(s) and cybersecurity properties from the architecture.
  2. type: "User-defined" — generate realistic, named attack scenarios that reference the derived DS rows via threat_ids.

**CRITICAL: If existing threat scenarios are shown below in the "EXISTING THREAT SCENARIOS" sections, 
you MUST include them VERBATIM in your output WITHOUT ANY MODIFICATIONS. You may only add additional 
threat scenarios as extras that do NOT duplicate the existing ones.**

### STRICT RULES:

**DERIVED OBJECT:**
1. Each `Details` entry maps to one damage scenario (DS001, DS002, ... in sequence).
2. Each DS entry contains one or more node `Details` items — one per affected node from the architecture.
3. Each node `Details` item contains:
   - `node`: Human-readable component name (MUST match architecture node label exactly)
   - `nodeId`: MUST be the EXACT node `id` from the architecture JSON. Copy it verbatim. Do NOT invent UUIDs.
   - `props`: Array of cybersecurity properties relevant to this node for this threat scenario.
   - `name`: The damage scenario name (same as the DS name from damage_scenarios).
4. Each prop entry MUST have:
   - `id`: A unique string ID (format: `"ts-<dsid>-<node-short>-<prop-short>"`, e.g. `"ts-ds001-codeflash-integ"`)
   - `is_risk_added`: boolean — set `true` if this prop is the PRIMARY loss type for this DS, else `false`
   - `name`: One of `Integrity` | `Confidentiality` | `Authenticity` | `Authorization` | `Availability` | `Non-repudiation`
   - `isSelected`: always `true`
   - `key`: integer, incrementing per prop within each node block starting at 1
5. `rowId`: A unique UUID-format string per DS row (generate a valid UUID v4).
6. `id`: Sequential DS identifier — "DS001", "DS002", etc.

**USER-DEFINED OBJECT:**
1. Generate one named attack scenario per 2–3 derived DS entries (group related DS rows together).
2. Each scenario MUST have:
   - `name`: A specific, realistic attack name (e.g. "CAN Bus Replay Attack", "JTAG Firmware Extraction")
   - `description`: A detailed, technically accurate attack description (2–4 sentences). Reference specific nodes, protocols, and consequences.
   - `id`: A unique UUID v4 string.
   - `threat_ids`: Array of prop references from the derived DS entries that this attack exploits. Each entry MUST have:
       - `propId`: The EXACT `id` value of the prop from the derived Details (copy verbatim).
       - `nodeId`: The EXACT node `id` from the architecture (copy verbatim).
       - `rowId`: The EXACT `rowId` of the DS row this prop belongs to (copy verbatim).

### CROSS-REFERENCE INTEGRITY (CRITICAL):
- Every `nodeId` in both derived and user-defined sections MUST exist in the architecture JSON.
- Every `propId` in `threat_ids` MUST match an `id` in the derived `props` array exactly.
- Every `rowId` in `threat_ids` MUST match a `rowId` in the derived Details exactly.
- Do NOT invent any IDs. Copy them exactly from the inputs provided.

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary. Start with `{`.

{
  "Threat_scenarios": [
    {
      "_id": "",
      "model_id": "",
      "type": "derived",
      "Details": [
        {
          "rowId": "<uuid-v4>",
          "id": "DS001",
          "Details": [
            {
              "node": "<exact-node-label-from-architecture>",
              "nodeId": "<exact-node-id-from-architecture>",
              "props": [
                {
                  "id": "ts-ds001-<node-short>-<prop-short>",
                  "is_risk_added": true,
                  "name": "Integrity",
                  "isSelected": true,
                  "key": 1
                }
              ],
              "name": "<damage-scenario-name>"
            }
          ]
        }
      ],
      "user_id": ""
    },
    {
      "_id": "",
      "model_id": "",
      "type": "User-defined",
      "Details": [
        {
          "name": "<realistic-attack-name>",
          "description": "<detailed-technical-attack-description>",
          "id": "<uuid-v4>",
          "threat_ids": [
            {
              "propId": "<exact-prop-id-from-derived-props>",
              "nodeId": "<exact-node-id-from-architecture>",
              "rowId": "<exact-rowid-from-derived-details>"
            }
          ]
        }
      ]
    }
  ]
}
"""



# ─────────────────────────────────────────────────────────────────────────────
# 5. ATTACK SCENARIO AGENT
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_SCENARIO_PROMPT = """
You are a Red-Team automotive cybersecurity expert performing ISO 21434 TARA attack analysis.

TARGET SYSTEM: {{ question }}

### SYSTEM ARCHITECTURE (for component reference):
{{ architecture }}

### UNCOVERED THREAT SCENARIOS (need attack trees):
{{ threat_scenarios }}

### EXISTING ATTACK SCENARIOS (DO NOT DUPLICATE):
{{ existing_attacks }}

### EXISTING ATTACK TREES (DO NOT DUPLICATE):
{{ existing_attack_trees }}

### YOUR TASK:
Generate attack trees and individual attack scenarios for the uncovered threat scenarios.

### ATTACK TREE REQUIREMENTS:
1. Each attack tree must have:
   - A root node representing the threat scenario
   - At least one OR Gate
   - Multiple attack vectors (Level 1)
   - Specific technical methods per vector (Level 2)
   
2. Node structure:
   ```json
   {
     "id": "uuid",
     "type": "derived" | "OR Gate" | "Event",
     "data": {
       "label": "node label",
       "nodeType": "derived" | null,
       "connections": [],
       "style": {
         "backgroundColor": "transparent",
         "borderColor": "black",
         "borderStyle": "solid",
         "borderWidth": "2px",
         "color": "black",
         "fontFamily": "Inter",
         "fontSize": "16px",
         "fontStyle": "normal",
         "fontWeight": 500,
         "height": 60,
         "textAlign": "center",
         "textDecoration": "none",
         "width": 150
       }
     },
     "position": {"x": 592, "y": 32},
     "width": 150,
     "height": 60,
     "nodeType": "derived",
     "threat_ids": []
   }

   IMPORTANT — node type rules:
   - Root node (threat scenario / top-level goal): MUST use "type": "derived". This is the threat scenario header, NOT an attack step.
   - Gate nodes: "type": "OR Gate" or "type": "AND Gate"
   - Leaf/attack-method nodes: "type": "Event"."""