# =============================================================================
# prompt.py — TARA generation prompt templates (Multi-Agent Pipeline)
# =============================================================================
#
# Each pipeline agent uses its own specialized prompt:
#   Architect Agent  → ARCHITECT_PROMPT  → System architecture (nodes, edges, Details)
#   Threat Analyst   → THREAT_PROMPT     → Threat derivations with nodeId refs
#   Damage Analyst   → DAMAGE_PROMPT     → Damage impact assessments
#
# TARA_PROMPT_TEMPLATE is retained for backward compatibility but is NOT
# called by any pipeline node. See the individual agent prompts below.
# =============================================================================


# ─────────────────────────────────────────────────────────────────────────────
# REFERENCE SCHEMA (imported by pipeline.py but NOT rendered by any node)
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

{% if bms_context %}
### REFERENCE BMS ARCHITECTURE (from Azure):
{{ bms_context }}
{% endif %}

### RETRIEVED CYBERSECURITY & REFERENCE CONTEXT:
{% for doc in documents %}
[{{ doc.meta.source }}]
{{ doc.content }}
---
{% endfor %}

### CRITICAL REQUIREMENT - EXACT COUNTS:
⚠️ YOU MUST GENERATE EXACTLY {{ max_nodes }} COMPONENT NODES (type "default" or "data").
⚠️ YOU MUST GENERATE EXACTLY {{ max_edges }} EDGES (connections between nodes).
⚠️ YOU MUST GENERATE NO MORE THAN {{ max_groups }} GROUP CONTAINERS (type "group").
- Groups (type "group") DO NOT count toward the {{ max_nodes }} limit.
- Count your component nodes before outputting. If you have more or less than {{ max_nodes }}, REGENERATE.
- Count your edges before outputting. If you have more or less than {{ max_edges }}, REGENERATE.
- Count your groups. If you have more than {{ max_groups }} groups, REGENERATE.

### YOUR TASK:
Design a professional-grade system architecture for "{{ question }}" with:
- EXACTLY {{ max_nodes }} component nodes (excluding groups)
- EXACTLY {{ max_edges }} edges
- NO MORE THAN {{ max_groups }} group containers for organization (1-{{ max_groups }} groups is acceptable)

{% if bms_context %}
⚠️ USE THE REFERENCE BMS ARCHITECTURE ABOVE AS YOUR EXACT TEMPLATE.
Copy the same number of nodes, same types, same edge patterns.
{% endif %}

### ARCHITECTURE RULES:

1. **COMPONENT LIST (generate exactly these {{ max_nodes }} components):**
   Based on the reference context, select the {{ max_nodes }} most critical components for this system.
   Example for BMS: MCU, Cell Monitor, Voltage Monitor, Temperature Sensor, Current Sensor, 
   CAN Transceiver, Power Supply, Watchdog, Flash Memory, RAM, Debug Port, External EEPROM, 
   Balancing FETs, Communication IC.

2. **GROUP CONTAINERS (maximum {{ max_groups }} groups):**
   Use groups to organize components logically. Examples:
   - "MCU and Core Components" group
   - "Power Management" group
   - "Communication Interfaces" group
   - "External Interfaces" group
   DO NOT create more than {{ max_groups }} group nodes.

3. **NODE IDs** — Use short, stable, lowercase, hyphenated strings:
   CORRECT: `"bms-cellmonitor"`, `"bms-mcu-group"`, `"ext-vehicle"`
   WRONG:   UUIDs, bare numbers like "1", or labels with spaces.

4. **EDGES (exactly {{ max_edges }} connections):**
   Create realistic connections between the {{ max_nodes }} components you defined.
   Each edge must have:
   - source: valid node ID from your components
   - target: valid node ID from your components
   - label: short protocol (CAN, SPI, I2C, UART, IO_PINS, etc.)
   
   Example edge list for BMS ({{ max_edges }} edges):
   1. MCU → Cell Monitor (SPI)
   2. MCU → CAN Transceiver (SPI)
   3. MCU → Flash Memory (SPI)
   4. MCU → Watchdog (IO_PINS)
   5. MCU → Debug Port (UART)
   6. Cell Monitor → Voltage Monitor (IO_PINS)
   7. Cell Monitor → Temperature Sensor (IO_PINS)
   8. MCU → Current Sensor (ADC)
   9. MCU → Power Supply (IO_PINS)
   10. CAN Transceiver → External Vehicle (CAN)
   11. MCU → Balancing FETs (IO_PINS)

5. **VERIFICATION CHECKLIST (complete before output):**
   □ I have exactly {{ max_nodes }} component nodes (type "default" or "data")
   □ I have exactly {{ max_edges }} edges
   □ I have {{ max_groups }} or fewer group containers
   □ Every edge source and target matches a component node ID
   □ Groups do NOT count toward the {{ max_nodes }} limit
   □ No duplicate node IDs

### OUTPUT FORMAT:
Return ONLY a valid JSON object. No markdown fences. No commentary.

{
  "template": {
    "nodes": [
      {
        "id": "sys-main-group",
        "type": "group",
        "parentId": null,
        "data": {
          "label": "System Name",
          "style": {
            "backgroundColor": "rgba(33,150,243,0.05)",
            "borderColor": "#2196F3",
            "borderStyle": "dashed",
            "borderWidth": "2px"
          }
        },
        "position": {"x": 0, "y": 0},
        "height": 600,
        "width": 1000,
        "zIndex": 0
      },
      // Add up to {{ max_groups - 1 }} more group containers here (total ≤ {{ max_groups }} groups)
      // Add your {{ max_nodes }} component nodes here...
    ],
    "edges": [
      // Add exactly {{ max_edges }} edges here...
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
   Example: If a node has `"id": "bms-cellmonitor"`, use `"nodeId": "bms-cellmonitor"`.
   Do NOT use the label, a UUID, or any invented string.

2. **SPREAD**: Target DIFFERENT nodes. Do not cluster all threats on one component.

3. **DIVERSITY**: Include at least:
   - One PHYSICAL attack (Debug port, JTAG, hardware tampering)
   - One NETWORK attack (CAN bus injection, Ethernet replay, OTA exploit)
   - One SOFTWARE/DATA attack (Firmware corruption, calibration tampering, key extraction)

4. **LOSS TYPE**: Specify which cybersecurity property is lost using one of:
   `Integrity` | `Confidentiality` | `Authenticity` | `Authorization` | `Availability` | `Non-repudiation`

5. **REASONING**: Ground threats in real attack patterns from CWE, CAPEC, or MITRE ATT&CK when available from the context.

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
# 3. DAMAGE ANALYST AGENT - USER-DEFINED ONLY
# ─────────────────────────────────────────────────────────────────────────────

DAMAGE_PROMPT = """
You are a Damage Assessment Specialist performing ISO 21434 impact analysis for automotive systems.

### SYSTEM ARCHITECTURE:
{{ architecture }}

### YOUR TASK:
Generate detailed, realistic cybersecurity damage scenarios for the system described above.
You MUST generate 10-15 comprehensive damage scenarios.

### DAMAGE SCENARIO REQUIREMENTS:

Each damage scenario must include:
1. **Name**: A short, descriptive title (max 8 words)
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
- Cover different components (MCU, memory, communication, sensors, power, etc.)
- Include various attack types (physical, network, software, side-channel, supply chain)
- Mix impact levels (some Severe, some Moderate, some Major)
- Reference specific node IDs from the architecture above

### OUTPUT FORMAT:
Return ONLY a valid JSON object with this exact structure.
No markdown fences. No extra text. Start with `{` and end with `}`.

{
  "type": "User-defined",
  "Details": [
    {
      "Name": "Thermal Runaway via Calibration Tampering",
      "Description": "Attacker modifies voltage/current thresholds in Data Flash, allowing the battery to operate outside the Safe Operating Area (SOA). This leads to uncontrolled overheating and potential fire.",
      "cyberLosses": [
        {
          "name": "Integrity",
          "node": "Data Flash",
          "nodeId": "data-flash-uuid-or-id"
        },
        {
          "name": "Authenticity", 
          "node": "Data Flash",
          "nodeId": "data-flash-uuid-or-id"
        }
      ],
      "impacts": {
        "Financial Impact": "Severe",
        "Safety Impact": "Severe",
        "Operational Impact": "Severe",
        "Privacy Impact": "Negligible"
      }
    },
    {
      "Name": "CAN Bus Denial of Service",
      "Description": "Attacker floods the CAN bus with high-priority messages, preventing critical BMS messages from being transmitted. This causes delayed response to fault conditions.",
      "cyberLosses": [
        {
          "name": "Availability",
          "node": "CAN Transceiver",
          "nodeId": "can-transceiver-uuid-or-id"
        }
      ],
      "impacts": {
        "Financial Impact": "Moderate",
        "Safety Impact": "Severe",
        "Operational Impact": "Major",
        "Privacy Impact": "Negligible"
      }
    }
  ]
}

### IMPORTANT REMINDERS:
- Generate 10-15 scenarios, not fewer
- Use realistic, specific scenario names (avoid generic names like "Damage Scenario 1")
- Descriptions must be detailed and technically accurate
- Reference actual components from the architecture using their exact nodeId
- Each scenario should have 2-4 cyberLosses on average
- Vary the impact ratings across scenarios
"""