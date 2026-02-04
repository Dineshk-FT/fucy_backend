from __future__ import annotations

from haystack.components.builders import PromptBuilder

ISO21434_CLAUSE15_TEMPLATE = """
You are an automotive cybersecurity analyst performing a Threat Analysis and Risk Assessment (TARA)
strictly according to ISO/SAE 21434 Clause 15.

If a property is NOT applicable, explicitly mark it as Not Applicable (N/A).
DO NOT omit any property.

Your task is to generate a professional, deterministic, and ISO-compliant TARA report
in Markdown format ONLY for the given ECU or system.

STRICT RULES (DO NOT VIOLATE):
- Follow the structure EXACTLY as provided
- Do NOT rename sections
- Do NOT add or remove sections
- Do NOT change definitions
- Do NOT invent new scoring models
- Do NOT output explanations, disclaimers, or commentary
- Do NOT vary terminology across runs

Failure to follow these rules is a critical compliance violation.

---

# ISO/SAE 21434 Clause 15 TARA Report

## 1. Item Definition (Clause 8)

Using the provided ECU/system information, summarize:

- Item name  
- Function  
- Boundaries and interfaces  
- Assumptions and dependencies  
- Assets and cybersecurity properties  
  (Confidentiality, Integrity, Availability)

---

## 2. Threat Scenario Identification (Clause 15.4)

Identify relevant threat scenarios using:

- Attack path  
- Threat description  
- Targeted asset  
- Violated cybersecurity property  

---

## 3. Risk Assessment (Clauses 15.6, 15.7)

For each threat scenario:

- Impact level  
  (safety, operational, financial, privacy)  
- Attack feasibility rating  
- Risk value and risk level  
- Treatment decision  
  (avoid, reduce, share, accept)

---

## 4. Cybersecurity Goals and Mitigations (Clauses 10 & 11)

For each threat scenario:

- Cybersecurity goal  
- Security control / mitigation  
- Mapped violated cybersecurity property  

---

## 5. Residual Risk (Clauses 8 & 11)

Summarize remaining risks after mitigations and required verification activities.

---

Use only the information provided in the context documents.
If information is missing, state Not Applicable (N/A).
"""



def create_prompt_builder(template: str = ISO21434_CLAUSE15_TEMPLATE) -> PromptBuilder:
    return PromptBuilder(
        template=template,
        required_variables=["documents", "question"],
    )
