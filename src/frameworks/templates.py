"""Specialized question templates and evaluation criteria for each cybersecurity framework."""

from dataclasses import dataclass
from typing import Dict, List
from typesafe_sdk import Choice, Noul, Score


@dataclass
class FrameworkTemplate:
    name: str
    label: str
    description: str

    def build_goal_question(self, current_node_id: str, goal: str) -> Noul:
        raise NotImplementedError

    def build_choice_question(self, goal: str, branches: Dict[str, str]) -> Choice:
        raise NotImplementedError

    def build_score_question(self, goal: str) -> Score:
        raise NotImplementedError


class CAPECTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="CAPEC",
            label="Attack Pattern",
            description="Explores adversary attack patterns, execution flow, prerequisites and escalation."
        )

    def build_goal_question(self, current_node_id: str, goal: str) -> Noul:
        return Noul(
            instructions=(
                f"Is the current entity '{current_node_id}' already the final desired answer or countermeasure "
                f"for the user goal: '{goal}'? (Note: CAPEC nodes represent offensive attacks, not defensive solutions)."
            )
        )

    def build_choice_question(self, goal: str, branches: Dict[str, str]) -> Choice:
        return Choice(
            instructions=(
                f"Goal: '{goal}'. We are analyzing attack patterns. Which branch represents the most accurate "
                f"progression or intermediate bridge toward understanding and mitigating this attack vector?"
            ),
            criteria=branches
        )

    def build_score_question(self, goal: str) -> Score:
        return Score(
            instructions=f"How relevant is this attack pattern to the overall threat investigation '{goal}'?",
            criteria=["Low relevance attack", "Moderate prerequisite attack", "Direct primary attack vector"]
        )


class CWETemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="CWE",
            label="Software Weakness",
            description="Explores code-level vulnerabilities, architectural flaws and root causes."
        )

    def build_goal_question(self, current_node_id: str, goal: str) -> Noul:
        return Noul(
            instructions=(
                f"Does the software weakness '{current_node_id}' constitute the definitive solution to the goal: '{goal}'? "
                f"(Weaknesses represent software flaws that must be fixed, not defensive tools)."
            )
        )

    def build_choice_question(self, goal: str, branches: Dict[str, str]) -> Choice:
        return Choice(
            instructions=(
                f"Goal: '{goal}'. We are diagnosing software weaknesses. Which branch represents the core programming "
                f"or architectural root-cause that enables the vulnerability?"
            ),
            criteria=branches
        )

    def build_score_question(self, goal: str) -> Score:
        return Score(
            instructions=f"Rate the severity of this software weakness in relation to '{goal}':",
            criteria=["Peripheral code defect", "Significant security flaw", "Critical exploitable vulnerability"]
        )


class AttackTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="ATTACK",
            label="Adversary Technique",
            description="Explores MITRE Enterprise ATT&CK tactical techniques, execution mechanisms and procedures."
        )

    def build_goal_question(self, current_node_id: str, goal: str) -> Noul:
        return Noul(
            instructions=(
                f"Does the adversary technique '{current_node_id}' directly satisfy the goal: '{goal}'? "
                f"(ATT&CK represents adversary actions, not defense mechanisms)."
            )
        )

    def build_choice_question(self, goal: str, branches: Dict[str, str]) -> Choice:
        return Choice(
            instructions=(
                f"Goal: '{goal}'. We are tracking adversary techniques. Which branch represents the critical "
                f"execution mechanism or operational step used in this scenario?"
            ),
            criteria=branches
        )

    def build_score_question(self, goal: str) -> Score:
        return Score(
            instructions=f"How critical is this adversary technique to achieving the objective '{goal}'?",
            criteria=["Incidental technique", "Core enabling technique", "Direct impact technique"]
        )


class AtlasTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="ATLAS",
            label="AI/ML Threat Technique",
            description="Explores MITRE ATLAS threats specific to AI/ML systems (data poisoning, prompt injection, model theft)."
        )

    def build_goal_question(self, current_node_id: str, goal: str) -> Noul:
        return Noul(
            instructions=(
                f"Does the AI threat technique '{current_node_id}' answer the defensive goal: '{goal}'?"
            )
        )

    def build_choice_question(self, goal: str, branches: Dict[str, str]) -> Choice:
        return Choice(
            instructions=(
                f"Goal: '{goal}'. We are analyzing AI/ML adversarial techniques. Which branch captures the specific "
                f"AI attack vector (prompt manipulation, data evasion, or model exploitation)?"
            ),
            criteria=branches
        )

    def build_score_question(self, goal: str) -> Score:
        return Score(
            instructions=f"Rate the specificity of this AI attack technique for '{goal}':",
            criteria=["Generic IT threat", "Indirect ML effect", "Direct adversarial AI exploit"]
        )


class D3FENDTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="D3FEND",
            label="Defensive Countermeasure",
            description="Explores MITRE D3FEND defensive countermeasures (Harden, Detect, Isolate, Evict, Model)."
        )

    def build_goal_question(self, current_node_id: str, goal: str) -> Noul:
        return Noul(
            instructions=(
                f"Does this defensive countermeasure '{current_node_id}' directly satisfy, neutralize, or answer "
                f"the user's defensive security goal: '{goal}'?"
            )
        )

    def build_choice_question(self, goal: str, branches: Dict[str, str]) -> Choice:
        return Choice(
            instructions=(
                f"Goal: '{goal}'. We are evaluating defensive countermeasures. Which D3FEND technique offers the most "
                f"effective and direct security mitigation for the identified threat?"
            ),
            criteria=branches
        )

    def build_score_question(self, goal: str) -> Score:
        return Score(
            instructions=f"Rate the mitigation effectiveness of this defensive countermeasure against '{goal}':",
            criteria=["Marginal defense", "Partial hardening/detection", "Complete primary mitigation"]
        )


class MetaRouterTemplate:
    """Template used by the Jev Meta-Router to select which framework/expert to query next."""

    @staticmethod
    def build_framework_selection_question(goal: str, current_phase: str, candidate_frameworks: Dict[str, str]) -> Choice:
        return Choice(
            instructions=(
                f"Investigation Goal: '{goal}'. Current Phase: '{current_phase}'. "
                f"Which cybersecurity domain/framework should the investigation navigate to next?"
            ),
            criteria=candidate_frameworks
        )

    @staticmethod
    def build_phase_score_question(goal: str, phase: str) -> Score:
        return Score(
            instructions=f"How close is the current phase '{phase}' to concluding the defensive investigation for '{goal}'?",
            criteria=["Phase 1: Attack surface", "Phase 2: Technical flaw", "Phase 3: Adversary action", "Phase 4: Defensive mitigation"]
        )


TEMPLATES: Dict[str, FrameworkTemplate] = {
    "CAPEC": CAPECTemplate(),
    "CWE": CWETemplate(),
    "ATTACK": AttackTemplate(),
    "ATLAS": AtlasTemplate(),
    "D3FEND": D3FENDTemplate(),
}

TEMPLATES_CATALOG = [
    {
        "framework": "CAPEC",
        "name": "CAPECTemplate",
        "label": "Attack Pattern",
        "icon": "Crosshair",
        "color": "#F97316",
        "description": "Explores adversary attack patterns, execution flow, prerequisites and privilege escalation.",
        "goalQuestion": "Is the current entity '{node}' already the final desired answer or countermeasure for the user goal: '{goal}'?",
        "choiceQuestion": "Given the threat objective '{goal}', which attack branch represents the most critical progression or intermediate bridge?",
        "scoreQuestion": "How relevant is this attack pattern to the overall threat investigation '{goal}'?",
        "criteriaScale": ["Low relevance attack", "Moderate prerequisite attack", "Direct primary attack vector"]
    },
    {
        "framework": "CWE",
        "name": "CWETemplate",
        "label": "Software Weakness",
        "icon": "Bug",
        "color": "#8B5CF6",
        "description": "Explores code-level vulnerabilities, architectural flaws and fundamental root-causes.",
        "goalQuestion": "Does the software weakness '{node}' constitute the definitive solution to the goal: '{goal}'?",
        "choiceQuestion": "Given the goal '{goal}', which branch represents the core programming or architectural root-cause flaw?",
        "scoreQuestion": "Rate the severity of this software weakness in relation to '{goal}':",
        "criteriaScale": ["Peripheral code defect", "Significant security flaw", "Critical exploitable vulnerability"]
    },
    {
        "framework": "ATTACK",
        "name": "AttackTemplate",
        "label": "Adversary Technique",
        "icon": "Flame",
        "color": "#EF4444",
        "description": "Explores MITRE Enterprise ATT&CK tactical techniques, operational execution mechanisms and procedures.",
        "goalQuestion": "Does adversary technique '{node}' directly satisfy the goal: '{goal}'?",
        "choiceQuestion": "Given the goal '{goal}', which adversary technique branch advances the operational attack chain towards the target?",
        "scoreQuestion": "How critical is this adversary technique to achieving the objective '{goal}'?",
        "criteriaScale": ["Incidental technique", "Core enabling technique", "Direct impact technique"]
    },
    {
        "framework": "ATLAS",
        "name": "AtlasTemplate",
        "label": "AI/ML Threat",
        "icon": "Cpu",
        "color": "#E11D48",
        "description": "Explores MITRE ATLAS threats specific to AI/ML systems (prompt injection, model evasion, data poisoning).",
        "goalQuestion": "Does AI/ML threat technique '{node}' satisfy the adversarial goal: '{goal}'?",
        "choiceQuestion": "Given the goal '{goal}', which branch captures the specific AI attack vector (prompt manipulation, data evasion, or model theft)?",
        "scoreQuestion": "Rate the specificity of this AI attack technique for '{goal}':",
        "criteriaScale": ["Generic IT threat", "Indirect ML effect", "Direct adversarial AI exploit"]
    },
    {
        "framework": "D3FEND",
        "name": "D3FENDTemplate",
        "label": "Defensive Countermeasure",
        "icon": "ShieldCheck",
        "color": "#10B981",
        "description": "Explores MITRE D3FEND defensive countermeasures (Harden, Detect, Isolate, Evict, Model, Verify).",
        "goalQuestion": "Does this defensive countermeasure '{node}' directly satisfy, neutralize, or answer the user's defensive security goal: '{goal}'?",
        "choiceQuestion": "Given the security goal '{goal}', which D3FEND technique offers the most effective and direct mitigation for the identified threat?",
        "scoreQuestion": "Rate the mitigation effectiveness of this defensive countermeasure against '{goal}':",
        "criteriaScale": ["Marginal defense", "Partial hardening/detection", "Complete primary mitigation"]
    },
    {
        "framework": "META_ROUTER",
        "name": "MetaRouterTemplate",
        "label": "Ontology Meta-Router",
        "icon": "Compass",
        "color": "#06B6D4",
        "description": "Evaluates cross-framework transitions and selects optimal domain experts (CWE, CAPEC, ATT&CK, ATLAS, D3FEND).",
        "goalQuestion": "Is current domain investigation phase concluding the user goal: '{goal}'?",
        "choiceQuestion": "Given the investigation goal '{goal}', which cybersecurity domain/framework should be navigated to next?",
        "scoreQuestion": "How close is the current phase to concluding the defensive investigation for '{goal}'?",
        "criteriaScale": ["Phase 1: Attack surface", "Phase 2: Technical flaw", "Phase 3: Adversary action", "Phase 4: Defensive mitigation"]
    }
]
