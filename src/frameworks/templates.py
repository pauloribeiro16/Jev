"""Question templates per cybersecurity framework.

Design rules these follow, from the TypeSafe docs:

* The model does not know our ontologies — "do not rely on knowledge stored in
  model weights when current information can come from your own knowledge base".
  So every question refers to entities by backticked state path, and the caller
  puts names and descriptions in the state. A bare id carries no meaning.
* The state carries the content; instructions carry only the judgment. Do not
  splice goal text into a template string — point at `analyst_question` instead.
* "Score levels must describe concrete situations and stand on their own." Each
  level below names a situation an analyst could recognise, never a degree.
* Question ids are not sent to the model, so the instructions restate the full
  meaning rather than relying on the key.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from typesafe_sdk import Choice, Noul, Score

# "Send less than you think you should" — unrelated state causes context rot, so
# descriptions are clipped rather than pasted whole.
DESC_CHARS = 260


def describe(node, desc_chars: int = DESC_CHARS) -> Optional[Dict]:
    """Ground an entity for the model: identity plus meaning, not a bare id."""
    if node is None:
        return None
    desc = (node.description or "").strip()
    clipped = desc[:desc_chars]
    if len(desc) > desc_chars:
        clipped += "…"
    out = {"id": node.id, "name": node.name, "framework": node.framework}
    if node.category:
        out["category"] = node.category
    if clipped:
        out["description"] = clipped
    return out


def entity_line(node) -> str:
    """Compact one-line label for a path summary."""
    return f"{node.id} — {node.name}"


# Shared instructions. They name the state paths instead of repeating content.
GOAL_REACHED_Q = (
    "Is `current_entity`, as described, already the answer to `analyst_question`? "
    "Answer yes only if a reader could answer the question using this entity alone."
)

BEST_BRANCH_Q = (
    "Which entry in `candidate_entities` adds the most new information needed to answer "
    "`analyst_question`? Judge each entry by what it adds beyond what `current_entity` "
    "already provides, not by which framework it belongs to."
)

GOAL_CRITERIA = {
    "true": (
        "This entity on its own answers what the analyst asked — the description already "
        "contains the specific thing being asked for."
    ),
    "false": (
        "This entity covers only one part of what was asked, or describes something adjacent "
        "to it; another entity would still be needed."
    ),
}


@dataclass
class FrameworkTemplate:
    name: str
    label: str
    description: str
    score_question: str = ""
    score_criteria: List[str] = field(default_factory=list)

    def build_goal_question(self) -> Noul:
        return Noul(instructions=GOAL_REACHED_Q, criteria=GOAL_CRITERIA)

    def build_choice_question(self, candidates: Dict[str, str]) -> Choice:
        return Choice(instructions=BEST_BRANCH_Q, criteria=candidates)

    def build_score_question(self) -> Score:
        return Score(instructions=self.score_question, criteria=self.score_criteria)


class CAPECTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="CAPEC",
            label="Attack Pattern",
            description="Adversary attack patterns: goal, execution flow, prerequisites and escalation.",
            score_question=(
                "How much new information does `current_entity` add about how this attack "
                "actually runs?"
            ),
            score_criteria=[
                "Restates the same attack pattern in different words; no mechanism is added.",
                "Describes a precondition for the attack without saying how it behaves.",
                "Describes a different attack pattern aimed at the same goal.",
                "Describes a concrete step or variation of how this attack executes.",
                "Explains the conditions in a real system under which this attack becomes possible.",
            ],
        )


class CWETemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="CWE",
            label="Software Weakness",
            description="Code-level vulnerabilities and the architectural flaws that cause them.",
            score_question=(
                "How much does `current_entity` sharpen the explanation of the underlying "
                "weakness?"
            ),
            score_criteria=[
                "Describes a weakness unrelated to why the current one occurs.",
                "Can co-occur with the current weakness but does not explain it.",
                "Can cause or worsen the current weakness.",
                "Names the specific coding or design flaw that produces the current weakness.",
                "Is the broader weakness of which the current one is a specific instance.",
            ],
        )


class AttackTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="ATTACK",
            label="Adversary Technique",
            description="Concrete adversary procedures observed in real intrusions.",
            score_question=(
                "How much does `current_entity` explain how an adversary would actually carry "
                "out this step of the operation?"
            ),
            score_criteria=[
                "Describes a capability with no bearing on the step under investigation.",
                "Belongs to a different phase of the operation than the one being investigated.",
                "Used by the same kind of adversary, but for a different objective.",
                "Plausibly the technique an adversary would use at this step.",
                "Specifies exactly how the step would be performed, down to the implementation detail.",
            ],
        )


class AtlasTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="ATLAS",
            label="AI/ML Threat Technique",
            description="Attacks specific to AI and machine-learning systems.",
            score_question=(
                "How much does `current_entity` explain the AI-specific failure being investigated?"
            ),
            score_criteria=[
                "Describes a conventional attack with no AI-specific aspect.",
                "Touches an ML system but concerns data or infrastructure rather than the model behaviour.",
                "Describes manipulating the model's training data or objective.",
                "Describes manipulating the model's input or output at inference time.",
                "Describes the specific manipulation used, with the model behaviour it subverts.",
            ],
        )


class D3FENDTemplate(FrameworkTemplate):
    def __init__(self):
        super().__init__(
            name="D3FEND",
            label="Defensive Countermeasure",
            description="Countermeasures and mitigations available to a defender.",
            score_question=(
                "How much does `current_entity` change what a defender could actually do about "
                "the situation?"
            ),
            score_criteria=[
                "Names a defensive concept without attaching any concrete action to it.",
                "Describes hardening the system already performs by default.",
                "Describes a configuration change a defender could apply without redesigning anything.",
                "Describes monitoring or detection that would reveal this activity happening.",
                "Describes a change to the system's design that removes the capability entirely.",
            ],
        )


TEMPLATES: Dict[str, FrameworkTemplate] = {
    "CAPEC": CAPECTemplate(),
    "CWE": CWETemplate(),
    "ATTACK": AttackTemplate(),
    "ATLAS": AtlasTemplate(),
    "D3FEND": D3FENDTemplate(),
    "ICS_ATTACK": AttackTemplate(),
    "MOBILE_ATTACK": AttackTemplate(),
}

# The router can emit either spelling; both must resolve to the ATT&CK template.
TEMPLATES["ATT&CK"] = TEMPLATES["ATTACK"]

TEMPLATES_CATALOG = [
    {
        "framework": "CAPEC",
        "name": "CAPECTemplate",
        "label": "Attack Pattern",
        "icon": "Crosshair",
        "color": "#E69F00",
        "description": "Adversary attack patterns, execution flow, prerequisites and privilege escalation.",
    },
    {
        "framework": "CWE",
        "name": "CWETemplate",
        "label": "Software Weakness",
        "icon": "Bug",
        "color": "#0072B2",
        "description": "Code-level vulnerabilities, architectural flaws and root causes.",
    },
    {
        "framework": "ATTACK",
        "name": "AttackTemplate",
        "label": "Adversary Technique",
        "icon": "Crosshair",
        "color": "#D55E00",
        "description": "MITRE ATT&CK tactics, techniques and procedures.",
    },
    {
        "framework": "ATLAS",
        "name": "AtlasTemplate",
        "label": "AI/ML Threat Technique",
        "icon": "Bot",
        "color": "#CC79A7",
        "description": "Attacks on AI/ML systems: data poisoning, prompt injection, model theft.",
    },
    {
        "framework": "D3FEND",
        "name": "D3FENDTemplate",
        "label": "Defensive Countermeasure",
        "icon": "Shield",
        "color": "#009E73",
        "description": "Countermeasures, hardening and detection for defending against a technique.",
    },
]