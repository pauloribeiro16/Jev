"""Meta-Router powered by Jev (System 1) to decide which framework/domain to query next."""

import time
from enum import Enum
from typing import Dict, Any, Tuple, Optional, List
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient, Choice
from .templates import describe, entity_line

# One judgment, stated once. The goal lives in `analyst_question` in the state
# rather than being spliced into the instruction.
ROUTER_INSTRUCTIONS = (
    "Which entry in `reachable_frameworks` would add the most new information needed to answer "
    "`analyst_question`? Judge by the example entity each entry names — choose the one whose "
    "description covers something `path_so_far` has not already established."
)


class MetaRouterStrategy(str, Enum):
    CANONICAL = "canonical"              # CWE -> CAPEC -> ATT&CK -> D3FEND
    FAST_DEFENSE = "fast_defense"        # Immediate jump to D3FEND when available
    THREAT_HUNTING = "threat_hunting"    # ATT&CK -> CAPEC -> CWE -> D3FEND
    FREE = "free"                        # Pure semantic unconstrained Jev


class MetaRouter:
    """
    Decides the high-level semantic navigation strategy:
    'Which domain/framework should we query next to progress toward the user goal?'
    """

    FRAMEWORK_DESCRIPTIONS = {
        "CAPEC": "Examine high-level attacker strategy and attack patterns (MITRE CAPEC)",
        "CWE": "Inspect root-cause software bugs and code-level weaknesses (MITRE CWE)",
        "ATTACK": "Trace concrete operational adversary execution techniques (MITRE ATT&CK)",
        "ATLAS": "Investigate AI/ML-specific threats like prompt injection and model evasion (MITRE ATLAS)",
        "D3FEND": "Consult defensive countermeasures and mitigation techniques (MITRE D3FEND)",
        "STAY_LOCAL": "Continue traversing within current framework for deeper refinement"
    }

    def __init__(
        self,
        client: TypeSafeClient,
        driver: Optional[GraphDatabase.driver] = None,
        store: Optional[Any] = None
    ):
        self.client = client
        self.driver = driver
        if store is None and driver is None:
            from .stores import FederatedStore
            self.store = FederatedStore.get_instance()
        else:
            self.store = store

    def detect_node_framework(self, node_id: str) -> str:
        """Determines the primary framework label of the node."""
        if self.store is not None:
            fw = self.store.detect_framework(node_id)
            if fw != "UNKNOWN":
                return fw

        norm = node_id.strip().upper()
        if norm.startswith("CAPEC-"):
            return "CAPEC"
        elif norm.startswith("CWE-") or (norm.isdigit() and len(norm) <= 4):
            return "CWE"
        elif norm.startswith("AML.T"):
            return "ATLAS"
        elif norm.startswith("T") and any(char.isdigit() for char in norm):
            return "ATTACK"
        elif norm.startswith("D3-") or norm.startswith("D3A-"):
            return "D3FEND"
        elif norm.startswith("D-"):
            return "SubDomain"

        if self.driver is not None:
            try:
                with self.driver.session() as s:
                    rec = s.run("""
                        MATCH (n)
                        WHERE coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.subDomainId, n.atlasId, n.id) = $nid
                        RETURN labels(n)[0] AS lbl
                    """, nid=node_id).single()
                    if rec and rec["lbl"]:
                        return rec["lbl"]
            except Exception:
                pass
        return "UNKNOWN"

    def get_candidate_frameworks(self, current_node_id: str, current_framework: str) -> Dict[str, str]:
        """Identifies which frameworks have direct bridge edges from the current node."""
        candidates = {"STAY_LOCAL": f"Continue refining within {current_framework}"}

        # 1. High-speed lookup using in-memory FederatedStore
        if self.store is not None:
            norm_id = current_node_id.strip().upper()
            bridges = self.store.crosswalk.bridges.get(norm_id, [])
            for b in bridges:
                fw = self.store.detect_framework(b.target_id)
                if fw != "UNKNOWN" and fw != current_framework:
                    candidates[fw] = self.FRAMEWORK_DESCRIPTIONS.get(fw, f"Consult {fw} framework")

            # Fallback domain-level transitions based on taxonomy
            if current_framework == "CWE" and self.store.cwe.get_capec_bridges(norm_id):
                candidates["CAPEC"] = self.FRAMEWORK_DESCRIPTIONS["CAPEC"]
            elif current_framework == "CAPEC":
                if self.store.capec.get_attack_bridges(norm_id):
                    candidates["ATTACK"] = self.FRAMEWORK_DESCRIPTIONS["ATTACK"]
                if self.store.capec.get_cwe_bridges(norm_id):
                    candidates["CWE"] = self.FRAMEWORK_DESCRIPTIONS["CWE"]
            elif current_framework in ("ATTACK", "ATT&CK"):
                if self.store.d3fend.get_mitigations_for_attack(norm_id):
                    candidates["D3FEND"] = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"

            if "D3FEND" in candidates:
                candidates["D3FEND"] = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"
            return candidates

        # 2. Fallback to Neo4j Cypher query
        if self.driver is not None:
            cypher = """
            MATCH (curr)
            WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.atlasId, curr.subDomainId, curr.id) = $nid
            MATCH (curr)-[r]-(neighbor)
            WITH DISTINCT labels(neighbor)[0] AS n_lbl
            WHERE n_lbl IN ['CAPEC', 'CWE', 'ATTACK', 'ATLAS', 'D3FEND'] AND n_lbl <> $cur_lbl
            RETURN collect(n_lbl) AS bridge_frameworks
            """
            try:
                with self.driver.session() as s:
                    rec = s.run(cypher, nid=current_node_id, cur_lbl=current_framework).single()
                    if rec and rec["bridge_frameworks"]:
                        for fw in rec["bridge_frameworks"]:
                            candidates[fw] = self.FRAMEWORK_DESCRIPTIONS.get(fw, f"Consult {fw} framework")
            except Exception:
                pass

        if "D3FEND" in candidates:
            candidates["D3FEND"] = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"

        return candidates

    def route(
        self,
        current_node_id: str,
        goal: str,
        path: list,
        strategy: str = "canonical",
        exclude: frozenset = frozenset()
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Evaluates current state and routes to target framework using selected strategy:
          - CANONICAL: Weakness (CWE) -> Attack Pattern (CAPEC) -> Technique (ATT&CK) -> Defense (D3FEND).
          - FAST_DEFENSE: Opportunistically jumps directly to D3FEND whenever bridge exists.
          - THREAT_HUNTING: Technique (ATT&CK) -> Attack Pattern (CAPEC) -> Weakness (CWE) -> Defense.
          - FREE: Unconstrained semantic Jev choice.
        """
        current_framework = self.detect_node_framework(current_node_id)
        candidates = self.get_candidate_frameworks(current_node_id, current_framework)

        # Frameworks the explorer already judged unhelpful this hop.
        for fw in exclude:
            candidates.pop(fw, None)

        if set(candidates) <= {"STAY_LOCAL"}:
            return current_framework, {
                "current_framework": current_framework,
                "router_decision": "EXHAUSTED",
                "target_framework": current_framework,
                "strategy_applied": strategy,
                "latency_ms": 0.0,
                "candidates": candidates,
            }

        # Fast Defense shortcut: if D3FEND is directly reachable, jump immediately
        if strategy == MetaRouterStrategy.FAST_DEFENSE.value and "D3FEND" in candidates:
            return "D3FEND", {
                "current_framework": current_framework,
                "router_decision": "D3FEND",
                "target_framework": "D3FEND",
                "strategy_applied": "FAST_DEFENSE_SHORTCUT",
                "latency_ms": 0.0,
                "candidates": candidates,
                "jev_state": {"strategy": "FAST_DEFENSE_SHORTCUT", "current_node": current_node_id},
                "jev_questions": {"shortcut": "Direct bridge to D3FEND taken by Fast Defense strategy."}
            }

        # If only STAY_LOCAL is available, no routing ambiguity
        if len(candidates) == 1:
            return current_framework, {
                "current_framework": current_framework,
                "router_decision": "STAY_LOCAL",
                "target_framework": current_framework,
                "strategy_applied": strategy,
                "latency_ms": 0.0,
                "candidates": candidates
            }

        # Ground the decision. The model cannot be expected to know what
        # "CAPEC-1" means, so each option names an entity it could actually reach
        # and what that entity would tell us.
        options = self._grounded_options(current_node_id, current_framework, candidates)

        state_payload = {
            "analyst_question": goal,
            "current_entity": describe(self._entity(current_node_id)) or {
                "id": current_node_id,
                "framework": current_framework,
            },
            "path_so_far": [
                entity_line(e) if (e := self._entity(pid)) else pid for pid in path
            ],
            "reachable_frameworks": options,
        }

        question = Choice(instructions=ROUTER_INSTRUCTIONS, criteria=options)

        t0 = time.time()
        response = self.client.system_one(
            state=state_payload,
            questions={"next_framework": question}
        )
        latency_ms = (time.time() - t0) * 1000

        chosen_key = response.choices["next_framework"].choice
        target_fw = current_framework if chosen_key == "STAY_LOCAL" else chosen_key

        record = {
            "current_framework": current_framework,
            "router_decision": chosen_key,
            "target_framework": target_fw,
            "strategy_applied": strategy,
            "latency_ms": latency_ms,
            "candidates": candidates,
            "jev_state": state_payload,
            "jev_questions": {"next_framework": question.instructions}
        }
        return target_fw, record

    def _entity(self, node_id: str):
        if self.store is None:
            return None
        try:
            return self.store.get_entity(node_id.strip().upper())
        except Exception:
            return None

    def _grounded_options(self, current_node_id: str, current_framework: str, candidates: Dict[str, str]) -> Dict[str, str]:
        """Turn framework labels into questions, each with a reachable example."""
        bridges = {}
        if self.store is not None:
            for b in self.store.crosswalk.bridges.get(current_node_id.strip().upper(), []):
                if b.direction != "OUTGOING":
                    continue
                fw = self.store.detect_framework(b.target_id)
                if fw != "UNKNOWN" and fw not in bridges:
                    ent = self.store.get_entity(b.target_id)
                    if ent is not None:
                        bridges[fw] = entity_line(ent)

        out = {}
        for fw, desc in candidates.items():
            if fw == "STAY_LOCAL":
                out[fw] = (
                    "No bridge from here would tell us more than the current entity's own "
                    "description already does."
                )
            elif fw in bridges:
                out[fw] = f"{desc} Reachable now, for example {bridges[fw]}."
            else:
                out[fw] = f"{desc} A bridge to this framework exists in the ontologies."
        return out
