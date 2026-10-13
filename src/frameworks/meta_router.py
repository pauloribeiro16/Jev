"""Meta-Router powered by Jev (System 1) to decide which framework/domain to query next."""

import time
from typing import Dict, Any, Tuple
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient
from .templates import MetaRouterTemplate


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

    def __init__(self, client: TypeSafeClient, driver: GraphDatabase.driver):
        self.client = client
        self.driver = driver

    def detect_node_framework(self, node_id: str) -> str:
        """Determines the primary framework label of the node."""
        if node_id.startswith("CAPEC-"):
            return "CAPEC"
        elif node_id.startswith("CWE-"):
            return "CWE"
        elif node_id.startswith("AML.T"):
            return "ATLAS"
        elif node_id.startswith("T") and any(char.isdigit() for char in node_id):
            return "ATTACK"
        elif node_id.startswith("D3-") or node_id.startswith("D3A-"):
            return "D3FEND"
        elif node_id.startswith("D-"):
            return "SubDomain"

        with self.driver.session() as s:
            rec = s.run("""
                MATCH (n)
                WHERE coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.subDomainId, n.atlasId, n.id) = $nid
                RETURN labels(n)[0] AS lbl
            """, nid=node_id).single()
            if rec and rec["lbl"]:
                return rec["lbl"]
        return "UNKNOWN"

    def get_candidate_frameworks(self, current_node_id: str, current_framework: str) -> Dict[str, str]:
        """Identifies which frameworks have direct bridge edges from the current node."""
        candidates = {"STAY_LOCAL": f"Continue refining within {current_framework}"}

        cypher = """
        MATCH (curr)
        WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.atlasId, curr.subDomainId, curr.id) = $nid
        MATCH (curr)-[r]-(neighbor)
        WITH DISTINCT labels(neighbor)[0] AS n_lbl
        WHERE n_lbl IN ['CAPEC', 'CWE', 'ATTACK', 'ATLAS', 'D3FEND'] AND n_lbl <> $cur_lbl
        RETURN collect(n_lbl) AS bridge_frameworks
        """
        with self.driver.session() as s:
            rec = s.run(cypher, nid=current_node_id, cur_lbl=current_framework).single()
            if rec and rec["bridge_frameworks"]:
                for fw in rec["bridge_frameworks"]:
                    candidates[fw] = self.FRAMEWORK_DESCRIPTIONS.get(fw, f"Consult {fw} framework")

        # If reaching defense is the ultimate target and we are near D3FEND
        if "D3FEND" in candidates:
            candidates["D3FEND"] = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"

        return candidates

    def route(self, current_node_id: str, goal: str, path: list) -> Tuple[str, Dict[str, Any]]:
        """
        Evaluates the current state and routes to the best target framework.
        Returns: (chosen_framework, metadata_record)
        """
        current_framework = self.detect_node_framework(current_node_id)
        candidates = self.get_candidate_frameworks(current_node_id, current_framework)

        # If only STAY_LOCAL is available, no routing ambiguity
        if len(candidates) == 1:
            return current_framework, {
                "current_framework": current_framework,
                "router_decision": "STAY_LOCAL",
                "target_framework": current_framework,
                "latency_ms": 0.0,
                "candidates": candidates
            }

        state_payload = {
            "user_goal": goal,
            "current_node": current_node_id,
            "current_framework": current_framework,
            "traversed_path": " -> ".join(path),
            "candidate_frameworks": candidates
        }

        question = MetaRouterTemplate.build_framework_selection_question(
            goal=goal,
            current_phase=f"Investigating {current_framework} ({current_node_id})",
            candidate_frameworks=candidates
        )
        score_q = MetaRouterTemplate.build_phase_score_question(goal, current_framework)

        t0 = time.time()
        response = self.client.system_one(
            state=state_payload,
            questions={
                "next_framework": question,
                "phase_progress": score_q
            }
        )
        latency_ms = (time.time() - t0) * 1000

        chosen_key = response.choices["next_framework"].choice
        target_fw = current_framework if chosen_key == "STAY_LOCAL" else chosen_key

        record = {
            "current_framework": current_framework,
            "router_decision": chosen_key,
            "target_framework": target_fw,
            "latency_ms": latency_ms,
            "candidates": candidates,
            "phase_score": response.scores["phase_progress"].score,
            "jev_state": state_payload,
            "jev_questions": {
                "next_framework": question.instructions,
                "phase_progress": score_q.instructions
            }
        }
        return target_fw, record
