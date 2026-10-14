"""Scoped framework explorer: queries candidate branches scoped to a specific framework and evaluates using specialized templates."""

import time
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient
from .templates import TEMPLATES, describe
from .stores import FederatedStore


class ScopedExplorer:
    """
    Executes scoped node expansion within a single framework (or across a chosen bridge),
    applying the framework's domain-specific question templates.
    Supports high-speed in-memory FederatedStore (<0.1ms) or legacy Neo4j driver.
    """

    def __init__(
        self,
        client: TypeSafeClient,
        driver: Optional[GraphDatabase.driver] = None,
        store: Optional[FederatedStore] = None
    ):
        self.client = client
        self.driver = driver
        self.store = store or (FederatedStore.get_instance() if driver is None else None)

    def query_scoped_neighbors(
        self,
        current_node_id: str,
        target_framework: str,
        visited_ids: list,
        max_limit: int = 12
    ) -> List[Dict[str, Any]]:
        """
        Queries for neighbors that specifically match the target framework label.
        Uses in-memory FederatedStore if available, otherwise queries Neo4j.
        """
        if self.store is not None:
            return self.store.get_scoped_neighbors(
                current_node_id,
                target_framework=target_framework,
                visited_ids=visited_ids,
                max_limit=max_limit
            )

        if self.driver is None:
            return []

        cypher = """
        MATCH (curr)
        WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.atlasId, curr.subDomainId, curr.id) = $curr_id
        MATCH (curr)-[r]-(neighbor)
        WHERE (labels(neighbor)[0] = $target_fw OR $target_fw = 'ALL')
          AND NOT coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.atlasId, neighbor.subDomainId, neighbor.id) IN $visited_ids
        RETURN 
            CASE WHEN startNode(r) = curr THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
            type(r) AS rel_type,
            labels(neighbor)[0] AS neighbor_label,
            coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.atlasId, neighbor.subDomainId, neighbor.id) AS neighbor_id,
            coalesce(neighbor.name, neighbor.title, neighbor.text, neighbor.id) AS neighbor_name,
            coalesce(neighbor.description, neighbor.definition, neighbor.solutions, '') AS neighbor_desc
        LIMIT $limit
        """
        with self.driver.session() as s:
            records = s.run(cypher, curr_id=current_node_id, target_fw=target_framework, visited_ids=visited_ids, limit=max_limit).data()

        if not records and target_framework != "ALL":
            with self.driver.session() as s:
                records = s.run(cypher, curr_id=current_node_id, target_fw="ALL", visited_ids=visited_ids, limit=max_limit).data()

        return records

    def explore(
        self,
        current_node_id: str,
        target_framework: str,
        goal: str,
        visited_ids: list
    ) -> Optional[Dict[str, Any]]:
        """
        Performs scoped expansion and Jev System 1 evaluation using the framework template.
        """
        template = self._resolve_template(target_framework)

        t0_db = time.time()
        if self.store is not None:
            cypher_used = f"FederatedStore.get_scoped_neighbors(current_id='{current_node_id}', target_fw='{target_framework}')"
        else:
            cypher_used = """MATCH (curr)
WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.atlasId, curr.subDomainId, curr.id) = $curr_id
MATCH (curr)-[r]-(neighbor)
WHERE (labels(neighbor)[0] = $target_fw OR $target_fw = 'ALL')
  AND NOT coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.atlasId, neighbor.subDomainId, neighbor.id) IN $visited_ids
RETURN 
    CASE WHEN startNode(r) = curr THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
    type(r) AS rel_type,
    labels(neighbor)[0] AS neighbor_label,
    coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.atlasId, neighbor.subDomainId, neighbor.id) AS neighbor_id,
    coalesce(neighbor.name, neighbor.title, neighbor.text, neighbor.id) AS neighbor_name,
    coalesce(neighbor.description, neighbor.definition, neighbor.solutions, '') AS neighbor_desc
LIMIT 12"""
        cypher_params = {"curr_id": current_node_id, "target_fw": target_framework, "visited_ids": visited_ids}

        neighbors = self.query_scoped_neighbors(current_node_id, target_framework, visited_ids)
        db_time = (time.time() - t0_db) * 1000

        if not neighbors:
            return None

        # Candidate entities go in the state with their full content; the Choice
        # only carries the id -> name mapping. Keys are entity ids, not
        # branch_1..N: the docs warn that Choice results shift toward the first
        # option, and a positional label invites exactly that bias.
        branches = {}
        option_map = {}
        candidates = {}
        for n in sorted(neighbors, key=lambda x: x["neighbor_id"]):
            key = n["neighbor_id"]
            arrow = "outgoing" if n["direction"] == "OUTGOING" else "incoming"
            rel_label = n["rel_type"]
            if rel_label == "MITIGATES" and n["direction"] == "INCOMING":
                rel_label = "DEFENDED_BY"

            branches[key] = n["neighbor_name"]
            option_map[key] = n
            candidates[key] = {
                "name": n["neighbor_name"],
                "framework": n["neighbor_label"],
                "relation": f"{rel_label} ({arrow} from current_entity)",
                "description": (n["neighbor_desc"] or "")[:220] or None,
            }

        # The model must be able to decline rather than pick the least bad branch;
        # the orchestrator already treats a dead end as a stopping condition.
        branches["none_advances"] = "None of the above"

        # Formulate questions using the domain template
        goal_q = template.build_goal_question()
        choice_q = template.build_choice_question(branches)
        score_q = template.build_score_question()

        state_payload = {
            "analyst_question": goal,
            "current_entity": describe(self._entity(current_node_id)) or {
                "id": current_node_id,
                "framework": target_framework,
            },
            "candidate_entities": candidates,
        }

        t0_jev = time.time()
        response = self.client.system_one(
            state=state_payload,
            questions={
                "goal_reached": goal_q,
                "best_branch": choice_q,
                "heuristic_score": score_q,
            }
        )
        jev_time = (time.time() - t0_jev) * 1000

        chosen_key = response.choices["best_branch"].choice
        if chosen_key == "none_advances" or chosen_key not in option_map:
            # Not a dead end in the graph — a judgement that this framework has
            # nothing useful here. The caller should try another framework.
            return {
                "status": "no-useful-branch",
                "target_framework": target_framework,
                "jev_state": state_payload,
                "noul_goal": response.nouls["goal_reached"].noul,
                "heuristic_score": response.scores["heuristic_score"].score,
            }
        chosen_neighbor = option_map[chosen_key]
        noul_goal = response.nouls["goal_reached"].noul
        score_val = response.scores["heuristic_score"].score

        return {
            "current_node": current_node_id,
            "active_framework": target_framework,
            "template_used": template.name,
            "cypher_query": cypher_used,
            "cypher_params": cypher_params,
            "db_time_ms": db_time,
            "jev_time_ms": jev_time,
            "neighbors_count": len(neighbors),
            "neighbors": neighbors,
            "branches": branches,
            "chosen_branch_key": chosen_key,
            "next_node_id": chosen_neighbor["neighbor_id"],
            "next_node_label": chosen_neighbor["neighbor_label"],
            "next_node_name": chosen_neighbor["neighbor_name"],
            "noul_goal": noul_goal,
            "heuristic_score": score_val,
            "goal_reached": noul_goal >= 0.70,
            "jev_state": state_payload,
            "jev_questions": {
                "goal_reached": goal_q.instructions,
                "best_branch": choice_q.instructions,
                "heuristic_score": score_q.instructions,
            }
        }

    @staticmethod
    def _resolve_template(target_framework: str):
        """Resolve a framework label to a template, loudly.

        This used to fall back to the D3FEND template on a miss, which meant a
        CAPEC node could be judged with the questions "which D3FEND technique
        mitigates this?" — wrong prompts, no error. A missing template is a bug,
        not a reason to answer a different question.
        """
        template = TEMPLATES.get(target_framework)
        if template is None:
            template = TEMPLATES.get(target_framework.replace("&", ""))
        if template is None:
            raise KeyError(
                f"No question template for framework '{target_framework}'. "
                f"Known: {sorted(TEMPLATES)}"
            )
        return template

    def _entity(self, node_id: str):
        if self.store is None:
            return None
        try:
            return self.store.get_entity(node_id.strip().upper())
        except Exception:
            return None
