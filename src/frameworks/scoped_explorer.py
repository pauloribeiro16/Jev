"""Scoped framework explorer: queries candidate branches scoped to a specific framework and evaluates using specialized templates."""

import time
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient
from .templates import TEMPLATES, D3FENDTemplate


class ScopedExplorer:
    """
    Executes scoped node expansion within a single framework (or across a chosen bridge),
    applying the framework's domain-specific question templates.
    """

    def __init__(self, client: TypeSafeClient, driver: GraphDatabase.driver):
        self.client = client
        self.driver = driver

    def query_scoped_neighbors(
        self,
        current_node_id: str,
        target_framework: str,
        visited_ids: list,
        max_limit: int = 12
    ) -> List[Dict[str, Any]]:
        """
        Queries Neo4j for neighbors that specifically match the target framework label
        or stay within current refinement hierarchy.
        """
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

        # If strict target_fw gave 0 results (e.g. at a bridge hub like SubDomain), allow cross-framework fallback
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
        template = TEMPLATES.get(target_framework, TEMPLATES["D3FEND"])

        t0_db = time.time()
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

        # Build clean, domain-specific criteria options for Jev Choice
        branches = {}
        option_map = {}
        for idx, n in enumerate(neighbors):
            key = f"branch_{idx+1}"
            arrow = "->" if n["direction"] == "OUTGOING" else "<-"
            rel_label = n["rel_type"]
            # Clarify inverted MITIGATES edges for defense
            if rel_label == "MITIGATES" and n["direction"] == "INCOMING":
                rel_label = "DEFENDED_BY"

            desc_preview = n["neighbor_desc"][:130] if n["neighbor_desc"] else ""
            branches[key] = f"[{rel_label}] {arrow} [{n['neighbor_label']}] '{n['neighbor_name']}' ({n['neighbor_id']}): {desc_preview}"
            option_map[key] = n

        # Formulate questions using the domain template
        goal_q = template.build_goal_question(current_node_id, goal)
        choice_q = template.build_choice_question(goal, branches)
        score_q = template.build_score_question(goal)

        state_payload = {
            "user_goal": goal,
            "current_node": current_node_id,
            "active_framework": target_framework,
            "scoped_branches": branches
        }

        t0_jev = time.time()
        response = self.client.system_one(
            state=state_payload,
            questions={
                "goal_reached": goal_q,
                "best_branch": choice_q,
                "heuristic_score": score_q
            }
        )
        jev_time = (time.time() - t0_jev) * 1000

        chosen_key = response.choices["best_branch"].choice
        chosen_neighbor = option_map.get(chosen_key, neighbors[0])
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
