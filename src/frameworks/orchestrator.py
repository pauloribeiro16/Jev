"""Modular Threat Traversal Orchestrator tying together Meta-Router and Scoped Framework Explorers."""

import os
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient

from .meta_router import MetaRouter
from .scoped_explorer import ScopedExplorer

load_dotenv()


class ModularOrchestrator:
    """
    Two-Level Hierarchical Traversal Engine:
      Level 1 (Meta-Router): Decides which framework to query next (CAPEC, CWE, ATTACK, ATLAS, D3FEND).
      Level 2 (Scoped Explorer): Uses specialized domain templates to select the optimal branch.
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        jev_api_key: Optional[str] = None
    ):
        self.uri = neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
        self.password = neo4j_password or os.getenv("NEO4J_PASSWORD")
        self.api_key = jev_api_key or os.getenv("API_JEV") or os.getenv("TYPESAFE_API_KEY")

        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        self.client = TypeSafeClient(api_key=self.api_key)

        self.meta_router = MetaRouter(self.client, self.driver)
        self.scoped_explorer = ScopedExplorer(self.client, self.driver)

    def close(self):
        self.driver.close()

    def execute_hop(
        self,
        current_node_id: str,
        traversed_path: List[str],
        goal: str
    ) -> Optional[Dict[str, Any]]:
        """
        Executes one full modular hop:
          1. Meta-Router selects target framework.
          2. Scoped Explorer applies domain template.
        """
        # Step 1: Meta-Router decision
        target_fw, router_info = self.meta_router.route(current_node_id, goal, traversed_path)

        # Step 2: Scoped Explorer decision
        explorer_result = self.scoped_explorer.explore(
            current_node_id=current_node_id,
            target_framework=target_fw,
            goal=goal,
            visited_ids=traversed_path
        )

        if not explorer_result:
            return {
                "status": "dead-end",
                "current_node": current_node_id,
                "router_info": router_info,
                "message": f"No further unvisited branches available in {target_fw} from '{current_node_id}'."
            }

        total_latency = router_info["latency_ms"] + explorer_result["jev_time_ms"]

        return {
            "status": "success",
            "hop": len(traversed_path),
            "current_node": current_node_id,
            "next_node": explorer_result["next_node_id"],
            "next_node_label": explorer_result["next_node_label"],
            "next_node_name": explorer_result["next_node_name"],
            "goal_reached": explorer_result["goal_reached"],
            "noul_goal": explorer_result["noul_goal"],
            "heuristic_score": explorer_result["heuristic_score"],
            "total_latency_ms": total_latency,
            "level_1_router": router_info,
            "level_2_explorer": explorer_result
        }
