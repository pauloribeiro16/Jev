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
        jev_api_key: Optional[str] = None,
        store: Optional[Any] = None,
        use_neo4j: bool = False
    ):
        from .stores import FederatedStore
        self.store = store or FederatedStore.get_instance()
        self.api_key = jev_api_key or os.getenv("API_JEV") or os.getenv("TYPESAFE_API_KEY") or "mock-key"
        self.client = TypeSafeClient(api_key=self.api_key)

        self.driver = None
        if use_neo4j:
            try:
                self.uri = neo4j_uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
                self.user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
                self.password = neo4j_password or os.getenv("NEO4J_PASSWORD")
                self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            except Exception:
                self.driver = None

        self.meta_router = MetaRouter(self.client, driver=self.driver, store=self.store)
        self.scoped_explorer = ScopedExplorer(self.client, driver=self.driver, store=self.store)

    def close(self):
        if self.driver is not None:
            try:
                self.driver.close()
            except Exception:
                pass

    def execute_hop(
        self,
        current_node_id: str,
        traversed_path: List[str],
        goal: str,
        strategy: str = "canonical"
    ) -> Optional[Dict[str, Any]]:
        """
        Executes one full modular hop:
          1. Meta-Router selects target framework using chosen strategy.
          2. Scoped Explorer applies domain template.
        """
        # Step 1: Meta-Router decision
        target_fw, router_info = self.meta_router.route(
            current_node_id, goal, traversed_path, strategy=strategy
        )

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

    def query_framework(
        self,
        current_node_id: str,
        target_framework: str,
        goal: str
    ) -> Optional[Dict[str, Any]]:
        """Queries a single framework directly on current_node_id without path restrictions."""
        return self.scoped_explorer.explore(
            current_node_id=current_node_id,
            target_framework=target_framework,
            goal=goal,
            visited_ids=[]
        )

    def fan_out_evaluation(
        self,
        current_node_id: str,
        frameworks: List[str],
        goal: str
    ) -> List[Dict[str, Any]]:
        """Evaluates multiple frameworks simultaneously for comparative analysis."""
        results = []
        for fw in frameworks:
            res = self.query_framework(current_node_id, fw, goal)
            if res:
                results.append(res)
        return results
