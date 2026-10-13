"""
Jev Graph Explorer — Semantic Graph Traversal with Total Visibility (English Native).
Demonstrates step-by-step Neo4j navigation using TypeSafe AI's Jev (System 1).
Every Cypher query, Jev state payload, questions, criteria, and probabilities are logged.
"""

import os
import json
from dotenv import load_dotenv
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient, Choice, Noul, Score

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
JEV_API_KEY = os.getenv("TYPESAFE_API_KEY") or os.getenv("API_JEV")


def format_json(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)


class JevGraphExplorer:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.jev_client = TypeSafeClient(api_key=JEV_API_KEY)

    def close(self):
        self.driver.close()
        self.jev_client.close()

    def get_neighbors(self, current_node_id: str, visited_ids: list):
        """Execute transparent Cypher query to discover adjacent edges without repeating visited nodes."""
        cypher = """
        MATCH (curr {id: $curr_id})-[r]-(neighbor)
        WHERE NOT neighbor.id IN $visited_ids
        RETURN 
            CASE WHEN startNode(r) = curr THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
            type(r) AS rel_type,
            labels(neighbor)[0] AS neighbor_label,
            neighbor.id AS neighbor_id,
            coalesce(neighbor.name, neighbor.title, neighbor.text, neighbor.id) AS neighbor_name,
            coalesce(neighbor.description, neighbor.text, neighbor.focus, '') AS neighbor_desc
        """
        params = {"curr_id": current_node_id, "visited_ids": visited_ids}
        
        print("\n" + "="*80)
        print("  [NEO4J CYPHER QUERY EXECUTION]")
        print("="*80)
        print(f"QUERY:\n{cypher.strip()}\n")
        print(f"PARAMETERS: {params}")

        with self.driver.session() as session:
            records = session.run(cypher, params).data()

        print(f"\nNEO4J RETURNED {len(records)} CANDIDATE BRANCHES:")
        for i, rec in enumerate(records, 1):
            arrow = "->" if rec["direction"] == "OUTGOING" else "<-"
            print(f"  [{i}] {arrow} [:{rec['rel_type']}] ({rec['neighbor_label']} id='{rec['neighbor_id']}', name='{rec['neighbor_name']}')")

        return records

    def navigate(self, start_node_id: str, search_goal: str, max_hops: int = 5):
        """
        Traverse the Knowledge Graph node-by-node guided by Jev decisions.
        """
        print("\n" + "#"*80)
        print(f"  SEMANTIC GRAPH TRAVERSAL WITH JEV & NEO4J")
        print(f"  Start Node: '{start_node_id}'")
        print(f"  Search Goal: \"{search_goal}\"")
        print("#"*80)

        current_node_id = start_node_id
        path_history = [current_node_id]

        for hop in range(1, max_hops + 1):
            print("\n" + "-"*80)
            print(f"  HOP #{hop} | Current Node: '{current_node_id}'")
            print("-"*80)

            # 1. Fetch neighbors from Neo4j
            neighbors = self.get_neighbors(current_node_id, visited_ids=path_history)
            if not neighbors:
                print(f"[!] Traversal end: node '{current_node_id}' has no unvisited neighbors.")
                break

            # 2. Formulate options for Jev Choice
            criteria_options = {}
            option_map = {}
            for idx, n in enumerate(neighbors):
                opt_key = f"branch_{idx+1}"
                direction_arrow = "to" if n["direction"] == "OUTGOING" else "from"
                opt_desc = (
                    f"Relationship [{n['rel_type']}] {direction_arrow} [{n['neighbor_label']}] "
                    f"'{n['neighbor_name']}': {n['neighbor_desc'][:120]}"
                )
                criteria_options[opt_key] = opt_desc
                option_map[opt_key] = n

            # 3. Build state payload and typed questions for Jev
            state_payload = {
                "user_goal": search_goal,
                "current_node": current_node_id,
                "traversed_path": " -> ".join(path_history),
                "available_branches": criteria_options
            }

            questions_payload = {
                # Goal evaluation: does the current node fulfill the target?
                "goal_reached": Noul(
                    instructions=f"Does the current node '{current_node_id}' directly satisfy or answer the user goal: '{search_goal}'?"
                ),
                # Next step selection: which candidate branch is most relevant?
                "best_next_step": Choice(
                    instructions=f"Given the user goal '{search_goal}', which branch is the most relevant path to follow?",
                    criteria=criteria_options
                ),
                # Heuristic alignment score
                "heuristic_score": Score(
                    instructions=f"How promising and semantically aligned is this current state with the goal '{search_goal}'?",
                    criteria=["not aligned", "moderately aligned", "highly aligned", "critically aligned"]
                )
            }

            # 4. Display transparent payload sent to the model
            print("\n" + "="*80)
            print("  [PAYLOAD SENT TO JEV (System 1 - TypeSafe AI)]")
            print("="*80)
            print(f"STATE:")
            print(format_json(state_payload))
            print("\nQUESTIONS:")
            print("  1. goal_reached [Noul]:", questions_payload["goal_reached"].instructions)
            print("  2. best_next_step [Choice]:", questions_payload["best_next_step"].instructions)
            print("     Options / Branches:", format_json(criteria_options))
            print("  3. heuristic_score [Score]:", questions_payload["heuristic_score"].instructions)
            print("     Scale:", questions_payload["heuristic_score"].criteria)

            # 5. Call Jev API
            print("\n>> Sending request to Jev...")
            response = self.jev_client.system_one(
                state=state_payload,
                questions=questions_payload
            )

            # 6. Parse transparent response from Jev
            noul_goal = response.nouls["goal_reached"]
            choice_step = response.choices["best_next_step"]
            score_heur = response.scores["heuristic_score"]

            print("\n" + "="*80)
            print("  [RAW RESPONSE FROM JEV]")
            print("="*80)
            print(f"  * Noul 'goal_reached': {noul_goal.noul:.2f} (Confidence: {noul_goal.noul:.0%})")
            print(f"  * Choice 'best_next_step': {choice_step.choice}")
            print(f"  * Score 'heuristic_score': {score_heur.score} (Ordinal index)")

            # 7. Check Goal Condition
            if noul_goal.noul >= 0.70:
                print(f"\n[+] TARGET GOAL REACHED! Jev confidence: {noul_goal.noul:.0%}")
                print(f"    Final Path: {' -> '.join(path_history)}")
                break

            # 8. Follow selected branch
            selected_branch = choice_step.choice
            if selected_branch in option_map:
                next_node = option_map[selected_branch]
                current_node_id = next_node["neighbor_id"]
                path_history.append(current_node_id)
                print(f"\n[->] Jev selected {selected_branch}: Moving to {next_node['neighbor_label']} '{current_node_id}' ({next_node['neighbor_name']})")
            else:
                print(f"[!] Jev selected unknown branch: {selected_branch}. Stopping traversal.")
                break

        print("\n" + "#"*80)
        print("  TRAVERSAL COMPLETE")
        print(f"  Full Path Traversed: {' -> '.join(path_history)}")
        print("#"*80 + "\n")


def main():
    explorer = JevGraphExplorer()
    try:
        # Example query: Starting from Data Exfiltration threat, find the applicable European legal article/clause
        explorer.navigate(
            start_node_id="T-EXFILTRATION",
            search_goal="Find the specific mandatory EU regulatory clause and article requiring encryption or technical safeguards against personal data breaches.",
            max_hops=4
        )
    finally:
        explorer.close()


if __name__ == "__main__":
    main()
