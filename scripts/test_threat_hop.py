"""Test single hop traversal on Threat Modeling Knowledge Graph with Jev."""

import os
import json
import time
from dotenv import load_dotenv
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient, Choice, Noul, Score

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
API_KEY = os.getenv("API_JEV")

def test():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    client = TypeSafeClient(api_key=API_KEY)
    
    start_node = "CAPEC-1"
    goal = "Find the D3FEND defensive countermeasure or verification technique that mitigates software file permissions or access control weaknesses."
    
    with driver.session() as session:
        cypher = """
        MATCH (curr)
        WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.subDomainId) = $curr_id
        MATCH (curr)-[r]-(neighbor)
        RETURN 
            type(r) AS rel,
            labels(neighbor)[0] AS lbl,
            coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.subDomainId) AS id,
            coalesce(neighbor.name, neighbor.title, neighbor.id) AS name
        LIMIT 6
        """
        records = session.run(cypher, {"curr_id": start_node}).data()
    
    print(f"[*] Current Node: {start_node}")
    print(f"[*] Goal: {goal}")
    print(f"[*] Neighbors ({len(records)}):")
    
    options = {}
    for i, r in enumerate(records):
        key = f"branch_{i+1}"
        options[key] = f"[:{r['rel']}] to [{r['lbl']}] {r['id']} ({r['name']})"
        print(f"    {key}: {options[key]}")
    
    t0 = time.time()
    res = client.system_one(
        state={
            "user_goal": goal,
            "current_node": start_node,
            "branches": options
        },
        questions={
            "goal_reached": Noul(instructions=f"Does node {start_node} satisfy the goal '{goal}'?"),
            "next_step": Choice(instructions="Which branch is the most relevant step toward the goal?", criteria=options),
            "score": Score(instructions="How aligned is this state with the goal?", criteria=["low", "medium", "high"])
        }
    )
    dt = (time.time() - t0) * 1000
    
    print("\n[+] Jev System 1 Decision:")
    print(f"    - Latency: {dt:.1f}ms")
    print(f"    - Goal Confidence (Noul): {res.nouls['goal_reached'].noul:.1%}")
    print(f"    - Selected Branch (Choice): {res.choices['next_step'].choice} -> {options[res.choices['next_step'].choice]}")
    print(f"    - Alignment Score: {res.scores['score'].score:.2f}")

    driver.close()

if __name__ == "__main__":
    test()
