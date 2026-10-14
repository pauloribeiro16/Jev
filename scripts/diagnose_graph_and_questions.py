"""Diagnostic script: Analyzes graph topology, path reachability, and question formulation calibration."""

import os
import json
import sys
import time
from dotenv import load_dotenv
from neo4j import GraphDatabase
from typesafe_sdk import Choice, Noul, Score

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from frameworks.jev_budget import get_client

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
API_KEY = os.getenv("API_JEV")


def analyze_topology():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as s:
        print("=" * 70)
        print("1. ANÁLISE DE CONECTIVIDADE E CAMINHOS TÍPICOS (CAPEC -> D3FEND)")
        print("=" * 70)

        # 1.1 Caminhos mais curtos de CAPEC-1 até D3FEND
        paths = s.run("""
            MATCH p = shortestPath((c:CAPEC {capecId: 'CAPEC-1'})-[*..4]-(df:D3FEND))
            RETURN 
                length(p) AS hops,
                [n IN nodes(p) | coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.subDomainId) + ' (' + labels(n)[0] + ')'] AS nodes_path,
                [r IN relationships(p) | type(r)] AS rels_path
            LIMIT 5
        """).data()
        
        for i, p in enumerate(paths, 1):
            print(f"  [Rota #{i}] {p['hops']} saltos:")
            print(f"     Nós: {' -> '.join(p['nodes_path'])}")
            print(f"     Relações: {' -> '.join(p['rels_path'])}")

        # 1.2 Distribuição de saltos e canais de ligação
        print("\n" + "=" * 70)
        print("2. ANÁLISE DE PONTES ENTRE ONTOLOGIAS (Cross-Framework Bridges)")
        print("=" * 70)

        bridge_stats = s.run("""
            RETURN 
                count { MATCH (:CAPEC)-[:MAPS_TO_ATTACK]->(:ATTACK) } AS capec_to_attack,
                count { MATCH (:D3FEND)-[:MITIGATES]->(:ATTACK) } AS d3fend_mitigates_attack,
                count { MATCH (:CAPEC)-[:EXPLOITS]->(:CWE) } AS capec_exploits_cwe,
                count { MATCH (:CAPEC)-[:MAPS_TO_SUBDOMAIN]->(:SubDomain) } AS capec_to_subdomain,
                count { MATCH (:D3FEND)-[:MAPS_TO_SUBDOMAIN]->(:SubDomain) } AS d3fend_to_subdomain,
                count { MATCH (:CWE)-[:MAPS_TO_SUBDOMAIN]->(:SubDomain) } AS cwe_to_subdomain,
                count { MATCH (:ATTACK)-[:MAPS_TO_SUBDOMAIN]->(:SubDomain) } AS attack_to_subdomain
        """).single()
        print(f"  * CAPEC -> ATTACK (direto): {bridge_stats['capec_to_attack']}")
        print(f"  * D3FEND -> ATTACK (mitigação direta): {bridge_stats['d3fend_mitigates_attack']}")
        print(f"  * CAPEC -> CWE (fraquezas exploradas): {bridge_stats['capec_exploits_cwe']}")
        print(f"  * Pontes via SubDomain:")
        print(f"      CAPEC -> SubDomain: {bridge_stats['capec_to_subdomain']}")
        print(f"      D3FEND -> SubDomain: {bridge_stats['d3fend_to_subdomain']}")
        print(f"      CWE -> SubDomain: {bridge_stats['cwe_to_subdomain']}")
        print(f"      ATTACK -> SubDomain: {bridge_stats['attack_to_subdomain']}")

        # 1.3 Fan-out / Grau Médio em nós de ataque
        print("\n" + "=" * 70)
        print("3. ANÁLISE DE FAN-OUT (NÚMERO DE RAMOS CANDIDATOS POR NÓ)")
        print("=" * 70)
        degree_stats = s.run("""
            MATCH (c:CAPEC)
            WITH c, count { MATCH (c)--() } AS deg
            RETURN min(deg) AS min_deg, avg(deg) AS avg_deg, max(deg) AS max_deg
        """).single()
        print(f"  * Grau nós CAPEC: Mín = {degree_stats['min_deg']}, Médio = {degree_stats['avg_deg']:.1f}, Máx = {degree_stats['max_deg']}")

        d3_degree = s.run("""
            MATCH (d:D3FEND)
            WITH d, count { MATCH (d)--() } AS deg
            RETURN min(deg) AS min_deg, avg(deg) AS avg_deg, max(deg) AS max_deg
        """).single()
        print(f"  * Grau nós D3FEND: Mín = {d3_degree['min_deg']}, Médio = {d3_degree['avg_deg']:.1f}, Máx = {d3_degree['max_deg']}")

    driver.close()


def test_question_formulations():
    print("\n" + "=" * 70)
    print("4. COMPARAÇÃO EMPÍRICA: FORMULAÇÃO GENÉRICA VS FORMULAÇÃO CONTEXTUAL")
    print("=" * 70)

    client = get_client(API_KEY, site="diagnose_graph")
    
    current_node = "CAPEC-1"
    goal = "Find the D3FEND defensive countermeasure or verification technique that mitigates software file permissions or access control weaknesses."
    
    # 4 ramos representativos
    branches = {
        "branch_1": "Relationship [CHILD_OF] to [CAPEC] 'Privilege Abuse' (CAPEC-122): Exploit reserved administrator features",
        "branch_2": "Relationship [EXPLOITS] to [CWE] 'Improper Authorization' (CWE-285): Missing authorization checks",
        "branch_3": "Relationship [MAPS_TO_SUBDOMAIN] to [SubDomain] 'Privileged Access Management' (D-03.4): Elevated access control taxonomy",
        "branch_4": "Relationship [MAPS_TO_ATTACK] to [ATTACK] 'Services File Permissions Weakness' (T1574.010): Modifying service binaries"
    }

    print("\n--- [A] Formulação Genérica Atual ---")
    res_generic = client.system_one(
        state={
            "user_goal": goal,
            "current_node": current_node,
            "available_branches": branches
        },
        questions={
            "goal_reached": Noul(instructions=f"Does the current node '{current_node}' directly satisfy, solve, or answer the user goal: '{goal}'?"),
            "best_next_step": Choice(instructions=f"Given the user goal '{goal}', which branch is the most relevant path to follow?", criteria=branches),
            "heuristic_score": Score(instructions=f"How promising and semantically aligned is this current state with the goal '{goal}'?", criteria=["not aligned", "moderately aligned", "highly aligned", "critically aligned"])
        }
    )
    print(f"  * Noul (Goal): {res_generic.nouls['goal_reached'].noul:.1%}")
    print(f"  * Choice: {res_generic.choices['best_next_step'].choice} -> {branches[res_generic.choices['best_next_step'].choice]}")
    print(f"  * Score: {res_generic.scores['heuristic_score'].score:.2f}")

    print("\n--- [B] Formulação Semântica e Orientada a Papel (Ontology-Aware) ---")
    res_domain = client.system_one(
        state={
            "user_goal": goal,
            "current_node_type": "Attack Pattern (CAPEC)",
            "current_node_id": current_node,
            "target_destination_type": "Defensive Countermeasure (D3FEND)",
            "context": "We are traversing a cybersecurity ontology starting from an offensive attack pattern to reach defensive mitigations.",
            "available_branches": branches
        },
        questions={
            "goal_reached": Noul(
                instructions="Is the current entity already a concrete defensive countermeasure (D3FEND) that accomplishes the user goal?"
            ),
            "best_next_step": Choice(
                instructions="To navigate from this attack pattern towards defensive D3FEND mitigations, which intermediate bridge branch offers the most direct semantic link?",
                criteria=branches
            ),
            "heuristic_score": Score(
                instructions="Assess the semantic proximity of this state toward reaching defensive countermeasures.",
                criteria=["far from defense", "intermediate bridge", "close to mitigation", "defense reached"]
            )
        }
    )
    print(f"  * Noul (Goal): {res_domain.nouls['goal_reached'].noul:.1%}")
    print(f"  * Choice: {res_domain.choices['best_next_step'].choice} -> {branches[res_domain.choices['best_next_step'].choice]}")
    print(f"  * Score: {res_domain.scores['heuristic_score'].score:.2f}")


if __name__ == "__main__":
    analyze_topology()
    test_question_formulations()
