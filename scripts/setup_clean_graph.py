"""Script to reset Neo4j and load the clean TinyTask Cybersecurity KG."""

import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

CYPHER_FILE = Path(__file__).parent.parent / "data" / "tinytask_kg.cypher"


def setup():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        print("[1/3] Limpar base de dados existente...")
        session.run("MATCH (n) DETACH DELETE n")

        print(f"[2/3] Ler ficheiro Cypher: {CYPHER_FILE}...")
        with open(CYPHER_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        clean_lines = [line for line in content.splitlines() if not line.strip().startswith("//")]
        clean_text = "\n".join(clean_lines)
        statements = [s.strip() for s in clean_text.split(";") if s.strip()]

        print(f"      Executando {len(statements)} blocos Cypher...")
        for i, stmt in enumerate(statements, 1):
            session.run(stmt)

        print("[3/3] Validando Knowledge Graph carregado:")
        node_cnt = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        rel_cnt = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        labels = session.run("CALL db.labels() YIELD label RETURN collect(label) AS l").single()["l"]
        rel_types = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) AS r").single()["r"]

        print(f"      -> Total de Nós: {node_cnt}")
        print(f"      -> Total de Relações: {rel_cnt}")
        print(f"      -> Labels de Nós: {labels}")
        print(f"      -> Tipos de Relações: {rel_types}")

        # Amostra das relações
        print("\n--- Amostra de Caminhos no Grafo ---")
        paths = session.run("""
            MATCH (t:Threat)-[:MITIGATED_BY]->(m:Mitigation)-[:IMPLEMENTS_CLAUSE]->(c:Clause)-[:BELONGS_TO_ARTICLE]->(a:Article)-[:PART_OF_REGULATION]->(r:Regulation)
            RETURN t.name AS Ameaça, m.name AS Mitigação, c.id AS Cláusula, r.name AS Regulação
        """).data()
        for p in paths:
            print(f"  * Ameaça: {p['Ameaça']}")
            print(f"    └── Mitigação: {p['Mitigação']}")
            print(f"        └── Cláusula: {p['Cláusula']} -> Regulação: {p['Regulação']}\n")

    driver.close()


if __name__ == "__main__":
    setup()
