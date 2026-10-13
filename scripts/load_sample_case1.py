"""Script to load Phase 1 schema and sample data from case1-aegis-tinytask into Neo4j."""

import os
import re
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

SCHEMA_FILE = Path(
    r"C:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Doutoramento\aegis-kg\cases\case1-aegis-tinytask\schema\01_create_schema.cypher"
)


def load_schema_and_sample_data():
    if not SCHEMA_FILE.exists():
        print(f"Error: Schema file not found at {SCHEMA_FILE}")
        return False

    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    # Split into individual Cypher statements
    # Remove single-line comments before splitting
    clean_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        clean_lines.append(line)
    
    clean_text = "\n".join(clean_lines)
    statements = [s.strip() for s in clean_text.split(";") if s.strip()]

    print(f"Found {len(statements)} Cypher statements to execute.")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        for idx, stmt in enumerate(statements, 1):
            try:
                session.run(stmt)
            except Exception as e:
                print(f"[{idx}/{len(statements)}] Error running: {stmt[:60]}... -> {e}")

        # Check node and relationship counts
        nodes = session.run("MATCH (n) RETURN count(n) AS cnt").single()["cnt"]
        rels = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt").single()["cnt"]
        labels = session.run("CALL db.labels() YIELD label RETURN collect(label) AS labels").single()["labels"]
        rel_types = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) AS types").single()["types"]

        print("\n--- Neo4j Ingestion Summary ---")
        print(f"Total nodes: {nodes}")
        print(f"Total relationships: {rels}")
        print(f"Node labels: {labels}")
        print(f"Relationship types: {rel_types}")

    driver.close()
    return True


if __name__ == "__main__":
    load_schema_and_sample_data()
