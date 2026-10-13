"""Load ATLAS nodes and subdomain mappings."""

import csv
import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

ATLAS_CSV = Path(r"C:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Doutoramento\Methodology-main\04_KNOWLEDGE_GRAPHS\threat_modeling_kg\data\aegis\atlas_to_subdomains.csv")

def load():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as s:
        s.run("CREATE CONSTRAINT atlas_id_unique IF NOT EXISTS FOR (a:ATLAS) REQUIRE a.atlasId IS UNIQUE")
        rows = []
        with open(ATLAS_CSV, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append({"atlasId": r["atlasId"].strip(), "subDomainId": r["subDomainId"].strip(), "conf": float(r.get("confidence", 0.7))})
        
        s.run("""
            UNWIND $rows AS r
            MERGE (a:ATLAS {atlasId: r.atlasId})
            ON CREATE SET a.name = "ATLAS AI Technique " + r.atlasId
            WITH a, r
            MATCH (sd:SubDomain {subDomainId: r.subDomainId})
            MERGE (a)-[rel:MAPS_TO_SUBDOMAIN]->(sd)
            SET rel.confidence = r.conf
        """, rows=rows)
        
        cnt = s.run("MATCH (a:ATLAS) RETURN count(a) AS c").single()["c"]
        print(f"ATLAS loaded: {cnt} nodes")
    driver.close()

if __name__ == "__main__":
    load()
