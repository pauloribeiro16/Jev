"""
ETL Loader for Case 1 (TinyTask) Knowledge Graph into Neo4j.
Loads Regulations, Articles, Clauses, Domains, SubDomains, Mappings, Threats, and Mitigations.
"""

import csv
import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

BASE_DATA_DIR = Path(
    r"C:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Doutoramento\aegis-kg\cases\case1-aegis-tinytask\data"
)
PHASE1_DIR = BASE_DATA_DIR / "phase1"
PHASE2_DIR = BASE_DATA_DIR / "phase2"
PHASE3_DIR = BASE_DATA_DIR / "phase3"


def get_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def load_all_case1():
    driver = get_driver()
    with driver.session() as session:
        print("=== Ingesting TinyTask Knowledge Graph ===")

        # 1. Domains & SubDomains
        print("1. Loading Domains & SubDomains...")
        dom_file = PHASE1_DIR / "01_domains.csv"
        if dom_file.exists():
            with open(dom_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MERGE (d:Domain {domainId: $did, case: 'case1'})
                        SET d.name = $name, d.description = $desc
                        """,
                        did=row.get("domainId", "").strip(),
                        name=row.get("name", "").strip(),
                        desc=row.get("description", "").strip(),
                    )

        subdom_file = PHASE1_DIR / "02_subdomains.csv"
        if subdom_file.exists():
            with open(subdom_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MERGE (sd:SubDomain {subDomainId: $sdId, case: 'case1'})
                        SET sd.name = $name, sd.description = $desc
                        WITH sd
                        MATCH (d:Domain {domainId: $did, case: 'case1'})
                        MERGE (sd)-[:BELONGS_TO]->(d)
                        """,
                        sdId=row.get("subDomainId", "").strip(),
                        name=row.get("name", "").strip(),
                        desc=row.get("description", "").strip(),
                        did=row.get("domainId", "").strip(),
                    )

        # 2. Regulations, Articles & Clauses
        print("2. Loading Regulations, Articles & Clauses...")
        reg_file = PHASE1_DIR / "00_regulations.csv"
        if reg_file.exists():
            with open(reg_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MERGE (r:Regulation {regulationId: $rid, case: 'case1'})
                        SET r.name = $name, r.fullName = $fullName, r.type = $type
                        """,
                        rid=row.get("regulationId", "").strip(),
                        name=row.get("name", "").strip(),
                        fullName=row.get("fullName", "").strip(),
                        type=row.get("type", "").strip(),
                    )

        art_file = PHASE1_DIR / "03_articles.csv"
        if art_file.exists():
            with open(art_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MATCH (r:Regulation {regulationId: $rid, case: 'case1'})
                        MERGE (a:Article {articleId: $aid, case: 'case1'})
                        SET a.title = $title, a.number = $num
                        MERGE (r)-[:HAS_ARTICLE]->(a)
                        """,
                        rid=row.get("regulationId", "").strip(),
                        aid=row.get("articleId", "").strip(),
                        title=row.get("title", "").strip(),
                        num=row.get("number", "").strip(),
                    )

        cl_file = PHASE1_DIR / "04_clauses.csv"
        if cl_file.exists():
            with open(cl_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MATCH (a:Article {articleId: $aid, case: 'case1'})
                        MERGE (c:Clause {clauseId: $cid, case: 'case1'})
                        SET c.text = $text, c.normativeIntensity = $intensity
                        MERGE (a)-[:HAS_CLAUSE]->(c)
                        """,
                        aid=row.get("articleId", "").strip(),
                        cid=row.get("clauseId", "").strip(),
                        text=row.get("text", "").strip(),
                        intensity=row.get("normativeIntensity", "").strip(),
                    )

        # 3. Clause -> SubDomain Mappings
        print("3. Linking Clauses to SubDomains...")
        map_file = PHASE1_DIR / "07_clause_subdomain_mapping.csv"
        if map_file.exists():
            with open(map_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MATCH (c:Clause {clauseId: $cid, case: 'case1'})
                        MATCH (sd:SubDomain {subDomainId: $sdid, case: 'case1'})
                        MERGE (c)-[:MAPS_TO {weight: toFloat($weight)}]->(sd)
                        """,
                        cid=row.get("clauseId", "").strip(),
                        sdid=row.get("subDomainId", "").strip(),
                        weight=row.get("weight", "1.0"),
                    )

        # 4. Phase 3: Threats, Risks & Mitigations (if present)
        print("4. Loading Threats, Risks & Mitigations...")
        risks_file = PHASE3_DIR / "10_risks.csv"
        if risks_file.exists():
            with open(risks_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MERGE (rk:Risk {riskId: $rid, case: 'case1'})
                        SET rk.name = $name, rk.description = $desc, rk.severity = $sev
                        """,
                        rid=row.get("riskId", row.get("id", "")).strip(),
                        name=row.get("name", "").strip(),
                        desc=row.get("description", "").strip(),
                        sev=row.get("severity", "MEDIUM").strip(),
                    )

        use_cases_file = PHASE3_DIR / "05_use_cases.csv"
        if use_cases_file.exists():
            with open(use_cases_file, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    session.run(
                        """
                        MERGE (uc:UseCase {useCaseId: $ucid, case: 'case1'})
                        SET uc.name = $name, uc.description = $desc
                        """,
                        ucid=row.get("useCaseId", row.get("id", "")).strip(),
                        name=row.get("name", "").strip(),
                        desc=row.get("description", "").strip(),
                    )

        # Stats
        nodes = session.run("MATCH (n {case: 'case1'}) RETURN count(n) AS cnt").single()["cnt"]
        rels = session.run("MATCH (a {case: 'case1'})-[r]->(b {case: 'case1'}) RETURN count(r) AS cnt").single()["cnt"]
        print("\n=== TinyTask KG Loaded Successfully ===")
        print(f"Total Case1 nodes: {nodes}")
        print(f"Total Case1 relationships: {rels}")

    driver.close()


if __name__ == "__main__":
    load_all_case1()
