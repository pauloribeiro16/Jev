"""Script to load ATT&CK techniques and link them with D3FEND, CAPEC, CWE and SubDomains."""

import csv
import os
from pathlib import Path
from dotenv import load_dotenv
from neo4j import GraphDatabase
from lxml import etree

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

BASE_PATH = Path(r"C:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Doutoramento\Methodology-main\04_KNOWLEDGE_GRAPHS\threat_modeling_kg")
D3FEND_CSV = BASE_PATH / "data" / "d3fend" / "d3fend-full-mappings.csv"
CAPEC_XML = BASE_PATH / "data" / "capec" / "capec.xml"
AEGIS_DIR = BASE_PATH / "data" / "aegis"


def enrich():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        print("[1/6] Criar constraints para ATTACK...")
        session.run("CREATE CONSTRAINT attack_id_unique IF NOT EXISTS FOR (a:ATTACK) REQUIRE a.attackId IS UNIQUE")

        print("[2/6] Extrair e criar nós ATTACK...")
        attack_nodes = {}

        # 1. De d3fend-full-mappings.csv
        with open(D3FEND_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tid = row.get("off_tech_id", "").strip()
                if tid:
                    attack_nodes[tid] = {
                        "attackId": tid,
                        "name": row.get("off_tech_label", "").strip(),
                        "tactic": row.get("off_tactic_label", "").strip(),
                        "parent_id": row.get("off_tech_parent", "").replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "").strip()
                    }

        # 2. De attack_to_subdomains.csv
        att_sub_path = AEGIS_DIR / "attack_to_subdomains.csv"
        if att_sub_path.exists():
            with open(att_sub_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tid = row.get("attackId", "").strip()
                    if tid and tid not in attack_nodes:
                        attack_nodes[tid] = {
                            "attackId": tid,
                            "name": f"ATT&CK Technique {tid}",
                            "tactic": "",
                            "parent_id": ""
                        }

        # 3. De capec.xml taxonomy mappings
        tree = etree.parse(str(CAPEC_XML))
        root = tree.getroot()
        capec_ns = {"capec": "http://capec.mitre.org/capec-3"}
        capec_to_attack = []

        for pattern in root.xpath("//capec:Attack_Pattern", namespaces=capec_ns):
            capec_id = f"CAPEC-{pattern.get('ID')}"
            for tm in pattern.xpath(".//capec:Taxonomy_Mapping[@Taxonomy_Name='ATTACK']", namespaces=capec_ns):
                entry_id = tm.findtext("{http://capec.mitre.org/capec-3}Entry_ID")
                entry_name = tm.findtext("{http://capec.mitre.org/capec-3}Entry_Name") or ""
                if entry_id:
                    att_id = f"T{entry_id}" if not entry_id.startswith("T") else entry_id
                    if att_id not in attack_nodes:
                        attack_nodes[att_id] = {
                            "attackId": att_id,
                            "name": entry_name,
                            "tactic": "",
                            "parent_id": ""
                        }
                    capec_to_attack.append({"capecId": capec_id, "attackId": att_id})

        print(f"      Total de nós ATTACK identificados: {len(attack_nodes)}")
        session.run("""
            UNWIND $rows AS row
            MERGE (a:ATTACK {attackId: row.attackId})
            SET a.name = CASE WHEN row.name <> '' THEN row.name ELSE a.name END,
                a.tactic = CASE WHEN row.tactic <> '' THEN row.tactic ELSE a.tactic END
        """, rows=list(attack_nodes.values()))

        print("[3/6] Criar relações D3FEND -[:MITIGATES]-> ATTACK...")
        mitigates_rels = set()
        with open(D3FEND_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                def_uri = row.get("def_tech", "").strip()
                off_id = row.get("off_tech_id", "").strip()
                if def_uri and off_id:
                    mitigates_rels.add((def_uri, off_id))

        mitigates_list = [{"d3fendUri": u, "attackId": a} for u, a in mitigates_rels]
        session.run("""
            UNWIND $rows AS row
            MATCH (d:D3FEND {uri: row.d3fendUri})
            MATCH (a:ATTACK {attackId: row.attackId})
            MERGE (d)-[:MITIGATES]->(a)
        """, rows=mitigates_list)
        print(f"      Relações MITIGATES criadas: {len(mitigates_list)}")

        print(f"[4/6] Criar relações CAPEC -[:MAPS_TO_ATTACK]-> ATTACK ({len(capec_to_attack)})...")
        session.run("""
            UNWIND $rows AS row
            MATCH (c:CAPEC {capecId: row.capecId})
            MATCH (a:ATTACK {attackId: row.attackId})
            MERGE (c)-[:MAPS_TO_ATTACK]->(a)
        """, rows=capec_to_attack)

        print("[5/6] Criar mapeamentos para SubDomain...")
        # CAPEC -> SubDomain
        capec_sub = []
        c_sub_path = AEGIS_DIR / "capec_to_subdomains.csv"
        if c_sub_path.exists():
            with open(c_sub_path, mode="r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    capec_sub.append({"id": row.get("capecId"), "subId": row.get("subDomainId"), "conf": float(row.get("confidence", 0.8))})
            session.run("""
                UNWIND $rows AS row
                MATCH (c:CAPEC {capecId: row.id})
                MATCH (s:SubDomain {subDomainId: row.subId})
                MERGE (c)-[r:MAPS_TO_SUBDOMAIN]->(s)
                SET r.confidence = row.conf
            """, rows=capec_sub)

        # CWE -> SubDomain
        cwe_sub = []
        w_sub_path = AEGIS_DIR / "cwe_to_subdomains.csv"
        if w_sub_path.exists():
            with open(w_sub_path, mode="r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    cwe_sub.append({"id": row.get("cweId"), "subId": row.get("subDomainId"), "conf": float(row.get("confidence", 0.8))})
            session.run("""
                UNWIND $rows AS row
                MATCH (w:CWE {cweId: row.id})
                MATCH (s:SubDomain {subDomainId: row.subId})
                MERGE (w)-[r:MAPS_TO_SUBDOMAIN]->(s)
                SET r.confidence = row.conf
            """, rows=cwe_sub)

        # D3FEND -> SubDomain
        d3_sub = []
        d3_sub_path = AEGIS_DIR / "d3fend_to_subdomains.csv"
        if d3_sub_path.exists():
            with open(d3_sub_path, mode="r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    d3_sub.append({"id": row.get("d3fendId"), "subId": row.get("subDomainId"), "conf": float(row.get("confidence", 0.8))})
            session.run("""
                UNWIND $rows AS row
                MATCH (d:D3FEND {d3fendId: row.id})
                MATCH (s:SubDomain {subDomainId: row.subId})
                MERGE (d)-[r:MAPS_TO_SUBDOMAIN]->(s)
                SET r.confidence = row.conf
            """, rows=d3_sub)

        # ATTACK -> SubDomain
        att_sub = []
        if att_sub_path.exists():
            with open(att_sub_path, mode="r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    att_sub.append({"id": row.get("attackId"), "subId": row.get("subDomainId"), "conf": float(row.get("confidence", 0.8))})
            session.run("""
                UNWIND $rows AS row
                MATCH (a:ATTACK {attackId: row.id})
                MATCH (s:SubDomain {subDomainId: row.subId})
                MERGE (a)-[r:MAPS_TO_SUBDOMAIN]->(s)
                SET r.confidence = row.conf
            """, rows=att_sub)

        print("[6/6] Estatísticas Finais do Grafo de Ameaças:")
        labels = session.run("CALL db.labels() YIELD label CALL (label) { MATCH (n) WHERE label IN labels(n) RETURN count(n) AS cnt } RETURN label, cnt ORDER BY cnt DESC").data()
        for l in labels:
            print(f"      * {l['label']}: {l['cnt']}")

        rels = session.run("CALL db.relationshipTypes() YIELD relationshipType CALL (relationshipType) { MATCH ()-[r]->() WHERE type(r) = relationshipType RETURN count(r) AS cnt } RETURN relationshipType, cnt ORDER BY cnt DESC").data()
        print("\n--- Relações Principais ---")
        for r in rels:
            print(f"      * {r['relationshipType']}: {r['cnt']}")

    driver.close()


if __name__ == "__main__":
    enrich()
