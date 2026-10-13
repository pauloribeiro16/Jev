"""Graph Exporter & Visual Projector: Transforms decoupled traversal paths and subgraphs into visual graph formats."""

import json
from typing import Dict, Any, List, Set, Optional
import networkx as nx
from .base_store import NodeEntity, EdgeLink
from .federated_store import FederatedStore


class GraphExporter:
    """
    Projects decoupled cybersecurity entities and cross-framework walks into
    standard graph representations:
    - NetworkX (in-memory graph analysis)
    - Cytoscape / React Flow JSON (for modern UI graph visualization)
    - Graphviz DOT (for publications and SVG diagrams)
    - Cypher statements (for on-demand Neo4j import/export)
    """

    def __init__(self, federated_store: Optional[FederatedStore] = None):
        self.store = federated_store or FederatedStore.get_instance()

    def build_subgraph(self, node_ids: List[str], include_neighbors: bool = False) -> nx.DiGraph:
        """Constructs a NetworkX DiGraph for the specified node IDs."""
        G = nx.DiGraph()
        target_ids = set(n.strip().upper() for n in node_ids)

        if include_neighbors:
            expanded = set(target_ids)
            for nid in target_ids:
                nbrs = self.store.get_scoped_neighbors(nid, target_framework="ALL", max_limit=10)
                for n in nbrs:
                    expanded.add(n["neighbor_id"])
            target_ids = expanded

        # Add nodes
        for nid in target_ids:
            entity = self.store.get_entity(nid)
            if entity:
                G.add_node(
                    entity.id,
                    label=entity.name,
                    framework=entity.framework,
                    category=entity.category,
                    description=entity.description[:200]
                )

        # Add edges between present nodes
        for nid in target_ids:
            nbrs = self.store.get_scoped_neighbors(nid, target_framework="ALL", max_limit=20)
            for n in nbrs:
                tgt_id = n["neighbor_id"]
                if tgt_id in target_ids:
                    G.add_edge(nid, tgt_id, rel_type=n["rel_type"], direction=n["direction"])

        return G

    def to_cytoscape_json(self, node_ids: List[str], include_neighbors: bool = False) -> List[Dict[str, Any]]:
        """Exports graph elements formatted for Cytoscape.js visual canvas."""
        G = self.build_subgraph(node_ids, include_neighbors)
        elements = []

        # Color palette by framework
        colors = {
            "CWE": "#a855f7",     # Purple
            "CAPEC": "#f97316",   # Orange
            "ATT&CK": "#3b82f6",  # Blue
            "D3FEND": "#10b981",  # Emerald Green
            "ATLAS": "#ec4899"    # Pink
        }

        for node_id, data in G.nodes(data=True):
            fw = data.get("framework", "CWE")
            elements.append({
                "data": {
                    "id": node_id,
                    "label": f"{node_id}\n{data.get('label', '')[:30]}",
                    "framework": fw,
                    "color": colors.get(fw, "#64748b"),
                    "category": data.get("category", "")
                }
            })

        for u, v, data in G.edges(data=True):
            elements.append({
                "data": {
                    "id": f"{u}->{v}",
                    "source": u,
                    "target": v,
                    "label": data.get("rel_type", "RELATES_TO")
                }
            })

        return elements

    def to_cypher(self, node_ids: List[str], include_neighbors: bool = False) -> str:
        """Generates clean Cypher statements to reproduce the subgraph in Neo4j on-demand."""
        G = self.build_subgraph(node_ids, include_neighbors)
        lines = ["// Generated Subgraph from Jev Decoupled Federated Store"]

        for node_id, data in G.nodes(data=True):
            fw = data.get("framework", "Node").replace("&", "").replace("'", "")
            name = data.get("label", "").replace("'", "\\'")
            lines.append(f"MERGE (n:{fw} {{id: '{node_id}'}}) SET n.name = '{name}';")

        for u, v, data in G.edges(data=True):
            rel = data.get("rel_type", "RELATES_TO")
            lines.append(f"MATCH (a {{id: '{u}'}}), (b {{id: '{v}'}}) MERGE (a)-[:{rel}]->(b);")

        return "\n".join(lines)
