"""Exports the decoupled federated cybersecurity ontologies into a unified canonical graph snapshot for React UI visualization."""

import json
import time
from pathlib import Path
import sys

# Ensure src is in python path
src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from frameworks.stores import FederatedStore


def export_canonical_graph() -> Path:
    t0 = time.time()
    store = FederatedStore.get_instance()
    out_file = Path(__file__).parent.parent / "data" / "canonical_graph_snapshot.json"

    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    # Framework color palette
    colors = {
        "CWE": "#8B5CF6",        # Purple
        "CAPEC": "#F97316",      # Orange
        "ATTACK": "#EF4444",     # Red
        "D3FEND": "#10B981",     # Emerald
        "ATLAS": "#E11D48",      # Pink
    }

    # 1. Collect all Nodes
    for s in (store.cwe, store.capec, store.attack, store.d3fend, store.atlas):
        fw = s.framework_name.replace("&", "")
        for eid, e in s.entities.items():
            if eid not in seen_nodes:
                seen_nodes.add(eid)
                nodes.append({
                    "id": eid,
                    "label": f"{eid}\n({fw})",
                    "title": f"<b>{eid} - {e.name}</b><br><br>{e.description[:350]}...",
                    "group": fw,
                    "color": colors.get(fw, "#64748B"),
                    "name": e.name,
                    "category": e.category,
                    "description": e.description,
                    "metadata": e.metadata
                })

    # 2. Collect Crosswalk Bridges (Inter-framework)
    for src_id, links in store.crosswalk.bridges.items():
        for l in links:
            if l.direction == "OUTGOING":
                edge_key = f"{l.source_id}->{l.target_id}"
                if edge_key not in seen_edges and l.source_id in seen_nodes and l.target_id in seen_nodes:
                    seen_edges.add(edge_key)
                    edges.append({
                        "id": edge_key,
                        "from": l.source_id,
                        "to": l.target_id,
                        "label": l.rel_type
                    })

    # 3. Collect Local Hierarchy Edges (Intra-framework)
    for s in (store.cwe, store.capec, store.attack, store.d3fend, store.atlas):
        for src_id, links in s.local_edges.items():
            for l in links:
                edge_key = f"{l.source_id}->{l.target_id}"
                if edge_key not in seen_edges and l.source_id in seen_nodes and l.target_id in seen_nodes:
                    seen_edges.add(edge_key)
                    edges.append({
                        "id": edge_key,
                        "from": l.source_id,
                        "to": l.target_id,
                        "label": l.rel_type
                    })

    payload = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generationTimeMs": round((time.time() - t0) * 1000, 2),
        "totalNodes": len(nodes),
        "totalEdges": len(edges),
        "nodes": nodes,
        "edges": edges
    }

    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"Exported Canonical Graph Snapshot to: {out_file}")
    print(f"  Nodes: {len(nodes)} | Edges: {len(edges)} | Time: {payload['generationTimeMs']} ms | Size: {out_file.stat().st_size / 1024 / 1024:.2f} MB")
    return out_file


if __name__ == "__main__":
    export_canonical_graph()
