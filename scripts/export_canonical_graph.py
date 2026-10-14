"""Exports the federated cybersecurity ontologies into the graph the web UI reads.

Writes web/public/graph.json (nodes + edges) and web/public/provenance.json
(which dataset revision those nodes came from), so the site is reproducible and
can state exactly what it is showing.
"""

import json
import re
import sys
import time
from pathlib import Path

src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from frameworks.stores import FederatedStore  # noqa: E402

ROOT = Path(__file__).parent.parent
PUBLIC_DIR = ROOT / "web" / "public"
MANIFEST = ROOT / "data" / "versions" / "manifest.jsonl"
OUT_FILE = PUBLIC_DIR / "graph.json"
PROV_FILE = PUBLIC_DIR / "provenance.json"

# Okabe-Ito: five hues that stay separable under deuteranopia and protanopia,
# which matters because colour is the only cue carrying framework identity.
COLORS = {
    "CWE": "#0072B2",
    "CAPEC": "#E69F00",
    "ATT&CK": "#D55E00",
    "D3FEND": "#009E73",
    "ATLAS": "#CC79A7",
}


def clean_text(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"<[^>]+>", "", text)).strip()


def dataset_revisions() -> list:
    """Latest manifest entry per source, so the UI can name the exact revision."""
    latest = {}
    if MANIFEST.exists():
        for line in MANIFEST.read_text(errors="ignore").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            latest[rec["key"]] = rec
    return [
        {
            "key": k,
            "filename": v["filename"],
            "sha256": v["sha256"],
            "bytes": v["bytes"],
            "fetchedAt": v["iso"],
            "url": v["url"],
        }
        for k, v in latest.items()
    ]


def export_canonical_graph() -> Path:
    t0 = time.time()
    store = FederatedStore.get_instance()
    stores = [store.cwe, store.capec, store.attack, store.d3fend, store.atlas]

    nodes, edges = [], []
    seen_nodes, seen_edges = set(), set()
    counts = {}

    for s in stores:
        fw = s.framework_name  # keep "ATT&CK" intact; the site renders it verbatim
        counts[fw] = counts.get(fw, 0) + len(s.entities)
        for eid, e in s.entities.items():
            if eid in seen_nodes:
                continue
            seen_nodes.add(eid)
            desc = clean_text(e.description)
            nodes.append({
                "id": eid,
                "name": e.name,
                "group": fw,
                "color": COLORS.get(fw, "#64748B"),
                "category": e.category,
                "description": desc,
                "metadata": e.metadata,
            })

    def add_edges(links_map):
        for src_id, links in links_map.items():
            for l in links:
                if l.direction != "OUTGOING":
                    continue
                key = f"{l.source_id}->{l.target_id}"
                if key in seen_edges or l.source_id not in seen_nodes or l.target_id not in seen_nodes:
                    continue
                seen_edges.add(key)
                edges.append({"id": key, "from": l.source_id, "to": l.target_id, "label": l.rel_type})

    add_edges(store.crosswalk.bridges)
    for s in stores:
        add_edges(s.local_edges)

    payload = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generationTimeMs": round((time.time() - t0) * 1000, 2),
        "totalNodes": len(nodes),
        "totalEdges": len(edges),
        "frameworks": counts,
        "nodes": nodes,
        "edges": edges,
    }

    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))

    with PROV_FILE.open("w", encoding="utf-8") as f:
        json.dump({
            "generatedAt": payload["generatedAt"],
            "generationTimeMs": payload["generationTimeMs"],
            "totalNodes": len(nodes),
            "totalEdges": len(edges),
            "frameworks": counts,
            "datasets": dataset_revisions(),
        }, f, ensure_ascii=False, indent=2)

    print(f"Exported graph      -> {OUT_FILE}  ({OUT_FILE.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"Exported provenance -> {PROV_FILE}")
    print(f"  Nodes: {len(nodes)} | Edges: {len(edges)} | {payload['generationTimeMs']} ms")
    for fw, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {fw:8s} {n:5d}")
    return OUT_FILE


if __name__ == "__main__":
    import argparse
    import shutil

    ap = argparse.ArgumentParser(description="Export the federated graph for the web UI.")
    ap.add_argument("--with-traces", action="store_true",
                    help="also copy data/jev_traces.jsonl into web/public for the trace panel")
    args = ap.parse_args()

    export_canonical_graph()

    if args.with_traces:
        src = ROOT / "data" / "jev_traces.jsonl"
        if src.exists():
            shutil.copy2(src, PUBLIC_DIR / "jev_traces.jsonl")
            n = sum(1 for _ in src.open(encoding="utf-8", errors="ignore"))
            print(f"Copied traces     -> {PUBLIC_DIR / 'jev_traces.jsonl'}  ({n} calls)")
        else:
            print("No traces yet — run a Jev script first (e.g. scripts/test_modular_traversal.py).")