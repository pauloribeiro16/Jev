"""High-speed in-memory Domain Store for MITRE ATLAS (Adversarial Threat Landscape for AI Systems)."""

import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_store import BaseDomainStore, NodeEntity, EdgeLink


class ATLASStore(BaseDomainStore):
    """
    Parses and indexes the official MITRE ATLAS v6 YAML matrix (atlas.yaml).
    Covers machine learning threat vectors, AI security tactics, and direct cross-walks to ATT&CK.
    """

    def __init__(self, yaml_path: Optional[Path] = None):
        if yaml_path is None:
            yaml_path = Path(__file__).parent.parent.parent.parent / "data" / "official" / "atlas.yaml"
        self.yaml_path = Path(yaml_path)

        self.entities: Dict[str, NodeEntity] = {}              # AML.T0000 -> NodeEntity
        self.local_edges: Dict[str, List[EdgeLink]] = {}       # AML.T0000 -> [EdgeLink, ...]
        self.attack_bridges: Dict[str, List[str]] = {}        # AML.T0000 -> [T1596, ...]
        self._load()

    @property
    def framework_name(self) -> str:
        return "ATLAS"

    def _normalize_id(self, raw_id: str) -> str:
        clean = raw_id.strip().upper()
        return clean

    def _load(self):
        if not self.yaml_path.exists():
            return

        with open(self.yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        techs = data.get("techniques", {})
        if isinstance(techs, dict):
            tech_items = techs.values()
        elif isinstance(techs, list):
            tech_items = techs
        else:
            tech_items = []

        for t in tech_items:
            tid = t.get("id")
            if not tid:
                continue
            norm_id = self._normalize_id(tid)

            att_ref = t.get("attack-reference", {})
            att_id = att_ref.get("id", "").strip().upper() if isinstance(att_ref, dict) else ""

            tactics = t.get("tactics", [])
            primary_tactic = tactics[0] if tactics else "AI Security"

            entity = NodeEntity(
                id=norm_id,
                framework="ATLAS",
                name=t.get("name", f"ATLAS Technique {norm_id}"),
                description=t.get("description", ""),
                category=primary_tactic,
                metadata={
                    "maturity": t.get("maturity", ""),
                    "platforms": t.get("platforms", []),
                    "attack_id": att_id
                }
            )
            self.entities[norm_id] = entity
            self.local_edges[norm_id] = []
            self.attack_bridges[norm_id] = [att_id] if att_id else []

        # Parse relationships
        rels = data.get("relationships", [])
        if isinstance(rels, list):
            for r in rels:
                src = self._normalize_id(r.get("source", ""))
                tgt = self._normalize_id(r.get("target", ""))
                rtype = r.get("type", "relates-to")
                if src in self.entities and tgt in self.entities:
                    self.local_edges[src].append(
                        EdgeLink(source_id=src, target_id=tgt, rel_type=rtype, direction="OUTGOING")
                    )

    def get_entity(self, entity_id: str) -> Optional[NodeEntity]:
        norm = self._normalize_id(entity_id)
        return self.entities.get(norm)

    def get_local_neighbors(self, entity_id: str) -> List[EdgeLink]:
        norm = self._normalize_id(entity_id)
        return self.local_edges.get(norm, [])

    def get_attack_bridges(self, entity_id: str) -> List[str]:
        norm = self._normalize_id(entity_id)
        return self.attack_bridges.get(norm, [])

    def search(self, query: str, limit: int = 10) -> List[NodeEntity]:
        q = query.lower().strip()
        matches = []
        for e in self.entities.values():
            if q in e.id.lower() or q in e.name.lower() or q in e.description.lower():
                matches.append(e)
                if len(matches) >= limit:
                    break
        return matches

    def count(self) -> int:
        return len(self.entities)
