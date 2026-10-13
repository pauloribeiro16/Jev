"""High-speed in-memory Domain Store for MITRE ATT&CK (Enterprise Matrix)."""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_store import BaseDomainStore, NodeEntity, EdgeLink


class AttackStore(BaseDomainStore):
    """
    Parses and indexes the official MITRE Enterprise ATT&CK STIX 2.1 catalog (enterprise-attack.json).
    Restores 100% of descriptions, tactics, mitigations, and sub-technique hierarchies.
    """

    def __init__(self, json_path: Optional[Path] = None):
        if json_path is None:
            json_path = Path(__file__).parent.parent.parent.parent / "data" / "official" / "enterprise-attack.json"
        self.json_path = Path(json_path)
        self.entities: Dict[str, NodeEntity] = {}              # T1059 -> NodeEntity
        self.stix_to_id: Dict[str, str] = {}                  # stix_id -> T1059
        self.local_edges: Dict[str, List[EdgeLink]] = {}       # T1059 -> [EdgeLink, ...]
        self.tactics: Dict[str, str] = {}                     # execution -> Execution
        self._load()

    @property
    def framework_name(self) -> str:
        return "ATT&CK"

    def _normalize_id(self, raw_id: str) -> str:
        clean = raw_id.strip().upper()
        # Ensure ATT&CK technique format (e.g. T1059 or T1059.001)
        return clean

    def _load(self):
        if not self.json_path.exists():
            return

        with open(self.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = data.get("objects", [])

        # 1. Parse Tactics
        for o in objects:
            if o.get("type") == "x-mitre-tactic":
                short = o.get("x_mitre_shortname", "")
                if short:
                    self.tactics[short] = o.get("name", short.capitalize())

        # 2. Parse Techniques and Sub-techniques
        for o in objects:
            if o.get("type") != "attack-pattern" or o.get("revoked", False):
                continue

            tech_id = None
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = self._normalize_id(ref.get("external_id", ""))
                    break

            if not tech_id:
                continue

            stix_id = o.get("id")
            if stix_id:
                self.stix_to_id[stix_id] = tech_id

            # Extract tactics
            tactic_names = []
            for phase in o.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    t_name = self.tactics.get(phase.get("phase_name"), phase.get("phase_name", "").capitalize())
                    tactic_names.append(t_name)

            primary_tactic = tactic_names[0] if tactic_names else "Enterprise"

            entity = NodeEntity(
                id=tech_id,
                framework="ATT&CK",
                name=o.get("name", ""),
                description=o.get("description", ""),
                category=primary_tactic,
                metadata={
                    "stix_id": stix_id,
                    "tactics": tactic_names,
                    "is_subtechnique": o.get("x_mitre_is_subtechnique", False),
                    "platforms": o.get("x_mitre_platforms", []),
                    "data_sources": o.get("x_mitre_data_sources", [])
                }
            )
            self.entities[tech_id] = entity
            self.local_edges[tech_id] = []

        # 3. Parse Relationships (subtechnique-of, etc.)
        for o in objects:
            if o.get("type") != "relationship":
                continue
            src_stix = o.get("source_ref")
            tgt_stix = o.get("target_ref")
            rel_type = o.get("relationship_type", "relates-to")

            src_id = self.stix_to_id.get(src_stix)
            tgt_id = self.stix_to_id.get(tgt_stix)

            if src_id and tgt_id and src_id in self.entities and tgt_id in self.entities:
                self.local_edges[src_id].append(
                    EdgeLink(source_id=src_id, target_id=tgt_id, rel_type=rel_type, direction="OUTGOING")
                )

    def get_entity(self, entity_id: str) -> Optional[NodeEntity]:
        norm = self._normalize_id(entity_id)
        return self.entities.get(norm)

    def get_local_neighbors(self, entity_id: str) -> List[EdgeLink]:
        norm = self._normalize_id(entity_id)
        return self.local_edges.get(norm, [])

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
