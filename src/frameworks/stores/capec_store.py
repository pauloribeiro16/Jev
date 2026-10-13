"""High-speed in-memory Domain Store for MITRE CAPEC (Common Attack Pattern Enumeration and Classification)."""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_store import BaseDomainStore, NodeEntity, EdgeLink


class CAPECStore(BaseDomainStore):
    """
    Parses and indexes the official MITRE CAPEC STIX 2.1 catalog (capec.json).
    Preserves all execution flows, prerequisites, and embedded CWE/ATT&CK cross-walks.
    """

    def __init__(self, json_path: Optional[Path] = None):
        if json_path is None:
            json_path = Path(__file__).parent.parent.parent.parent / "data" / "official" / "capec.json"
        self.json_path = Path(json_path)
        self.entities: Dict[str, NodeEntity] = {}              # CAPEC-ID -> NodeEntity
        self.stix_to_id: Dict[str, str] = {}                  # stix_id -> CAPEC-ID
        self.local_edges: Dict[str, List[EdgeLink]] = {}       # CAPEC-ID -> [EdgeLink, ...]
        self.cwe_bridges: Dict[str, List[str]] = {}           # CAPEC-ID -> [CWE-ID, ...]
        self.attack_bridges: Dict[str, List[str]] = {}        # CAPEC-ID -> [ATTACK-ID, ...]
        self._load()

    @property
    def framework_name(self) -> str:
        return "CAPEC"

    def _normalize_id(self, raw_id: str) -> str:
        clean = raw_id.strip()
        if not clean.upper().startswith("CAPEC-"):
            return f"CAPEC-{clean}"
        return clean.upper()

    def _load(self):
        if not self.json_path.exists():
            return

        with open(self.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = data.get("objects", [])

        # 1. Parse Attack Patterns
        for o in objects:
            if o.get("type") != "attack-pattern" or o.get("revoked", False):
                continue

            capec_id = None
            cwes = []
            attacks = []

            for ref in o.get("external_references", []):
                src = ref.get("source_name", "").lower()
                ext_id = ref.get("external_id", "")
                if src == "capec" and ext_id:
                    capec_id = self._normalize_id(ext_id)
                elif "cwe" in src and ext_id:
                    cwe_norm = ext_id if ext_id.upper().startswith("CWE-") else f"CWE-{ext_id}"
                    cwes.append(cwe_norm.upper())
                elif ("attack" in src or "mitre" in src) and ext_id:
                    att_norm = ext_id.strip().upper()
                    attacks.append(att_norm)

            if not capec_id:
                continue

            stix_id = o.get("id")
            if stix_id:
                self.stix_to_id[stix_id] = capec_id

            entity = NodeEntity(
                id=capec_id,
                framework="CAPEC",
                name=o.get("name", ""),
                description=o.get("description", ""),
                category=o.get("x_capec_likelihood_of_attack", "Medium"),
                metadata={
                    "stix_id": stix_id,
                    "severity": o.get("x_capec_typical_severity", "Medium"),
                    "prerequisites": o.get("x_capec_prerequisites", []),
                    "skills_required": o.get("x_capec_skills_required", []),
                    "execution_flow": o.get("x_capec_execution_flow", [])
                }
            )
            self.entities[capec_id] = entity
            self.local_edges[capec_id] = []
            self.cwe_bridges[capec_id] = list(set(cwes))
            self.attack_bridges[capec_id] = list(set(attacks))

        # 2. Parse STIX Relationships (hierarchies and progressions)
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

    def get_cwe_bridges(self, entity_id: str) -> List[str]:
        norm = self._normalize_id(entity_id)
        return self.cwe_bridges.get(norm, [])

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
