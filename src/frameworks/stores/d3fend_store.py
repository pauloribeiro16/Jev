"""High-speed in-memory Domain Store for MITRE D3FEND (Defensive Countermeasures)."""

import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_store import BaseDomainStore, NodeEntity, EdgeLink


class D3FENDStore(BaseDomainStore):
    """
    Parses and indexes the official MITRE D3FEND ontology and full mappings.
    Provides sub-millisecond lookup of defensive techniques and bidirectional bridges to ATT&CK.
    """

    def __init__(self, json_path: Optional[Path] = None, csv_path: Optional[Path] = None):
        base_dir = Path(__file__).parent.parent.parent.parent / "data" / "official"
        if json_path is None:
            json_path = base_dir / "d3fend.json"
        if csv_path is None:
            csv_path = base_dir / "d3fend-full-mappings.csv"
        self.json_path = Path(json_path)
        self.csv_path = Path(csv_path)

        self.entities: Dict[str, NodeEntity] = {}              # D3-MFA -> NodeEntity
        self.name_to_id: Dict[str, str] = {}                  # "Multi-factor Authentication" -> D3-MFA
        self.local_edges: Dict[str, List[EdgeLink]] = {}       # D3-MFA -> [EdgeLink, ...]
        self.attack_bridges: Dict[str, List[str]] = {}        # D3-MFA -> [T1059, ...]
        self.attack_to_d3fend: Dict[str, List[str]] = {}      # T1059 -> [D3-MFA, ...]
        self._load()

    @property
    def framework_name(self) -> str:
        return "D3FEND"

    def _normalize_id(self, raw_id: str) -> str:
        clean = raw_id.strip().upper()
        return clean

    def _load(self):
        # 1. Parse JSON for definitions
        if self.json_path.exists():
            with open(self.json_path, "r", encoding="utf-8") as f:
                d3_data = json.load(f)

            for item in d3_data.get("@graph", []):
                did = item.get("d3f:d3fend-id")
                if not did:
                    continue
                norm_id = self._normalize_id(did)
                name = item.get("rdfs:label", "")
                desc = item.get("d3f:definition", "")

                entity = NodeEntity(
                    id=norm_id,
                    framework="D3FEND",
                    name=name,
                    description=desc,
                    category="Defensive Technique",
                    metadata={"uri": item.get("@id", "")}
                )
                self.entities[norm_id] = entity
                self.local_edges[norm_id] = []
                self.attack_bridges[norm_id] = []
                if name:
                    self.name_to_id[name.lower().strip()] = norm_id

        # 2. Parse CSV for ATT&CK bridges
        if self.csv_path.exists():
            with open(self.csv_path, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    def_label = row.get("def_tech_label", "").strip()
                    off_tech_uri = row.get("off_tech", "")
                    off_tech_id = off_tech_uri.split("#")[-1] if "#" in off_tech_uri else off_tech_uri
                    off_tech_id = off_tech_id.strip().upper()

                    did = self.name_to_id.get(def_label.lower())
                    if did and off_tech_id:
                        if off_tech_id not in self.attack_bridges[did]:
                            self.attack_bridges[did].append(off_tech_id)
                        self.attack_to_d3fend.setdefault(off_tech_id, []).append(did)

    def get_entity(self, entity_id: str) -> Optional[NodeEntity]:
        norm = self._normalize_id(entity_id)
        return self.entities.get(norm)

    def get_local_neighbors(self, entity_id: str) -> List[EdgeLink]:
        norm = self._normalize_id(entity_id)
        return self.local_edges.get(norm, [])

    def get_attack_bridges(self, entity_id: str) -> List[str]:
        norm = self._normalize_id(entity_id)
        return self.attack_bridges.get(norm, [])

    def get_mitigations_for_attack(self, attack_id: str) -> List[str]:
        norm = attack_id.strip().upper()
        return list(set(self.attack_to_d3fend.get(norm, [])))

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
