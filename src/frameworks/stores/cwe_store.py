"""High-speed in-memory Domain Store for MITRE CWE (Common Weakness Enumeration)."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base_store import BaseDomainStore, NodeEntity, EdgeLink


class CWEStore(BaseDomainStore):
    """
    Parses and indexes the official MITRE CWE XML catalog (cwec.xml).
    Provides O(1) lookups and sub-millisecond local hierarchy traversal.
    """

    def __init__(self, xml_path: Optional[Path] = None):
        if xml_path is None:
            xml_path = Path(__file__).parent.parent.parent.parent / "data" / "official" / "cwec.xml"
        self.xml_path = Path(xml_path)
        self.entities: Dict[str, NodeEntity] = {}
        self.local_edges: Dict[str, List[EdgeLink]] = {}
        self.capec_bridges: Dict[str, List[str]] = {}  # CWE-ID -> [CAPEC-ID, ...]
        self._load()

    @property
    def framework_name(self) -> str:
        return "CWE"

    def _normalize_id(self, raw_id: str) -> str:
        clean = raw_id.strip()
        if not clean.upper().startswith("CWE-"):
            return f"CWE-{clean}"
        return clean.upper()

    def _load(self):
        if not self.xml_path.exists():
            return

        tree = ET.parse(self.xml_path)
        root = tree.getroot()
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

        # Parse Weaknesses
        for w in root.findall(".//cwe:Weakness", ns):
            raw_id = w.get("ID", "")
            if not raw_id:
                continue
            cid = self._normalize_id(raw_id)
            name = w.get("Name", "")
            abstraction = w.get("Abstraction", "Base")

            desc_el = w.find("cwe:Description", ns)
            desc = desc_el.text.strip() if (desc_el is not None and desc_el.text) else ""

            ext_desc_el = w.find("cwe:Extended_Description", ns)
            if ext_desc_el is not None and ext_desc_el.text:
                desc = f"{desc}\n\n{ext_desc_el.text.strip()}".strip()

            entity = NodeEntity(
                id=cid,
                framework="CWE",
                name=name,
                description=desc,
                category=abstraction,
                metadata={"status": w.get("Status", "Draft"), "structure": w.get("Structure", "")}
            )
            self.entities[cid] = entity
            self.local_edges[cid] = []
            self.capec_bridges[cid] = []

            # Related Weaknesses (hierarchical parent/child)
            for rw in w.findall(".//cwe:Related_Weakness", ns):
                target_raw = rw.get("CWE_ID", "")
                nature = rw.get("Nature", "ChildOf")
                if target_raw:
                    target_id = self._normalize_id(target_raw)
                    self.local_edges[cid].append(
                        EdgeLink(source_id=cid, target_id=target_id, rel_type=nature, direction="OUTGOING")
                    )

            # Related Attack Patterns (bridges to CAPEC)
            for rap in w.findall(".//cwe:Related_Attack_Pattern", ns):
                cap_raw = rap.get("CAPEC_ID", "")
                if cap_raw:
                    cap_id = f"CAPEC-{cap_raw.strip()}" if not cap_raw.strip().upper().startswith("CAPEC-") else cap_raw.strip().upper()
                    self.capec_bridges[cid].append(cap_id)

    def get_entity(self, entity_id: str) -> Optional[NodeEntity]:
        norm = self._normalize_id(entity_id)
        return self.entities.get(norm)

    def get_local_neighbors(self, entity_id: str) -> List[EdgeLink]:
        norm = self._normalize_id(entity_id)
        return self.local_edges.get(norm, [])

    def get_capec_bridges(self, entity_id: str) -> List[str]:
        norm = self._normalize_id(entity_id)
        return self.capec_bridges.get(norm, [])

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
