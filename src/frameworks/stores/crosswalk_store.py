"""Canonical Crosswalk Store linking decoupled frameworks without monolithic graph pollution."""

from typing import Dict, List, Set, Optional
from .base_store import EdgeLink
from .cwe_store import CWEStore
from .capec_store import CAPECStore
from .attack_store import AttackStore
from .d3fend_store import D3FENDStore
from .atlas_store import ATLASStore


class CrosswalkStore:
    """
    Manages official bidirectional bridges between autonomous domain stores:
    - CWE <-> CAPEC (EXPLOITED_BY / EXPLOITS)
    - CAPEC <-> ATT&CK (LEADS_TO / EVOLVES_FROM)
    - ATT&CK <-> D3FEND (MITIGATED_BY / MITIGATES)
    - ATT&CK <-> ATLAS (MAPPED_TO)
    """

    def __init__(
        self,
        cwe_store: CWEStore,
        capec_store: CAPECStore,
        attack_store: AttackStore,
        d3fend_store: D3FENDStore,
        atlas_store: ATLASStore
    ):
        self.cwe = cwe_store
        self.capec = capec_store
        self.attack = attack_store
        self.d3fend = d3fend_store
        self.atlas = atlas_store

        # Forward & backward index of cross-framework links
        # node_id -> [EdgeLink, ...]
        self.bridges: Dict[str, List[EdgeLink]] = {}
        self._build_crosswalks()

    def _add_bridge(self, src: str, tgt: str, rel: str, weight: float = 1.0):
        src_norm = src.strip().upper()
        tgt_norm = tgt.strip().upper()

        # Outgoing link from src to tgt
        self.bridges.setdefault(src_norm, []).append(
            EdgeLink(source_id=src_norm, target_id=tgt_norm, rel_type=rel, direction="OUTGOING", weight=weight)
        )
        # Reverse incoming link
        self.bridges.setdefault(tgt_norm, []).append(
            EdgeLink(source_id=tgt_norm, target_id=src_norm, rel_type=f"{rel}_REV", direction="INCOMING", weight=weight)
        )

    def _build_crosswalks(self):
        # 1. CWE <-> CAPEC bridges (from CWEStore & CAPECStore)
        for cid, entity in self.cwe.entities.items():
            for cap_id in self.cwe.get_capec_bridges(cid):
                if cap_id in self.capec.entities:
                    self._add_bridge(cid, cap_id, "EXPLOITED_BY")

        for cap_id, entity in self.capec.entities.items():
            for cwe_id in self.capec.get_cwe_bridges(cap_id):
                if cwe_id in self.cwe.entities:
                    self._add_bridge(cwe_id, cap_id, "EXPLOITED_BY")

        # 2. CAPEC <-> ATT&CK bridges (from CAPECStore)
        for cap_id, entity in self.capec.entities.items():
            for att_id in self.capec.get_attack_bridges(cap_id):
                if att_id in self.attack.entities:
                    self._add_bridge(cap_id, att_id, "LEADS_TO")

        # 3. ATT&CK <-> D3FEND bridges (from D3FENDStore)
        for did, entity in self.d3fend.entities.items():
            for att_id in self.d3fend.get_attack_bridges(did):
                if att_id in self.attack.entities:
                    self._add_bridge(att_id, did, "DEFENDED_BY")

        # 4. ATT&CK <-> ATLAS bridges (from ATLASStore)
        for aml_id, entity in self.atlas.entities.items():
            for att_id in self.atlas.get_attack_bridges(aml_id):
                if att_id in self.attack.entities:
                    self._add_bridge(aml_id, att_id, "MAPS_TO_ATTACK")

    def get_crosswalk_links(self, entity_id: str, target_framework: Optional[str] = None) -> List[EdgeLink]:
        norm = entity_id.strip().upper()
        links = self.bridges.get(norm, [])
        if target_framework and target_framework != "ALL":
            filtered = []
            for l in links:
                tgt = l.target_id
                if target_framework == "CWE" and tgt.startswith("CWE-"):
                    filtered.append(l)
                elif target_framework == "CAPEC" and tgt.startswith("CAPEC-"):
                    filtered.append(l)
                elif target_framework in ("ATTACK", "ATT&CK") and (tgt.startswith("T") or tgt.startswith("TA")):
                    filtered.append(l)
                elif target_framework == "D3FEND" and (tgt.startswith("D3-") or tgt.startswith("D3A-")):
                    filtered.append(l)
                elif target_framework == "ATLAS" and tgt.startswith("AML."):
                    filtered.append(l)
            return filtered
        return links
