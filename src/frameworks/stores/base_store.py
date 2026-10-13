"""Base interfaces and unified data models for Decoupled Cybersecurity Domain Stores."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class NodeEntity:
    """Standardized representation of any cybersecurity entity across frameworks."""
    id: str                         # e.g., 'CWE-79', 'CAPEC-63', 'T1059', 'D3-MFA', 'AML.T0000'
    framework: str                  # 'CWE', 'CAPEC', 'ATT&CK', 'D3FEND', 'ATLAS'
    name: str                       # Official human-readable label/title
    description: str = ""           # Complete official description
    category: str = ""              # Tactic, abstraction level, tactic phase, etc.
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "framework": self.framework,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "metadata": self.metadata
        }


@dataclass
class EdgeLink:
    """Standardized representation of a relationship within or across frameworks."""
    source_id: str
    target_id: str
    rel_type: str                   # 'EXPLOITED_BY', 'LEADS_TO', 'MITIGATES', 'CHILD_OF', etc.
    direction: str = "OUTGOING"     # 'OUTGOING' or 'INCOMING'
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "rel_type": self.rel_type,
            "direction": self.direction,
            "weight": self.weight,
            "metadata": self.metadata
        }


class BaseDomainStore(ABC):
    """Abstract base class for high-speed, in-memory domain stores."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Name of the framework (e.g. 'CWE', 'CAPEC', 'ATT&CK', etc.)."""
        pass

    @abstractmethod
    def get_entity(self, entity_id: str) -> Optional[NodeEntity]:
        """Lookup an entity by canonical ID in O(1) time."""
        pass

    @abstractmethod
    def get_local_neighbors(self, entity_id: str) -> List[EdgeLink]:
        """Return intra-framework relationships (parent/child, prerequisites)."""
        pass

    @abstractmethod
    def search(self, query: str, limit: int = 10) -> List[NodeEntity]:
        """Full-text / token search across names and descriptions."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Total number of indexed entities."""
        pass
