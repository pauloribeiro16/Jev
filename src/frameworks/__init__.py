"""Frameworks package: Modular cybersecurity graph navigation with Jev."""

from .templates import (
    TEMPLATES,
    TEMPLATES_CATALOG,
    FrameworkTemplate,
    CAPECTemplate,
    CWETemplate,
    AttackTemplate,
    AtlasTemplate,
    D3FENDTemplate,
    describe,
    entity_line,
)
from .meta_router import MetaRouter
from .scoped_explorer import ScopedExplorer
from .orchestrator import ModularOrchestrator
from .stores import FederatedStore, GraphExporter

# ICS_ATTACK and MOBILE_ATTACK are ATT&CK matrices, so they share AttackTemplate;
# the distinct subclasses that used to live here added nothing but a key mismatch.
__all__ = [
    "TEMPLATES",
    "TEMPLATES_CATALOG",
    "FrameworkTemplate",
    "CAPECTemplate",
    "CWETemplate",
    "AttackTemplate",
    "AtlasTemplate",
    "D3FENDTemplate",
    "describe",
    "entity_line",
    "MetaRouter",
    "ScopedExplorer",
    "ModularOrchestrator",
    "FederatedStore",
    "GraphExporter",
]