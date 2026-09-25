"""
SupplyGraph Graph Schema
Defines the canonical node and edge types for the security graph.
Version: 1.0.0

Node Types (NodeType enum):
  Repository, Package, Version, Vulnerability, Commit,
  Maintainer, Service, Container, API, Deployment, Pipeline,
  Behaviour, RuntimeObservation, Finding, Asset

Edge Types (EdgeType enum):
  CONTAINS, DEPENDS_ON, VERSION_OF, MODIFIED_BY, RELEASED_BY,
  BUILT_BY, DEPLOYED_AS, USES, CALLS, TRIGGERS, EXHIBITS,
  AFFECTS, PROPAGATES_TO, OBSERVED_IN

Layout Algorithm:
  1. Build NetworkX DiGraph from dependency edges
  2. If acyclic: use topological generations for layer assignment
  3. If cyclic: use BFS from root nodes for layer assignment
  4. Assign x = layer * horizontal_spacing
  5. Assign y = sibling_index * vertical_spacing (centered)
  6. Positions are deterministic given same input

Graph Serialization Format:
  See models/core.py: SecurityGraph, GraphNode, GraphEdge

Security Boundaries:
  - Graph is built from parsed/static data only
  - No arbitrary code from repository is executed
  - Runtime observations are SIMULATED and labeled as such
  - Gemini cannot modify graph structure
"""

# Graph schema version
GRAPH_SCHEMA_VERSION = "v1.0"

# Default layout configuration
DEFAULT_HORIZONTAL_SPACING = 280.0
DEFAULT_VERTICAL_SPACING = 120.0

# Node color palette (used by frontend React Flow)
NODE_COLORS = {
    "Repository": "#6366f1",      # indigo
    "Package": "#3b82f6",         # blue
    "Version": "#0ea5e9",         # sky
    "Vulnerability": "#ef4444",   # red
    "Commit": "#8b5cf6",          # violet
    "Maintainer": "#ec4899",      # pink
    "Service": "#f97316",         # orange
    "Container": "#14b8a6",       # teal
    "API": "#f59e0b",             # amber
    "Deployment": "#dc2626",      # red-600
    "Pipeline": "#7c3aed",        # violet-600
    "Behaviour": "#6b7280",       # gray
    "RuntimeObservation": "#be185d",  # pink-700 (SIMULATED)
    "Finding": "#b91c1c",         # red-700
    "Asset": "#059669",           # emerald
}

# Edge color palette
EDGE_COLORS = {
    "DEPENDS_ON": "#64748b",      # slate
    "AFFECTS": "#ef4444",         # red
    "PROPAGATES_TO": "#dc2626",   # red-600 (attack path)
    "CONTAINS": "#94a3b8",        # slate-400
    "EXHIBITS": "#f97316",        # orange
    "VERSION_OF": "#3b82f6",      # blue
    "DEPLOYED_AS": "#8b5cf6",     # violet
    "BUILT_BY": "#6366f1",        # indigo
    "USES": "#0ea5e9",            # sky
    "CALLS": "#f59e0b",           # amber
    "TRIGGERS": "#ec4899",        # pink
    "MODIFIED_BY": "#7c3aed",     # violet-600
    "RELEASED_BY": "#14b8a6",     # teal
    "OBSERVED_IN": "#be185d",     # pink-700
}
