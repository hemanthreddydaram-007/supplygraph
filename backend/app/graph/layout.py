"""
SupplyGraph Server-Side Graph Layout Engine v2.0

Upgrades from v1.0:
- X_SPACING increased to 380px (was 280px)
- Y_SPACING increased to 125px (was 120px) 
- Threat-priority node sorting: vulnerable/suspicious nodes are positioned
  at the TOP/CENTER of their layer, safe nodes below them
- Accepts optional set of threat_node_ids for priority sorting

Algorithm:
    1. Attempt topological sort (DAG path)
    2. If graph is cyclic, fall back to BFS layering
    3. Assign layers (depth levels)
    4. Within each layer, sort by threat priority THEN alphabetically
    5. Center each layer vertically
    6. Compute (x, y) = (layer * h_spacing, sibling_offset * v_spacing)
"""

from __future__ import annotations
from typing import Dict, Any, Set, Optional
import networkx as nx


def compute_layout(
    graph: nx.DiGraph,
    h_spacing: float = 380.0,
    v_spacing: float = 125.0,
    threat_node_ids: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, float]]:
    """
    Compute server-side node positions for a security graph.

    Args:
        graph: NetworkX directed graph.
        h_spacing: Horizontal spacing between layers (pixels). Default 380.
        v_spacing: Vertical spacing between siblings in same layer (pixels). Default 125.
        threat_node_ids: Set of node IDs that are vulnerable/suspicious.
                         These are sorted to the top of their layer.

    Returns:
        Dictionary mapping node_id -> {"x": float, "y": float}
    """
    positions: Dict[str, Dict[str, float]] = {}
    threat_ids: Set[str] = threat_node_ids or set()

    if graph.number_of_nodes() == 0:
        return positions

    is_dag = nx.is_directed_acyclic_graph(graph)

    if is_dag:
        layers = list(nx.topological_generations(graph))
    else:
        layers = _bfs_layering(graph)

    for layer_index, layer_nodes in enumerate(layers):
        node_strs = [str(n) for n in layer_nodes]
        # Sort: threat nodes first (alphabetically among themselves),
        # then safe nodes alphabetically below
        threat_in_layer = sorted([n for n in node_strs if n in threat_ids])
        safe_in_layer = sorted([n for n in node_strs if n not in threat_ids])
        sorted_nodes = threat_in_layer + safe_in_layer

        layer_size = len(sorted_nodes)
        total_height = (layer_size - 1) * v_spacing
        start_y = -total_height / 2.0

        for sibling_index, node_id in enumerate(sorted_nodes):
            x = layer_index * h_spacing
            y = start_y + sibling_index * v_spacing
            positions[node_id] = {"x": round(x, 2), "y": round(y, 2)}

    return positions


def _bfs_layering(graph: nx.DiGraph) -> list[set[Any]]:
    """BFS-based layer assignment for cyclic graphs. Cycle-safe."""
    roots = sorted([n for n in graph.nodes() if graph.in_degree(n) == 0], key=str)
    if not roots:
        roots = [sorted(list(graph.nodes()), key=str)[0]]

    layer_map: Dict[Any, int] = {}
    from collections import deque
    queue: deque = deque()
    for root in roots:
        if root not in layer_map:
            layer_map[root] = 0
            queue.append(root)

    while queue:
        node = queue.popleft()
        current_layer = layer_map[node]
        for successor in sorted(graph.successors(node), key=str):
            if successor not in layer_map:
                layer_map[successor] = current_layer + 1
                queue.append(successor)

    for node in graph.nodes():
        if node not in layer_map:
            layer_map[node] = 0

    max_layer = max(layer_map.values()) if layer_map else 0
    layers: list[set[Any]] = [set() for _ in range(max_layer + 1)]
    for node, layer in layer_map.items():
        layers[layer].add(node)

    return layers


def detect_cycles(graph: nx.DiGraph) -> bool:
    """Return True if the graph contains cycles."""
    return not nx.is_directed_acyclic_graph(graph)


def get_graph_statistics(graph: nx.DiGraph) -> Dict[str, Any]:
    """Return key graph statistics for the API response."""
    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "has_cycles": detect_cycles(graph),
        "is_connected": nx.is_weakly_connected(graph) if graph.number_of_nodes() > 0 else True,
        "average_depth": _average_depth(graph),
    }


def _average_depth(graph: nx.DiGraph) -> float:
    """Compute average node depth from root nodes."""
    if graph.number_of_nodes() == 0:
        return 0.0
    roots = [n for n in graph.nodes() if graph.in_degree(n) == 0]
    if not roots:
        return 0.0
    depths = []
    for root in roots:
        for node in nx.descendants(graph, root):
            try:
                path_lengths = nx.single_source_shortest_path_length(graph, root)
                if node in path_lengths:
                    depths.append(path_lengths[node])
            except Exception:
                pass
    return round(sum(depths) / len(depths), 2) if depths else 0.0
