"""
SupplyGraph Server-Side Graph Layout Engine
Version: 1.0.0

Purpose:
    Compute deterministic (x, y) positions for all graph nodes
    before sending the graph payload to the frontend.
    The frontend renders the positions supplied here without
    recalculating layout.

Algorithm:
    1. Attempt topological sort (DAG path)
    2. If graph is cyclic, fall back to BFS layering
    3. Assign layers (depth levels)
    4. Within each layer, order siblings deterministically
    5. Center each layer vertically
    6. Compute (x, y) = (layer * h_spacing, sibling_offset * v_spacing)

Inputs:
    graph: networkx.DiGraph
    h_spacing: float (horizontal spacing in pixels, default 280)
    v_spacing: float (vertical spacing in pixels, default 120)

Outputs:
    positions: Dict[str, Dict[str, float]]
    {"node_id": {"x": float, "y": float}, ...}

Security:
    - Pure computation on the graph structure
    - No external calls
    - No untrusted code execution
    - Deterministic given same input

Implementation Note:
    Full implementation in Milestone 2A.
    This stub defines the interface and algorithm contract.
"""

from __future__ import annotations
from typing import Dict, Any
import networkx as nx


def compute_layout(
    graph: nx.DiGraph,
    h_spacing: float = 280.0,
    v_spacing: float = 120.0,
) -> Dict[str, Dict[str, float]]:
    """
    Compute server-side node positions for a security graph.

    Args:
        graph: NetworkX directed graph. Nodes can be any hashable type.
        h_spacing: Horizontal spacing between layers (pixels).
        v_spacing: Vertical spacing between siblings in same layer (pixels).

    Returns:
        Dictionary mapping node_id -> {"x": float, "y": float}

    Notes:
        - For acyclic graphs: uses topological generations (BFS layers)
        - For cyclic graphs: uses BFS from root nodes with cycle-safe fallback
        - Siblings within a layer are sorted deterministically (alphabetically)
        - All positions are >= 0
    """
    positions: Dict[str, Dict[str, float]] = {}

    if graph.number_of_nodes() == 0:
        return positions

    # Determine if graph is a DAG
    is_dag = nx.is_directed_acyclic_graph(graph)

    if is_dag:
        # Use topological generations for clean layering
        layers = list(nx.topological_generations(graph))
    else:
        # Fall back to BFS layering from nodes with no predecessors
        layers = _bfs_layering(graph)

    # Assign positions layer by layer
    for layer_index, layer_nodes in enumerate(layers):
        sorted_nodes = sorted(str(n) for n in layer_nodes)
        layer_size = len(sorted_nodes)
        # Center the layer vertically
        total_height = (layer_size - 1) * v_spacing
        start_y = -total_height / 2.0

        for sibling_index, node_id in enumerate(sorted_nodes):
            x = layer_index * h_spacing
            y = start_y + sibling_index * v_spacing
            positions[node_id] = {"x": round(x, 2), "y": round(y, 2)}

    return positions


def _bfs_layering(graph: nx.DiGraph) -> list[set[Any]]:
    """
    BFS-based layer assignment for cyclic graphs.
    Assigns each node to the deepest layer reachable from root nodes.
    Cycle-safe: visited set prevents infinite loops.
    """
    # Root nodes: those with no predecessors
    roots = [n for n in graph.nodes() if graph.in_degree(n) == 0]
    if not roots:
        # All nodes have predecessors — pick arbitrary start
        roots = [next(iter(graph.nodes()))]

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
        for successor in graph.successors(node):
            new_layer = current_layer + 1
            if successor not in layer_map or layer_map[successor] < new_layer:
                layer_map[successor] = new_layer
                queue.append(successor)

    # Assign any unreachable nodes to layer 0
    for node in graph.nodes():
        if node not in layer_map:
            layer_map[node] = 0

    # Build layers list
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
