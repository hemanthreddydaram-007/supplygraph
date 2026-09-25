"""
Unit tests for the server-side graph layout engine.
Verifies deterministic positioning, cycle-safety, and spacing.
"""

import pytest
import networkx as nx
from app.graph.layout import compute_layout, detect_cycles, get_graph_statistics


class TestComputeLayout:

    def test_empty_graph_returns_empty_positions(self):
        g = nx.DiGraph()
        positions = compute_layout(g)
        assert positions == {}

    def test_single_node_gets_position(self):
        g = nx.DiGraph()
        g.add_node("A")
        positions = compute_layout(g)
        assert "A" in positions
        assert "x" in positions["A"]
        assert "y" in positions["A"]

    def test_dag_layout_assigns_all_nodes(self):
        g = nx.DiGraph()
        g.add_edge("App", "LibA")
        g.add_edge("LibA", "LibB")
        g.add_edge("LibB", "LibC")
        positions = compute_layout(g)
        for node in ["App", "LibA", "LibB", "LibC"]:
            assert node in positions

    def test_dag_layout_root_at_x_zero(self):
        g = nx.DiGraph()
        g.add_edge("App", "LibA")
        g.add_edge("LibA", "LibB")
        positions = compute_layout(g)
        # Root (App) should be at x=0 (layer 0)
        assert positions["App"]["x"] == 0.0

    def test_dag_depth_increases_x(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        positions = compute_layout(g, h_spacing=280.0)
        assert positions["B"]["x"] > positions["A"]["x"]
        assert positions["C"]["x"] > positions["B"]["x"]

    def test_layout_deterministic(self):
        """Same input graph must produce same positions on repeated calls."""
        g = nx.DiGraph()
        g.add_edge("App", "Pkg1")
        g.add_edge("App", "Pkg2")
        g.add_edge("Pkg1", "Dep1")
        g.add_edge("Pkg2", "Dep1")
        positions1 = compute_layout(g)
        positions2 = compute_layout(g)
        for node in g.nodes():
            assert positions1[node] == positions2[node]

    def test_cyclic_graph_does_not_crash(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        g.add_edge("C", "A")  # cycle
        # Must not raise
        positions = compute_layout(g)
        assert len(positions) == 3

    def test_horizontal_spacing_respected(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        positions = compute_layout(g, h_spacing=500.0)
        assert positions["B"]["x"] == 500.0

    def test_siblings_differ_in_y(self):
        g = nx.DiGraph()
        g.add_edge("App", "Pkg1")
        g.add_edge("App", "Pkg2")
        positions = compute_layout(g, v_spacing=120.0)
        # Both Pkg1 and Pkg2 should be at same x but different y
        assert positions["Pkg1"]["x"] == positions["Pkg2"]["x"]
        assert positions["Pkg1"]["y"] != positions["Pkg2"]["y"]

    def test_positions_are_numbers(self):
        g = nx.DiGraph()
        g.add_edge("X", "Y")
        positions = compute_layout(g)
        for node, pos in positions.items():
            assert isinstance(pos["x"], (int, float))
            assert isinstance(pos["y"], (int, float))


class TestCycleDetection:

    def test_dag_no_cycle(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        assert detect_cycles(g) is False

    def test_cyclic_graph_detected(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "A")
        assert detect_cycles(g) is True


class TestGraphStatistics:

    def test_node_count(self):
        g = nx.DiGraph()
        g.add_nodes_from(["A", "B", "C"])
        stats = get_graph_statistics(g)
        assert stats["node_count"] == 3

    def test_edge_count(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        g.add_edge("B", "C")
        stats = get_graph_statistics(g)
        assert stats["edge_count"] == 2

    def test_has_cycles_false_for_dag(self):
        g = nx.DiGraph()
        g.add_edge("A", "B")
        stats = get_graph_statistics(g)
        assert stats["has_cycles"] is False
