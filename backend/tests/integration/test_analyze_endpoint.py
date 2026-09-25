"""
Milestone 2A Gate Test
This integration test MUST pass before Milestone 2A is declared complete.

Tests:
    1. POST /api/v1/analyze/demo {scenario_id: "A"} returns 200
    2. Response has api_version: "v1"
    3. Response has graph.nodes (non-empty)
    4. Response has graph.edges (non-empty)
    5. Each node has position.x and position.y
    6. Response has findings (non-empty)
    7. Response has vulnerabilities (non-empty)
    8. scan.status == "completed"
    9. Response includes scan metadata
    10. Attack paths are present

Test Fixture:
    Demo scenario A: Vulnerable transitive dependency
    Expected: mixin-deep@1.3.1 flagged with GHSA-4xc9-xhrj-v574
"""

import pytest
from httpx import AsyncClient


@pytest.fixture
async def async_client():
    """Create an async test client for the FastAPI application."""
    from app.main import app
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


class TestMilestone2AGate:
    """
    MILESTONE 2A GATE TESTS
    All tests in this class MUST pass before Milestone 2A is complete.
    """

    @pytest.mark.asyncio
    async def test_health_endpoint_returns_200(self, async_client: AsyncClient):
        """Smoke test: backend is running."""
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    @pytest.mark.asyncio
    async def test_demo_scenario_a_returns_200(self, async_client: AsyncClient):
        """Demo endpoint is reachable and returns HTTP 200."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_demo_scenario_a_api_version(self, async_client: AsyncClient):
        """Response must include api_version: v1."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert data.get("api_version") == "v1"

    @pytest.mark.asyncio
    async def test_demo_scenario_a_graph_nodes_non_empty(self, async_client: AsyncClient):
        """Graph must contain at least one node."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert "graph" in data
        assert len(data["graph"]["nodes"]) > 0

    @pytest.mark.asyncio
    async def test_demo_scenario_a_graph_edges_non_empty(self, async_client: AsyncClient):
        """Graph must contain at least one edge."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert "graph" in data
        assert len(data["graph"]["edges"]) > 0

    @pytest.mark.asyncio
    async def test_demo_scenario_a_nodes_have_positions(self, async_client: AsyncClient):
        """CRITICAL: Every node must have position.x and position.y."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        for node in data["graph"]["nodes"]:
            assert "position" in node, f"Node {node.get('id')} missing position"
            assert "x" in node["position"], f"Node {node.get('id')} missing position.x"
            assert "y" in node["position"], f"Node {node.get('id')} missing position.y"
            assert isinstance(node["position"]["x"], (int, float))
            assert isinstance(node["position"]["y"], (int, float))

    @pytest.mark.asyncio
    async def test_demo_scenario_a_findings_non_empty(self, async_client: AsyncClient):
        """Analysis must produce at least one finding."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert "findings" in data
        assert len(data["findings"]) > 0

    @pytest.mark.asyncio
    async def test_demo_scenario_a_vulnerabilities_non_empty(self, async_client: AsyncClient):
        """Analysis must return at least one known vulnerability."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) > 0

    @pytest.mark.asyncio
    async def test_demo_scenario_a_scan_status_completed(self, async_client: AsyncClient):
        """Scan status must be 'completed'."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert data["scan"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_demo_scenario_a_is_demo_flagged(self, async_client: AsyncClient):
        """is_demo flag must be True for demo scenarios."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "A", "include_gemini_explanation": False},
        )
        data = response.json()
        assert data.get("is_demo") is True

    @pytest.mark.asyncio
    async def test_invalid_github_url_returns_422(self, async_client: AsyncClient):
        """Non-GitHub URL must be rejected with HTTP 422."""
        response = await async_client.post(
            "/api/v1/analyze",
            json={"github_url": "https://not-github.com/owner/repo"},
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_scenario_id_returns_422(self, async_client: AsyncClient):
        """Invalid scenario ID must be rejected."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "Z"},
        )
        assert response.status_code == 422


class TestFullPipeline:
    """
    End-to-end pipeline tests using demo scenario D
    (multi-level transitive propagation).
    """

    @pytest.mark.asyncio
    async def test_demo_d_transitive_path_found(self, async_client: AsyncClient):
        """Scenario D: 4-level transitive path must be detected."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "D", "include_gemini_explanation": False},
        )
        assert response.status_code == 200
        data = response.json()
        # Find the path with length >= 4
        paths = data.get("attack_paths", [])
        assert any(p["path_length"] >= 4 for p in paths), \
            "No transitive path of depth >= 4 found in Scenario D"

    @pytest.mark.asyncio
    async def test_demo_d_origin_identified(self, async_client: AsyncClient):
        """Scenario D: Origin candidate must be malicious-logger."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "D", "include_gemini_explanation": False},
        )
        data = response.json()
        findings = data.get("findings", [])
        origin_candidates = [f.get("origin_candidate") for f in findings if f.get("origin_candidate")]
        assert any("malicious-logger" in str(o) for o in origin_candidates), \
            "malicious-logger not identified as origin candidate"

    @pytest.mark.asyncio
    async def test_demo_d_affected_assets_not_empty(self, async_client: AsyncClient):
        """Scenario D: Production assets must be flagged as affected."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "D", "include_gemini_explanation": False},
        )
        data = response.json()
        assets = data.get("assets", [])
        assert len(assets) > 0, "No affected assets in Scenario D"

    @pytest.mark.asyncio
    async def test_demo_d_blast_radius_positive(self, async_client: AsyncClient):
        """Scenario D: Blast-radius score must be > 0."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "D", "include_gemini_explanation": False},
        )
        data = response.json()
        findings = data.get("findings", [])
        blast_scores = [f.get("impact", {}).get("blast_radius_score", 0) for f in findings]
        assert any(s > 0 for s in blast_scores), "Blast radius is 0 in Scenario D"

    @pytest.mark.asyncio
    async def test_demo_d_containment_present(self, async_client: AsyncClient):
        """Scenario D: At least one containment recommendation must be generated."""
        response = await async_client.post(
            "/api/v1/analyze/demo",
            json={"scenario_id": "D", "include_gemini_explanation": False},
        )
        data = response.json()
        findings = data.get("findings", [])
        all_recs = [r for f in findings for r in f.get("recommendations", [])]
        assert len(all_recs) > 0, "No containment recommendations in Scenario D"
