import pytest
from app.models.core import AnalysisRequest
from app.services.analysis_service import AnalysisService
import asyncio

@pytest.mark.asyncio
async def test_real_repo_analysis_mocked():
    # Because we don't want to make real github/OSV calls in unit tests,
    # we just instantiate the service to ensure no syntax errors.
    svc = AnalysisService()
    assert svc.github_service is not None
    assert svc.lockfile_parser is not None
    assert svc.sbom_engine is not None
    
    # We can also mock the methods to test the orchestrator
    class MockGitHub:
        def _extract_repo_name(self, url): return "user/repo"
        def list_files(self, url, ref): return ["package-lock.json"]
        def get_file_content(self, url, file, ref): return "{}"
    
    class MockLockfile:
        def parse_lockfile(self, content, name): return []
        
    class MockSBOM:
        def build_sbom(self, components, name):
            from app.models.core import SBOM
            return SBOM(metadata={"name": name, "version": "1.0"}, components=[], dependencies=[])
            
    class MockOSV:
        async def query_batch(self, purls): return {}
        
    class MockGraph:
        def build_graph(self, repo, sbom, vulns, findings, assets):
            from networkx import DiGraph
            from app.models.core import SecurityGraph
            return SecurityGraph(scan_id="test", nodes=[], edges=[], attack_path_count=0)
            
    class MockPath:
        def find_attack_paths(self, graph, findings, assets): return []
        
    class MockContainment:
        def generate_recommendations(self, finding): return []
        
    svc.github_service = MockGitHub()
    svc.lockfile_parser = MockLockfile()
    svc.sbom_engine = MockSBOM()
    svc.osv_client = MockOSV()
    svc.graph_engine = MockGraph()
    svc.path_engine = MockPath()
    svc.containment_engine = MockContainment()
    
    req = AnalysisRequest(github_url="https://github.com/user/repo", branch="main")
    res = await svc.run_analysis(req)
    
    assert res.scan.repository_url == "https://github.com/user/repo"
    assert res.scan.lockfile_detected is True
    assert res.scan.sbom_generated is True
    assert len(res.findings) == 0
    assert len(res.attack_paths) == 0
