# SupplyGraph - Analysis Service
from app.models.core import AnalysisRequest, AnalysisResponse, ScanMetadata, ScanStatus, FindingModel, FindingType, Severity, EvidenceItem, EvidenceClassification, EvidenceSource, PURL, AssetModel
from app.engines.confidence import compute_confidence, ConfidenceFactor, compute_blast_radius
from app.services.github_service import GitHubService
from app.services.lockfile_parser import LockfileParser
from app.services.sbom_engine import SBOMEngine
from app.services.osv_client import OSVClient
from app.engines.graph_engine import GraphEngine
from app.engines.path_engine import PathEngine
from app.engines.containment_engine import ContainmentEngine
import uuid
import datetime

class AnalysisService:
    def __init__(self):
        self.github_service = GitHubService()
        self.lockfile_parser = LockfileParser()
        self.sbom_engine = SBOMEngine()
        self.osv_client = OSVClient()
        self.graph_engine = GraphEngine()
        self.path_engine = PathEngine()
        self.containment_engine = ContainmentEngine()
        
    async def run_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        # 1. Init ScanMetadata
        scan_id = str(uuid.uuid4())
        scan_metadata = ScanMetadata(
            scan_id=scan_id,
            timestamp=datetime.datetime.utcnow(),
            status=ScanStatus.IN_PROGRESS
        )
        
        # 2. GitHubService.get_repo_metadata()
        repo_metadata = await self.github_service.get_repo_metadata(request.repository_url, request.branch)
        
        # 3. Fetch lockfiles via GitHubService.get_file_content()
        lockfile_contents = {}
        for lockfile in request.lockfiles:
            content = await self.github_service.get_file_content(request.repository_url, lockfile, request.branch)
            if content:
                lockfile_contents[lockfile] = content
                
        # 4. LockfileParser.parse_lockfile() & 5. SBOMEngine.build_sbom()
        all_components = []
        for lockfile, content in lockfile_contents.items():
            components = self.lockfile_parser.parse_lockfile(content, lockfile)
            all_components.extend(components)
            
        sbom = self.sbom_engine.build_sbom(all_components, repo_metadata)
        
        # 6. OSVClient.query_batch()
        vulnerabilities = await self.osv_client.query_batch(all_components)
        
        # 7. Generate FindingModels from vulnerabilities
        findings = []
        for vuln in vulnerabilities:
            # Assuming vuln can be accessed as dict or has similar attributes, fallback to defaults
            vuln_dict = vuln if isinstance(vuln, dict) else vuln.__dict__
            finding_id = str(uuid.uuid4())
            finding = FindingModel(
                id=finding_id,
                title=vuln_dict.get("summary", "Vulnerability Found"),
                description=vuln_dict.get("details", "Details not available."),
                severity=Severity.HIGH, 
                type=FindingType.VULNERABLE,
                component_id=vuln_dict.get("package_name", "unknown_component"),
                evidence=[],
                confidence_score=0.0,
                blast_radius=0
            )
            findings.append(finding)
            
        # Compute confidence and blast radius
        for finding in findings:
            factors = [ConfidenceFactor(type="OSV_MATCH", score=0.9, description="Matched OSV vulnerability database")]
            finding.confidence_score = compute_confidence(factors)
            finding.blast_radius = compute_blast_radius(finding.component_id, sbom.dependencies)
        
        # 8. GraphEngine.build_graph()
        graph = self.graph_engine.build_graph(sbom, findings)
        
        # 9. PathEngine.find_attack_paths() (mock targets if no assets)
        target_assets = []
        if not target_assets:
            target_assets = [AssetModel(id="mock-asset-1", name="Production Database", type="database", criticality="high")]
            
        attack_paths = self.path_engine.find_attack_paths(graph, findings, target_assets)
        
        # 10. ContainmentEngine.generate_recommendations()
        recommendations = []
        for finding in findings:
            finding_recs = self.containment_engine.generate_recommendations(finding)
            recommendations.extend(finding_recs)
            
        scan_metadata.status = ScanStatus.COMPLETED
        
        return AnalysisResponse(
            scan_metadata=scan_metadata,
            sbom=sbom,
            findings=findings,
            attack_paths=attack_paths,
            recommendations=recommendations,
            graph=graph
        )
