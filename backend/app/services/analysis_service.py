# SupplyGraph - Analysis Service
from app.models.core import (
    AnalysisRequest, AnalysisResponse, ScanMetadata, ScanStatus, 
    FindingModel, FindingType, Severity, EvidenceItem, EvidenceClassification, 
    EvidenceSource, PURL, AssetModel, RepositoryModel
)
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
            id=scan_id,
            repository_url=request.github_url,
            started_at=datetime.datetime.utcnow(),
            status=ScanStatus.RUNNING,
            scan_type="full"
        )
        
        repo_name = self.github_service._extract_repo_name(request.github_url)
        repo_owner, repo_repo = repo_name.split('/') if '/' in repo_name else ("unknown", repo_name)
        
        repo_model = RepositoryModel(
            github_url=request.github_url,
            owner=repo_owner,
            name=repo_repo
        )
        
        # 3. List files in root and detect lockfiles
        root_files = self.github_service.list_files(request.github_url, ref=request.branch)
        supported_lockfiles = ["package-lock.json", "poetry.lock", "requirements.txt", "package.json"]
        found_lockfiles = [f for f in root_files if any(f.endswith(ext) for ext in supported_lockfiles)]
        
        scan_metadata.lockfile_detected = len(found_lockfiles) > 0
        scan_metadata.lockfile_types = found_lockfiles
        
        # 4. Fetch lockfiles via GitHubService.get_file_content()
        all_components = []
        for lockfile in found_lockfiles:
            content = self.github_service.get_file_content(request.github_url, lockfile, request.branch)
            if content:
                components = self.lockfile_parser.parse_lockfile(content, lockfile)
                all_components.extend(components)
                
        # 5. SBOMEngine.build_sbom()
        sbom = self.sbom_engine.build_sbom(all_components, repo_name)
        scan_metadata.sbom_generated = True
        
        # 6. OSVClient.query_batch()
        purls = []
        for comp in sbom.components:
            try:
                purls.append(PURL.from_string(comp.purl))
            except:
                pass
        
        vulnerability_dict = await self.osv_client.query_batch(purls)
        scan_metadata.osv_queried = True
        
        # 7. Generate FindingModels from vulnerabilities
        findings = []
        all_vulnerabilities = []
        
        for purl_str, vulns in vulnerability_dict.items():
            for vuln in vulns:
                all_vulnerabilities.append(vuln)
                finding_id = str(uuid.uuid4())
                finding = FindingModel(
                    id=finding_id,
                    scan_id=scan_id,
                    entity_id=None,
                    entity_type="Version",
                    title=f"Vulnerability in {purl_str}",
                    description=vuln.summary or vuln.details or "Known vulnerability",
                    severity=vuln.severity if vuln.severity else Severity.HIGH,
                    finding_type=FindingType.VULNERABLE,
                    origin_candidate=purl_str,
                    affected_assets=[],
                    impact=None,
                    confidence=None,
                    evidence=[
                        EvidenceItem(
                            source=EvidenceSource.OSV,
                            evidence_type="VULNERABILITY",
                            classification=EvidenceClassification.FACT,
                            description=f"Matched OSV advisory {vuln.osv_id}",
                            confidence_contribution=0.9
                        )
                    ],
                    recommendations=[]
                )
                
                factors = [ConfidenceFactor(evidence_type="OSV_MATCH", source="osv", raw_weight=0.9, reliability=1.0)]
                conf_dict = compute_confidence(factors)
                finding.confidence = conf_dict
                finding.impact = compute_blast_radius(package_count=1, service_count=1, api_count=0, production_deployment_count=0)
                
                findings.append(finding)
        
        target_assets = [
            AssetModel(name="GitHub Repository", asset_type="repository", criticality="medium", is_production=False, scan_id=scan_id)
        ]
        
        # 8. GraphEngine.build_graph()
        graph = self.graph_engine.build_graph(repo_model, sbom, all_vulnerabilities, findings, target_assets)
        graph.scan_id = scan_id
        
        # 9. PathEngine.find_attack_paths()
        attack_paths = self.path_engine.find_attack_paths(graph, findings, target_assets)
        for ap in attack_paths:
            ap.scan_id = scan_id
        
        # 10. ContainmentEngine.generate_recommendations()
        for finding in findings:
            recs = self.containment_engine.generate_recommendations(finding)
            finding.recommendations.extend(recs)
            
        scan_metadata.status = ScanStatus.COMPLETED
        scan_metadata.completed_at = datetime.datetime.utcnow()
        scan_metadata.total_components = len(sbom.components)
        scan_metadata.total_vulnerabilities = len(all_vulnerabilities)
        scan_metadata.total_findings = len(findings)
        scan_metadata.total_attack_paths = len(attack_paths)
        
        explanation = f"SupplyGraph analyzed {repo_name}. Detected {len(sbom.components)} components and {len(findings)} security findings."
        if len(findings) > 0:
            explanation += "\n\nPlease review the attack paths and containment recommendations."
        else:
            explanation += "\n\nNo suspicious findings detected by the configured analyzers."
            
        return AnalysisResponse(
            scan=scan_metadata,
            sbom=sbom,
            components=sbom.components,
            vulnerabilities=all_vulnerabilities,
            findings=findings,
            attack_paths=attack_paths,
            assets=target_assets,
            graph=graph,
            gemini_explanation=explanation,
            gemini_available=True,
            is_demo=False
        )
