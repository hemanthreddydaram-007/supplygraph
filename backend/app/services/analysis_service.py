# SupplyGraph - Analysis Service v2.0
# Wires: OSV, Typosquatting, AST, CI/CD, Dependency Confusion detectors
import uuid
import datetime
import hashlib
import logging
from typing import List

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
from app.services.gemini_service import GeminiService
from app.engines.graph_engine import GraphEngine
from app.engines.path_engine import PathEngine
from app.engines.containment_engine import ContainmentEngine
from app.detectors.typosquatting import TyposquattingDetector
from app.detectors.ast_analyzer import ASTAnalyzer
from app.detectors.cicd_analyzer import CICDAnalyzer
from app.detectors.confusion_detector import DependencyConfusionDetector

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(self):
        self.github_service = GitHubService()
        self.lockfile_parser = LockfileParser()
        self.sbom_engine = SBOMEngine()
        self.osv_client = OSVClient()
        self.graph_engine = GraphEngine()
        self.path_engine = PathEngine()
        self.containment_engine = ContainmentEngine()
        self.gemini_service = GeminiService()
        self.typosquat_detector = TyposquattingDetector()
        self.ast_analyzer = ASTAnalyzer()
        self.cicd_analyzer = CICDAnalyzer()
        self.confusion_detector = DependencyConfusionDetector()

    async def run_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
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

        # --- STEP 1: Detect and parse lockfiles ---
        root_files = self.github_service.list_files(request.github_url, ref=request.branch)
        supported_lockfiles = ["package-lock.json", "poetry.lock", "requirements.txt", "package.json"]
        found_lockfiles = [f for f in root_files if any(f.endswith(ext) for ext in supported_lockfiles)]

        scan_metadata.lockfile_detected = len(found_lockfiles) > 0
        scan_metadata.lockfile_types = found_lockfiles

        all_components = []
        for lockfile in found_lockfiles:
            content = self.github_service.get_file_content(request.github_url, lockfile, request.branch)
            if content:
                components = self.lockfile_parser.parse_lockfile(content, lockfile)
                all_components.extend(components)

        # --- STEP 2: Build SBOM ---
        sbom = self.sbom_engine.build_sbom(all_components, repo_name)
        scan_metadata.sbom_generated = True

        # Compute SBOM attestation fields
        sbom_sha256 = self.sbom_engine.compute_sbom_sha256(sbom)
        blast_radius_prelim = 0.0  # will be updated after findings

        # --- STEP 3: OSV Batch Query ---
        purls = []
        for comp in sbom.components:
            try:
                purls.append(PURL.from_string(comp.purl))
            except Exception:
                pass

        vulnerability_dict = await self.osv_client.query_batch(purls)
        scan_metadata.osv_queried = True

        # --- STEP 4: Generate OSV findings ---
        findings: List[FindingModel] = []
        all_vulnerabilities = []
        osv_count = 0

        for purl_str, vulns in vulnerability_dict.items():
            for vuln in vulns:
                all_vulnerabilities.append(vuln)
                osv_count += 1
                finding_id = str(uuid.uuid4())
                finding = FindingModel(
                    id=finding_id,
                    scan_id=scan_id,
                    entity_id=None,
                    entity_type="Version",
                    title=f"Vulnerability in {purl_str}",
                    description=vuln.summary or vuln.details or "Known vulnerability identified by OSV.dev",
                    severity=vuln.severity if (vuln.severity and vuln.severity != Severity.UNKNOWN) else Severity.HIGH,
                    finding_type=FindingType.VULNERABLE,
                    origin_candidate=purl_str,
                    affected_assets=[],
                    impact=compute_blast_radius(package_count=1, service_count=1, api_count=0, production_deployment_count=0),
                    confidence=compute_confidence([
                        ConfidenceFactor(evidence_type="OSV_MATCH", source="osv", raw_weight=0.9, reliability=1.0)
                    ]),
                    evidence=[
                        EvidenceItem(
                            source=EvidenceSource.OSV,
                            evidence_type="VULNERABILITY",
                            classification=EvidenceClassification.FACT,
                            description=f"Matched OSV advisory {vuln.osv_id}: {vuln.summary or ''}",
                            confidence_contribution=0.9
                        )
                    ],
                    recommendations=[]
                )
                findings.append(finding)

        # --- STEP 5: Typosquatting Detection ---
        typosquat_count = 0
        for comp in sbom.components:
            try:
                purl_obj = PURL.from_string(comp.purl)
                evidence = self.typosquat_detector.detect(purl_obj)
                if evidence:
                    typosquat_count += 1
                    typo_finding = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        entity_type="Package",
                        finding_type=FindingType.TYPOSQUATTING,
                        severity=Severity.HIGH,
                        title=f"Typosquatting Suspect: {comp.name}",
                        description=evidence.description,
                        origin_candidate=comp.name,
                        confidence=compute_confidence([
                            ConfidenceFactor(
                                evidence_type="TYPOSQUAT",
                                source="typosquatting",
                                raw_weight=evidence.confidence_contribution,
                                reliability=0.8
                            )
                        ]),
                        impact=compute_blast_radius(package_count=1, service_count=0, api_count=0, production_deployment_count=0),
                        evidence=[evidence],
                        recommendations=[]
                    )
                    findings.append(typo_finding)
            except Exception as e:
                logger.debug(f"Typosquatting check failed for {comp.name}: {e}")

        # --- STEP 6: Dependency Confusion Detection ---
        confusion_count = 0
        try:
            confusion_evidence = self.confusion_detector.detect(sbom.components)
            for ev in confusion_evidence:
                confusion_count += 1
                pkg_name = ev.raw_data.get("package", "unknown")
                cf = self.confusion_detector.create_finding_from_evidence([ev], scan_id, pkg_name)
                if cf:
                    findings.append(cf)
        except Exception as e:
            logger.warning(f"Dependency confusion detection failed: {e}")

        # --- STEP 7: Static AST Analysis (Python files) ---
        ast_count = 0
        if request.enable_ast_analysis:
            try:
                # Find Python files in the repository root tree (up to 10 files, max 50KB)
                py_files = [f for f in root_files if f.endswith('.py') or f == 'setup.py']
                py_files = py_files[:10]
                ast_evidence_all: List[EvidenceItem] = []
                for py_file in py_files:
                    try:
                        content = self.github_service.get_file_content(
                            request.github_url, py_file, request.branch
                        )
                        if content and len(content) < 50_000:
                            ev_items = self.ast_analyzer.analyze(py_file, content)
                            ast_evidence_all.extend(ev_items)
                    except Exception as fe:
                        logger.debug(f"AST fetch/analyze failed for {py_file}: {fe}")

                if ast_evidence_all:
                    ast_count = len(ast_evidence_all)
                    ast_finding = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        entity_type="Repository",
                        finding_type=FindingType.SUSPICIOUS,
                        severity=Severity.HIGH,
                        title=f"Suspicious Code Patterns Detected ({ast_count} signals)",
                        description=(
                            f"Static AST analysis found {ast_count} suspicious code pattern(s) "
                            f"including: {', '.join(set(e.evidence_type for e in ast_evidence_all[:5]))}"
                        ),
                        confidence=compute_confidence([
                            ConfidenceFactor(
                                evidence_type="AST",
                                source="ast",
                                raw_weight=0.75,
                                reliability=0.85
                            )
                        ]),
                        impact=compute_blast_radius(package_count=0, service_count=1, api_count=1, production_deployment_count=0),
                        evidence=ast_evidence_all[:20],  # Cap evidence list
                        recommendations=[]
                    )
                    findings.append(ast_finding)
            except Exception as e:
                logger.warning(f"AST analysis pipeline failed: {e}")

        # --- STEP 8: CI/CD Workflow Scanning ---
        cicd_count = 0
        if request.enable_cicd_analysis:
            try:
                # Look for .github/workflows/*.yml files
                workflow_files = [
                    f for f in root_files
                    if '.github/workflows/' in f and (f.endswith('.yml') or f.endswith('.yaml'))
                ]
                workflow_files = workflow_files[:5]  # Max 5 workflow files

                for wf_file in workflow_files:
                    try:
                        wf_content = self.github_service.get_file_content(
                            request.github_url, wf_file, request.branch
                        )
                        if wf_content:
                            wf_evidence = self.cicd_analyzer.analyze(wf_file, wf_content)
                            if wf_evidence:
                                cicd_count += len(wf_evidence)
                                wf_finding = self.cicd_analyzer.create_finding_from_evidence(
                                    wf_evidence, scan_id, wf_file
                                )
                                if wf_finding:
                                    findings.append(wf_finding)
                    except Exception as fe:
                        logger.debug(f"CICD workflow fetch/analyze failed for {wf_file}: {fe}")
            except Exception as e:
                logger.warning(f"CI/CD analysis pipeline failed: {e}")

        # --- STEP 9: Assets ---
        target_assets = [
            AssetModel(
                name="GitHub Repository",
                asset_type="repository",
                criticality="medium",
                is_production=False,
                scan_id=scan_id
            )
        ]

        # --- STEP 10: Build Graph ---
        graph = self.graph_engine.build_graph(repo_model, sbom, all_vulnerabilities, findings, target_assets)
        graph.scan_id = scan_id

        # --- STEP 11: Attack Paths ---
        origin_ids = [
            str(f.entity_id) if f.entity_id else f.origin_candidate
            for f in findings if f.entity_id or f.origin_candidate
        ]
        target_ids = [str(a.id) for a in target_assets]
        attack_paths = self.path_engine.find_attack_paths(graph, origin_ids, target_ids)
        for ap in attack_paths:
            ap.scan_id = scan_id

        # --- STEP 12: Containment Recommendations ---
        for finding in findings:
            try:
                recs = self.containment_engine.generate_recommendations(finding)
                finding.recommendations.extend(recs)
            except Exception as e:
                logger.debug(f"Containment rec failed for finding: {e}")

        # --- STEP 13: Finalize scan metadata ---
        blast_radius_score = min(
            100.0,
            sum(p.blast_radius.blast_radius_score for p in attack_paths) or
            (len(findings) * 5.0)  # fallback if no attack paths
        )

        # SBOM attestation
        merkle_root = self.sbom_engine.compute_merkle_root(
            request.github_url, sbom_sha256, blast_radius_score
        )
        polygon_attestation = self.sbom_engine.build_polygon_attestation(
            request.github_url, sbom_sha256, merkle_root, blast_radius_score
        )

        scan_metadata.status = ScanStatus.COMPLETED
        scan_metadata.completed_at = datetime.datetime.utcnow()
        scan_metadata.total_components = len(sbom.components)
        scan_metadata.total_vulnerabilities = len(all_vulnerabilities)
        scan_metadata.total_findings = len(findings)
        scan_metadata.total_attack_paths = len(attack_paths)
        scan_metadata.blast_radius_score = blast_radius_score

        # --- STEP 14: AI Executive Briefing ---
        response_prelim = AnalysisResponse(
            scan=scan_metadata,
            sbom=sbom,
            components=sbom.components,
            vulnerabilities=all_vulnerabilities,
            findings=findings,
            attack_paths=attack_paths,
            assets=target_assets,
            graph=graph,
            gemini_explanation="Generating...",
            gemini_available=self.gemini_service.gemini_available or self.gemini_service.bedrock_available,
            is_demo=False
        )

        try:
            explanation = await self.gemini_service.generate_explanation(response_prelim)
        except Exception as e:
            logger.warning(f"AI briefing generation failed: {e}")
            explanation = (
                f"SupplyGraph analyzed {repo_name}. "
                f"Detected {len(sbom.components)} components and {len(findings)} security findings. "
                f"Blast Radius: {blast_radius_score:.1f}/100."
            )

        # Build detector telemetry breakdown
        detector_breakdown = {
            "osv_count": osv_count,
            "typosquat_count": typosquat_count,
            "ast_count": ast_count,
            "cicd_count": cicd_count,
            "confusion_count": confusion_count,
            "sbom_sha256": "0x" + sbom_sha256,
            "merkle_root": "0x" + merkle_root,
            "polygon_attestation": polygon_attestation,
            "model_provider": self.gemini_service.model_provider,
        }

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
            gemini_available=(
                self.gemini_service.gemini_available or self.gemini_service.bedrock_available
            ),
            is_demo=False,
            detector_breakdown=detector_breakdown,
        )
