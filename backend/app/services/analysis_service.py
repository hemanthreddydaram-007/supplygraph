# SupplyGraph - Analysis Service v2.0
# Wires: OSV, Typosquatting, AST, CI/CD, Dependency Confusion detectors
import uuid
import datetime
import hashlib
import logging
import re
import asyncio
from typing import List, Dict, Any, Set, Optional, Tuple

from app.models.core import (
    AnalysisRequest, AnalysisResponse, ScanMetadata, ScanStatus,
    FindingModel, FindingType, Severity, EvidenceItem, EvidenceClassification,
    EvidenceSource, PURL, AssetModel, RepositoryModel, FolderAnalysisRequest, CodeReviewItem
)
from app.engines.confidence import compute_confidence, ConfidenceFactor, compute_blast_radius
from app.services.github_service import GitHubService
from app.services.lockfile_parser import LockfileParser
from app.services.sbom_engine import SBOMEngine
from app.services.osv_client import OSVClient
from app.services.gemini_service import GeminiService
from app.services.code_reviewer import CodeReviewerService
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
        self.code_reviewer = CodeReviewerService()
        self.typosquat_detector = TyposquattingDetector()
        self.ast_analyzer = ASTAnalyzer()
        self.cicd_analyzer = CICDAnalyzer()
        self.confusion_detector = DependencyConfusionDetector()

    async def _fetch_files_concurrently(
        self, repo_url: str, paths: List[str], ref: Optional[str] = None, max_concurrency: int = 8, timeout: float = 4.0
    ) -> Dict[str, str]:
        """Fetch multiple files from GitHub concurrently with semaphore and strict timeout."""
        if not paths:
            return {}
        batch_fn = getattr(self.github_service, "get_files_batch", None)
        if batch_fn and callable(batch_fn):
            try:
                return await batch_fn(repo_url, paths, ref, max_concurrency=max_concurrency, timeout=timeout)
            except Exception:
                pass

        sem = asyncio.Semaphore(max_concurrency)

        async def _fetch_one(path: str):
            async with sem:
                try:
                    content = await asyncio.wait_for(
                        asyncio.to_thread(self.github_service.get_file_content, repo_url, path, ref),
                        timeout=timeout
                    )
                    return path, content
                except Exception:
                    return path, None

        tasks = [_fetch_one(p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = {}
        for r in results:
            if isinstance(r, tuple) and r[1] is not None:
                out[r[0]] = r[1]
        return out

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

        # --- STEP 1: Detect and parse lockfiles across root and subdirectories ---
        all_repo_files = self.github_service.list_files(request.github_url, ref=request.branch)
        supported_lockfiles = ["package-lock.json", "poetry.lock", "requirements.txt", "package.json"]
        found_lockfiles = [f for f in all_repo_files if any(f.endswith(ext) for ext in supported_lockfiles)]

        # If a directory has both package-lock.json and package.json, prefer package-lock.json
        filtered_lockfiles = []
        lock_dirs_with_lock = set()
        for f in found_lockfiles:
            if f.endswith("package-lock.json"):
                dir_name = f.rsplit("/", 1)[0] if "/" in f else ""
                lock_dirs_with_lock.add(dir_name)
                filtered_lockfiles.append(f)

        for f in found_lockfiles:
            if f.endswith("package.json"):
                dir_name = f.rsplit("/", 1)[0] if "/" in f else ""
                if dir_name not in lock_dirs_with_lock:
                    filtered_lockfiles.append(f)
            elif not f.endswith("package-lock.json"):
                filtered_lockfiles.append(f)

        scan_metadata.lockfile_detected = len(filtered_lockfiles) > 0
        scan_metadata.lockfile_types = filtered_lockfiles

        raw_components = []
        lockfile_contents = await self._fetch_files_concurrently(
            request.github_url, filtered_lockfiles, request.branch, max_concurrency=8, timeout=4.0
        )
        for lockfile, content in lockfile_contents.items():
            if content:
                try:
                    components = self.lockfile_parser.parse_lockfile(content, lockfile)
                    raw_components.extend(components)
                except Exception as pe:
                    logger.warning(f"Error parsing lockfile {lockfile}: {pe}")

        # --- STEP 2: Deduplicate components & build SBOM ---
        # Deduplicate components by (ecosystem, name, version), prioritizing direct dependencies
        unique_components_map = {}
        for comp in raw_components:
            eco_val = comp.ecosystem.value if comp.ecosystem else "unknown"
            key = (eco_val, comp.name.lower(), comp.version or "")
            if key not in unique_components_map:
                unique_components_map[key] = comp
            else:
                if not unique_components_map[key].is_direct and comp.is_direct:
                    unique_components_map[key] = comp

        # Sort direct dependencies first, cap at 500 unique packages
        deduped_components = sorted(
            unique_components_map.values(),
            key=lambda c: (not c.is_direct, getattr(c, "depth", 0))
        )[:500]

        sbom = self.sbom_engine.build_sbom(deduped_components, repo_name)
        scan_metadata.sbom_generated = True

        # Compute SBOM attestation fields
        sbom_sha256 = self.sbom_engine.compute_sbom_sha256(sbom)

        # --- STEP 3: OSV Batch Query (chunked to <= 150) ---
        purls = []
        for comp in sbom.components:
            try:
                purls.append(PURL.from_string(comp.purl))
            except Exception:
                pass

        vulnerability_dict = await self.osv_client.query_batch(purls)
        scan_metadata.osv_queried = True

        # --- STEP 4: Generate OSV findings (deduplicated) ---
        findings: List[FindingModel] = []
        all_vulnerabilities = []
        osv_count = 0
        seen_vuln_keys: Set[str] = set()

        for purl_str, vulns in vulnerability_dict.items():
            for vuln in vulns:
                vuln_key = f"{purl_str}:{vuln.osv_id}"
                if vuln_key in seen_vuln_keys:
                    continue
                seen_vuln_keys.add(vuln_key)

                all_vulnerabilities.append(vuln)
                osv_count += 1

                # Extract real fixed version from OSV data
                fixed_ver = None
                if vuln.fixed_versions:
                    fixed_ver = next(iter(vuln.fixed_versions.values()), None)

                # Fallback fixed version derivation if none provided
                if not fixed_ver and "@" in purl_str:
                    ver_part = purl_str.split("@")[-1]
                    import re
                    match = re.match(r"^(\d+)", ver_part)
                    if match:
                        fixed_ver = f">={int(match.group(1)) + 1}.0.0"

                finding_id = str(uuid.uuid4())
                finding = FindingModel(
                    id=finding_id,
                    scan_id=scan_id,
                    entity_id=None,
                    entity_type="Version",
                    title=f"{vuln.osv_id}: {purl_str}" if vuln.osv_id else f"Vulnerability in {purl_str}",
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
                            confidence_contribution=0.9,
                            raw_data={
                                "vuln_id": vuln.osv_id,
                                "fixed_version": fixed_ver,
                                "purl": purl_str
                            }
                        )
                    ],
                    recommendations=[]
                )
                findings.append(finding)

        # --- STEP 5: Typosquatting Detection (strict ecosystem & whitelist) ---
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
                        origin_candidate=comp.purl,
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

        # --- STEP 7: Static AST Analysis (Python files across repo) ---
        ast_count = 0
        if request.enable_ast_analysis:
            try:
                py_files = [
                    f for f in all_repo_files
                    if f.endswith('.py') and not any(ign in f for ign in ['tests/', 'test/', 'venv/', 'node_modules/'])
                ][:15]
                ast_evidence_all: List[EvidenceItem] = []
                py_map = await self._fetch_files_concurrently(
                    request.github_url, py_files, request.branch, max_concurrency=8, timeout=4.0
                )
                for py_file, content in py_map.items():
                    if content and len(content) < 50_000:
                        try:
                            ev_items = self.ast_analyzer.analyze(py_file, content)
                            ast_evidence_all.extend(ev_items)
                        except Exception as fe:
                            logger.debug(f"AST analyze failed for {py_file}: {fe}")

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
                        evidence=ast_evidence_all[:20],
                        recommendations=[]
                    )
                    findings.append(ast_finding)
            except Exception as e:
                logger.warning(f"AST analysis pipeline failed: {e}")

        # --- STEP 8: CI/CD Workflow Scanning (.github/workflows/*.yml) ---
        cicd_count = 0
        if request.enable_cicd_analysis:
            try:
                workflow_files = [
                    f for f in all_repo_files
                    if ('.github/workflows/' in f or f.startswith('.github/workflows/')) and (f.endswith('.yml') or f.endswith('.yaml'))
                ][:8]

                wf_map = await self._fetch_files_concurrently(
                    request.github_url, workflow_files, request.branch, max_concurrency=8, timeout=4.0
                )
                for wf_file, wf_content in wf_map.items():
                    if wf_content:
                        try:
                            wf_evidence = self.cicd_analyzer.analyze(wf_file, wf_content)
                            if wf_evidence:
                                cicd_count += len(wf_evidence)
                                wf_finding = self.cicd_analyzer.create_finding_from_evidence(
                                    wf_evidence, scan_id, wf_file
                                )
                                if wf_finding:
                                    findings.append(wf_finding)
                        except Exception as fe:
                            logger.debug(f"CICD workflow analyze failed for {wf_file}: {fe}")
            except Exception as e:
                logger.warning(f"CI/CD analysis pipeline failed: {e}")

        # Deduplicate final findings across all detectors
        unique_findings = []
        seen_finding_keys: Set[str] = set()
        for f in findings:
            f_key = f"{f.finding_type.value}:{f.origin_candidate or ''}:{f.title}"
            if f_key not in seen_finding_keys:
                seen_finding_keys.add(f_key)
                unique_findings.append(f)
        findings = unique_findings

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

        # Mark attack path edges and nodes in the graph
        attack_nodes_set: Set[str] = set()
        for ap in attack_paths:
            for n_id in ap.path_nodes:
                attack_nodes_set.add(n_id)

        for edge in graph.edges:
            if edge.source in attack_nodes_set and edge.target in attack_nodes_set:
                edge.data.is_attack_path = True
                edge.animated = True

        for node in graph.nodes:
            if node.id in attack_nodes_set:
                node.data.is_affected = True

        # --- STEP 12: Containment Recommendations ---
        for finding in findings:
            try:
                # Extract fixed version if present in evidence
                rec_fixed_ver = None
                for ev in finding.evidence:
                    if ev.raw_data and ev.raw_data.get("fixed_version"):
                        rec_fixed_ver = ev.raw_data.get("fixed_version")
                        break
                recs = self.containment_engine.generate_recommendations(finding, fixed_version=rec_fixed_ver)
                finding.recommendations.extend(recs)
            except Exception as e:
                logger.debug(f"Containment rec failed for finding: {e}")

        # --- STEP 13: Finalize scan metadata ---
        blast_radius_score = min(
            100.0,
            sum(p.blast_radius.blast_radius_score for p in attack_paths) or
            (len(findings) * 5.0)
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

        # --- STEP 13.5: AI Code Reviewer for Source Code ---
        code_reviews: List[CodeReviewItem] = []
        try:
            source_candidates = [
                f for f in all_repo_files
                if any(f.endswith(ext) for ext in ['.py', '.js', '.ts', '.tsx', '.jsx', '.yml'])
                and not any(ign in f for ign in ['node_modules/', '.git/', 'venv/', '__pycache__/', '.next/'])
            ][:10]
            if source_candidates:
                source_files_dict = await self._fetch_files_concurrently(
                    request.github_url, source_candidates, request.branch, max_concurrency=8, timeout=4.0
                )
                source_files_bounded = {
                    k: v for k, v in source_files_dict.items() if v and len(v) < 50_000
                }
                if source_files_bounded:
                    code_reviews = self.code_reviewer.review_files(source_files_bounded, max_files=10)
        except Exception as cre:
            logger.warning(f"Code reviewer failed in run_analysis: {cre}")

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
            is_demo=False,
            code_reviews=code_reviews
        )

        try:
            explanation = await self.gemini_service.generate_explanation(response_prelim)
        except Exception as e:
            logger.warning(f"AI briefing generation failed: {e}")
            explanation = (
                f"SupplyGraph analyzed {repo_name}. "
                f"Detected {len(sbom.components)} components, {len(findings)} security findings, and {len(code_reviews)} code review suggestions. "
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
            code_reviews=code_reviews,
        )

    async def run_folder_analysis(self, request: FolderAnalysisRequest) -> AnalysisResponse:
        """
        Analyzes a locally uploaded project folder:
        Runs lockfile parsing, OSV batch intel, Typosquatting, Confusion, AST, CI/CD,
        Reverse DAG attack graph, Blast Radius, CycloneDX SBOM, Polygon Attestation,
        and AI Code Reviewer with line-level corrected diffs.
        """
        scan_id = str(uuid.uuid4())
        project_name = request.project_name or "Uploaded Project"
        clean_slug = re.sub(r'[^a-zA-Z0-9_\-]', '-', project_name).lower()
        fake_url = f"https://github.com/local-upload/{clean_slug}"

        scan_metadata = ScanMetadata(
            id=scan_id,
            repository_url=fake_url,
            started_at=datetime.datetime.utcnow(),
            status=ScanStatus.RUNNING,
            scan_type="folder_upload"
        )

        repo_model = RepositoryModel(
            github_url=fake_url,
            owner="local-upload",
            name=project_name
        )

        files_map = {f.path: f.content for f in request.files}

        # 1. Parse lockfiles
        supported_lockfiles = ["package-lock.json", "poetry.lock", "requirements.txt", "package.json"]
        found_lockfiles = [p for p in files_map.keys() if any(p.endswith(ext) for ext in supported_lockfiles)]

        filtered_lockfiles = []
        lock_dirs_with_lock = set()
        for f in found_lockfiles:
            if f.endswith("package-lock.json"):
                dir_name = f.rsplit("/", 1)[0] if "/" in f else ""
                lock_dirs_with_lock.add(dir_name)
                filtered_lockfiles.append(f)

        for f in found_lockfiles:
            if f.endswith("package.json"):
                dir_name = f.rsplit("/", 1)[0] if "/" in f else ""
                if dir_name not in lock_dirs_with_lock:
                    filtered_lockfiles.append(f)
            elif not f.endswith("package-lock.json"):
                filtered_lockfiles.append(f)

        scan_metadata.lockfile_detected = len(filtered_lockfiles) > 0
        scan_metadata.lockfile_types = filtered_lockfiles

        raw_components = []
        for lf in filtered_lockfiles:
            content = files_map.get(lf, "")
            if content:
                try:
                    comps = self.lockfile_parser.parse_lockfile(content, lf)
                    raw_components.extend(comps)
                except Exception as pe:
                    logger.warning(f"Error parsing uploaded lockfile {lf}: {pe}")

        if not raw_components:
            for p, content in files_map.items():
                if "requirements" in p and p.endswith(".txt"):
                    try:
                        comps = self.lockfile_parser.parse_lockfile(content, "requirements.txt")
                        raw_components.extend(comps)
                    except Exception:
                        pass
                elif p.endswith("package.json"):
                    try:
                        comps = self.lockfile_parser.parse_lockfile(content, "package.json")
                        raw_components.extend(comps)
                    except Exception:
                        pass

        # Deduplicate components
        unique_components_map = {}
        for comp in raw_components:
            eco_val = comp.ecosystem.value if comp.ecosystem else "unknown"
            key = (eco_val, comp.name.lower(), comp.version or "")
            if key not in unique_components_map:
                unique_components_map[key] = comp
            else:
                if not unique_components_map[key].is_direct and comp.is_direct:
                    unique_components_map[key] = comp

        deduped_components = sorted(
            unique_components_map.values(),
            key=lambda c: (not c.is_direct, getattr(c, "depth", 0))
        )[:500]

        sbom = self.sbom_engine.build_sbom(deduped_components, project_name)
        scan_metadata.sbom_generated = True
        sbom_sha256 = self.sbom_engine.compute_sbom_sha256(sbom)

        # OSV batch query
        purls = []
        for comp in sbom.components:
            try:
                purls.append(PURL.from_string(comp.purl))
            except Exception:
                pass

        vulnerability_dict = await self.osv_client.query_batch(purls)
        scan_metadata.osv_queried = True

        findings: List[FindingModel] = []
        all_vulnerabilities = []
        osv_count = 0
        seen_vuln_keys: Set[str] = set()

        for purl_str, vulns in vulnerability_dict.items():
            for vuln in vulns:
                vuln_key = f"{purl_str}:{vuln.osv_id}"
                if vuln_key in seen_vuln_keys:
                    continue
                seen_vuln_keys.add(vuln_key)
                all_vulnerabilities.append(vuln)
                osv_count += 1

                fixed_ver = None
                if vuln.fixed_versions:
                    fixed_ver = next(iter(vuln.fixed_versions.values()), None)
                if not fixed_ver and "@" in purl_str:
                    ver_part = purl_str.split("@")[-1]
                    m = re.match(r"^(\d+)", ver_part)
                    if m:
                        fixed_ver = f">={int(m.group(1)) + 1}.0.0"

                finding_id = str(uuid.uuid4())
                finding = FindingModel(
                    id=finding_id,
                    scan_id=scan_id,
                    entity_id=None,
                    entity_type="Version",
                    title=f"{vuln.osv_id}: {purl_str}" if vuln.osv_id else f"Vulnerability in {purl_str}",
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
                            evidence_type="CVE_MATCH",
                            classification=EvidenceClassification.FACT,
                            description=f"OSV Advisory: {vuln.osv_id} ({vuln.severity.value if vuln.severity else 'HIGH'}) affects {purl_str}",
                            raw_data={"osv_id": vuln.osv_id, "fixed_version": fixed_ver, "summary": vuln.summary}
                        )
                    ],
                    recommendations=[]
                )
                findings.append(finding)

        # Typosquatting
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
                        origin_candidate=comp.purl,
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

        # Dependency Confusion
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

        # AST Analyzer on Python files
        ast_count = 0
        py_files = {p: c for p, c in files_map.items() if p.endswith(".py") and not any(ign in p for ign in ['tests/', 'test/', 'venv/', 'node_modules/'])}
        ast_evidence_all: List[EvidenceItem] = []
        for py_path, py_code in list(py_files.items())[:15]:
            try:
                evs = self.ast_analyzer.analyze(py_path, py_code)
                ast_evidence_all.extend(evs)
            except Exception as e:
                logger.debug(f"AST analyze failed for {py_path}: {e}")

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
                    ConfidenceFactor(evidence_type="AST", source="ast", raw_weight=0.75, reliability=0.85)
                ]),
                impact=compute_blast_radius(package_count=0, service_count=1, api_count=1, production_deployment_count=0),
                evidence=ast_evidence_all[:20],
                recommendations=[]
            )
            findings.append(ast_finding)

        # CI/CD Analyzer
        cicd_count = 0
        wf_files = {p: c for p, c in files_map.items() if ('.github/workflows/' in p or p.startswith('.github/workflows/')) and (p.endswith('.yml') or p.endswith('.yaml'))}
        for wf_path, wf_code in wf_files.items():
            try:
                wf_ev = self.cicd_analyzer.analyze(wf_path, wf_code)
                if wf_ev:
                    cicd_count += len(wf_ev)
                    wf_f = self.cicd_analyzer.create_finding_from_evidence(wf_ev, scan_id, wf_path)
                    if wf_f:
                        findings.append(wf_f)
            except Exception as e:
                logger.debug(f"CI/CD analyze failed for {wf_path}: {e}")

        # Deduplicate findings
        unique_findings = []
        seen_keys: Set[str] = set()
        for f in findings:
            key = f"{f.finding_type.value}:{f.origin_candidate or ''}:{f.title}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
        findings = unique_findings

        # Target assets
        target_assets = [
            AssetModel(
                name=f"{project_name} Workspace",
                asset_type="repository",
                criticality="medium",
                is_production=False,
                scan_id=scan_id
            )
        ]

        # Build Graph
        graph = self.graph_engine.build_graph(repo_model, sbom, all_vulnerabilities, findings, target_assets)
        graph.scan_id = scan_id

        # Attack Paths
        origin_ids = [
            str(f.entity_id) if f.entity_id else f.origin_candidate
            for f in findings if f.entity_id or f.origin_candidate
        ]
        asset_ids = [str(a.id) for a in target_assets]
        attack_paths = self.path_engine.find_attack_paths(graph, origin_ids, asset_ids)

        # Edge attack path coloring
        attack_path_node_ids = set()
        for p in attack_paths:
            attack_path_node_ids.update(p.path_nodes)

        for edge in graph.edges:
            if edge.source in attack_path_node_ids and edge.target in attack_path_node_ids:
                edge.data.is_attack_path = True
                edge.animated = True

        for vuln in all_vulnerabilities:
            for edge in graph.edges:
                if edge.source == vuln.osv_id or edge.target == vuln.osv_id:
                    edge.data.is_attack_path = True
                    edge.animated = True

        # Containment recommendations
        for finding in findings:
            try:
                rec_fixed_ver = None
                for ev in finding.evidence:
                    if ev.raw_data and ev.raw_data.get("fixed_version"):
                        rec_fixed_ver = ev.raw_data.get("fixed_version")
                        break
                recs = self.containment_engine.generate_recommendations(finding, fixed_version=rec_fixed_ver)
                finding.recommendations.extend(recs)
            except Exception as e:
                logger.debug(f"Containment rec failed for finding: {e}")

        # Blast radius
        blast_radius_score = min(
            100.0,
            sum(p.blast_radius.blast_radius_score for p in attack_paths) or
            (len(findings) * 5.0)
        )

        merkle_root = self.sbom_engine.compute_merkle_root(fake_url, sbom_sha256, blast_radius_score)
        polygon_attestation = self.sbom_engine.build_polygon_attestation(fake_url, sbom_sha256, merkle_root, blast_radius_score)

        scan_metadata.status = ScanStatus.COMPLETED
        scan_metadata.completed_at = datetime.datetime.utcnow()
        scan_metadata.total_components = len(sbom.components)
        scan_metadata.total_vulnerabilities = len(all_vulnerabilities)
        scan_metadata.total_findings = len(findings)
        scan_metadata.total_attack_paths = len(attack_paths)
        scan_metadata.blast_radius_score = blast_radius_score

        # Code Review on uploaded files
        code_reviews: List[CodeReviewItem] = []
        if request.enable_code_review:
            try:
                code_reviews = self.code_reviewer.review_files(files_map, max_files=20)
            except Exception as e:
                logger.warning(f"Folder code review failed: {e}")

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

        explanation = (
            f"SupplyGraph analyzed uploaded project '{project_name}'. "
            f"Evaluated {len(sbom.components)} dependencies, {len(findings)} security findings, and {len(code_reviews)} code review suggestions. "
            f"Overall Blast Radius: {blast_radius_score:.1f}/100."
        )

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
            gemini_available=self.gemini_service.gemini_available or self.gemini_service.bedrock_available,
            is_demo=False,
            detector_breakdown=detector_breakdown,
            code_reviews=code_reviews
        )
