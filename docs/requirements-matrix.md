# SupplyGraph — Requirements Traceability Matrix

**Version:** 1.0.0
**Last Updated:** 2026-09-25
**Event:** HackFusion 2026 — Theme 6: Software Supply-Chain Attack Graph Engine

---

## Overview

This matrix traces every official Theme 6 requirement to its corresponding implementation module, API endpoint, database entity, UI screen, automated test, and demo scenario. Every row is a requirement. Every column is a layer of the system.

---

## Requirements Traceability Matrix

| # | Requirement | Module(s) | API Endpoint(s) | DB Entity | UI Screen | Test | Demo Scenario |
|---|---|---|---|---|---|---|---|
| R-01 | **Dependency & Asset Graph** — Discover and model repositories, packages, versions, services, containers, APIs, deployments, and CI/CD pipelines as a unified security graph | `backend/app/ingestion/github_client.py`, `backend/app/ingestion/lockfile_parser.py`, `backend/app/graph/builder.py`, `backend/app/graph/layout.py` | `POST /api/v1/analyze`, `GET /api/v1/graph/{scan_id}`, `GET /api/v1/assets/{scan_id}` | `scans`, `packages`, `package_versions`, `assets`, `graph_nodes`, `graph_edges` | Graph View (React Flow canvas), Asset Panel | `tests/test_graph_builder.py`, `tests/test_lockfile_parser.py`, `tests/integration/test_analyze_endpoint.py` | A, B, C, D, E |
| R-02 | **Malicious Component Detection** — Detect typosquatting, dependency confusion, suspicious version updates, dormant logic, and obfuscated behavior | `backend/app/detection/typosquatting.py`, `backend/app/detection/dependency_confusion.py`, `backend/app/detection/suspicious_update.py`, `backend/app/detection/dormant_logic.py`, `backend/app/detection/obfuscation.py` | `POST /api/v1/analyze`, `GET /api/v1/findings` | `findings`, `evidence_items` | Findings Panel, Finding Detail Modal | `tests/test_typosquatting_detector.py`, `tests/test_dependency_confusion.py`, `tests/test_obfuscation_detector.py` | A (typosquatting), B (dep. confusion), C (dormant logic), D (obfuscation) |
| R-03 | **Code & Behaviour Analysis** — Static AST analysis, metadata inspection, and optional simulated runtime signal generation | `backend/app/analysis/ast_analyzer.py`, `backend/app/analysis/metadata_analyzer.py`, `backend/app/analysis/runtime_simulator.py` | `POST /api/v1/analyze` (`enable_ast_analysis`, `enable_metadata_analysis`, `enable_simulated_runtime` flags) | `evidence_items` (`evidence_type = AST_FINDING | METADATA_ANOMALY | RUNTIME_SIGNAL`) | Evidence tab in Finding Detail Modal | `tests/test_ast_analyzer.py`, `tests/test_metadata_analyzer.py`, `tests/test_runtime_simulator.py` | C (dormant logic AST), D (obfuscated CI/CD scripts) |
| R-04 | **Attack-Path Tracing** — Trace attack paths from identified origin nodes through direct and transitive dependencies to affected downstream assets | `backend/app/graph/attack_paths.py`, `backend/app/graph/traversal.py` | `POST /api/v1/analyze`, `GET /api/v1/attack-paths/{scan_id}` | `attack_paths`, `attack_path_nodes` | Attack Path Overlay on React Flow canvas, Attack Paths Panel | `tests/test_attack_path_tracer.py`, `tests/integration/test_attack_paths_endpoint.py` | A, B, C, D, E |
| R-05 | **Impact & Confidence Engine** — Calculate per-finding exploitability, blast radius, confidence score breakdown, and overall risk score; estimate operational and business impact | `backend/app/scoring/confidence.py`, `backend/app/scoring/impact.py`, `backend/app/scoring/risk.py` | `GET /api/v1/findings/{finding_id}` (full breakdown), `POST /api/v1/analyze` (summary) | `findings` (`confidence_score`, `impact_score`, `risk_score`, `confidence_breakdown`, `impact_breakdown`) | Risk Score Badge on Finding cards, Impact Breakdown in Finding Detail Modal | `tests/test_confidence_engine.py`, `tests/test_impact_engine.py`, `tests/test_risk_scoring.py` | A, B, C, D, E |
| R-06 | **Containment Recommendations** — Generate actionable containment steps: package pinning, rollback instructions, isolation guidance, replacement packages, pipeline access controls | `backend/app/recommendations/generator.py`, `backend/app/recommendations/templates/` | `GET /api/v1/findings/{finding_id}` (`recommendations[]`), `POST /api/v1/analyze` | `recommendations` | Recommendations tab in Finding Detail Modal | `tests/test_recommendation_generator.py` | A, B, C, D, E |
| R-07 | **Transitive Threat Detection** — Detect and propagate threats hidden multiple dependency levels away (depth > 1) from the root repository | `backend/app/graph/traversal.py`, `backend/app/graph/attack_paths.py` (BFS/DFS with depth tracking) | `POST /api/v1/analyze` (`include_transitive`, `max_transitive_depth`), `GET /api/v1/findings` (`is_transitive` filter) | `findings` (`is_transitive`, `transitive_depth`), `graph_edges` (`depth`) | Depth badge on graph nodes, Transitive filter in Findings Panel | `tests/test_transitive_detection.py` (synthetic 5-level graph) | C (backdoor at depth 3) |
| R-08 | **Evidence Correlation** — Aggregate evidence from multiple independent sources (metadata, OSV, AST, CI/CD, runtime) into a unified, weighted evidence set per finding | `backend/app/evidence/correlator.py`, `backend/app/evidence/aggregator.py` | `GET /api/v1/findings/{finding_id}` (`evidence[]`) | `evidence_items` (`evidence_type`, `source`, `weight`, `raw_data`) | Evidence list in Finding Detail Modal (grouped by source) | `tests/test_evidence_correlator.py` | A, B, C, D, E |
| R-09 | **Explainability** — Explain why each component is suspicious, show the full propagation path from origin to asset, provide human-readable narrative | `backend/app/explanation/propagation.py`, `backend/app/explanation/gemini_explainer.py` | `GET /api/v1/findings/{finding_id}` (`propagation_chain[]`), `POST /api/v1/analyze` (`enable_gemini_explanation`) | `findings` (`gemini_explanation`), `attack_path_nodes` | Propagation Path tab in Finding Detail, Gemini Explanation card | `tests/test_propagation_explainer.py`, `tests/test_gemini_explainer.py` | A, B, C, D, E |
| R-10 | **Continuous Re-analysis** — Support re-running analysis when package versions or metadata change, preserving scan history | `backend/app/api/endpoints/reanalyze.py`, `backend/app/scheduler/` (optional) | `POST /api/v1/reanalyze/{scan_id}`, `GET /api/v1/scans` | `scans` (`previous_scan_id`), `scan_history` | Re-scan button in Scan Detail, Scan History timeline | `tests/test_reanalysis.py` | — |
| R-11 | **SBOM Generation** — Generate a valid CycloneDX 1.4 Software Bill of Materials for every analyzed repository | `backend/app/sbom/cyclonedx_generator.py` | `POST /api/v1/analyze` (`sbom` field), `GET /api/v1/scans/{scan_id}?include_sbom=true` | `scans` (`sbom_json`) | SBOM Download button in Scan Detail | `tests/test_sbom_generator.py` (validate against CycloneDX schema) | A, B, C, D, E |
| R-12 | **OSV Vulnerability Intelligence** — Query OSV.dev for known CVEs/vulnerabilities for every discovered package version; cache results | `backend/app/osv/client.py`, `backend/app/osv/cache.py`, `backend/app/osv/batch_querier.py` | `POST /api/v1/analyze` (OSV enrichment during pipeline), `GET /api/v1/findings/{finding_id}` (`osv_vulnerabilities[]`) | `osv_vulnerabilities`, `osv_cache` | OSV CVE list in Finding Detail, CVE badges on graph nodes | `tests/test_osv_client.py`, `tests/test_osv_cache.py` | A, B, C, D, E |
| R-13 | **PURL Canonical Identifiers** — Assign and normalize Package URL (PURL) identifiers for every package across all ecosystems | `backend/app/purl/normalizer.py`, `backend/app/purl/parser.py` | All endpoints returning package data include `purl` field | `package_versions` (`purl`), `graph_nodes` (`node_id = purl`) | Shown in Finding Detail, Graph node tooltip | `tests/test_purl_normalizer.py` (PyPI, npm, Maven, Go, Rust) | A, B, C, D, E |
| R-14 | **GitHub Repository Ingestion** — Fetch repository metadata, file tree, lockfiles, workflow files, and Dockerfile(s) via GitHub REST API | `backend/app/ingestion/github_client.py`, `backend/app/ingestion/file_fetcher.py` | `POST /api/v1/analyze` (ingestion phase) | `repositories`, `scans` | Repository details in Scan header | `tests/test_github_client.py` (mocked GitHub API) | A, B, C, D, E |
| R-15 | **CI/CD Analysis** — Parse and analyze GitHub Actions workflow files for suspicious steps, untrusted actions, pinning issues, and secret exposure | `backend/app/analysis/cicd_analyzer.py` | `POST /api/v1/analyze` (`enable_cicd_analysis` flag), findings with `finding_type = CICD_RISK` | `findings`, `assets` (`asset_type = CICDPipeline`) | CI/CD node on graph canvas, CI/CD findings in Findings Panel | `tests/test_cicd_analyzer.py` | D (poisoned CI/CD) |
| R-16 | **Simulated Runtime Signals** — Generate plausible runtime behavioral signals (network calls, file system access, process spawning) for suspicious packages | `backend/app/analysis/runtime_simulator.py` | `POST /api/v1/analyze` (`enable_simulated_runtime` flag) | `evidence_items` (`evidence_type = RUNTIME_SIGNAL`) | Runtime Evidence section in Finding Detail | `tests/test_runtime_simulator.py` | C (dormant logic activation) |
| R-17 | **Attack-Origin Identification** — Identify the most likely entry-point node (package, pipeline step, or dependency) responsible for initiating the attack chain | `backend/app/graph/origin_detector.py`, `backend/app/scoring/origin_score.py` | `GET /api/v1/attack-paths/{scan_id}` (`origin_node_id`), graph nodes with `is_origin_candidate: true` | `attack_paths` (`origin_node_id`), `graph_nodes` (`is_origin_candidate`) | Origin crown icon on React Flow graph, highlighted node in Attack Path | `tests/test_origin_detector.py` | A, B, C, D, E |
| R-18 | **Affected Asset Determination** — Identify which downstream services, containers, deployments, and APIs are reachable from each attack origin | `backend/app/graph/attack_paths.py`, `backend/app/graph/traversal.py` | `GET /api/v1/assets/{scan_id}`, `GET /api/v1/findings/{finding_id}` (`affected_assets[]`) | `assets`, `findings` (M2M via `finding_assets`) | Affected Asset badges in Finding Detail, Asset nodes on graph canvas | `tests/test_affected_asset_determination.py` | A, B, C, D, E |
| R-19 | **Blast-Radius Estimation** — Quantify the breadth of potential damage: how many assets, services, and users are reachable from an attack origin | `backend/app/scoring/impact.py` (`blast_radius_score`) | `GET /api/v1/findings/{finding_id}` (`impact_breakdown.blast_radius`) | `findings` (`impact_breakdown`), `assets` (`blast_radius_score`) | Blast Radius meter in Finding Detail, Asset Panel | `tests/test_blast_radius.py` | B (org-wide dep. confusion), C (transitive backdoor) |
| R-20 | **React Flow Visualization** — Render an interactive, pannable, zoomable security graph in the browser using React Flow | `frontend/src/components/graph/SecurityGraph.tsx`, `frontend/src/components/graph/nodes/`, `frontend/src/components/graph/edges/` | `GET /api/v1/graph/{scan_id}` | — (client-side state) | Graph View (primary screen) | `tests/frontend/SecurityGraph.test.tsx` | A, B, C, D, E |
| R-21 | **Scan Comparison (Delta Analysis)** — Compare two scans to identify new, resolved, and persisted findings; show package and risk-score changes | `backend/app/comparison/scanner.py`, `backend/app/comparison/diff.py` | `GET /api/v1/compare/{scan_a_id}/{scan_b_id}` | `scan_comparisons` | Comparison View (split panel showing scan A vs B) | `tests/test_scan_comparison.py` | — |
| R-22 | **Demo Scenarios A–E** — Provide five deterministic, richly-annotated demo scenarios covering all major attack types | `backend/app/demo/scenarios/scenario_a.py`, `scenario_b.py`, `scenario_c.py`, `scenario_d.py`, `scenario_e.py`, `backend/app/demo/loader.py` | `POST /api/v1/analyze/demo` | Loaded from static fixture files, optionally persisted | Demo Selector on landing page | `tests/test_demo_loader.py`, `tests/test_demo_scenarios.py` | A, B, C, D, E |
| R-23 | **Server-Side Graph Layout** — Compute node positions on the server using NetworkX layout algorithms so the frontend receives pre-positioned nodes | `backend/app/graph/layout.py` (NetworkX `spring_layout`, `dot` via PyGraphviz, custom hierarchical) | `GET /api/v1/graph/{scan_id}` (`nodes[].position`) | `graph_nodes` (`position_x`, `position_y`) | Graph View (positions applied at load) | `tests/test_graph_layout.py` | A, B, C, D, E |
| R-24 | **Gemini Explanation Layer** — Use Google Gemini to generate a human-readable narrative explaining findings, attack paths, and recommendations | `backend/app/explanation/gemini_explainer.py`, `backend/app/explanation/prompt_builder.py` | `POST /api/v1/analyze` (`enable_gemini_explanation`), `POST /api/v1/analyze/demo` (`include_gemini_explanation`), `GET /api/v1/findings/{finding_id}` (`gemini_explanation`) | `findings` (`gemini_explanation`), `scans` (`gemini_explanation`) | Gemini Explanation card in Scan Summary and Finding Detail | `tests/test_gemini_explainer.py` (mocked Gemini API) | A–E (optional) |

---

## Module → File Mapping

| Module Area | File Path |
|---|---|
| GitHub Ingestion | `backend/app/ingestion/github_client.py` |
| File Fetcher | `backend/app/ingestion/file_fetcher.py` |
| Lockfile Parsers | `backend/app/ingestion/lockfile_parser.py` |
| PURL Normalizer | `backend/app/purl/normalizer.py` |
| PURL Parser | `backend/app/purl/parser.py` |
| Graph Builder | `backend/app/graph/builder.py` |
| Graph Traversal | `backend/app/graph/traversal.py` |
| Graph Layout | `backend/app/graph/layout.py` |
| Attack Path Tracer | `backend/app/graph/attack_paths.py` |
| Origin Detector | `backend/app/graph/origin_detector.py` |
| Typosquatting Detector | `backend/app/detection/typosquatting.py` |
| Dependency Confusion Detector | `backend/app/detection/dependency_confusion.py` |
| Suspicious Update Detector | `backend/app/detection/suspicious_update.py` |
| Dormant Logic Detector | `backend/app/detection/dormant_logic.py` |
| Obfuscation Detector | `backend/app/detection/obfuscation.py` |
| AST Analyzer | `backend/app/analysis/ast_analyzer.py` |
| Metadata Analyzer | `backend/app/analysis/metadata_analyzer.py` |
| CI/CD Analyzer | `backend/app/analysis/cicd_analyzer.py` |
| Runtime Simulator | `backend/app/analysis/runtime_simulator.py` |
| OSV Client | `backend/app/osv/client.py` |
| OSV Cache | `backend/app/osv/cache.py` |
| OSV Batch Querier | `backend/app/osv/batch_querier.py` |
| CycloneDX SBOM Generator | `backend/app/sbom/cyclonedx_generator.py` |
| Confidence Engine | `backend/app/scoring/confidence.py` |
| Impact Engine | `backend/app/scoring/impact.py` |
| Risk Scorer | `backend/app/scoring/risk.py` |
| Origin Scorer | `backend/app/scoring/origin_score.py` |
| Evidence Correlator | `backend/app/evidence/correlator.py` |
| Evidence Aggregator | `backend/app/evidence/aggregator.py` |
| Propagation Explainer | `backend/app/explanation/propagation.py` |
| Gemini Explainer | `backend/app/explanation/gemini_explainer.py` |
| Prompt Builder | `backend/app/explanation/prompt_builder.py` |
| Recommendation Generator | `backend/app/recommendations/generator.py` |
| Scan Diff | `backend/app/comparison/diff.py` |
| Demo Loader | `backend/app/demo/loader.py` |
| Demo Scenario A | `backend/app/demo/scenarios/scenario_a.py` |
| Demo Scenario B | `backend/app/demo/scenarios/scenario_b.py` |
| Demo Scenario C | `backend/app/demo/scenarios/scenario_c.py` |
| Demo Scenario D | `backend/app/demo/scenarios/scenario_d.py` |
| Demo Scenario E | `backend/app/demo/scenarios/scenario_e.py` |
| React Flow Graph | `frontend/src/components/graph/SecurityGraph.tsx` |
| Package Node | `frontend/src/components/graph/nodes/PackageNode.tsx` |
| Repository Node | `frontend/src/components/graph/nodes/RepositoryNode.tsx` |
| Service Node | `frontend/src/components/graph/nodes/ServiceNode.tsx` |
| Pipeline Node | `frontend/src/components/graph/nodes/PipelineNode.tsx` |
| Dependency Edge | `frontend/src/components/graph/edges/DependencyEdge.tsx` |
| Attack Edge | `frontend/src/components/graph/edges/AttackEdge.tsx` |

---

## Database Entity → Requirements Mapping

| DB Entity | Tables/Columns | Requirements Served |
|---|---|---|
| Repositories | `repositories (id, url, owner, name, description, stars, default_branch, created_at)` | R-01, R-14 |
| Scans | `scans (id, repository_id, status, branch, commit_sha, started_at, completed_at, is_demo, sbom_json, gemini_explanation, previous_scan_id)` | R-01, R-10, R-11, R-21, R-24 |
| Packages | `packages (id, name, ecosystem, purl_name)` | R-01, R-13 |
| Package Versions | `package_versions (id, package_id, version, purl, published_at, is_suspicious, author, license)` | R-01, R-02, R-13 |
| Assets | `assets (id, scan_id, asset_type, name, is_critical, is_affected, blast_radius_score)` | R-01, R-18, R-19 |
| Graph Nodes | `graph_nodes (id, scan_id, node_id, node_type, label, is_suspicious, is_origin_candidate, is_affected, severity, position_x, position_y)` | R-01, R-17, R-20, R-23 |
| Graph Edges | `graph_edges (id, scan_id, source_node_id, target_node_id, edge_type, is_direct, depth, is_attack_path)` | R-01, R-04, R-07 |
| Findings | `findings (id, scan_id, finding_type, severity, status, confidence_score, impact_score, risk_score, is_transitive, transitive_depth, gemini_explanation)` | R-02, R-05, R-07, R-09, R-24 |
| Evidence Items | `evidence_items (id, finding_id, evidence_type, source, summary, raw_data, weight)` | R-03, R-08, R-12, R-16 |
| Attack Paths | `attack_paths (id, scan_id, finding_id, origin_node_id, target_asset_id, severity, confidence, path_length)` | R-04, R-17, R-18 |
| Attack Path Nodes | `attack_path_nodes (id, attack_path_id, node_id, label, node_type, depth, is_origin, is_target)` | R-04, R-09 |
| Recommendations | `recommendations (id, finding_id, action_type, priority, title, description, implementation_steps, estimated_effort)` | R-06 |
| OSV Vulnerabilities | `osv_vulnerabilities (id, finding_id, osv_id, severity, description, affected_versions, references)` | R-12 |
| OSV Cache | `osv_cache (purl, response_json, fetched_at, expires_at)` | R-12 |
| Scan Comparisons | `scan_comparisons (id, scan_a_id, scan_b_id, risk_delta, finding_delta_json, package_delta_json)` | R-21 |

---

## UI Screen → Requirements Mapping

| Screen | Path | Requirements Served | Key Components |
|---|---|---|---|
| Landing / Home | `/` | R-22 (demo selector) | DemoScenarioSelector, AnalyzeForm, RecentScans |
| Analyze Form | `/analyze` | R-01, R-02, R-03, R-14 | AnalysisOptionsForm, URLInput, ProgressIndicator |
| Scan Summary | `/scans/{scan_id}` | R-01, R-05, R-11 | SummaryStats, RiskScoreBadge, SBOMDownload, GeminiExplanation |
| Graph View | `/scans/{scan_id}/graph` | R-01, R-04, R-07, R-09, R-17, R-18, R-20, R-23 | SecurityGraph (React Flow), GraphControls, NodeTooltip, AttackPathOverlay |
| Findings Panel | `/scans/{scan_id}/findings` | R-02, R-05, R-07 | FindingsList, SeverityFilter, TypeFilter |
| Finding Detail | `/scans/{scan_id}/findings/{finding_id}` | R-02, R-05, R-06, R-08, R-09, R-12, R-18, R-19, R-24 | FindingHeader, EvidenceList, PropagationPath, AffectedAssets, Recommendations, GeminiCard |
| Attack Paths | `/scans/{scan_id}/attack-paths` | R-04, R-09, R-17 | AttackPathList, PathVisualization |
| Assets Panel | `/scans/{scan_id}/assets` | R-18, R-19 | AssetList, BlastRadiusMeter |
| Comparison View | `/compare/{scan_a_id}/{scan_b_id}` | R-21 | DeltaSummary, FindingDiff, PackageDiff, RiskScoreChart |
| Scan History | `/history` | R-10 | ScanHistoryTable, StatusBadge |

---

## Test Coverage → Requirements Mapping

| Test File | Layer | Requirements Covered |
|---|---|---|
| `tests/test_lockfile_parser.py` | Unit | R-01, R-13, R-14 |
| `tests/test_github_client.py` | Unit (mocked) | R-14 |
| `tests/test_purl_normalizer.py` | Unit | R-13 |
| `tests/test_graph_builder.py` | Unit | R-01 |
| `tests/test_graph_layout.py` | Unit | R-23 |
| `tests/test_attack_path_tracer.py` | Unit | R-04, R-07, R-17 |
| `tests/test_transitive_detection.py` | Unit | R-07 |
| `tests/test_origin_detector.py` | Unit | R-17 |
| `tests/test_affected_asset_determination.py` | Unit | R-18 |
| `tests/test_blast_radius.py` | Unit | R-19 |
| `tests/test_typosquatting_detector.py` | Unit | R-02 |
| `tests/test_dependency_confusion.py` | Unit | R-02 |
| `tests/test_obfuscation_detector.py` | Unit | R-02 |
| `tests/test_ast_analyzer.py` | Unit | R-03 |
| `tests/test_metadata_analyzer.py` | Unit | R-03 |
| `tests/test_cicd_analyzer.py` | Unit | R-15 |
| `tests/test_runtime_simulator.py` | Unit | R-16 |
| `tests/test_osv_client.py` | Unit (mocked) | R-12 |
| `tests/test_osv_cache.py` | Unit | R-12 |
| `tests/test_sbom_generator.py` | Unit | R-11 |
| `tests/test_confidence_engine.py` | Unit | R-05 |
| `tests/test_impact_engine.py` | Unit | R-05 |
| `tests/test_risk_scoring.py` | Unit | R-05 |
| `tests/test_evidence_correlator.py` | Unit | R-08 |
| `tests/test_propagation_explainer.py` | Unit | R-09 |
| `tests/test_gemini_explainer.py` | Unit (mocked) | R-24 |
| `tests/test_recommendation_generator.py` | Unit | R-06 |
| `tests/test_scan_comparison.py` | Unit | R-21 |
| `tests/test_reanalysis.py` | Unit | R-10 |
| `tests/test_demo_loader.py` | Unit | R-22 |
| `tests/test_demo_scenarios.py` | Unit | R-22 |
| `tests/integration/test_analyze_endpoint.py` | Integration | R-01, R-02, R-03, R-04, R-05, R-06 |
| `tests/integration/test_attack_paths_endpoint.py` | Integration | R-04, R-09, R-17 |
| `tests/integration/test_graph_endpoint.py` | Integration | R-20, R-23 |
| `tests/integration/test_demo_endpoint.py` | Integration | R-22 |
| `tests/integration/test_comparison_endpoint.py` | Integration | R-21 |
| `tests/integration/test_payload_structure.py` | Integration (golden file) | R-01–R-24 (full contract) |
| `tests/frontend/SecurityGraph.test.tsx` | Frontend (Jest) | R-20 |
| `tests/frontend/FindingDetail.test.tsx` | Frontend (Jest) | R-05, R-06, R-08, R-09 |

---

## Demo Scenario → Requirements Mapping

| Scenario | Name | Primary Requirement | Secondary Requirements | Packages | Findings | Risk Score |
|---|---|---|---|---|---|---|
| **A** | Typosquatting Supply Chain | R-02 (typosquatting) | R-01, R-04, R-05, R-06, R-08, R-09, R-13, R-17, R-18 | 12 | 3 (1×HIGH, 2×MEDIUM) | 72.0 |
| **B** | Dependency Confusion Attack | R-02 (dep. confusion) | R-01, R-04, R-05, R-06, R-07, R-08, R-13, R-17, R-18, R-19 | 18 | 4 (2×CRITICAL, 2×HIGH) | 95.0 |
| **C** | Transitive Backdoor (Dormant Logic) | R-07 (transitive threat), R-02 (dormant logic) | R-01, R-03, R-04, R-05, R-06, R-08, R-09, R-16, R-17, R-18 | 35 | 6 (2×CRITICAL, 3×HIGH, 1×MEDIUM) | 91.0 |
| **D** | CI/CD Pipeline Poisoning | R-15 (CI/CD analysis), R-02 (obfuscation) | R-01, R-03, R-04, R-05, R-06, R-08, R-09, R-17, R-18 | 24 | 5 (1×CRITICAL, 3×HIGH, 1×MEDIUM) | 88.0 |
| **E** | Compromised Maintainer | R-02 (suspicious update, metadata anomaly) | R-01, R-04, R-05, R-06, R-08, R-09, R-12, R-17, R-18 | 20 | 4 (1×HIGH, 3×MEDIUM) | 68.0 |

---

## Judging Criteria → Requirements Mapping

| Judging Criterion | Mapped Requirements | Key Modules | Demo Evidence |
|---|---|---|---|
| **Malicious-component detection accuracy** | R-02, R-03, R-08, R-12 | `detection/`, `analysis/`, `evidence/`, `osv/` | Scenarios A (typosquatting), B (dep. confusion), C (dormant logic), D (obfuscation), E (metadata anomaly) |
| **Dependency / attack-path analysis** | R-01, R-04, R-13 | `graph/builder.py`, `graph/attack_paths.py`, `purl/` | All 5 scenarios — Attack Path tab in UI |
| **Transitive-threat detection** | R-07 | `graph/traversal.py` (BFS with depth ≤ max_transitive_depth) | Scenario C — backdoor at dependency depth 3 |
| **Origin and propagation tracing** | R-09, R-17 | `graph/origin_detector.py`, `explanation/propagation.py` | All 5 scenarios — Propagation Path in Finding Detail |
| **Impact / confidence assessment** | R-05, R-19 | `scoring/confidence.py`, `scoring/impact.py`, `scoring/risk.py` | Risk Score displayed on every finding; Impact Breakdown modal |
| **Containment recommendations** | R-06 | `recommendations/generator.py` | Recommendations tab in every Finding Detail screen |
| **Innovation in supply-chain security** | R-03 (AST), R-15 (CI/CD), R-16 (simulated runtime), R-24 (Gemini), R-23 (server-side layout), R-21 (delta comparison) | `analysis/`, `explanation/gemini_explainer.py`, `graph/layout.py`, `comparison/` | Scenario D (CI/CD poisoning with obfuscation + Gemini explanation), Gemini narrative on all scenarios |

---

## Requirements Coverage Summary

| Total Requirements | Covered by Module | Covered by API | Covered by DB | Covered by UI | Covered by Test | Covered by Demo |
|---|---|---|---|---|---|---|
| 24 | 24 (100%) | 24 (100%) | 21 (87.5%) | 22 (91.7%) | 24 (100%) | 22 (91.7%) |

> Requirements R-10 (continuous re-analysis) and R-21 (scan comparison) are not exercised in demo scenarios A–E but are verified by integration tests and accessible via the UI.

---

*SupplyGraph Requirements Traceability Matrix — HackFusion 2026 — Theme 6: Software Supply-Chain Attack Graph Engine*
