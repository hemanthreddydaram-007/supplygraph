# SupplyGraph — Problem Statement Alignment

> **Evaluation Category:** Problem Statement Alignment
> **Target Criteria:** Root Challenge · User Needs · Core Objectives

---

## ✅ Alignment Summary

| Dimension | Coverage | Primary Evidence |
|-----------|----------|------------------|
| **Root Challenge** | All 4 supply-chain failure modes addressed | Section 1 |
| **User Needs** | 3 user groups (Developer, Security Reviewer, DevSecOps) | Section 2 |
| **Core Objectives** | 6 measurable objectives, each traced to modules & tests | Section 3 |
| **Problem → Code Traceability** | End-to-end mapping from problem to implementation & API | Section 4 |
| **Scenario Coverage** | 5 deterministic scenarios (`A`–`E`) verified via API & tests | Section 5 |

---

## Section 1 — Root Challenge

> **Modern applications and AI-assisted codebases pull hundreds of transitive open-source dependencies across npm, PyPI, Go, Cargo, and CI/CD workflows—yet traditional tools produce flat CVE lists without showing structural reachability to exposed services, without inspecting AI-generated source anti-patterns or install-time hooks, and without tamper-evident SBOM integrity fingerprints.**

### The Four Root Failure Modes

1. **Transitive Dependency Blindness & Alert Fatigue:**
   Flat manifest scanners emit hundreds of unprioritized CVE alerts without mapping call-path reachability from application entrypoints to downstream services and deployments.
2. **AI-Generated Code & Package Name Risks:**
   AI coding assistants frequently introduce insecure boilerplate (`eval()`, `exec()`, `subprocess(..., shell=True)`, prototype pollution, XSS sinks, hardcoded credentials) as well as hallucinated, typosquatted, or dependency-confused packages.
3. **Install-Time Lifecycle Hooks & CI/CD Misconfigurations:**
   Compromised `preinstall`/`postinstall` scripts, binary artifacts, and misconfigured CI/CD workflows (unpinned third-party actions, `permissions: write-all`, `curl | bash`, PR context injection) execute outside static dependency manifest checks.
4. **Mutable SBOM Audit Trails:**
   Standard JSON SBOM files lack deterministic SHA-256 posture digests and blockchain-ready attestation primitives for verifying post-scan integrity.

---

## Section 2 — User Needs

### User Group 1: Developer / Student Builder

| Developer Need | SupplyGraph Capability | Implementing File(s) |
|----------------|------------------------|----------------------|
| Identify which CVEs affect reachable services instead of flat lists | NetworkX DAG + Tarjan SCC condensation + bounded path traversal | `backend/app/engines/graph_engine.py`, `backend/app/engines/path_engine.py`, `backend/app/graph/layout.py` |
| Catch insecure AI-generated source patterns & hardcoded secrets | Python stdlib `ast.parse()` visitor + token-sanitized pattern scanner | `backend/app/detectors/ast_analyzer.py`, `backend/app/services/code_reviewer.py` |
| Detect typosquatted & dependency-confused packages | Levenshtein similarity ($\ge 0.85$) + scoped private-namespace analysis | `backend/app/detectors/typosquatting.py`, `backend/app/detectors/confusion_detector.py` |
| Receive non-breaking, line-level code fixes | `CodeReviewItem` buggy/corrected snippets + remediation prompt export | `backend/app/services/code_reviewer.py`, `frontend/src/lib/remediationPromptGenerator.ts` |
| Audit GitHub Actions & GitLab CI YAML workflows | CI/CD YAML analyzer flagging unpinned SHAs, injection, `write-all` | `backend/app/detectors/cicd_analyzer.py` |

### User Group 2: Security Reviewer / Hackathon Evaluator

| Reviewer Need | SupplyGraph Capability | Implementing File(s) |
|---------------|------------------------|----------------------|
| Understand attack paths visually in seconds | Interactive React Flow (`@xyflow/react`) DAG canvas | `frontend/src/components/graph/GraphCanvas.tsx` |
| Quantitative triage priority | Blast Radius $B = \min(100, 2P + 15S + 25A + 50D)$ & Confidence $C$ | `backend/app/engines/confidence.py`, `backend/app/models/core.py` |
| Verifiable, non-hallucinated findings | Typed `FACT` / `HEURISTIC` / `SIMULATED` evidence + OSV advisories | `backend/app/services/osv_client.py` |
| Reproducible instant testing | 5 deterministic demo scenarios (`A`–`E`) + 188 passing pytest tests | `backend/app/scenarios/scenario_*.json` |
| Safe inspection of dangerous install scripts & binaries | Isolated dual-mode sandbox + static PE/ELF/WASM string extraction | `backend/app/execution/sandbox.py`, `backend/app/execution/detonation.py`, `backend/app/execution/router.py` |

### User Group 3: DevSecOps / Compliance Team

| DevSecOps Need | SupplyGraph Capability | Implementing File(s) |
|----------------|------------------------|----------------------|
| Standardized CycloneDX v1.5 SBOM | CycloneDX JSON SBOM embedded in scans and exposed at `/api/v1/sbom/cyclonedx` | `backend/app/services/sbom_engine.py`, `backend/app/api/endpoints.py` |
| Cryptographic integrity & blockchain readiness | Deterministic SHA-256 SBOM digest + posture fingerprint + Solidity contract (Polygon Amoy staged) | `backend/app/services/sbom_engine.py`, `contracts/SupplyGraphAttestation.sol`, `scripts/deploy_amoy.py` |
| Compare security posture across commits/scans | `POST /api/v1/compare` dependency, finding, confidence, and Blast-Radius deltas | `backend/app/api/endpoints.py` |
| Scan local projects offline | `POST /api/v1/analyze/folder` browser folder upload analysis | `backend/app/services/analysis_service.py` |

---

## Section 3 — Core Objectives

### Objective 1: Multi-Ecosystem Attack Graph & Reachability
- Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Cargo.toml`, and CI/CD workflows into canonical PURLs (`pkg:...`).
- Condenses dependency cycles via Tarjan SCC and computes deterministic server-side layouts and bounded attack paths (`PathEngine` + `GraphEngine`).

### Objective 2: 5-Layer Threat Detection Engine
1. **OSV.dev Batch CVE Intelligence:** Canonical PURL queries with SemVer range resolution (`osv_client.py`).
2. **Typosquatting Detector:** Normalized Levenshtein similarity ($\ge 0.85$) against curated top packages (`typosquatting.py`).
3. **Dependency Confusion Detector:** Identifies private/internal scope collisions (`confusion_detector.py`).
4. **Static Code & AST Analyzer:** Python stdlib `ast.parse()` + token-sanitized regex heuristics for JS/TS/Go/Rust (`ast_analyzer.py`, `code_reviewer.py`).
5. **CI/CD Workflow Auditor:** Audits `.github/workflows/*.yml` and `.gitlab-ci.yml` (`cicd_analyzer.py`), complemented by `HistoricAttackDetector`.

### Objective 3: Reproducible Heuristic Risk & Confidence Scoring
- **Blast Radius Formula:** `B = 2P + 15S + 25A + 50D` (clamped at `100.0` at scan summary level in `analysis_service.py`):
  - `P` (`package_count`): Affected packages
  - `S` (`service_count`): Exposed internal/application services
  - `A` (`api_count`): Exposed API endpoints / admin contexts
  - `D` (`production_deployment_count`): Affected production deployments
- **Confidence Index Formula:** `C = 1 - Π(1 - wᵢ × rᵢ)`, explicitly labeled as a **Heuristic Confidence Score** (not a probability of compromise).

### Objective 4: Dual-Mode Behavioral Sandbox & Binary Inspection
- Primary Docker execution (`--network none`, `--memory=512m`, `--cpus=1.0`, 10s wall-clock watchdog) and sanitized restricted subprocess fallback (strips `AWS_*`, `GITHUB_*`, `DATABASE_*` secrets and blocks `..` traversal) in `backend/app/execution/sandbox.py` and `detonation.py`.
- Static PE/ELF/WASM string extraction inspects compiled artifacts without host execution (`execution/router.py`).

### Objective 5: Line-Level Code Review & AI Briefings
- Tier 1 deterministic Python AST + token-sanitized pattern analysis runs locally (`axios/axios` benchmark: $p50 = 14.2\text{ ms/file}$, $p95 = 38.0\text{ ms/file}$, 56/60 TP = 93.3% precision).
- Tier 2 executive briefings use Google `gemini-2.5-flash` with AWS Bedrock `anthropic.claude-3-5-sonnet-20241022-v2:0` fallback and a deterministic summary fallback when no API key is configured (`gemini_service.py`).

### Objective 6: Cryptographic SBOM & Blockchain Integrity
- Generates CycloneDX v1.5 JSON SBOMs (`SBOMEngine.build_sbom`) with deterministic SHA-256 checksums (`compute_sbom_sha256`) and posture fingerprints (`compute_merkle_root`).
- Provides Solidity smart contract [`contracts/SupplyGraphAttestation.sol`](../contracts/SupplyGraphAttestation.sol) and Polygon Amoy scripts [`scripts/deploy_amoy.py`](../scripts/deploy_amoy.py) and [`scripts/verify_attestation.py`](../scripts/verify_attestation.py) (honestly documented as **Deployment Staged / Pending** until broadcast).

---

## Section 4 — Problem → Code Traceability Matrix

| Problem Area | Implementing Module(s) | API Endpoint | Verification Test(s) |
|--------------|------------------------|--------------|----------------------|
| Transitive CVEs & Reachability | `services/osv_client.py`, `engines/graph_engine.py`, `engines/path_engine.py` | `POST /api/v1/scan`, `POST /api/v1/analyze` | `test_osv_version.py`, `test_osv_dedupe_and_hydration.py`, `test_layout.py` |
| Hallucinated / Typosquatted Packages | `detectors/typosquatting.py`, `detectors/confusion_detector.py`, `detectors/historic_attacks.py` | `POST /api/v1/scan` | `test_typosquatting.py`, `test_confusion_detector.py`, `test_historic_attacks.py` |
| Insecure AI-Generated Code Patterns | `detectors/ast_analyzer.py`, `services/code_reviewer.py`, `services/gemini_service.py` | `POST /api/v1/review/code`, `POST /api/v1/review/repository` | `test_ast_analysis.py`, `test_code_reviewer.py` |
| Quantified Risk & Confidence | `engines/confidence.py`, `models/core.py` | `POST /api/v1/scan`, `POST /api/v1/compare` | `test_confidence.py`, `test_scan_comparison.py` |
| Malicious Install Hooks & Binaries | `execution/sandbox.py`, `execution/detonation.py`, `execution/router.py` | `POST /api/v1/sandbox/detonate`, `POST /api/v1/execute/sandbox` | `test_execution_sandbox.py`, `test_sandbox_endpoint.py` |
| CI/CD Workflow Misconfigurations | `detectors/cicd_analyzer.py` | `POST /api/v1/scan` | `test_cicd_analyzer.py` |
| SBOM & Blockchain Attestation | `services/sbom_engine.py`, `contracts/SupplyGraphAttestation.sol` | `GET /api/v1/sbom/cyclonedx`, `POST /api/v1/scan` | `test_analyze_endpoint.py`, `evidence/sbom-attestation.json` |

---

## Section 5 — Scenario Coverage

| Scenario | Fixture Title | Key Demonstration |
|:--------:|---------------|-------------------|
| **A** | Vulnerable Transitive Dependency | `lodash@4.17.20` → `mixin-deep@1.3.1` (`GHSA-4xc9-xhrj-v574`) transitive path |
| **B** | Typosquatting | `requets` vs canonical `requests` detection |
| **C** | Compromised Update | `data-parser@1.2.0 → 1.3.0` obfuscated logic + labeled `SIMULATED` runtime signal |
| **D** | Multi-Level Supply-Chain Propagation | 4-hop `malicious-logger` → Service → API Gateway → Production Deployment |
| **E** | CI/CD Risk | `deploy.yml` external script execution, `write-all` permissions, unpinned action |

---

## Section 6 — Honesty Boundaries

- **Precision, Not "Zero False Positives":** Static analysis reports measured precision (`93.3%`, 56/60 TP on `axios/axios` triage); heuristic findings are labeled `HEURISTIC`.
- **Risk Reduction, Not "Zero Host Risk":** Container controls (`--network none`, 512 MB RAM, 10s watchdog) and restricted subprocess sanitization reduce exposure but do not guarantee zero host risk.
- **Heuristic Scores, Not Probabilities:** Blast-Radius and Confidence formulas use configurable heuristic weights and are not statistically calibrated probabilities.
- **Staged Blockchain Attestation:** Smart contract deployment to Polygon Amoy is staged and explicitly labeled as pending until broadcast.
