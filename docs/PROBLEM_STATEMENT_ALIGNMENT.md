# SupplyGraph — Problem Statement Alignment

> **Target Challenge:** PromptWars – AI Prompt Challenge (*PromptWars x Echo Engineer’s AI Vibeathon 2026*)
> **Evaluation Criteria:** Root Challenge · User Needs · Core Objectives · Dynamic Assistant Context Logic

---

## ✅ Alignment Summary

| Requirement / Criterion | How SupplyGraph Satisfies It | Primary Evidence |
|---|---|---|
| **Chosen Vertical & Persona** | Cybersecurity & AI Developer Safety — Context-Aware AppSec & Supply-Chain Copilot | `README.md`, Section 1 |
| **Smart, Dynamic Assistant** | Context-aware pipeline adapting to ecosystems, graph scale (`>35` auto-filtering), and input artifact types | `backend/app/services/analysis_service.py`, `backend/app/execution/router.py` |
| **Logical Decision Making Based on User Context** | Deterministic routing across lockfiles, AST vs. token-sanitized patterns, OSV SemVer fixes, sandbox modes, and Gemini 2.5 Flash grounding | `backend/app/engines/path_engine.py`, `confidence.py`, `gemini_service.py` |
| **Approach, Logic & How It Works** | 5-layer detection + Tarjan SCC NetworkX DAG + Blast-Radius & Confidence formulas + remediation diffs | Section 3 & Section 4 |
| **Assumptions Made** | Explicit assumptions covering public GitHub/rate limits, heuristic weights, AST vs. regex precision, sandbox modes, LLM fallbacks, and staged Polygon contract | Section 6 |
| **Google Services Integration** | Google Gemini 2.5 Flash (`google-generativeai`) + Google OSV.dev batch API (`api.osv.dev/v1`) | `backend/app/services/gemini_service.py`, `osv_client.py` |
| **Repository Rules Compliance** | Single branch (`main`), public repo, tracked size `4.14 MB` (`< 10 MB`) | Git repository metadata |

---

## Section 1 — Chosen Vertical, Persona & Root Challenge

- **Chosen Vertical:** **Cybersecurity, Threat/Fraud Shield & AI Developer Safety**
- **Assistant Persona:** **Context-Aware Software Supply-Chain Security Copilot**
- **Root Challenge:**
  > Modern applications and AI-assisted codebases pull hundreds of transitive open-source dependencies across npm, PyPI, Go, Cargo, and CI/CD workflows—yet traditional tools emit flat CVE alerts without showing structural reachability to exposed services, without inspecting AI-generated source code patterns or lifecycle install hooks, and without tamper-evident SBOM integrity fingerprints.

### The Four Root Failure Modes Addressed
1. **Transitive Dependency Blindness & Alert Fatigue:** Flat scanners lack multi-hop reachability from entrypoints to downstream services and deployments.
2. **AI-Generated Code & Package Name Risks:** AI coding assistants introduce insecure boilerplate (`eval()`, `exec()`, `subprocess(..., shell=True)`, prototype pollution, XSS sinks, hardcoded secrets) as well as typosquatted or dependency-confused package names.
3. **Install-Time Lifecycle Hooks & CI/CD Misconfigurations:** Malicious `preinstall`/`postinstall` scripts, binary artifacts, and unpinned/over-privileged CI/CD workflows execute outside static manifest checks.
4. **Mutable SBOM Audit Trails:** Standard JSON SBOMs lack deterministic SHA-256 posture digests and blockchain-ready attestation primitives.

---

## Section 2 — User Needs

### User Group 1: Developer / Vibe Coder (Primary)

| User Need | Dynamic Assistant Response | Implementing File(s) |
|---|---|---|
| Separate reachable risks from dormant CVE noise | NetworkX DAG + Tarjan SCC condensation + bounded path traversal (`PathEngine`) | `backend/app/engines/graph_engine.py`, `path_engine.py`, `graph/layout.py` |
| Catch AI-generated source vulnerabilities & secrets | Python stdlib `ast.parse()` visitor + token-sanitized pattern scanner | `backend/app/detectors/ast_analyzer.py`, `services/code_reviewer.py` |
| Detect hallucinated, typosquatted & confused packages | Levenshtein similarity ($\ge 0.85$) + scoped private-namespace collision analysis | `backend/app/detectors/typosquatting.py`, `confusion_detector.py` |
| Fix issues safely without breaking APIs | Line-level `CodeReviewItem` patches + OSV SemVer fix resolution + AI fix prompt generator | `services/osv_client.py`, `code_reviewer.py`, `frontend/src/lib/remediationPromptGenerator.ts` |
| Audit GitHub Actions & GitLab CI pipelines | CI/CD YAML analyzer flagging unpinned SHAs, script injection, `write-all` | `backend/app/detectors/cicd_analyzer.py` |

### User Group 2: Security Reviewer / Hackathon Judge

| Reviewer Need | Dynamic Assistant Response | Implementing File(s) |
|---|---|---|
| Instant visual attack surface | Interactive React Flow (`@xyflow/react`) DAG canvas with auto Attack-Paths-Only mode (`>35` nodes) | `frontend/src/components/graph/GraphCanvas.tsx`, `app/page.tsx` |
| Quantitative triage priority | Blast Radius $B = \min(100, 2P + 15S + 25A + 50D)$ & Confidence $C = 1 - \prod(1 - w_i r_i)$ | `backend/app/engines/confidence.py`, `models/core.py` |
| Verifiable, non-hallucinated findings | Typed `FACT` / `HEURISTIC` / `SIMULATED` evidence + OSV advisories | `backend/app/services/osv_client.py` |
| Reproducible instant testing | 5 deterministic demo scenarios (`A`–`E`) + 188 passing pytest tests | `backend/app/scenarios/scenario_*.json` |
| Safe inspection of install scripts & binaries | Dual-mode sandbox + static PE/ELF/WASM string extraction | `execution/sandbox.py`, `detonation.py`, `router.py` |

### User Group 3: DevSecOps / Compliance Team

| DevSecOps Need | Dynamic Assistant Response | Implementing File(s) |
|---|---|---|
| Standardized CycloneDX v1.5 SBOM | CycloneDX JSON SBOM embedded in scans and served at `/api/v1/sbom/cyclonedx` | `backend/app/services/sbom_engine.py`, `api/endpoints.py` |
| Cryptographic integrity & blockchain readiness | Deterministic SHA-256 SBOM digest + posture fingerprint + staged Polygon Amoy contract | `services/sbom_engine.py`, `contracts/SupplyGraphAttestation.sol`, `scripts/deploy_amoy.py` |
| Compare posture across commits/scans | `POST /api/v1/compare` dependency, finding, confidence, and Blast-Radius deltas | `backend/app/api/endpoints.py` |
| Analyze local/private projects offline | `POST /api/v1/analyze/folder` browser folder upload analysis | `backend/app/services/analysis_service.py` |

---

## Section 3 — Core Objectives & Context-Driven Decision Logic

1. **Multi-Ecosystem Attack Graph & Reachability:**
   Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Cargo.toml`, and CI/CD YAML workflows into canonical PURLs (`pkg:...`), prioritizing lockfiles over raw manifests per directory.
2. **5-Layer Threat Detection Engine:**
   Combines Google OSV.dev batch CVE intelligence, Typosquatting ($\ge 0.85$), Dependency Confusion, Python `ast.parse()` + token-sanitized JS/TS/Go/Rust static patterns, and CI/CD YAML checks (plus `HistoricAttackDetector`).
3. **Closed-Form Heuristic Risk & Confidence Scoring:**
   - **Blast Radius:** `B = 2P + 15S + 25A + 50D` (clamped at `100.0` at scan summary level in `analysis_service.py`), where `P` = affected packages, `S` = exposed services, `A` = exposed APIs, `D` = production deployments.
   - **Confidence Index:** `C = 1 - Π(1 - wᵢ × rᵢ)`, explicitly labeled as a **Heuristic Confidence Score** (not a probability of compromise).
4. **Dual-Mode Behavioral Sandbox & Binary Inspection:**
   Primary Docker isolation (`--network none`, `--memory=512m`, `--cpus=1.0`, 10s watchdog) and sanitized restricted subprocess fallback (`get_sanitized_env()`, Zip-Slip `..` protection, 10s process-tree timeout), plus zero-execution PE/ELF/WASM binary string extraction.
5. **Context-Bounded AI Reasoning (Google Gemini 2.5 Flash):**
   `GeminiService` passes only bounded, verified scan summaries (`<=10` top findings) to `gemini-2.5-flash` with strict anti-hallucination constraints, falling back cleanly to AWS Bedrock Claude 3.5 Sonnet or deterministic summaries.
6. **Cryptographic SBOM Integrity & Blockchain Attestation:**
   CycloneDX v1.5 JSON SBOMs + SHA-256 digests (`sbom_engine.py`), with Solidity smart contract (`contracts/SupplyGraphAttestation.sol`) and deployment tooling (`scripts/deploy_amoy.py`) honestly labeled as **Deployment Staged / Pending**.

---

## Section 4 — Problem → Code Traceability Matrix

| Problem Area | Implementing Module(s) | API Endpoint | Verification Test(s) |
|---|---|---|---|
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
|:---:|---|---|
| **A** | Vulnerable Transitive Dependency | `lodash@4.17.20` → `mixin-deep@1.3.1` (`GHSA-4xc9-xhrj-v574`) transitive path |
| **B** | Typosquatting | `requets` vs canonical `requests` detection |
| **C** | Compromised Update | `data-parser@1.2.0 → 1.3.0` obfuscated logic + labeled `SIMULATED` runtime signal |
| **D** | Multi-Level Supply-Chain Propagation | 4-hop `malicious-logger` → Service → API Gateway → Production Deployment |
| **E** | CI/CD Risk | `deploy.yml` external script execution, `write-all` permissions, unpinned action |

---

## Section 6 — Explicit Assumptions & Honesty Boundaries

1. **Public GitHub / Rate Limits:** Remote scans assume public repositories (or server-side `GITHUB_TOKEN`); offline folder upload handles private/large projects without GitHub API rate limits.
2. **Heuristic Scoring, Not Probabilities:** Blast-Radius and Confidence scores use configurable heuristic weights for triage prioritization and are not statistically calibrated probabilities.
3. **Measured Precision, Not "Zero False Positives":** Static analysis reports measured precision (`93.3%`, 56/60 TP on `axios/axios` triage; recall unmeasured); heuristic findings carry `HEURISTIC` classification.
4. **Risk Reduction, Not "Zero Host Risk":** Container controls (`--network none`, 512 MB RAM, 10s watchdog) and restricted subprocess sanitization reduce exposure without guaranteeing zero host risk.
5. **Staged Blockchain Attestation:** Smart contract deployment to Polygon Amoy is staged and explicitly labeled as pending until broadcast.
