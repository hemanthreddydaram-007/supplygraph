# SupplyGraph — Problem Statement Alignment Document

> **Purpose:** This document explicitly maps every stated problem to its concrete implementation
> so that evaluators can verify one-to-one alignment between the problem statement and the
> working solution.

---

## 1. Problem Statement

Modern web and cloud applications are built from hundreds of open-source packages across
**npm, PyPI, Go, and GitHub Actions workflows**. AI-generated codebases amplify this risk
by introducing:

| # | Stated Problem | Severity |
|---|----------------|----------|
| P1 | **Vulnerable & Outdated Dependencies** — AI suggests packages with known CVEs or unpatched transitive dependencies | Critical |
| P2 | **Hallucinated & Typosquatted Packages** — AI hallucinates package names or suggests typosquatted variants | Critical |
| P3 | **Silent Security Flaws** — AI boilerplate includes `pickle.loads`, unsanitized inputs, hardcoded tokens, `permissions: write-all` | High |
| P4 | **Absence of Reachability Verification** — Developers deploy without knowing which CVEs are actually reachable | High |
| P5 | **Reachability Blindspot** — Security tools report thousands of CVEs with no context on which are active vs. dormant | High |
| P6 | **Unsafe Lifecycle Hooks** — Malicious packages embed dangerous code in `preinstall`/`postinstall` hooks | Critical |
| P7 | **CI/CD Pipeline Misconfiguration** — Unpinned actions, excessive runner permissions leak credentials | High |
| P8 | **No SBOM / Compliance Trail** — No standardized software bill of materials for audits and compliance | Medium |

---

## 2. Solution → Implementation Mapping

### P1 — Vulnerable & Outdated Dependencies

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| Multi-ecosystem lockfile ingestion (npm, PyPI, Go, GitHub Actions) | `LockfileParser.parse_lockfile()` supports `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `go.mod`, `Cargo.lock` | `backend/app/services/lockfile_parser.py` |
| CVE lookup via OSV.dev API | `OSVClient.query_batch()` performs batch PURL-based OSV.dev queries with retry, timeout, and cache | `backend/app/services/osv_client.py` |
| Blast-Radius scoring to prioritize remediation | `compute_blast_radius()` applies `B = min(100, 2P+15S+25A+50D)` formula | `backend/app/engines/confidence.py` |
| Surgical lockfile patch recommendations | `ContainmentEngine` generates version-pinning and override recommendations | `backend/app/engines/containment_engine.py` |

### P2 — Hallucinated & Typosquatted Packages

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| Typosquatting detection (edit-distance + Levenshtein) | `TyposquattingDetector.detect()` checks all packages against known-good registry names with configurable similarity threshold (default: 0.85) | `backend/app/detectors/typosquatting.py` |
| Dependency confusion detection (private namespace spoof) | `DependencyConfusionDetector.detect()` identifies private scoped packages that may be confused with public registry names | `backend/app/detectors/confusion_detector.py` |
| Historic malicious package list | `HistoricAttackDetector` cross-references packages against known bad actors (e.g., `flatmap-stream`, `event-stream`) | `backend/app/detectors/historic_attacks.py` |

### P3 — Silent Security Flaws in AI-Generated Code

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| Python AST-based code analysis (`eval`, `exec`, `pickle.loads`, `shell=True`) | `ASTVisitor` traverses the Python AST tree with `ast.NodeVisitor`, detecting real AST nodes — not just regex patterns | `backend/app/detectors/ast_analyzer.py` |
| JavaScript/TypeScript pattern detection (prototype pollution, XSS sinks, `child_process.exec`) | Regex-based pattern engine for JS/TS; labels results as `classification=HEURISTIC` to avoid overclaiming | `backend/app/detectors/ast_analyzer.py` |
| Secret / credential detection (AWS keys, GitHub PATs, OpenAI keys, hardcoded passwords) | `_SECRET_PATTERNS` list of compiled regex patterns scans all source files | `backend/app/detectors/ast_analyzer.py` |
| Line-level AI code review with unified git diffs | `CodeReviewerService.review_files()` returns `CodeReviewItem` with `buggy_code`, `corrected_code`, `line_number`, `file_path` | `backend/app/services/code_reviewer.py` |

### P4 — Absence of Reachability Verification

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| Reverse BFS reachability on NetworkX DAG | `PathEngine` uses `nx.all_simple_paths()` and reverse BFS to find all paths from app entrypoints to vulnerable packages | `backend/app/engines/path_engine.py` |
| Attack graph visualization (animated red reachability paths) | `GraphEngine.build_graph()` constructs a `SecurityGraph` with typed nodes (REPOSITORY, VERSION, VULNERABILITY, ASSET) and edges (CONTAINS, DEPENDS_ON, AFFECTS, REACHES) | `backend/app/engines/graph_engine.py` |
| Distinguishing reachable vs. dormant CVEs | `FindingModel.finding_type` discriminates `VULNERABLE` (OSV-confirmed + reachable) from `SUSPICIOUS` (heuristic only) | `backend/app/models/core.py` |

### P5 — Reachability Blindspot

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| Multi-hop call path tracing | `GraphEngine` builds directed edges from repo → direct deps → transitive deps → vulnerabilities. `PathEngine` traces all hops. | `backend/app/engines/graph_engine.py`, `path_engine.py` |
| Blast-Radius score with documented formula `B = min(100, 2P+15S+25A+50D)` | `compute_blast_radius()` returns score, full breakdown, formula string, and variable definitions | `backend/app/engines/confidence.py` |
| Confidence score with heuristic disclaimer | `compute_confidence()` returns `C = 1 - Π(1 - wᵢ×rᵢ)` score labelled **"Heuristic Confidence Score"** with explicit disclaimer | `backend/app/engines/confidence.py` |

### P6 — Unsafe Lifecycle Hooks

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| Dynamic detonation sandbox for lifecycle hooks | `DetonationService.detonate_project_hooks()` extracts `preinstall`, `install`, `postinstall` scripts and executes them with timeout in a resource-restricted subprocess | `backend/app/execution/detonation.py` |
| Network egress interception | Sandbox environment is configured to block outbound connections; `curl`, `wget`, `bash -c` patterns flagged as violations | `backend/app/execution/detonation.py` |
| Sandbox API endpoints | `POST /api/v1/sandbox/detonate` and `POST /api/v1/execute/sandbox` | `backend/app/api/endpoints.py` |

### P7 — CI/CD Pipeline Misconfiguration

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| GitHub Actions YAML auditing | `CICDAnalyzer.analyze()` parses `.github/workflows/*.yml` for unpinned third-party actions, excessive permissions (`write-all`), and direct secret embedding | `backend/app/detectors/cicd_analyzer.py` |
| Surgical SHA-pinning patch recommendations | Code Reviewer returns a unified diff changing `actions/checkout@v2` → `actions/checkout@<40-char-SHA>` | `backend/app/services/code_reviewer.py`, `backend/app/api/endpoints.py` |

### P8 — No SBOM / Compliance Trail

| Claim | Implementation | File(s) |
|-------|---------------|---------|
| CycloneDX v1.5 JSON SBOM generation with SHA-256 digests | `SBOMEngine` constructs a CycloneDX-compliant SBOM with `bom_ref`, `purl`, and cryptographic component hashes | `backend/app/services/sbom_engine.py` |
| SBOM available as standalone API response | `GET /api/v1/sbom/cyclonedx?github_url=<url>` returns the SBOM JSON; also embedded in every `/scan` response | `backend/app/api/endpoints.py` |

---

## 3. Formula Reference Card

### Blast-Radius Score

```
B = min(100, 2P + 15S + 25A + 50D)
```

| Variable | Meaning | Type | Range |
|----------|---------|------|-------|
| P | Number of distinct reachable dependency paths (transitive depth count) | Integer | ≥ 0 |
| S | 1 if path reaches a sensitive asset; 0 otherwise | Binary flag | {0, 1} |
| A | 1 if path reaches an admin-context asset; 0 otherwise | Binary flag | {0, 1} |
| D | 1 if direct exploit evidence exists; 0 otherwise | Binary flag | {0, 1} |

**Example** (Scenario A — Log4Shell RCE chain):
- P = 3 reachable paths, S = 1 (sensitive DB asset), A = 0, D = 1 (direct RCE exploit)
- B = min(100, 2×3 + 15×1 + 25×0 + 50×1) = min(100, 6+15+0+50) = min(100, 71) = **71.0**

Score is deterministic for identical inputs. Weights are configurable via environment variables. This is a **heuristic score, not a probability of compromise**.

### Confidence Score

```
C = 1 - Π(1 - wᵢ × rᵢ)   for all evidence items i
```

| Symbol | Meaning | Range |
|--------|---------|-------|
| wᵢ | Evidence weight (OSV=0.80, AST=0.60, Typosquatting=0.50, CI/CD=0.60) | [0.0, 1.0] |
| rᵢ | Source reliability (OSV=1.0, GitHub=0.9, AST=0.7, Heuristic=0.5) | [0.0, 1.0] |

Simulated evidence receives an additional synthetic discount of 0.15×. The UI explicitly labels this as **"Heuristic Confidence Score — not a validated probability"**.

---

## 4. API Endpoints (All Verified)

| Endpoint | Method | Maps to Problem |
|----------|--------|----------------|
| `/api/v1/scan` | POST | P1–P8 (full pipeline) |
| `/api/v1/analyze` | POST | P1–P8 (alias) |
| `/api/v1/analyze/demo` | POST | P1–P7 (preloaded scenarios A–E) |
| `/api/v1/sandbox/detonate` | POST | P6 (lifecycle hook execution) |
| `/api/v1/execute/sandbox` | POST | P6 (alias) |
| `/api/v1/sbom/cyclonedx` | GET | P8 (SBOM generation) |
| `/api/v1/review/repository` | POST | P3 (line-level code review) |
| `/api/v1/compare` | POST | P1–P7 (delta between two scans) |
| `/api/v1/health` | GET | Platform availability |
| **API Docs** | GET | `/api/docs` (OpenAPI/Swagger UI) |

---

## 5. Preloaded Scenarios — Problem Coverage Matrix

| Scenario | Problem(s) Demonstrated |
|----------|------------------------|
| **A** — Transitive CVE (Log4j / mixin-deep RCE) | P1 (CVE), P4 (reachability), P5 (blast radius) |
| **B** — Dependency Confusion (internal namespace hijack) | P2 (confusion), P4, P5 |
| **C** — Malicious Post-Install (flatmap-stream) | P6 (lifecycle hooks), P3 (AST curl detection) |
| **D** — Deep Chain (4-hop transitive) | P4 (multi-hop reachability), P5, P1 |
| **E** — CI/CD Workflow Leak (unpinned actions, `write-all`) | P7 (CI/CD), P3 (hardcoded AWS keys) |

---

## 6. What This Project Does NOT Claim

To maintain honesty-first evidence standards:

- ❌ **Not "Zero False Positives"** — AST/heuristic detectors may produce false positives; results labelled `HEURISTIC` or `SIMULATED` accordingly.
- ❌ **Not "Zero Host Risk"** — Sandbox uses resource-limited subprocess isolation, not a full VM/container. Controls reduce exposure but do not guarantee zero host risk.
- ❌ **Not "Probability of Compromise"** — Blast-Radius and Confidence scores are heuristic estimates with configurable, subjective weights.
- ❌ **Not certified by any standard** — CycloneDX SBOM output conforms to v1.5 schema but has not been independently audited.
