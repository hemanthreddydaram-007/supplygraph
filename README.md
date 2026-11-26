<div align="center">

# SupplyGraph

**Smart Dynamic AI Application Security Assistant & Software Supply-Chain Attack Graph**

*Context-aware AI assistant that protects applications and AI-generated codebases from transitive CVEs, hallucinated dependencies, malicious install hooks, and CI/CD misconfigurations using deterministic graph reachability, Google Gemini 2.5 Flash reasoning, and isolated sandbox verification.*

[![Live Platform](https://img.shields.io/badge/Live%20Platform-supplygraph--five.vercel.app-6366f1?style=for-the-badge&logo=vercel)](https://supplygraph-five.vercel.app)
[![Challenge](https://img.shields.io/badge/Challenge-PromptWars%20x%20AI%20Vibeathon%202026-f59e0b?style=for-the-badge)](https://supplygraph-five.vercel.app)
[![Vertical](https://img.shields.io/badge/Vertical-Cybersecurity%20%26%20AI%20Code%20Defense-10b981?style=for-the-badge)](https://supplygraph-five.vercel.app)
[![Google Gemini](https://img.shields.io/badge/AI-Google%20Gemini%202.5%20Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev)
[![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15%20App%20Router-black?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

---

### [🌐 Live Platform](https://supplygraph-five.vercel.app) • [🎯 Problem Statement Alignment](docs/PROBLEM_STATEMENT_ALIGNMENT.md) • [📐 Architecture](docs/architecture.md) • [📋 Evidence Dossier](docs/EVIDENCE.md) • [⚡ API Contracts](docs/api-contract.md) • [🧪 Demo Scenarios](docs/demo-scenarios.md)

</div>

---

## 🌐 Live Deployed Application — Zero Setup Required

<div align="center">

### 👉 **[https://supplygraph-five.vercel.app](https://supplygraph-five.vercel.app)**

*Deployed Next.js 15 Frontend (Vercel) + FastAPI AI Security Engine (Render) • Instant direct access (no login gate)*

</div>

- **Live Evaluation Flow:** Open [supplygraph-five.vercel.app](https://supplygraph-five.vercel.app), click **Get Started — Scan Project**, and either submit any public GitHub URL, upload a local project folder, or launch any of the 5 preloaded interactive attack scenarios (`A`–`E`).
- **Interactive API Docs:** OpenAPI / Swagger UI exposed by the FastAPI backend at `/api/docs`.

---

## 🧭 Chosen Vertical

- **Event & Track:** **PromptWars – AI Prompt Challenge** (*PromptWars x Echo Engineer’s AI Vibeathon 2026*)
- **Chosen Vertical:** **Cybersecurity, Fraud/Threat Shield & AI Developer Safety** — *Autonomous Application Security Posture Management (ASPM) Assistant*
- **Assistant Persona:** **Context-Aware AppSec & Supply-Chain Copilot** designed for three user personas:
  1. **Developers / Vibe Coders** using AI assistants to scaffold apps and needing safe, non-breaking fixes without CVE alert fatigue.
  2. **Security Reviewers / Evaluators** needing an instant visual attack surface, mathematical triage priority, and safe lifecycle-hook inspection.
  3. **DevSecOps / Compliance Engineers** requiring CycloneDX v1.5 SBOMs, SHA-256 posture digests, and scan-to-scan regression diffs.

### 🚨 The Root Challenge Being Solved
Developers — especially teams rapidly building with AI coding assistants — ship applications containing hundreds of nested open-source packages across **npm, PyPI, Go, Cargo, and GitHub Actions**. Standard dependency scanners flood users with flat CVE lists without showing:
1. Whether a buried transitive vulnerability actually reaches exposed services, APIs, or production deployments.
2. Whether AI-generated source code contains silent security flaws (`eval()`, `exec()`, `subprocess(..., shell=True)`, prototype pollution, XSS sinks, hardcoded keys) or typosquatted / dependency-confused package names.
3. Whether package install hooks (`preinstall`/`postinstall`), compiled artifacts, or CI/CD workflows attempt malicious execution or credential exposure.
4. Whether the resulting Software Bill of Materials (SBOM) has a verifiable cryptographic integrity digest.

---

## 🧠 Approach and Logic

SupplyGraph is architected as a **smart, dynamic assistant** combining **deterministic graph & AST reasoning** with **context-bounded Google Gemini 2.5 Flash intelligence** so that decisions adapt logically to each user's project context without LLM hallucination:

### 1. Logical Decision Making Based on User Context
Depending on what the user provides (GitHub repository URL, local folder upload, raw code snippet, package manifest, or binary/hook payload), the backend dynamically adapts its pipeline:

| User Input / Context | Dynamic Decision & Routing Logic | Implementing Module(s) |
|---|---|---|
| **Polyglot Repo / Lockfiles** | Auto-detects ecosystems (`npm`, `PyPI`, `Go`, `Rust`, `GitHub Actions`, `GitLab CI`), resolves directory-aware lockfile precedence (`package-lock.json` over `package.json`, `Cargo.lock` over `Cargo.toml`), and normalizes canonical PURLs (`pkg:...`). | `lockfile_parser.py`, `analysis_service.py` |
| **Large Graphs (`>35` Components)** | Frontend & layout engine automatically activate **Attack-Paths-Only** filtering and multi-column grid wrapping while keeping full topological graph traversal bounded (`PathEngine`). | `page.tsx`, `layout.py`, `path_engine.py` |
| **Source Code Context (`.py` vs `.js/.ts/.go/.rs`)** | Selects Python stdlib `ast.parse()` (`ASTVisitor`) for Python files and `strip_strings_and_comments()` + token-sanitized regex rules for JS/TS/Go/Rust so comments/mocks do not inflate alerts. | `ast_analyzer.py`, `code_reviewer.py` |
| **Remediation Context** | Resolves non-breaking version upgrades from OSV fixed ranges (`resolve_best_fixed_version`), generates line-level `CodeReviewItem` patches, and synthesizes context-specific AI fix prompts. | `osv_client.py`, `code_reviewer.py`, `remediationPromptGenerator.ts` |
| **Untrusted Script / Binary Payload** | `ExecutionRouter` dynamically routes inputs to Docker isolation (`--network none`, `512m`, `10s`), sanitized subprocess fallback, or static PE/ELF/WASM inspection (zero host execution for binaries). | `execution/router.py`, `sandbox.py`, `detonation.py` |
| **AI Provider Availability** | Uses **Google Gemini 2.5 Flash** (`google-generativeai`) with strict JSON grounding and a 4.0s timeout, falling back to AWS Bedrock Claude 3.5 Sonnet or a deterministic summary if keys are absent/rate-limited. | `gemini_service.py` |

### 2. Google Services & Deterministic Mathematical Scoring
- **Google Gemini 2.5 Flash (`google-generativeai`):** Generates plain-language executive security briefings strictly grounded in the top findings JSON payload — explicitly instructed not to invent CVEs or evidence absent from the scan data.
- **Google OSV.dev Batch API (`api.osv.dev/v1`):** Queries authoritative multi-ecosystem vulnerability advisories in chunked async batches with SemVer range resolution and local caching.
- **Closed-Form Heuristic Risk & Confidence Scoring:**
  - **Blast Radius:** $B = 2P + 15S + 25A + 50D$ (clamped to $\min(100, \dots)$ at the scan summary level), where $P$ = affected packages, $S$ = exposed services, $A$ = exposed APIs, $D$ = production deployments.
  - **Heuristic Confidence Index:** $C = 1 - \prod_{i=1}^{n}(1 - w_i \cdot r_i)$, weighting source reliability $r_i$ and evidence weight $w_i$ (with a $0.15$ synthetic discount on simulated signals).

---

## ⚙️ How the Solution Works

```
User Input (GitHub Repo URL / Local Folder Upload / Code Snippet / Scenario A–E)
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Context Ingestion (analysis_service.py & lockfile_parser.py) │
│    Detects ecosystems · Parses lockfiles · Extracts workflows   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. 5-Layer Threat Engine                                        │
│    ① Google OSV.dev batch CVE lookup (SemVer range evaluation)  │
│    ② Typosquatting heuristics (Levenshtein similarity >= 0.85)  │
│    ③ Dependency confusion (private/internal scope collisions)   │
│    ④ Python stdlib AST + token-sanitized JS/TS/Go/Rust review   │
│    ⑤ GitHub Actions & GitLab CI YAML security audit             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. NetworkX DAG & Heuristic Scoring                             │
│    Tarjan SCC cycle condensation → Bounded path traversal       │
│    → Blast Radius B & Heuristic Confidence C calculation        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Dynamic Assistant Response & Defense                         │
│    Google Gemini 2.5 Flash briefing · Line-level code patches   │
│    Isolated hook sandbox / static binary audit · CycloneDX SBOM │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Interactive ASPM Workspace (Next.js 15 + @xyflow/react)      │
│    Attack graph canvas · Findings drill-down · Code Reviewer    │
│    Sandbox terminal · Scan comparison (/compare) · SBOM export  │
└─────────────────────────────────────────────────────────────────┘
```

### User Workflow & Preloaded Scenarios (`A`–`E`)
1. **Live GitHub or Folder Scan:** Paste a GitHub URL (e.g., `knadh/listmonk`, `axios/axios`) or upload a local folder offline (`POST /api/v1/analyze/folder`).
2. **Interactive Attack Graph & Triage:** Inspect highlighted attack paths on the React Flow DAG canvas, view evidence classification (`FACT`, `HEURISTIC`, `SIMULATED`), and inspect exact Blast-Radius and Confidence breakdowns.
3. **AI Code Reviewer & Sandbox Terminal:** Review file/line-level buggy vs. corrected snippets (`POST /api/v1/review/repository`) and test `preinstall`/`postinstall` hooks or binaries safely (`POST /api/v1/sandbox/detonate` / `/api/v1/execute/sandbox`).
4. **SBOM & Scan Delta:** Export CycloneDX v1.5 JSON SBOM with deterministic SHA-256 digests (`GET /api/v1/sbom/cyclonedx`) or compare posture across commits (`POST /api/v1/compare`).
5. **5 Preloaded Deterministic Scenarios (`POST /api/v1/analyze/demo`):**
   - **Scenario A:** *Vulnerable Transitive Dependency* (`lodash@4.17.20` → `mixin-deep@1.3.1`, `GHSA-4xc9-xhrj-v574`)
   - **Scenario B:** *Typosquatting* (`requets` vs canonical `requests`)
   - **Scenario C:** *Compromised Update* (`data-parser@1.2.0 → 1.3.0`, AST signals + clearly labeled `SIMULATED` runtime trace)
   - **Scenario D:** *Multi-Level Supply-Chain Propagation* (`malicious-logger@0.9.1` 4 hops deep → Service → API Gateway → Production Deployment)
   - **Scenario E:** *CI/CD Risk* (`.github/workflows/deploy.yml` with `curl | bash`, `permissions: write-all`, unpinned action)

---

## 📋 Assumptions Made

1. **Public GitHub API & Rate Limits:** Remote URL scans assume the target repository is public (or accompanied by a server-side `GITHUB_TOKEN`); for large or private projects without token quota, users are guided to the offline **Folder Upload** flow (`/api/v1/analyze/folder`).
2. **Heuristic Scoring Scope:** Blast-Radius ($B$) and Confidence ($C$) weights are configurable heuristics (`config.py`, `confidence.py`) intended for triage prioritization—not statistically calibrated probabilities of compromise or financial loss.
3. **Static Precision vs. Full Semantic Parsing:** Python source analysis uses stdlib `ast.parse()`, whereas JS/TS/Go/Rust files use token-sanitized regex heuristics (`strip_strings_and_comments()`), assuming heuristic classification (`93.3%` measured precision on `axios/axios` 60-finding triage; recall unmeasured) rather than full compiler type resolution.
4. **Sandbox Execution Environment:** Full container controls (`--network none`, `--memory=512m`, `--cpus=1.0`, `10s` watchdog) apply when a Docker daemon is available; on serverless/Windows environments without Docker, the sandbox automatically falls back to a sanitized restricted subprocess (`get_sanitized_env()`, path-traversal jail, `10s` process-tree timeout) and relies on host network policy.
5. **LLM Fallback & Grounding:** If `GEMINI_API_KEY` (or optional AWS Bedrock credentials) is unavailable or times out past `4.0s`, the assistant seamlessly degrades to a deterministic briefing generated directly from verified scan metadata.
6. **Blockchain Attestation Status:** CycloneDX v1.5 JSON SBOM generation and SHA-256 posture digests run live on every scan (`sbom_engine.py`), while EVM on-chain anchoring ([SupplyGraphAttestation.sol](contracts/SupplyGraphAttestation.sol), Polygon Amoy Chain ID `80002`) is explicitly marked as **Deployment Staged / Pending** until broadcast with testnet POL.

---

## 👥 User Needs & Core Objectives Alignment

- **Developers / AI Builders:** Eliminates flat CVE alert fatigue via reachability graphs, flags AI boilerplate risks (`eval`, `pickle`/`subprocess`, prototype pollution, hardcoded secrets), and suggests non-breaking fixes.
- **Security Reviewers / Judges:** Provides deterministic scenarios (`A`–`E`), typed evidence provenance (`FACT` / `HEURISTIC` / `SIMULATED`), and safe binary/hook inspection.
- **DevSecOps Teams:** Delivers CycloneDX v1.5 SBOMs, SHA-256 posture verification, and scan-comparison deltas (`/api/v1/compare`).

For full requirement-by-requirement traceability, see **[docs/PROBLEM_STATEMENT_ALIGNMENT.md](docs/PROBLEM_STATEMENT_ALIGNMENT.md)**.

---

## 📊 Verified Benchmarks & Test Evidence

Full reproducible commands and telemetry live in **[docs/EVIDENCE.md](docs/EVIDENCE.md)** and **[evidence/benchmark-summary.md](evidence/benchmark-summary.md)**:

- **Automated Backend Test Suite:** `python -m pytest tests/ -q` → **188 passed, 0 failed** (unit + integration coverage across parsers, detectors, graph layout, confidence math, sandbox controls, and API endpoints).
- **Wasmtime Worked Math Example (`bytecodealliance/wasmtime`):** 94 package PURLs, 16 findings; $P=16, S=1, A=0, D=0 \implies B = 2(16) + 15(1) = \mathbf{47/100}$, $C = \mathbf{0.88}$.
- **Axios Static Rule Triage (`axios/axios`):** 60 candidate findings evaluated against labeled ground truth → 56 True Positives, 4 False Positives (**93.3% precision**; recall unmeasured); scan latency $p50 = 14.2\text{ ms/file}$, $p95 = 38.0\text{ ms/file}$.
- **Next.js Graph Scaling (`vercel/next.js`):** 500 package components → 633 DAG nodes, 891 edges (1.80s build, 142.4 MB peak RAM).

---

## 🔌 API Reference Summary

Full OpenAPI documentation is served at `/api/docs` on the FastAPI backend (see **[docs/api-contract.md](docs/api-contract.md)**):

| Endpoint | Method | Purpose |
|:---------|:------:|:--------|
| `/api/v1/scan` | `POST` | Canonical entry point — executes the full 5-layer analysis pipeline (alias for `/api/v1/analyze`) |
| `/api/v1/analyze` | `POST` | Primary GitHub repository analysis endpoint |
| `/api/v1/analyze/folder` | `POST` | Analyzes uploaded local project directories offline |
| `/api/v1/analyze/demo` | `POST` | Loads deterministic evaluation scenarios (`A`–`E`) |
| `/api/v1/sandbox/detonate` | `POST` | Detonates package lifecycle hooks in the isolated sandbox |
| `/api/v1/execute/sandbox` | `POST` | Runs `detonate`, `test`, or `auto` sandbox execution / static binary inspection |
| `/api/v1/sbom/cyclonedx` | `GET` | Generates CycloneDX v1.5 JSON SBOM for `?github_url=...` |
| `/api/v1/review/code` | `POST` | Reviews an individual code snippet with line-level fix suggestions |
| `/api/v1/review/repository` | `POST` | Scans repository source files and returns `CodeReviewItem[]` + Markdown report |
| `/api/v1/compare` | `POST` | Computes dependency, finding, confidence, and Blast-Radius deltas between two scans |
| `/api/v1/health` | `GET` | System health check and version status |

---

## 💻 Tech Stack

- **Frontend:** Next.js 15 (App Router), React 18, `@xyflow/react` (React Flow), Recharts, Tailwind CSS, Lucide Icons, TypeScript
- **Backend:** FastAPI, Python 3.11+, NetworkX 3.3, Pydantic v2, Uvicorn, HTTPX
- **AI & Vulnerability Intelligence:** Google Gemini 2.5 Flash (`google-generativeai`), Google OSV.dev REST API (`api.osv.dev/v1`), AWS Bedrock Claude 3.5 Sonnet fallback
- **Static Analysis:** Python stdlib `ast.parse()` (`ASTVisitor`) + Token-Sanitized Pattern Engine (JS/TS/Go/Rust) + YAML CI/CD Analyzer
- **Sandbox & Binary Inspection:** Docker (`--network none`, `--memory=512m`, `--cpus=1.0`, 10s watchdog) with sanitized subprocess fallback + static PE/ELF/WASM extraction
- **Standards & Integrity:** CycloneDX v1.5 JSON SBOM (`cyclonedx-python-lib`), SHA-256 digests, Solidity contract (`contracts/SupplyGraphAttestation.sol`) staged for Polygon Amoy Testnet

---

## 📁 Repository Structure

```
supplygraph/
├── frontend/                     # Next.js 15 App Router Frontend (Vercel)
│   └── src/
│       ├── app/                  # Main workspace & routes
│       ├── components/
│       │   ├── dashboard/        # Overview Dashboard
│       │   ├── graph/            # React Flow attack graph canvas
│       │   ├── reviewer/         # Code Reviewer panel & diffs
│       │   └── sandbox/          # Detonation Sandbox terminal & logs
│       └── lib/                  # API client & remediation prompt generator
├── backend/                      # FastAPI Python Backend (Render)
│   ├── app/
│   │   ├── api/                  # REST API route handlers (/scan, /analyze, /sandbox, /sbom)
│   │   ├── detectors/            # AST, CI/CD, Typosquatting, Confusion & Historic detectors
│   │   ├── engines/              # GraphEngine, PathEngine, Confidence & Containment engines
│   │   ├── execution/            # SecureSandboxRunner, DetonationService & ExecutionRouter
│   │   ├── graph/                # Tarjan SCC layout & schema
│   │   └── services/             # AnalysisService, OSVClient, SBOMEngine, CodeReviewer, GeminiService
│   └── tests/                    # 188 unit & integration tests
├── contracts/                    # Solidity attestation smart contract (Polygon Amoy staged)
├── scripts/                      # Amoy deployment & attestation verification scripts
├── evidence/                     # Benchmark telemetry, claim audit & implementation inventory
├── docs/                         # Architecture, API contract, EVIDENCE.md & PROBLEM_STATEMENT_ALIGNMENT.md
└── README.md
```

---

## 📄 License

MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
<b>SupplyGraph</b> • Single-branch repository (`main`, &lt;10 MB) • Cybersecurity &amp; AI Supply-Chain Defense Assistant
</div>
