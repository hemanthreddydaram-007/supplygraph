# SUPPLYGRAPH — SYSTEM STATE

**Last Updated:** 2026-10-15  
**Current Milestone:** SUPPLYGRAPH v3.0 — AUTH, OVERVIEW DASHBOARD, FOLDER UPLOAD & AI CODE REVIEWER 🚀  
**Target Event:** YUKTHI 2026 (Mohan Babu University) — Blockchain & Cybersecurity  
**API Version:** v3.0  
**Schema Version:** 3.0.0  
**Graph Model Version:** v3.0  
**Analysis Engine Version:** v3.0  
**Test Suite Status:** 100 Passed, 0 Failures (100% passing)  
**Frontend Build Status:** Next.js 14 Production Build Clean (0 errors, 5/5 static pages)  

---

## v3.0 UPGRADE HIGHLIGHTS 🌟

### 1. Stage 1: Split-Screen Authentication & Evaluator Fast-Pass
- **Live Cyber Telemetry:** Left branding panel with animated attack-graph badge and ASPM status.
- **Multi-Provider Auth:** Email/password credentials, Google Cloud OAuth, and GitHub Developer OAuth.
- **YUKTHI 2026 Judge Fast-Pass:** One-click instant evaluator login bypassing credential typing for hackathon judging.

### 2. Stage 2: Product Overview Dashboard
- **Top Navigation Bar:** Persistent logo, ASPM v3 badge, view tabs (`Overview` | `Scanner & Graph` | `Code Reviewer`), user badge, and glowing `🚀 Get Started →` CTA.
- **Hero Banner:** Explains zero-trust software supply-chain graph theory and AI code remediation.
- **4-Step Architecture Pipeline:** Dual Ingestion → 5-Layer Threat Detection → Reverse DAG Reachability → Auto-Fixer & Polygon Attestation.
- **Enterprise ASPM Features Grid:** 6 cards with live capability descriptions.
- **Competitor Comparison Matrix Table:** Direct feature-by-feature comparison against traditional CVE scanners (Dependabot, npm audit) and static SAST tools (SonarQube, Snyk).

### 3. Stage 3: Dual-Mode Scanner Workspace & Local Folder Upload
- **Mode 1 (GitHub URL):** Live URL scanning with Scenario A–E simulation pills.
- **Mode 2 (Local Folder Upload):** Browser `webkitdirectory` integration to upload, parse, and analyze local projects offline without git pushes.
- **Full Engine Pipeline:** Runs lockfile parser, OSV batch intel, Typosquatting, Dependency Confusion, AST static checks, CI/CD workflow auditing, Reverse DAG attack graph, and Polygon blockchain attestation.

### 4. Stage 4: AI Code Reviewer Engine & Auto-Patcher
- **Hybrid Inspection:** Evaluates Python (`.py`), JavaScript/TypeScript (`.js`, `.ts`, `.tsx`), React JSX, and CI/CD workflows (`.yml`).
- **Detected Rules:** Syntax errors, mutable default arguments, bare `except:`, SQL injection string formatting, hardcoded secrets/API keys, unsafe `eval()`/`exec()`, `subprocess(shell=True)`, weak hashes (`md5`/`sha1`), `dangerouslySetInnerHTML`, loose equality (`==`), unpinned GitHub actions, and excessive permissions (`write-all`).
- **CodeReviewItem Format:** Precise file path, line number, severity, category, problem explanation, ❌ buggy code snippet, and ✅ production-ready corrected replacement code.
- **One-Click Remediation:** Copy corrected code and download patched file snippets.
- **Ad-Hoc Snippet Tester:** Live tester box in the reviewer tab for on-the-spot code evaluation.

## v2.0 UPGRADE HIGHLIGHTS ✅

### 1. 5-Layer Threat Detection Fabric
- **OSV.dev Intelligence:** Live batch CVE queries with persistent cache.
- **Typosquatting Engine:** Levenshtein distance detector identifying namespace squatting.
- **Static AST Code Analyzer:** Detects `subprocess(shell=True)`, `eval()`, `exec()`, `b64decode()`, and credential environment accesses.
- **CI/CD Workflow Scanner (`cicd_analyzer.py`):** Scans `.github/workflows/*.yml` for unpinned actions, script injection via PR titles/branch names, and `write-all` permissions.
- **Dependency Confusion Detector (`confusion_detector.py`):** Scans for internal/private scope hijacking risks.

### 2. Blockchain & CycloneDX SBOM Attestation
- **Deterministic SHA-256 Checksum:** Cryptographic digest of CycloneDX v1.5 SBOM.
- **Merkle Security Root:** Combines repository URL, SBOM digest, and Blast Radius.
- **Polygon Amoy Testnet Attestation (Chain ID: 80002):** One-click MetaMask or simulated relayer anchoring with verifiable Solidity payload.
- **In-App SBOM Modal:** Interactive preview and `.json` export.

### 3. Server-Side Graph Layout v2.0
- **Expanded Spacing:** Horizontal spacing increased to `380px`, vertical spacing to `125px`.
- **Threat-Priority Sorting:** Vulnerable and compromised nodes automatically positioned at the top/center of topological layers.

### 4. Interactive React Flow Canvas & ASPM UI
- **Ghost Border Elimination:** Stripped default React Flow wrapper boxes.
- **Edge Highlighting:** Attack path edges glow in red with animated traversal and arrowheads.
- **Attack-Paths-Only Filter:** Automatically activated on large repos (>35 components) with 1-click toggle to view all nodes.
- **Scenario A–E Quick Switcher:** One-click simulation pills below the URL bar.
- **Interactive Finding Cards:** Click-to-focus on graph nodes + copyable lockfile overrides.
- **Mathematical HUD:** Live metric breakdown and hover formula tooltips.
- **AI Executive Briefing:** Dual AWS Bedrock (Claude 3.5 Sonnet) + Gemini 1.5 Flash support with `.md` export.

## PRODUCTION HOTFIXES VERIFIED (v2.0.1) 🛠️
1. **Attack Paths Only Bi-directional Traversal & Multi-Column Grid Wrapping:**
   - Retains root repository, parent packages, and asset nodes connected to vulnerabilities across 1–3 hops.
   - Fixed vertical skyscraper stacking: capped vertical columns at 8 nodes with horizontal wrapping (`col_offset = idx // 8 * 320px`, `row_offset = idx % 8 * 115px`).
2. **Monorepo & Subdirectory Lockfile/Workflow Discovery:**
   - Uses GitHub Git Trees recursive search (`recursive=1`) and checks common subdirectories (`frontend/`, `backend/`, `client/`, `server/`, etc.) for lockfiles, Python files, and workflows.
3. **Component Deduplication, Chunked OSV Queries, & Typosquat Whitelist:**
   - Deduplicated components (capped at 500) and deduplicated findings by `(finding_type, origin_candidate, vuln_id/title)`.
   - Chunked OSV batch queries into 150-package chunks.
   - Isolated npm vs PyPI ecosystems and added known library whitelist so popular libraries (like `request`) are never flagged as typosquats.
4. **Resolved Real Fixed Version in Containment Snippets:**
   - Eradicated literal `">=patched_version"` in favor of real OSV fixed version, next major increment, or `"latest"`.
5. **Full Test Suite & Production Build Verification:**
   - `pytest backend/tests`: 91 passed in 6.37s.
   - `npm run build`: Next.js 14 production build compiled cleanly with 0 errors.

---

## VERIFIED TEST SUITE
```
pytest backend/tests: 91 passed, 0 failures (100% passing)
npm run build (frontend): Compiled successfully, 0 errors
```
