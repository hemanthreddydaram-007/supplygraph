# SUPPLYGRAPH — SYSTEM STATE

**Last Updated:** 2026-10-15  
**Current Milestone:** SUPPLYGRAPH v2.0 UPGRADE COMPLETE 🚀  
**Target Event:** YUKTHI 2026 (Mohan Babu University) — Blockchain & Cybersecurity  
**API Version:** v2.0  
**Schema Version:** 2.0.0  
**Graph Model Version:** v2.0  
**Analysis Engine Version:** v2.0  
**Test Suite Status:** 91 Passed, 0 Failures  
**Frontend Build Status:** Next.js 14 Production Build Clean (0 errors)  

---

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
