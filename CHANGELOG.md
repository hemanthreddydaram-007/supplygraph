# CHANGELOG.md
# SupplyGraph Presentation Deck — Round 1 Silent Screening Audit Fixes
# Files: SupplyGraph_Final_v5.pptx & SupplyGraph_Blue_Final.pptx
# Date: October 19, 2026

This document records every modification made to the hackathon pitch deck to resolve all 26 Claude Evaluator deductions, satisfy strict evidence-first screening criteria, and guarantee 100% repo verifiability in under 15 seconds per slide.

---

## 1. Global & Architectural Corrections

| Category | Prior Deck Wording | New Verified Wording | Reason for Change | Evidence Reference |
|---|---|---|---|---|
| **JS/TS Parser** | "tree-sitter AST engine" | "Token-Sanitized Pattern Engine" | `tree-sitter` is not in requirements or codebase; JS/TS uses regex on stripped tokens. | `code_reviewer.py:14-44`, `VERIFIED_FACTS.md:12` |
| **LLM Model** | "Gemini 1.5 Flash" | "Gemini 2.5 Flash" (with Bedrock Claude 3.5 fallback) | Gemini 1.5 is retired; codebase pinned to `gemini-2.5-flash`. | `gemini_service.py:25`, `VERIFIED_FACTS.md:25` |
| **CI Systems** | "GitHub Actions, GitLab CI & Jenkins" | "GitHub Actions & GitLab CI" | Jenkins was never implemented in repo; GitLab CI parser added to `cicd_analyzer.py`. | `cicd_analyzer.py:45-85` |
| **Threat Engine** | "5-Layer Threat Fabric Engine" | "5-Layer Threat Engine" | Removed "Fabric" marketing buzzword; matches exact 5 modular pipeline steps. | `analysis_service.py:185-390` |
| **Blockchain Attestation** | Truncated fake hash `0x7f9c...3a8b` | "Target: Polygon Amoy Testnet (Deployment Pending)" | No on-chain broadcast was made; honest labeling with reproducible scripts. | `scripts/deploy_amoy.py`, `docs/EVIDENCE.md:136` |
| **Full-Suite Coverage** | "94% Core Coverage" | "74% Full-Suite Line Coverage (Core Engines: 87%–100%)" | Real measured line coverage is 74% across all 3,037 statements; 87%–100% on core security detectors. | `pytest backend/tests/ --cov=backend/app` |
| **Sandbox Execution** | "Zero-host detonation" | "Isolated Docker runner (--network none) with subprocess fallback" | Host execution risk cannot be mathematically zeroed; accurately describes dual-mode runner. | `sandbox.py:43-65`, `test_sandbox_truth.py` |
| **Competitor Socket Cell** | Socket: "Isolated Install Detonation = Yes" | Socket: "Isolated Install Detonation = Partial*" | Socket documentation highlights static heuristics on lifecycle scripts, not container sandbox. | Socket public docs (Oct 2026) |

---

## 2. Slide-by-Slide Audit & Text Changes

### Slide 1: Title Slide (Hero Card & Verifiable Proof Banner)
- **Slide 1 Banner Line 1:**
  - *Old:* `WORKING PROTOTYPE — LIVE & DEPLOYED`
  - *New:* `WORKING PROTOTYPE — EVIDENCE-LINKED`
  - *Reason:* Replaces bare assertion with link to verified evidence dossier and public repository commit.
  - *Evidence Path:* `docs/EVIDENCE.md`
- **Slide 1 Banner Line 2:**
  - *Old:* `https://supplygraph-five.vercel.app  |  128/128 Pytest Passing (94% Core Coverage)  |  Polygon Amoy Anchor: 0x7f9c...3a8b`
  - *New:* `Frontend: https://supplygraph-five.vercel.app   |   GitHub: hemanthreddydaram-007/supplygraph (Commit: 6f3c2b4)`
  - *Reason:* Eliminates fake transaction hash, provides direct GitHub repository link and Git commit SHA.
  - *Evidence Path:* Git commit log
- **Slide 1 Banner Line 3 & 4:**
  - *Old:* None / Truncated text
  - *New:* `Automated Tests: 130/130 Passed   |   Coverage: 74% Full-Suite Line Coverage (Core Engines: 87%-100%)`  
    `Evidence Dossier: docs/EVIDENCE.md   |   Target: Polygon Amoy Testnet (Deployment Pending)`  
    `*Test coverage and passing tests do not constitute an independent security audit.*`
  - *Reason:* Cites verified test results (130 passing tests) and real coverage, includes mandatory disclaimer.
  - *Evidence Path:* `backend/tests/`, `docs/EVIDENCE.md:37-60`
- **Slide 1 QR Code:**
  - *Addition:* Embedded high-contrast scannable QR code on right of banner linking directly to `https://supplygraph-five.vercel.app`.

---

### Slide 2: Problem Statement (Primary Citations & Footnotes)
- **Top-Right Header Badge:**
  - *Old:* `OWASP: 50% AI CODE = VULNERABLE`
  - *New:* `VERACODE 2025: 45% AI CODE FLAW RATE`
  - *Reason:* OWASP does not publish a 50% stat; Veracode GenAI 2025 report measured 45% flaw rate.
  - *Evidence Path:* Veracode GenAI Code Security Report (Jan 2025)
- **Card 01 (AI Code Security):**
  - *Old:* Generic statement about Copilot without citation.
  - *New:* Citations from Veracode 2025 (100+ LLMs, 80 tasks, 45% flaw rate). Footnoted at 8pt.
- **Card 02 (Open-Source Complexity):**
  - *Old:* "85-90% of code is open source" without primary source.
  - *New:* "Synopsys OSSRA 2024: 96% of codebases contain OSS, 77% of code is OSS." Footnoted at 8pt.
- **Card 03 (Fragmented Context):**
  - *Old:* Casual vendor callouts.
  - *New:* "Ponemon Institute Vulnerability Management Benchmark." Footnoted at 8pt.
- **Card 04 (Install-Time Threats):**
  - *Old:* "Obfuscated install hooks evade static rules."
  - *New:* Clarifies static detection vs dynamic execution telemetry. Footnoted with OpenSSF/Socket 2024.
- **Card 05 (Tamper-Evident Records):**
  - *Old:* Claimed mandatory SLSA L3 compliance.
  - *New:* Reframed around NIST SP 800-218 (SSDF) and EO 14028 Section 4 audit trails without claiming automatic compliance.

---

### Slide 3: Proposed Solution (Two-Tier Sync, Formulas, Worked Example)
- **Card 01 (Dependency Attack Graph):**
  - *Old:* Variables in Blast Radius formula undefined; 60 FPS placed in middle of equation.
  - *New:* Defined $B = \min(100, 2P + 15S + 25A + 50D)$ with $(P, S, A, D)$ parameter definitions; $C = 1 - \prod(1 - w_i r_i)$; added concrete wasmtime worked example ($P=16, S=1 \implies B=47/100, C=0.88$).
- **Card 02 (Two-Tier AI Code Reviewer):**
  - *Old:* Mentioned legacy Gemini 1.5; omitted two-tier architecture.
  - *New:* Defined Tier 1 (deterministic AST + token-sanitized regex, <50ms/file) and Tier 2 (Gemini 2.5 Flash unified diff PR synthesis, ~1.2s/finding).
- **Card 03 (Install-Hook Sandbox):**
  - *Old:* Docker-only claim with contradictory mentions of subprocess.
  - *New:* Dual-mode Docker container (`--network none`, 512MB RAM, 10s watchdog) with restricted subprocess fallback.
- **Card 04 (CI/CD Pipeline Security):**
  - *Old:* Mentioned Jenkins parsing.
  - *New:* Scoped strictly to GitHub Actions and GitLab CI YAML parsing; Jenkins removed.
- **Card 05 (Polygon Amoy SBOM Attestation):**
  - *Old:* Claimed live verified transaction on Polygon Amoy with fake hash.
  - *New:* Defined deterministic CycloneDX SHA-256 digest with deployment target Polygon Amoy Testnet.

---

### Slide 4: Key Features & Competitor Matrix
- **F1–F5 Feature Cards:**
  - Upgraded body text to 10pt for readability.
  - Replaced all square brackets with standard parentheses.
  - Corrected model string to Gemini 2.5 Flash.
- **Competitor Matrix Table:**
  - Added dedicated Socket column. Sigstore placed in comprehensive footnote.
  - Full vendor names: "Dependabot", "SonarQube".
  - Row `F3: Isolated Install-Hook Execution`: Socket calibrated to `Partial*` (static analysis of lifecycle scripts; no container sandbox in public docs).
  - Row `F4: On-Chain SBOM Attestation`: Sigstore footnoted as complementary signing/Rekor transparency log.
  - Footnote clearance: Maintained $\ge 0.18\text{ in}$ clearance above dark navy footer bar.

---

### Slide 5: Implementation Approach (4-Stage Pipeline)
- **Stage 1 (Next.js Monorepo Benchmark):**
  - Replaced ambiguous component count with verified explanation: 500 deduplicated package PURLs -> 633 topological graph nodes (repository node + component nodes + CVE nodes) and 891 dependency edges built in 1.8s.
- **Stage 2 (Axios Precision Benchmark):**
  - Documented ground-truth triage: 60 findings evaluated, 56 True Positives (93.3% Precision), 4 False Positives. Explicitly noted recall unmeasured.
- **Stage 3 (Wasmtime Blast Radius Example):**
  - Re-stated worked example: $P=16, S=1, A=0, D=0 \implies B = \min(100, 32+15) = 47/100$, $C = 0.88$.
- **Stage 4 (Pytest Suite & Polygon Attestation):**
  - Updated badge to `✔ 130/130 Pytest Suite Passing (74% Full-Suite Line Coverage) | Target: Polygon Amoy`.

---

### Slide 6: Technology Stack & Architecture Blueprint
- **AI / Sandbox Layer:**
  - Pinned `Gemini 2.5 Flash (AI Triage & Review)` and `AWS Bedrock (Claude 3.5 Fallback)`.
  - Renamed "5-Layer Threat Fabric Engine" to **"5-Layer Threat Detection Engine"** (0 occurrences of "Fabric").
- **Analysis Engine Layer:**
  - Labeled `Python AST + Token-Sanitized Pattern Engine` (0 occurrences of "tree-sitter").
- **Deployment & Verification Banner:**
  - Updated to reflect verified live architecture: Vercel frontend, Render Docker backend worker, Supabase PostgreSQL 15, Target: Polygon Amoy Testnet (Deployment Pending), GitHub Actions CI (130/130 passing).
