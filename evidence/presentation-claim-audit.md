# SupplyGraph v3.5 — Presentation Claim Audit Table

**Evaluation Target:** `SupplyGraph_Final_v4.pptx`  
**Audit Standard:** Strict Silent Screening Rubric (YUKTHI 2026 — Blockchain & Cybersecurity Track)  
**Verification Date:** October 19, 2026  

---

## Slide-by-Slide Verification Matrix

| Slide | Stated Claim in Deck | Supporting Source Artifact | Verification Method | Measured Result | Final Audit Status |
|---|---|---|---|---|---|
| **S1** | **Working Prototype Deployed** | `https://supplygraph-five.vercel.app` | Vercel Next.js edge deployment | HTTP 200 Live URL with QR code | **VERIFIED** |
| **S1** | **GitHub Repository & Commit SHA** | `https://github.com/hemanthreddydaram-007/supplygraph` | Git commit verification | Commit `6f3c2b4` on branch `main` | **VERIFIED** |
| **S1** | **130/130 Automated Pytest Suite Passing** | `evidence/benchmark-summary.md` | Pytest test runner (`pytest backend/tests -q`) | 130 passed, 0 failed in 49.60s | **VERIFIED** |
| **S1** | **74% Full-Suite Line Coverage** | Coverage report (`pytest --cov=app`) | Full-suite pytest-cov measurement | 74% total (core detectors 86%–100%) | **VERIFIED** |
| **S1** | **Polygon Amoy Smart Contract 0x5FbDB...0aa3** | `contracts/SupplyGraphAttestation.sol` | Polygonscan Amoy RPC & ABI audit | Contract address verified on Chain ID 80002 | **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED** |
| **S2** | **Veracode 2025: 45% AI Code Flaw Rate** | Veracode GenAI Code Security Report 2025 | Primary literature citation (80 tasks, 100+ LLMs) | 45% introduces OWASP Top-10 flaws | **VERIFIED** |
| **S2** | **Synopsys OSSRA 2024: 77% OSS Composition** | Synopsys OSSRA 2024 & Sonatype State of Supply Chain | Primary literature citation | 77% code is OSS; 96% codebases contain OSS | **VERIFIED** |
| **S2** | **Alert Fatigue & Disconnected Context** | Ponemon Institute Benchmark | Primary literature citation | Flat CVE lists obscure multi-ecosystem reachability | **VERIFIED** |
| **S2** | **Obfuscated Install Hooks Evade Static Rules** | OpenSSF & Socket Malicious Package Research | Primary literature citation | Postinstall scripts & PE/ELF/WASM evasion | **VERIFIED** |
| **S2** | **Mutable JSON SBOMs Lack Cryptographic Provenance** | NIST SP 800-218 (SSDF) & EO 14028 §4 | Official standard citation | Need for immutable cryptographic audit trails | **VERIFIED** |
| **S3** | **Tarjan SCC Condensation & NetworkX Reverse DAG** | `backend/app/engines/layout.py` | Unit test `test_layout.py` | Eliminates cyclic loops into DAG up to 10 hops | **VERIFIED** |
| **S3** | **Formula: B = min(100, 2P + 15S + 25A + 50D)** | `backend/app/engines/confidence.py` | Unit test `test_confidence.py` | Exact formula verified; $P$:Packages, $S$:Services, $A$:API, $D$:Deployments | **VERIFIED** |
| **S3** | **Formula: C = 1 - Prod(1 - wi * ri)** | `backend/app/engines/confidence.py` | Unit test `test_confidence.py` | Exact formula verified; weights $w_i$, reliability $r_i$ | **VERIFIED** |
| **S3** | **Wasmtime Worked Example: B=47/100, C=0.88** | `evidence/benchmark-summary.json` | Deterministic mathematical derivation | $2(16) + 15(1) = 47$; $1 - (0.20)(0.58) = 0.884$ | **VERIFIED** |
| **S3** | **Two-Tier Engine: <50ms AST Scan + Gemini 2.5 Flash** | `backend/app/services/code_reviewer.py` | Benchmark harness & `gemini_service.py` | Deterministic p50: 14.2ms, p95: 38ms; LLM diff: ~1.2s | **VERIFIED** |
| **S3** | **Isolated Docker Sandbox (--network none, 512MB, 10s)** | `backend/app/services/sandbox_runner.py` | Unit test `test_execution_sandbox.py` | Network blocked, memory capped, watchdog killed | **VERIFIED** |
| **S3** | **CI/CD Pipeline Auditor for GitHub Actions & GitLab CI** | `backend/app/detectors/cicd_analyzer.py` | Unit test `test_cicd_analyzer.py` | YAML workflow token, script injection & SHA audit | **VERIFIED** |
| **S3** | **CycloneDX SBOM SHA-256 Polygon Amoy Anchor** | `backend/app/services/sbom_engine.py` | Unit test `test_sbom.py` | Deterministic SHA-256 digest & posture fingerprint | **VERIFIED** |
| **S4** | **5 Core Capabilities Mapped to Competitors** | `evidence/competitor-sources.md` | Vendor documentation audit (Oct 2026) | Defensible Yes/Partial/No distinctions | **VERIFIED** |
| **S4** | **Socket & Sigstore Evaluated Independently** | `evidence/competitor-sources.md` | Separate analysis of package gating vs signing | Differentiates ASPM from transparency log | **VERIFIED** |
| **S5** | **Next.js Benchmark: 500 PURLs -> 633 Nodes, 891 Edges** | `evidence/benchmark-summary.md` | Benchmark harness run | Built in 1.8s, 142MB peak RAM | **VERIFIED** |
| **S5** | **Axios Benchmark: 60 Findings, 56 TP (93.3% Precision)** | `evidence/benchmark-summary.md` | Labeled ground-truth triage | 56 TP, 4 FP (93.3% precision, p95: 38ms) | **VERIFIED** |
| **S5** | **Wasmtime Benchmark: 94 PURLs, B=47/100, C=0.88** | `evidence/benchmark-summary.json` | Deterministic mathematical derivation | $2(16) + 15(1) = 47$; $C=0.88$ | **VERIFIED** |
| **S5** | **Stage 4: 130/130 Pytest Passing & 74% Coverage** | `evidence/benchmark-summary.md` | Automated pytest run | 130 passed, 0 failed in 49.60s | **VERIFIED** |
| **S6** | **Authoritative Technology Stack Layers** | Codebase repository scan | Direct code inspection | Next.js, FastAPI, NetworkX, Gemini 2.5, Web3.py | **VERIFIED** |
| **S6** | **Dual LLM Architecture: Gemini 2.5 Flash + Bedrock Fallback**| `backend/app/services/gemini_service.py` | Code inspection of fallback handler | Primary configured; Bedrock Claude 3.5 adapter ready | **IMPLEMENTED, NOT INDEPENDENTLY VERIFIED** |
| **S6** | **Render Docker + Vercel + Supabase PG 15 Deployment** | Live deployment configurations | Architectural deployment check | Multi-tier live deployment | **VERIFIED** |
