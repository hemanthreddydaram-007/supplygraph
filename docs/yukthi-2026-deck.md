# SUPPLYGRAPH — YUKTHI 2026 (ROUND 1 PPT DECK)
**Target Submission Deadline:** October 18, 2026, 12:00 PM IST  
**Event:** YUKTHI 2026 | Mohan Babu University  
**Track:** Blockchain & Cybersecurity  
**Sponsors:** AWS, Chai aur Code, Masterji, RTIH  
**Live Platform:** https://supplygraph-five.vercel.app  

---

### SLIDE 1: TITLE & LIVE DEPLOYMENT
- **Title:** SupplyGraph — Zero-Trust Software Supply-Chain Attack Graph & Cryptographic SBOM Integrity Platform
- **Track:** Blockchain & Cybersecurity (YUKTHI 2026)
- **Live System URL:** https://supplygraph-five.vercel.app
- **Team Tagline:** Syncing dependency intelligence, solving transitive blind spots, and scaling zero-trust CI/CD compliance.
- **Key Badges:** 
  - 100% Deterministic DAG Engine with Bounded Traversal
  - Dual AI Intelligence: AWS Bedrock (Claude 3.5 Sonnet) & Google Gemini 2.5 Flash Bounded Triage
  - CycloneDX 1.5 Deterministic SHA-256 Digest (Polygon Amoy Smart Contract Staged)
  - 152 Automated Passing Tests with Full Regression Gates

---

### SLIDE 2: THE PROBLEM STATEMENT
- **800+ Hidden Transitive Dependencies:** Modern applications rely on hundreds of nested packages. Traditional CVE alerts often lack structural reachability context—making it hard to prioritize whether a deeply buried flaw propagates to internet-facing entry points or production assets.
- **Supply-Chain Behavioral Blind Spots:** Advisory databases primarily catalog reported vulnerabilities. Emerging risks such as typosquatted package names (`reqeusts`), suspicious AST patterns (`eval`, `b64decode`, shell invocation), dependency confusion namespace collisions, and unpinned `.github/workflows` actions require proactive multi-layer inspection.
- **Audit Verification & Compliance Gaps:** Software Bill of Materials (SBOMs) in standard deployments often lack a verifiable cryptographic integrity digest linked to the scanned posture, leaving audit trails prone to post-build modification.

---

### SLIDE 3: OUR SOLUTION — SUPPLYGRAPH v2.0 / v3.0
- **Multi-Ecosystem Attack Graph Engine:** Ingests live GitHub repositories and drag-and-drop folders, parses `package-lock.json` (v1–v3), `poetry.lock`, `requirements.txt`, `Cargo.lock`, and `go.mod`, normalizes canonical PURLs, and constructs a NetworkX Directed Acyclic Graph (DAG).
- **5-Layer Hybrid Threat Detection Engine:**
  1. *OSV.dev Batch Intelligence:* Multi-ecosystem vulnerability matching with chunked queries (CHUNK_SIZE=300, Semaphore=25) and local in-memory caching.
  2. *Typosquatting Engine:* Levenshtein distance matching against top ecosystem packages with verified org whitelisting.
  3. *Static AST Code Analyzer:* Detects suspicious patterns including `eval()`, `exec()`, `b64decode()`, and `subprocess(shell=True)`.
  4. *Dependency Confusion Detector:* Identifies scoped and private namespace collision signals between internal and public registries.
  5. *CI/CD Workflow Scanner:* Flags mutable GitHub Actions tags, potential script injection points, and unconstrained `write-all` permissions.
- **Cryptographic SBOM Integrity & Attestation:** Generates standardized CycloneDX v1.5 SBOMs, computes a deterministic SHA-256 posture digest across components and blast radius, with smart contract attestation staged for Polygon Amoy Testnet.

---

### SLIDE 4: MATHEMATICAL SCORING & GRAPH ENGINE
- **Reverse Reachability Traversal:** Inverts dependency trees via bounded `networkx.all_simple_paths` traversal (capped to 5 paths per root pair and 50 paths total) to trace topological structural propagation from origin packages to production assets.
- **Heuristic Confidence Scoring Formula:**
  $$\mathcal{C} = 1 - \prod_{i=1}^n (1 - w_i \times r_i)$$
  *(Weights source reliability $r_i$ and evidence contribution $w_i$, with a 15% discount on synthetic indicators).*
- **Quantified Blast Radius Formula:**
  $$\mathcal{B} = \min(100,\, 2P + 15S + 25A + 50D)$$
  *(Where $P$ = Compromised Packages, $S$ = Internal Services, $A$ = Exposed APIs, $D$ = Production Deployments. Quantifies topological graph impact for triage prioritization, distinct from runtime exploitability).*

---

### SLIDE 5: SYSTEM ARCHITECTURE & AWS INTEGRATION
- **Frontend Layer:** Next.js 14, TypeScript, Tailwind CSS, custom React Flow canvas with topological DAG layout (Deployed on Vercel).
- **Core Graph & Detector Backend:** Python FastAPI, NetworkX DAG Engine, AST & YAML Analyzers, 152 passing automated pytest suites.
- **AI & Cloud Intelligence:** Dual-provider architecture featuring AWS Bedrock (Claude 3.5 Sonnet) & Google Gemini 2.5 Flash bounded by strict anti-hallucination graph payloads and 4-second fail-safe timeouts.
- **Cryptographic Trust Layer:** CycloneDX v1.5 SBOM Engine with deterministic SHA-256 digest + Staged Polygon Amoy Testnet smart contract attestation receipt.

---

### SLIDE 6: LIVE PROTOTYPE PROOF (BENCHMARKS & SCENARIOS)
- **Live Latency Benchmarks:**
  - Built-in Attack Scenarios: < 300 ms response time
  - Local Project Folder Uploads: < 2.0 s total processing time
  - Live Remote GitHub Repositories: < 8.0 s end-to-end (branch caching + bounded traversal)
- **5 Built-In Attack Simulations:**
  - *Scenario A:* Transitive CVE propagation
  - *Scenario B:* Dependency Confusion & Scope hijacking
  - *Scenario C:* Malicious Post-Install AST backdoors
  - *Scenario D:* Depth-4 multi-hop attack chains
  - *Scenario E:* CI/CD Workflow script injection & permission leaks
- **Engineering Rigor:** 152 automated tests verifying parser accuracy, graph determinism, bounded traversal, and mathematical scoring bounds.

---

### SLIDE 7: ROADMAP TO PHYSICAL FINALE (OCT 30–31)
- **Sprint 1 (Now Deployed):** Multi-lockfile ingestion, deterministic graph visualizer, 5-layer hybrid detector engine, CycloneDX 1.5 SBOM export with SHA-256 digest, and staged Polygon smart contract attestation.
- **Sprint 2 (Finale Milestone):**
  1. *Automated GitHub Remediation Bot:* Automated pull requests applying one-click version overrides when Blast Radius > 50.
  2. *AWS Fargate Behavioral Sandbox:* Live ephemeral container sandbox intercepting outbound C2 network calls during package installation using YUKTHI AWS Cloud Credits.
  3. *Historical Posture Diffing:* Scan comparison engine (`/api/v1/compare`) tracking security regressions across release tags.
