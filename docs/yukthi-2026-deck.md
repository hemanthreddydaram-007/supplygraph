# SUPPLYGRAPH — YUKTHI 2026 (ROUND 1 PPT DECK)
**Target Submission Deadline:** October 18, 2026, 12:00 PM IST  
**Event:** YUKTHI 2026 | Mohan Babu University  
**Track:** Blockchain & Cybersecurity  
**Sponsors:** AWS, Chai aur Code, Masterji, RTIH  
**Live Platform:** https://supplygraph-five.vercel.app  

---

### SLIDE 1: TITLE & LIVE DEPLOYMENT
- **Title:** SupplyGraph — Zero-Trust Software Supply-Chain Attack Graph & On-Chain SBOM Firewall
- **Track:** Blockchain & Cybersecurity (YUKTHI 2026)
- **Live System URL:** https://supplygraph-five.vercel.app
- **Team Tagline:** Syncing dependency intelligence, solving transitive blind spots, and scaling zero-trust CI/CD compliance.
- **Key Badges:** 
  - 100% Deterministic DAG Engine
  - AWS Bedrock (Claude 3.5) & Gemini 1.5 Flash Bounded Triage
  - Polygon Amoy Testnet Anchoring (Chain ID: 80002)

---

### SLIDE 2: THE PROBLEM STATEMENT
- **800+ Hidden Transitive Dependencies:** Modern applications rely on hundreds of nested packages. Traditional CVE scanners produce flat alert fatigue without reachability context—failing to show if a deeply buried flaw touches internet-facing endpoints or deployments.
- **Zero-Day Behavioral Blind Spots:** Advisory databases miss typosquatted packages (`reqeusts`), malicious `postinstall` AST backdoors (`eval`, `b64decode`, shell execution), dependency confusion, and unpinned `.github/workflows` context injections.
- **Mutable Compliance Records:** Software Bill of Materials (SBOMs) remain static files vulnerable to tampering post-build, offering zero verifiable cryptographic authenticity during supply-chain compliance audits.

---

### SLIDE 3: OUR SOLUTION — SUPPLYGRAPH v2.0
- **Multi-Ecosystem Attack Graph Engine:** Ingests live GitHub repositories, parses `package-lock.json` (v1–v3), `poetry.lock`, and `requirements.txt`, normalizes canonical PURLs, and constructs a NetworkX Directed Acyclic Graph (DAG).
- **5-Layer Threat Detection Fabric:**
  1. *OSV.dev Batch Intelligence:* Multi-ecosystem CVE matching with local caching.
  2. *Typosquatting Engine:* Levenshtein distance matching against top ecosystem packages.
  3. *Static AST Code Analyzer:* Detects `eval()`, `exec()`, `b64decode()`, and `subprocess(shell=True)`.
  4. *Dependency Confusion Detector:* Identifies scoped and private namespace collision vulnerabilities.
  5. *CI/CD Workflow Scanner:* Flags mutable GitHub Actions tags, branch script injection, and `write-all` permissions.
- **Immutable Blockchain Attestation:** Generates standardized CycloneDX v1.5 SBOMs, computes a deterministic SHA-256 Merkle root, and anchors the security posture to Polygon Amoy Testnet.

---

### SLIDE 4: MATHEMATICAL SCORING & GRAPH ENGINE
- **Reverse Reachability Traversal:** Inverts dependency trees via `networkx.all_simple_paths` to trace propagation from origin packages up to production services, public APIs, and containers.
- **Heuristic Confidence Scoring Formula:**
  $$\mathcal{C} = 1 - \prod_{i=1}^n (1 - w_i \times r_i)$$
  *(Weights source reliability $r_i$ and evidence contribution $w_i$, with a 15% discount on synthetic indicators).*
- **Quantified Blast Radius Formula:**
  $$\mathcal{B} = \min(100,\, 2P + 15S + 25A + 50D)$$
  *(Where $P$ = Compromised Packages, $S$ = Internal Services, $A$ = Exposed APIs, $D$ = Production Deployments).*

---

### SLIDE 5: SYSTEM ARCHITECTURE & AWS INTEGRATION
- **Frontend Layer:** Next.js 14, TypeScript, Tailwind CSS, custom React Flow canvas with topological DAG layout (Deployed on Vercel).
- **Core Graph & Detector Backend:** Python FastAPI, NetworkX DAG Engine, AST & YAML Analyzers, 91 passing automated pytest suites.
- **AI & Cloud Intelligence:** AWS Bedrock (Claude 3.5 Sonnet) & Google Gemini 1.5 Flash bounded by strict anti-hallucination graph payloads for CISO executive summaries.
- **Web3 Trust Layer:** CycloneDX v1.5 SBOM Engine with deterministic SHA-256 digest + Polygon Amoy Testnet smart contract attestation receipt.

---

### SLIDE 6: LIVE PROTOTYPE PROOF (BENCHMARKS & SCENARIOS)
- **Live Production Ingestion (`fractal-web`):** Parsed 357 components, isolated 12 GHSA vulnerabilities, calculated a 72/100 Blast Radius, and rendered one-click lockfile overrides in < 2.5 seconds.
- **5 Built-In Attack Simulations:**
  - *Scenario A:* Transitive CVE propagation
  - *Scenario B:* Dependency Confusion & Scope hijacking
  - *Scenario C:* Malicious Post-Install AST backdoors
  - *Scenario D:* Depth-4 multi-hop attack chains
  - *Scenario E:* CI/CD Workflow script injection & permission leaks
- **Engineering Rigor:** 91 automated tests verifying parser accuracy, graph determinism, and mathematical scoring bounds.

---

### SLIDE 7: ROADMAP TO PHYSICAL FINALE (OCT 30–31)
- **Sprint 1 (Now Deployed):** Multi-lockfile ingestion, deterministic graph visualizer, 5-layer detector fabric, CycloneDX SBOM export, and Polygon blockchain attestation.
- **Sprint 2 (Finale Milestone):**
  1. *Automated GitHub Remediation Bot:* Automated pull requests applying one-click version overrides when Blast Radius > 50.
  2. *AWS Fargate Behavioral Sandbox:* Live ephemeral container sandbox intercepting outbound C2 network calls during package installation using YUKTHI AWS Cloud Credits.
  3. *Historical Posture Diffing:* Scan comparison engine (`/api/v1/compare`) tracking security regressions across release tags.
