# SupplyGraph v3.5 — Competitor Matrix Evidence & Official Documentation Audit

**Audit Date:** October 2026  
**Auditor:** Software Supply-Chain Security Researcher  
**Scope:** Verified against official vendor documentation for commercial/open-source tools as of October 2026.

---

## 1. Official Documentation Sources

1. **Snyk**
   - **Source:** [Snyk Documentation](https://docs.snyk.io/)
   - **Relevant Subsystems:**
     - Snyk Open Source (SCA & Dependency Tree): `https://docs.snyk.io/scan-using-snyk/snyk-open-source`
     - Snyk Reachability Analysis: `https://docs.snyk.io/scan-using-snyk/snyk-open-source/reachability-analysis`
     - Snyk DeepCode AI Fix: `https://docs.snyk.io/scan-using-snyk/snyk-code/ai-engine-and-fix`
   - **Notes:** Reachable vulnerabilities supported primarily for Java and JavaScript; requires runtime context or static call-graph generation in enterprise plans. Does not execute install hooks in an isolated sandbox.

2. **GitHub Dependabot & Dependency Graph**
   - **Source:** [GitHub Code Security Documentation](https://docs.github.com/en/code-security/)
   - **Relevant Subsystems:**
     - Dependency Graph: `https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph`
     - Dependabot Alerts & Security Updates: `https://docs.github.com/en/code-security/dependabot`
   - **Notes:** Generates flat manifests and automated version-bump PRs. Does not provide an interactive multi-hop DAG canvas, reachability scoring, code-level AST vulnerability fixes, sandbox execution, or blockchain attestation.

3. **SonarQube**
   - **Source:** [SonarSource Documentation](https://docs.sonarsource.com/)
   - **Relevant Subsystems:**
     - SonarQube Server / Cloud: `https://docs.sonarsource.com/sonarqube/latest/`
     - AI CodeFix: `https://docs.sonarsource.com/sonarqube/latest/instance-administration/ai-codefix/`
   - **Notes:** Leading SAST tool with AI CodeFix for source flaws. Does not construct multi-hop dependency attack graphs, detonate install hooks, or anchor SBOMs to a blockchain.

4. **Socket**
   - **Source:** [Socket Documentation](https://docs.socket.dev/)
   - **Relevant Subsystems:**
     - Socket for GitHub / npm / PyPI: `https://docs.socket.dev/docs/getting-started`
     - Package Risk & Install Script Inspection: `https://docs.socket.dev/docs/capabilities`
   - **Notes:** Inspects packages for behavioral threats, install scripts, and network calls. Specializes in proactive package registry gating. Does not provide unified SAST + SCA reachability attack graphs or blockchain SBOM attestation.

5. **Sigstore**
   - **Source:** [Sigstore Documentation](https://docs.sigstore.dev/)
   - **Relevant Subsystems:**
     - Cosign: `https://docs.sigstore.dev/cosign/overview/`
     - Rekor Transparency Log: `https://docs.sigstore.dev/rekor/overview/`
     - Fulcio Certificate Authority: `https://docs.sigstore.dev/fulcio/overview/`
   - **Notes:** Industry-standard public-key signing and append-only transparency log (Rekor). Operates as complementary signing infrastructure; does not perform AST scanning, vulnerability graph reachability, or install-hook sandboxing.

---

## 2. Granular Feature-by-Feature Justification (Slide 4 Matrix)

| Feature | SupplyGraph | Snyk | Dependabot | SonarQube | Socket | Sigstore |
|---|---|---|---|---|---|---|
| **Interactive Multi-Hop DAG Canvas** | **Yes** (NetworkX + @xyflow/react) | **Partial** (Dependency tree explorer; lacks unified attack DAG) | **No** (Flat dependency list) | **No** (SAST call graphs, no package DAG) | **No** (Flat package alert view) | **No** (Signing infrastructure only) |
| **Blast Radius Score Formula** | **Yes** ($B = \min(100, 2P+15S+25A+50D)$) | **Partial** (Risk score / Priority score heuristic) | **No** (Raw CVSS score only) | **No** (Remediation effort days) | **No** (Socket score 0-100 package risk) | **No** (N/A) |
| **Cross-Ecosystem Reachability** | **Yes** (Reverse DAG path tracing) | **Yes\*** (Java/JS call-graph reachability) | **No** (No call analysis) | **Partial** (Dataflow within source only) | **No** (Package registry level) | **No** (N/A) |
| **4-Ecosystem Manifest/Lockfile Graph** | **Yes** (npm, PyPI, Go, Cargo) | **Yes** (Multi-ecosystem SCA) | **Yes** (Multi-ecosystem Dependency Graph) | **Partial** (Integrated with 3rd-party SCA) | **Partial** (npm, PyPI, Go focus) | **Partial** (Artifact attestation) |
| **LLM Unified-Diff Remediation** | **Yes** (Gemini 2.5 Flash unified diffs) | **Yes\*** (DeepCode AI Fix) | **No** (Version bump PRs only) | **Yes\*** (AI CodeFix) | **No** (Alerts/blocks, no code diffs) | **No** (N/A) |
| **Unified SAST + SCA + Sandbox Triage** | **Yes** (Single graph-correlated view) | **Partial** (Separate SAST and SCA modules) | **No** (SCA only) | **No** (SAST focus) | **No** (Package security focus) | **No** (Signing only) |
| **Isolated Install-Hook Detonation** | **Yes** (Docker `--network none`, 512MB, 10s) | **No** (Static heuristics) | **No** (Static only) | **No** (Static only) | **Yes\*** (Safe execution / package analysis) | **No** (N/A) |
| **Zero-Host PE/ELF/WASM String Audit** | **Yes** (Static regex / C2 import extractor) | **No** (Source/package level) | **No** (Manifest only) | **No** (Source level) | **Partial** (Binary risk detection) | **No** (Artifact signature verification) |
| **On-Chain / Transparency Attestation** | **Yes** (Polygon Amoy Smart Contract) | **No** (Proprietary dashboard audit log) | **No** (GitHub audit log) | **No** (Server database log) | **No** (Web dashboard) | **Yes\*** (Rekor public transparency log) |
| **CI/CD Pipeline Security & SHA Audit** | **Yes** (YAML token, injection & SHA audit) | **Partial** (Snyk IaC parses GitHub Actions) | **No** (No workflow AST/heuristic audit) | **Partial** (Basic IaC scanning) | **Partial** (Socket CLI for GitHub Actions) | **Partial** (GitHub Actions OIDC signing) |

*\* Footnotes:*
- *Snyk: Reachability requires Enterprise subscription for Java/JS; DeepCode AI Fix covers selected CWEs.*
- *SonarQube: AI CodeFix generates patches for static code findings.*
- *Socket: Detonates package hooks in hosted analysis engine; package-centric, not an ASPM.*
- *Sigstore: Rekor provides cryptographic transparency log for signed artifacts; complementary to SupplyGraph's application security posture management.*
