<div align="center">

# SupplyGraph

**Zero-Trust Application Security Posture Management (ASPM) & Supply-Chain Attack Graph**

*Stop software supply-chain threats before production deployment with deterministic reachability analysis, AST code review, and isolated sandbox detonation.*

[![Live Platform](https://img.shields.io/badge/Live%20Platform-supplygraph--five.vercel.app-6366f1?style=for-the-badge&logo=vercel)](https://supplygraph-five.vercel.app)
[![Target Event](https://img.shields.io/badge/Event-YUKTHI%202026%20Hackathon-f59e0b?style=for-the-badge)](https://supplygraph-five.vercel.app)
[![Track](https://img.shields.io/badge/Track-Cybersecurity%20%26%20ASPM-10b981?style=for-the-badge)](https://supplygraph-five.vercel.app)
[![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-14%20App%20Router-black?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

---

### [🌐 Access Live Platform](https://supplygraph-five.vercel.app) • [📐 System Architecture](docs/architecture.md) • [📋 Evidence Dossier](docs/EVIDENCE.md) • [⚡ API Contracts](docs/api-contract.md) • [🧪 Demo Scenarios Guide](docs/demo-scenarios.md)

</div>

---

## 🌐 Live Platform Access

SupplyGraph is fully deployed and accessible in production without any local environment installation:

<div align="center">

### 👉 **[https://supplygraph-five.vercel.app](https://supplygraph-five.vercel.app)**

*Zero setup required • Instant Evaluator Fast-Pass enabled*

</div>

### Evaluation & Access Details:
- **Instant Login:** Click the **⚡ YUKTHI 2026 Judge Fast-Pass** button on the login screen for 1-click evaluator access with pre-configured permissions.
- **Social Login:** Authenticate using Google OAuth, GitHub, or direct evaluator credentials.
- **Preloaded Demos:** All 5 deterministic scenarios (Scenarios A through E) and repository analysis features are instantly testable on the live cloud environment.
- **REST API Docs:** Interactive OpenAPI swagger contracts are available at `https://supplygraph-five.vercel.app/api/docs`.

---

## 💡 Executive Summary & Problem Statement

Modern web and cloud applications are built from hundreds of open-source packages and dependencies across **npm, Python (PyPI), Go, and GitHub Actions workflows**. While modular ecosystems accelerate development, managing their security has grown exponentially difficult due to deep, multi-tier transitive nesting and modern automated development workflows.

### ⚠️ The Problem Statement: AI-Generated Web Applications & Supply-Chain Blindspots
Today, a rapidly growing number of students, builders, and developers build complete websites and applications using AI coding assistants. While generative AI significantly accelerates prototyping and feature delivery, AI-generated codebases frequently introduce critical security vulnerabilities and architectural errors:
- **Vulnerable & Outdated Dependencies:** AI models often suggest packages with known CVEs, unpatched transitive dependencies, or outdated library versions without verifying upstream security status.
- **Hallucinated & Typosquatted Packages:** Generative AI can hallucinate package names or suggest internal modules that leave projects vulnerable to typosquatting, package hijacking, and dependency confusion attacks.
- **Silent Security Flaws:** AI-generated boilerplate code frequently includes insecure defaults, such as unsanitized input parsing, insecure deserialization (`pickle.loads`), prototype pollution, hardcoded tokens, or overly permissive CI/CD workflow configurations (`permissions: write-all`).
- **Absence of Reachability Verification:** Developers often deploy AI-generated applications directly to production without knowing which imported packages are actually reachable and active in executable paths.

### 🔍 The Reachability Problem
In modern software projects, dependencies frequently nest several levels deep. Security teams and developers are often faced with thousands of reported CVE alerts, but lack critical operational context:
- **Which vulnerabilities are active and reachable** through executable call paths from application entrypoints?
- **Which findings are dormant** (e.g., dead code, uncalled utilities, development-only artifacts) that do not threaten production?
- **How can issues be fixed safely** without breaking live backend APIs or forcing major version jumps?

### The SupplyGraph Approach
**SupplyGraph** is an Application Security Posture Management (ASPM) platform that treats your software supply chain as a **deterministic Directed Acyclic Graph (DAG)**. It maps relationships from user-facing entry points all the way down to nested packages, quantifies operational impact using a mathematically grounded **Blast Radius Score (0–100)**, generates **surgical line-level code patches**, and inspects untrusted lifecycle hooks inside an **isolated container sandbox**.

---

## 🏆 Why SupplyGraph Stands Apart: Key Advantages

SupplyGraph advances supply-chain defense through several core architectural innovations:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CORE ARCHITECTURAL STRENGTHS                                    │
├──────────────────────────┬──────────────────────────┬─────────────────────────┬──────────────────┤
│ 🗺️ Multi-Hop Reachability│ 🎯 Quantified Blast Radius│ 🔍 Surgical AI Patching │ 💥 Sandbox Guard │
│ Reverse BFS DAG maps call│ Mathematical impact      │ Line-level unified diffs│ Dynamic container│
│ paths to vulnerable code │ scoring (0-100)          │ prevent API breaks      │ stops hook traps │
└──────────────────────────┴──────────────────────────┴─────────────────────────┴──────────────────┘
```

1. **Code-Aware Multi-Hop Graph Traversal vs. Isolated Manifest Checking**
   - Traditional security tools evaluate packages in flat, isolated lists.
   - **SupplyGraph's Advantage:** Employs NetworkX server-side topological sort and reverse BFS graph algorithms. It maps exact multi-hop call paths from application controllers down to deeply nested libraries, clearly distinguishing reachable attack paths from unreachable code.

2. **Quantified Blast Radius Algorithm vs. Generic Severity Labels**
   - Rather than relying solely on abstract high/medium tags, SupplyGraph evaluates risk using an objective mathematical formula normalized from **0.0 to 100.0**:
     $$\text{Blast Radius} = \min(100.0, \; 2P + 15S + 25A + 50D)$$
     *(Where $P$ = transitive package depth, $S$ = CVSS severity, $A$ = verified reachable attack paths, and $D$ = direct external exposure).*

3. **Surgical Line-Level Code Auto-Patching vs. Breaking Major Version Jumps**
   - Upgrading an entire major package version often introduces breaking API changes and downtime.
   - **SupplyGraph's Advantage:** The AI Code Reviewer pinpoints the exact file and line numbers where vulnerable methods are invoked, producing surgical unified git diffs that correct the specific vulnerable lines while preserving backward compatibility.

4. **Dynamic Container Detonation Sandbox vs. Static Metadata Scans**
   - Malicious packages often hide dangerous payloads inside lifecycle hooks (`preinstall`, `postinstall`).
   - **SupplyGraph's Advantage:** Features an isolated execution sandbox with zero unauthorized outbound network egress. It intercepts unauthorized external downloaders (`curl | bash`), detects token exfiltration attempts, and detains processes safely.

5. **Multi-Ecosystem Unified Monorepo Observability**
   - Simultaneously indexes npm (`package-lock.json`), PyPI (`requirements.txt`, `poetry.lock`), Go (`go.mod`), and GitHub Actions workflows (`.github/workflows/*.yml`), providing a single pane of glass across frontend, backend, and CI/CD pipelines.

6. **Deterministic Cryptographic Verification**
   - Automatically exports standard CycloneDX v1.5 JSON Software Bill of Materials (SBOM) with SHA-256 integrity digests for verifiable compliance.

---

## 🧪 Comprehensive Scenario Guide (5 Preloaded Evaluator Modes)

SupplyGraph features 5 preloaded real-world scenarios accessible from the header dropdown (`Scenario A` through `Scenario E`). Here is what each scenario demonstrates:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        PRELOADED DETERMINISTIC SECURITY SCENARIOS                      │
├────────────┬─────────────────────────────┬─────────────────┬───────────────────────────┤
│ Scenario   │ Title                       │ Ecosystem       │ Threat Vector             │
├────────────┼─────────────────────────────┼─────────────────┼───────────────────────────┤
│ Scenario A │ Transitive CVE              │ Java / npm      │ Deep Log4j RCE Call Path  │
│ Scenario B │ Dependency Confusion        │ Private npm     │ Internal Namespace Spoof  │
│ Scenario C │ Malicious Post-Install      │ npm Hooks       │ Exfiltration C2 Beacon    │
│ Scenario D │ Deep Chain (Depth 4)        │ Multi-tier JS   │ 4-Hop Transitive Exploit  │
│ Scenario E │ CI/CD Workflow Leak         │ GitHub Actions  │ Unpinned Runner Poisoning │
└────────────┴─────────────────────────────┴─────────────────┴───────────────────────────┘
```

### 🔗 Scenario A: Transitive CVE (Transitive Exploit Chain)
- **The Threat:** Models a severe remote code execution (RCE) vector introduced via a transitive dependency (e.g., `log4j-core:2.14.1` / `mixin-deep:1.3.1`).
- **What SupplyGraph Demonstrates:**
  - Connects the application root entrypoint through intermediate service layers (`demo-app` → `lodash@4.17.20` → `mixin-deep@1.3.1`).
  - Graph nodes highlight the reachability path in animated red, verifying that untrusted user inputs reach the vulnerable component.
  - Computes a contextual Blast Radius score of **85.0/100** and provides non-breaking lockfile override recommendations in the Executive AI panel.

### 🎭 Scenario B: Dependency Confusion (Internal Namespace Hijacking)
- **The Threat:** Simulates a dependency confusion vulnerability in a private corporate module (`@corp-internal/auth-token`).
- **What SupplyGraph Demonstrates:**
  - Identifies that private organization packages lack scoped registry configuration (`.npmrc`), allowing public registries to be probed.
  - Explains how external attackers publish identical package names with higher version numbers (`99.0.0`), tricking build runners into pulling untrusted code.
  - Generates a Blast Radius score of **78.5/100** with step-by-step containment instructions to enforce scoped registry routing.

### 💀 Scenario C: Malicious Post-Install (Lifecycle Hook Injection)
- **The Threat:** Examines a compromised package (`flatmap-stream:0.1.1`) where malicious code is embedded directly within package lifecycle scripts.
- **What SupplyGraph Demonstrates:**
  - AST static pattern detection flags unauthorized subprocess calls (`curl -sSL ... | bash`) intended to harvest environment variables and developer credentials.
  - Allows 1-click execution inside the **Dynamic Detonation Sandbox**, demonstrating zero-egress network containment and process termination with watchdog violation logs.
  - Computes a critical Blast Radius of **92.0/100**.

### 🕸️ Scenario D: Deep Chain (Transitive Depth 4 Propagation)
- **The Threat:** Illustrates vulnerability propagation across an extended, 4-tier dependency hierarchy (`app` → `service` → `middleware` → `utility` → `compromised-core`).
- **What SupplyGraph Demonstrates:**
  - Highlights why flat dependency tools fail: leaf packages appear disconnected without full structural mapping.
  - SupplyGraph's reverse BFS engine traces all 4 intermediate hops, calculating exact reachability and proving how a vulnerability at depth 4 affects the root service.
  - Computes an operational Blast Radius of **74.0/100**.

### ⚙️ Scenario E: CI/CD Workflow Leak (GitHub Actions Runner Hardening)
- **The Threat:** Audits build automation pipelines (`.github/workflows/*.yml`) for unpinned third-party actions (`actions/checkout@v2`) and excessive runner privileges (`permissions: write-all`).
- **What SupplyGraph Demonstrates:**
  - Flags that mutable branch or tag references can be compromised upstream to execute unauthorized code on privileged build runners.
  - In the **AI Code Reviewer**, displays a surgical unified git diff enforcing immutable 40-character commit SHA pinning (`actions/checkout@11bd71...`) and least-privilege token permissions (`contents: read`).
  - Computes a risk score of **81.0/100**.

---

## 🔬 Real-World Repository Deep Dive: `knadh/listmonk`

SupplyGraph was validated against the high-performance open-source mailing and newsletter manager **[knadh/listmonk](https://github.com/knadh/listmonk)** (Go + Vue monorepo):

```
┌─────────────────────────────────────────────────────────────┐
│             knadh/listmonk — SupplyGraph Audit              │
├──────────────────────────┬──────────────────────────────────┤
│ Scanned Submodules       │ 35 modules across Go & frontend  │
│ Total Components         │ 94 direct and transitive packages│
│ Security Findings        │ 21 CVE & CI/CD workflow issues   │
│ Computed Blast Radius    │ 60.0 / 100 (Prioritized)         │
│ Unified Git Diff Patches │ 3 surgical non-breaking diffs    │
│ Sandbox Interceptions    │ 8 hook safety violations caught  │
└──────────────────────────┴──────────────────────────────────┘
```

When scanning a complex monorepo like `listmonk`, SupplyGraph unifies dependencies across Go backend manifests, npm frontend packages, and GitHub Actions automation, providing actionable containment steps within seconds.

---

## 🏛️ System Architecture & Dataflow

```mermaid
flowchart TD
    subgraph INGESTION["1. Multi-Ecosystem Ingestion"]
        A1["GitHub Repository / Folder"] --> B1["Manifest & Workflow Ingestion"]
        B1 --> |npm| M1["package-lock.json / package.json"]
        B1 --> |PyPI| M2["requirements.txt / poetry.lock"]
        B1 --> |Go| M3["go.mod"]
        B1 --> |CI/CD| M4[".github/workflows/*.yml"]
    end

    subgraph THREAT_ENGINE["2. 5-Layer Threat Detection Engine"]
        M1 & M2 & M3 --> D1["OSV.dev Batch Vulnerability Ingestion"]
        M1 & M2 --> D2["Typosquatting & Scope Confusion Engine"]
        M4 --> D3["CI/CD Runner & Action Pinning Auditor"]
        A1 --> D4["Tree-Sitter AST Static Code Pattern Scanner"]
    end

    subgraph GRAPH_ENGINE["3. Graph Theory & Reachability Engine"]
        D1 & D2 & D3 & D4 --> G1["NetworkX Directed Graph (DAG)"]
        G1 --> G2["Reverse BFS Reachability Traversal"]
        G2 --> G3["Blast Radius Scoring (0-100)"]
    end

    subgraph DEFENSE["4. Defense & Remediation Layer"]
        G3 --> R1["AI Code Reviewer (Unified Git Diffs)"]
        G3 --> R2["Autonomous Executive AI Briefings"]
        G3 --> R3["Dynamic Detonation Sandbox (Hooks Quarantine)"]
        G3 --> R4["CycloneDX v1.5 SBOM (SHA-256 Digest)"]
    end

    subgraph UI["5. Enterprise ASPM User Interface"]
        R1 & R2 & R3 & R4 --> UI1["Next.js 14 Dashboard"]
        UI1 --> UI2["React Flow Animated Attack Graph Canvas"]
        UI1 --> UI3["Interactive Findings & Sandbox Terminal"]
    end
```

---

## 💻 Tech Stack & Open Standards

- **Frontend:** Next.js 14 (App Router), React 18, React Flow (`@xyflow/react`), Tailwind CSS, Lucide Icons, TypeScript.
- **Backend:** FastAPI, Python 3.11+, NetworkX, Pydantic v2, Uvicorn, Tree-sitter.
- **Vulnerability Intelligence:** OSV.dev REST API, GitHub Advisory Database (GHSA), National Vulnerability Database (NVD).
- **Execution Containment:** Ephemeral sandbox container wrapper with network interface restriction and syscall inspection.
- **Standards:** CycloneDX v1.5 JSON SBOM, SHA-256 cryptographic verification.

---

## 🔌 API Reference Summary

| Endpoint | Method | Description |
|:---|:---:|:---|
| `/api/v1/scan` | `POST` | Ingests a repository URL and executes the 5-layer supply chain analysis pipeline. |
| `/api/v1/scenarios/{scenario_id}` | `GET` | Fetches preloaded evaluation scenario data (`A`, `B`, `C`, `D`, `E`). |
| `/api/v1/sandbox/detonate` | `POST` | Executes and monitors package lifecycle hooks inside the isolated container sandbox. |
| `/api/v1/sbom/cyclonedx` | `GET` | Generates standardized CycloneDX v1.5 JSON SBOM with deterministic SHA-256 digest. |
| `/api/v1/health` | `GET` | System health check and upstream service availability probe. |

For full payload contracts and schema models, see **[docs/api-contract.md](docs/api-contract.md)**.

---

## 📁 Repository Structure

```
supplygraph/
├── frontend/                     # Next.js 14 App Router Frontend
│   ├── src/
│   │   ├── app/                  # Application routes & layout
│   │   ├── components/           # React UI components
│   │   │   ├── auth/             # Authentication & Judge Fast-Pass
│   │   │   ├── dashboard/        # ASPM Overview Dashboard
│   │   │   ├── graph/            # React Flow interactive graph canvas
│   │   │   ├── reviewer/         # AI Code Reviewer unified git diffs
│   │   │   └── sandbox/          # Detonation Sandbox terminal & logs
│   │   └── lib/                  # Client utilities & state management
│   └── public/                   # Static branding assets and documentation
├── backend/                      # FastAPI Python Backend
│   ├── app/
│   │   ├── api/                  # REST API route handlers
│   │   ├── detectors/            # 5-Layer threat detectors & AST scanners
│   │   ├── graph/                # NetworkX DAG builder & BFS algorithms
│   │   ├── sandbox/              # Subprocess execution containment sandbox
│   │   ├── sbom/                 # CycloneDX v1.5 generator & SHA-256
│   │   └── services/             # OSV.dev client & AI briefing engines
│   └── tests/                    # Backend unit & integration test suites
├── docs/                         # In-depth architectural & evidence documents
│   ├── architecture.md           # Full system design and component breakdown
│   ├── api-contract.md           # Complete OpenAPI specification
│   ├── demo-scenarios.md         # Scenario walkthroughs and attack proofs
│   ├── detection.md              # Threat detection algorithms and heuristics
│   └── EVIDENCE.md               # Forensic evidence & validation dossier
└── README.md                     # Project documentation
```

---

## 🔒 Security & Evidence Integrity Principles

SupplyGraph enforces a strict **honesty-first evidence standard**:
1. **No Hallucinated Findings:** Every reported vulnerability maps to verified OSV.dev CVE/GHSA intelligence or deterministic AST syntax patterns.
2. **Honest Metric Boundaries:** Blast Radius scores reflect quantifiable parameters (dependency depth, path count, CVSS severity) rather than opaque arbitrary scores.
3. **Safe Execution Guarantee:** No untrusted repository code is ever executed directly on host runners; all dynamic inspections are strictly restricted to the sandboxed containment environment.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
<b>SupplyGraph</b> • Built for <b>YUKTHI 2026 Hackathon</b> • Mohan Babu University • Cybersecurity & ASPM Track
</div>
