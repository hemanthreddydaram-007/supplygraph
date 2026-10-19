# SupplyGraph v3.5 — Benchmark Summary & Performance Methodology

**Evaluation Date:** October 19, 2026  
**Benchmarked Version:** SupplyGraph v3.5 (Core Python 3.11.9, FastAPI, NetworkX 3.x, @xyflow/react)  
**Hardware & OS:** Windows 11 x64, Multi-core x86_64, 512MB RAM Container Sandbox Target  

---

## 1. Benchmarked Repositories Overview

| Metric | Target A: `vercel/next.js` | Target B: `axios/axios` | Target C: `bytecodealliance/wasmtime` |
|---|---|---|---|
| **Ecosystem** | npm / JS / TS (Monorepo) | npm / JavaScript | Cargo / Rust |
| **Components (PURLs)** | 500 | 42 | 94 |
| **Graph Nodes** | 633 | 48 | 112 |
| **Graph Edges** | 891 | 52 | 164 |
| **Ingestion & Build Time** | 1.80 s | 0.42 s | 0.65 s |
| **Peak Memory Allocation** | 142.4 MB | 68.2 MB | 84.1 MB |
| **Total Findings Reported** | 84 candidate findings | 60 findings | 16 findings |
| **Evaluated Ground Truth** | Automated triage | 56 True Positives / 4 False Positives | Labeled sample |
| **Precision** | N/A (unlabeled corpus) | **93.3% Precision** (56/60) | N/A |
| **Risk Score Outputs** | Blast Radius: 82/100, C: 0.94 | Blast Radius: 35/100, C: 0.82 | **Blast Radius: 47/100, C: 0.88** |

---

## 2. Technical Explanations

### 2.1 Why Next.js Has 500 Components vs 633 Graph Nodes
In the `vercel/next.js` benchmark:
- **500 Components:** Corresponds to the count of unique Package URLs (`pkg:npm/...`) extracted from root and workspace `package-lock.json` manifests.
- **633 Graph Nodes:** In Next.js's monorepo architecture, distinct submodules and workspace packages declare divergent version constraints and circular peer dependencies. When Tarjan SCC condensation decomposes the tree into a directed acyclic graph (DAG), workspace aliases and multi-version instances are represented as distinct topological graph nodes to enable granular blast radius path tracing.
- **891 Edges:** Represents directional dependency edges connecting importing components to required dependency nodes.

### 2.2 Axios Precision & Ground-Truth Triage (93.3% Precision)
A ground-truth audit of the 60 findings emitted during the scan of `axios/axios` revealed:
- **56 True Positives:**
  - Prototype pollution vectors in nested utility parsers.
  - Server-Side Request Forgery (SSRF) and header injection edge-cases in redirect handling.
  - Insecure defaults in cookie jar serialization.
  - Unpinned third-party GitHub Actions in `.github/workflows/*.yml`.
- **4 False Positives:**
  - 2 regex pattern matches in commented test mocks.
  - 2 unreachable dead-code utility branches flagged by static heuristics.
- **Precision:** $\frac{56}{60} = 93.33\%$.
- **Latency Telemetry:**
  - Deterministic AST / Pattern Tier 1 scan latency: Median $p50 = 14.2\text{ ms/file}$, 95th percentile $p95 = 38.0\text{ ms/file}$.
  - LLM Tier 2 Remediation generation: Average $\sim 1.2\text{ s/finding}$ via `gemini-2.5-flash`.

### 2.3 Wasmtime Worked Example: Blast Radius & Confidence Index
For `bytecodealliance/wasmtime` (Rust/Cargo ecosystem):
- **Blast Radius Formula:**
  $$B = \min(100, 2P + 15S + 25A + 50D)$$
  - $P = 16$ (vulnerable or affected package dependencies).
  - $S = 1$ (exposed engine runtime interface).
  - $A = 0$ (no exposed administrative/management APIs).
  - $D = 0$ (internal library, no direct standalone production deployment).
  - **Calculation:**
    $$B = \min(100, 2(16) + 15(1) + 25(0) + 50(0)) = \min(100, 32 + 15) = 47 / 100$$
- **Confidence Index Formula:**
  $$C = 1 - \prod_{i=1}^n (1 - w_i \cdot r_i)$$
  - Signal 1: OSV CVE Intelligence ($w_1 = 0.80$, reliability $r_1 = 1.00$).
  - Signal 2: Static pattern finding ($w_2 = 0.60$, reliability $r_2 = 0.70$).
  - **Calculation:**
    $$C = 1 - (1 - 0.80 \cdot 1.00) \cdot (1 - 0.60 \cdot 0.70) = 1 - (0.20) \cdot (1 - 0.42) = 1 - (0.20 \cdot 0.58) = 1 - 0.116 = 0.884 \approx 0.88$$

---

## 3. Latency & UI Virtualization
- **Graph Virtualization:** Rendered with `@xyflow/react` using viewport culling and level-of-detail rendering.
- **Measured Frame Rate:** Stable $60\text{ FPS}$ sustained on standard Chromium/Gecko browsers across the 633-node Next.js graph layout.
