# SupplyGraph — Architecture Document

> **Evidence-driven software supply-chain attack analysis.**

---

## 1. System Overview

SupplyGraph is a full-stack cybersecurity platform that ingests a GitHub repository URL, performs deep static analysis of its software supply chain, identifies known vulnerabilities, suspicious components, and behavioural anomalies, constructs a structured security knowledge graph, and renders an interactive dashboard with actionable findings and containment recommendations.

The platform is designed around a strict **evidence-first principle**: every finding, every risk score, and every propagation path must be anchored to structured, traceable evidence. No vulnerability is reported without a matching evidence item. No confidence score is presented as a probability. No simulated runtime signal is presented as production telemetry.

### Core Design Goals

| Goal | Description |
|------|-------------|
| Evidence integrity | Every finding references one or more typed evidence items |
| Deterministic analysis | Static analysis produces the same results for the same inputs |
| Honest uncertainty | Confidence scores are heuristic weights, not Bayesian probabilities |
| Separation of concerns | Ingestion, analysis, scoring, and presentation are decoupled layers |
| Demo safety | No untrusted repository code is executed at any point |
| Transparency | Simulated signals are clearly labeled; OSV data is never fabricated |

---

## 2. High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              USER BROWSER                                        │
│                                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                        Next.js 14 Frontend (Vercel)                      │   │
│   │                                                                          │   │
│   │  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │   │
│   │  │  Dashboard UI    │  │  React Flow Graph │  │  Findings Panel        │ │   │
│   │  │  (Tailwind CSS)  │  │  Visualization   │  │  (Evidence Drill-Down) │ │   │
│   │  └────────┬─────────┘  └────────┬─────────┘  └───────────┬────────────┘ │   │
│   │           └───────────────────┬─┘─────────────────────────┘             │   │
│   │                               │  REST API (HTTPS)                        │   │
│   └───────────────────────────────┼──────────────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────────────┘
                                    │
                    ┌───────────────▼────────────────┐
                    │   FastAPI Backend (Render)       │
                    │   POST /api/v1/analyze           │
                    │   GET  /api/v1/scans/{id}        │
                    │   GET  /api/v1/health/*          │
                    └───┬───────────────────────┬─────┘
                        │                       │
          ┌─────────────▼──────────┐   ┌────────▼─────────────────────┐
          │  GitHub Ingestion       │   │  Supabase / PostgreSQL        │
          │  Service                │   │  (Scan results, graph cache,  │
          │  - REST API v3          │   │   evidence store, findings)   │
          │  - Tree walking         │   └──────────────────────────────┘
          │  - File download        │
          │  - Rate-limit handling  │
          └─────────────┬──────────┘
                        │  Raw repository data
          ┌─────────────▼─────────────────────────────────────────────┐
          │                   Analysis Engine                           │
          │                                                             │
          │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐ │
          │  │ SBOM Engine │  │ AST Analysis │  │ CI/CD Analysis    │ │
          │  │ (CycloneDX) │  │ Engine       │  │ Engine            │ │
          │  │ + PURL Norm │  │ (Python AST) │  │ (GH Actions YAML) │ │
          │  └──────┬──────┘  └──────┬───────┘  └─────────┬─────────┘ │
          │         │                │                      │           │
          │  ┌──────▼──────────────────────────────────────▼─────────┐ │
          │  │            Metadata / Maintainer Analysis Engine        │ │
          │  │  (Release history, contributor anomalies, timestamps)   │ │
          │  └─────────────────────────────┬──────────────────────────┘ │
          │                                │                             │
          │  ┌─────────────────────────────▼──────────────────────────┐ │
          │  │              OSV Intelligence Engine                     │ │
          │  │  (Batch querying, cache layer, PURL → CVE resolution)   │ │
          │  └─────────────────────────────┬──────────────────────────┘ │
          └────────────────────────────────┼─────────────────────────────┘
                                           │  Structured evidence items
          ┌────────────────────────────────▼─────────────────────────────┐
          │               Evidence Correlation Engine                      │
          │  (Aggregates typed evidence per entity, deduplicates, ranks)  │
          └──────────────────────┬────────────────────────────────────────┘
                                 │  Correlated findings
         ┌───────────────────────┼──────────────────────────────────────┐
         │                       │                                       │
┌────────▼────────┐   ┌──────────▼──────────┐   ┌───────────────────────┐
│  Origin Engine  │   │ Attack-Path Engine   │   │ Impact / Blast-Radius │
│  (Entry-point   │   │ (Propagation path    │   │ Engine                │
│   candidate     │   │  tracing through     │   │ (Score = 2P+15S+25A   │
│   detection)    │   │  dependency graph)   │   │  +50D formula)        │
└────────┬────────┘   └──────────┬──────────┘   └───────────┬───────────┘
         │                       │                           │
         └───────────────────────┼───────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Confidence Engine      │
                    │  C = 1 - Π(1 - wᵢ × rᵢ) │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Containment Engine     │
                    │  (Recommendations, pin   │
                    │   versions, isolate svc) │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Gemini Explanation      │
                    │   Layer (Gemini 1.5 Pro) │
                    │   (Summarize findings,   │
                    │    plain-language output) │
                    └────────────┬─────────────┘
                                 │
         ┌───────────────────────┼──────────────────────────────────┐
         │                       │                                   │
┌────────▼────────┐   ┌──────────▼──────────┐              ┌────────▼──────────┐
│ NetworkX Graph  │   │ Server-Side Layout   │              │  React Flow +     │
│ Engine          │   │ Engine               │              │  Dashboard        │
│ (Node/edge      │   │ (Topological BFS,    │              │  (Interactive     │
│  construction,  │   │  x/y coordinates)    │              │   graph, panels,  │
│  traversal)     │   │                      │              │   evidence view)  │
└─────────────────┘   └──────────────────────┘              └───────────────────┘
```

---

## 3. Component Descriptions

### 3.1 GitHub Ingestion Service

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Authenticate to GitHub, enumerate repository structure, download relevant files for analysis |
| **Inputs** | GitHub repository URL, GitHub Personal Access Token (server-side only) |
| **Outputs** | Repository metadata, file tree, raw source files (Python, YAML, TOML, JSON, lock files), commit history, contributor list, release history |
| **Key Technologies** | GitHub REST API v3, `httpx` async client, rate-limit backoff, content size guards |

The service first resolves the URL to an `owner/repo` pair, retrieves repository metadata (stars, default branch, last commit), then walks the git tree recursively to identify files within size and count limits. Only files relevant to security analysis are downloaded: Python source (`*.py`), GitHub Actions workflows (`.github/workflows/*.yml`), dependency manifests (`requirements.txt`, `pyproject.toml`, `setup.py`, `package.json`, `Cargo.toml`, `go.mod`), and lock files (`poetry.lock`, `package-lock.json`, `yarn.lock`, `Pipfile.lock`). Binary files, compiled artifacts, and data blobs are intentionally excluded.

**Security constraint**: The ingestion service only reads files via authenticated GitHub API calls. It never clones the repository, never executes any scripts, and never spawns shell processes.

---

### 3.2 SBOM Engine (CycloneDX)

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Parse dependency manifests and lock files to produce a structured Software Bill of Materials (SBOM) in CycloneDX format |
| **Inputs** | Raw dependency manifest files (requirements.txt, pyproject.toml, package.json, Cargo.toml, go.mod, etc.), lock files |
| **Outputs** | CycloneDX BOM JSON, list of components with name/version/ecosystem tuples |
| **Key Technologies** | `cyclonedx-python-lib`, `pip-requirements-parser`, `toml`, `json` |

The SBOM engine resolves both direct and transitive dependencies where lockfiles are available. It extracts component name, version, ecosystem, and metadata fields. For each component, it emits a structured component record suitable for PURL normalization and OSV querying. Where lockfiles are absent, it resolves only direct dependencies with explicit version pins; range specifiers are recorded but not resolved.

---

### 3.3 PURL Normalization Layer

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Normalize every identified package into a canonical Package URL (PURL) for consistent cross-system referencing |
| **Inputs** | Component records from SBOM engine (name, version, ecosystem) |
| **Outputs** | Normalized PURL strings (e.g., `pkg:pypi/requests@2.31.0`) |
| **Key Technologies** | `packageurl-python` library, custom normalization rules |

PURLs are required for OSV API queries. The normalization layer handles edge cases: PyPI package names are lowercased and hyphens/underscores are canonicalized, npm scoped packages are correctly encoded, version strings are stripped of `v` prefixes and build metadata.

---

### 3.4 OSV Intelligence Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Query the OSV (Open Source Vulnerabilities) database to retrieve known vulnerability advisories for each identified package version |
| **Inputs** | List of PURLs from PURL normalization layer |
| **Outputs** | OSV advisory records per PURL: CVE/GHSA/OSV IDs, aliases, severity, CVSS scores, affected version ranges, fix versions |
| **Key Technologies** | OSV REST API (`api.osv.dev`), batch query endpoint, local disk cache (JSON files keyed by PURL hash) |

The engine batches PURL queries using the OSV `/v1/querybatch` endpoint to minimize API round-trips. Responses are cached to disk (default: `.cache/osv/`) with a configurable TTL to reduce external API dependency during demo runs. The cache is never mutated to fabricate results: if the OSV API returns no findings, no findings are reported. OSV data is the only external source of vulnerability truth; no internal vulnerability databases are maintained.

---

### 3.5 AST/Static Analysis Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Parse Python source files into Abstract Syntax Trees and detect suspicious capability patterns without executing any code |
| **Inputs** | Python source files (`.py`) downloaded from repository |
| **Outputs** | Structured findings per file with: file path, line number, rule identifier, pattern description, severity, evidence item |
| **Key Technologies** | Python `ast` module (built-in), custom visitor classes, pattern registry |

The engine uses Python's built-in `ast` module for safe, non-executing static analysis. A registry of detector visitors is applied to each parsed AST. Patterns detected include: subprocess invocation, shell=True usage, exec/eval calls, dynamic imports (`importlib`, `__import__`), network socket or urllib access, environment variable access, credential-like string patterns, base64 decoding chains, and download-execute sequences.

All findings are tagged with their source file and line number and emitted as typed evidence items with `classification=HEURISTIC` unless the pattern is unambiguous (e.g., a hardcoded credential string, which is `FACT`).

---

### 3.6 Typosquatting Detector

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Identify package names that closely resemble well-known legitimate packages, suggesting potential typosquatting attacks |
| **Inputs** | List of package names from the SBOM |
| **Outputs** | Typosquatting candidate pairs: (suspicious_package, reference_package, similarity_score, evidence_item) |
| **Key Technologies** | `rapidfuzz` (edit distance), custom character substitution maps, curated reference package list |

The detector computes normalized edit distance between each observed package name and every package in a curated reference list of popular packages (top 1000 PyPI, top 500 npm). A configurable similarity threshold (default: 0.85) flags candidates. Common substitution patterns are additionally checked: character transposition (e.g., `reqeusts`), vowel replacement, homoglyph substitution, appended suffixes (`-sdk`, `-api`, `-utils`).

**Limitation**: High similarity score indicates structural resemblance, not confirmed malicious intent. All typosquatting findings are classified `HEURISTIC`.

---

### 3.7 Dependency Confusion Detector

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Detect potential dependency confusion attacks where an internal package name is also resolvable from a public registry |
| **Inputs** | Package metadata (name, version, source registry), internal namespace hints from repository configuration |
| **Outputs** | Dependency confusion risk records: (package, risk_type, source_ambiguity_evidence) |
| **Key Technologies** | PyPI JSON API, npm registry API (read-only checks), namespace heuristics |

The detector identifies package names that: (a) appear to follow internal naming conventions (e.g., company-prefix patterns), (b) are resolvable from public registries, and (c) have version numbers higher than expected for a real public package. This triangulation produces a dependency confusion risk signal classified `HEURISTIC`.

---

### 3.8 Suspicious Update Detector

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Detect package versions that appear to have introduced new suspicious capabilities relative to a prior version |
| **Inputs** | Package version history from GitHub releases or PyPI release metadata, commit metadata |
| **Outputs** | Suspicious version records: (package, version_before, version_after, new_capabilities[], evidence) |
| **Key Technologies** | GitHub Releases API, PyPI JSON API, version comparison, AST diff (capability-level, not line-level) |

The detector compares capability signals (e.g., presence of subprocess calls, network access) between consecutive package versions. A version that introduces new capability signals without a corresponding changelog entry or with anomalous commit timing is flagged as suspicious. Evidence is classified `HEURISTIC`.

---

### 3.9 Obfuscation Detector

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Identify code patterns consistent with intentional obfuscation of malicious payloads |
| **Inputs** | Python source files (AST) |
| **Outputs** | Obfuscation findings: (file, line, pattern_type, evidence) |
| **Key Technologies** | Python `ast` module, `base64`/`zlib`/`marshal` usage detection, string encoding heuristics |

Patterns detected: base64-encoded strings passed to `exec`, nested `eval` calls, `marshal.loads` usage, `__builtins__` manipulation, `compile()` with obfuscated source strings, `chr()` concatenation chains, `zlib.decompress` + `exec` chains.

**Limitation**: Not all obfuscation is malicious (some legitimate tools use encoding). All findings are classified `HEURISTIC`.

---

### 3.10 Dormant Logic Detector

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Identify conditional logic that might represent time-bombs, environment-triggered payloads, or logic bombs |
| **Inputs** | Python source files (AST) |
| **Outputs** | Dormant logic findings: (file, line, pattern_type, trigger_condition, evidence) |
| **Key Technologies** | Python `ast` module, datetime comparison detection, environment variable conditional detection |

Patterns detected: date/time comparison in conditionals (e.g., `datetime.now() > datetime(2024, 1, 1)`), environment variable switches that control execution paths (`if os.environ.get("DEPLOY") == "prod"`), hostname or username checks in execution paths, delayed execution patterns (`time.sleep` + payload).

---

### 3.11 CI/CD Analysis Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Analyze GitHub Actions workflow files for supply-chain risks in the build and deployment pipeline |
| **Inputs** | YAML workflow files from `.github/workflows/` |
| **Outputs** | CI/CD risk findings: workflow name, step name, pattern type, severity, evidence |
| **Key Technologies** | `PyYAML`, custom pattern matchers, GitHub Actions schema awareness |

Patterns detected: remote script download in run steps (`curl`, `wget`), shell execution of remote content (`curl | bash`, `wget | sh`), use of unversioned or SHA-unpinned external actions, excessive permissions (`permissions: write-all`), suspicious secret names, self-hosted runner misuse patterns, artifact upload without signing.

---

### 3.12 Metadata/Maintainer Analysis Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Analyze package and repository metadata for anomalies that may indicate a compromised or suspicious package |
| **Inputs** | GitHub release history, commit history, contributor list, package registry metadata |
| **Outputs** | Metadata anomaly signals: (entity, anomaly_type, evidence) |
| **Key Technologies** | GitHub REST API, PyPI JSON API, statistical anomaly detection |

Anomalies detected: new maintainer added within 30 days of release, sudden spike in commit activity, release with no associated commits, package with zero prior download history, maintainer account age < 30 days, project transferred between owners without announcement.

---

### 3.13 Simulated Runtime Signal Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Generate synthetic runtime observations for demo purposes based on AST-detected capabilities, clearly labeled as simulated |
| **Inputs** | AST findings, capability signals |
| **Outputs** | Simulated runtime signals: (signal_type, source_package, target, is_simulated=true, label="SIMULATED") |
| **Key Technologies** | Rule-based projection from static findings |

**Critical requirement**: All simulated runtime signals must carry `is_simulated=true` in their evidence item and must be displayed with a "SIMULATED" badge in the UI. They must never be presented as real production telemetry. Simulated signals receive a 0.15 confidence weight discount relative to confirmed static evidence.

Signal types generated: `OUTBOUND_CONNECTION`, `FILE_MODIFICATION`, `SUBPROCESS_CREATION`, `ENV_ACCESS`, `SUSPICIOUS_DOMAIN_CONTACT`.

---

### 3.14 Evidence Correlation Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Aggregate, deduplicate, and rank evidence items from all detectors into coherent findings per entity |
| **Inputs** | Raw evidence items from all detectors and engines |
| **Outputs** | Correlated findings with aggregated evidence lists, deduplicated by source+type, ranked by confidence contribution |
| **Key Technologies** | Python dataclasses, UUID-based deduplication, evidence type priority ordering |

The correlation engine groups evidence by entity (package, repository, pipeline step), merges overlapping findings, removes duplicate evidence items (same source, same type, same location), and produces a final finding record per entity with a complete evidence list and a pre-computed confidence score.

---

### 3.15 Origin Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Identify the most likely entry point of a supply-chain attack within the dependency graph |
| **Inputs** | Correlated findings, dependency graph |
| **Outputs** | Origin candidate record: (entity_id, entity_name, confidence, supporting_evidence) |
| **Key Technologies** | Graph traversal (NetworkX), finding score ranking |

The origin engine scores each flagged entity based on: (a) its position in the dependency graph (leaf nodes are more likely entry points), (b) the number and severity of its evidence items, (c) its distance from the root application. The highest-scoring leaf-direction entity with the most evidence is nominated as the `origin_candidate`.

---

### 3.16 Attack-Path Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Trace propagation paths from the identified origin through the dependency graph to the application and downstream assets |
| **Inputs** | Origin candidate, dependency graph (NetworkX), asset nodes |
| **Outputs** | Propagation path: ordered list of (entity_id, entity_type, edge_type) tuples |
| **Key Technologies** | NetworkX shortest path and all-paths algorithms, BFS traversal |

The engine finds all paths from the origin candidate to application-level nodes and downstream assets (services, APIs, deployments). It records the complete propagation path as an ordered list of graph nodes and edges, which is embedded in the finding record and rendered as a highlighted subgraph in the UI.

---

### 3.17 Impact/Blast-Radius Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Quantify the potential impact of a supply-chain compromise by counting and weighting affected assets |
| **Inputs** | Propagation path, asset nodes reachable from origin |
| **Outputs** | Blast radius score (numeric), affected asset list |
| **Key Technologies** | NetworkX reachability analysis, weighted scoring formula |

**Formula**: `B = 2P + 15S + 25A + 50D`
- `P` = number of affected packages
- `S` = number of affected services
- `A` = number of affected API endpoints
- `D` = number of affected production deployments

---

### 3.18 Confidence Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Compute a composite confidence score for each finding based on its evidence items |
| **Inputs** | Evidence items with individual weight (wᵢ) and reliability (rᵢ) values |
| **Outputs** | Composite confidence score C ∈ [0.0, 1.0] |
| **Key Technologies** | Probabilistic combination formula |

**Formula**: `C = 1 - Π(1 - wᵢ × rᵢ)` for all evidence items i

Where:
- `wᵢ` = configured weight for evidence type (e.g., OSV match = 0.90, AST heuristic = 0.60, simulated signal = 0.15)
- `rᵢ` = reliability multiplier (FACT=1.0, HEURISTIC=0.7, SIMULATED=0.15, INFERENCE=0.5, UNKNOWN=0.3)

Simulated signals receive an additional 0.15 reliability multiplier to prevent artificial inflation of scores from synthetic data. Confidence scores are presented as heuristic estimates, never as probabilities.

---

### 3.19 Containment Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Generate actionable, specific remediation recommendations based on finding type and affected entities |
| **Inputs** | Finding records with finding_type, severity, affected entities, propagation path |
| **Outputs** | Ordered recommendation list per finding: action, target, urgency |
| **Key Technologies** | Rule-based recommendation templates per finding_type |

Recommendation types generated: version pinning (pin to last known good version), package replacement (replace suspicious package with trusted alternative), isolation (isolate affected service from network), workflow hardening (pin action versions, restrict permissions), dependency removal, rebuild instruction (rebuild container after clean), maintainer audit.

---

### 3.20 Gemini Explanation Layer

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Generate human-readable, plain-language summaries of findings using the Gemini 1.5 Pro language model |
| **Inputs** | Structured finding records (JSON), evidence lists, propagation paths |
| **Outputs** | Plain-language explanation per finding, executive summary for the full scan |
| **Key Technologies** | Google Gemini API (`google-generativeai`), structured prompting |

The Gemini layer receives structured JSON data and produces narrative explanations. It is explicitly prohibited from: inventing evidence not present in the input JSON, generating CVE IDs not provided to it, claiming certainty beyond what the confidence score indicates, or inventing propagation paths. The prompt instructs Gemini to summarize only what the structured data states.

---

### 3.21 NetworkX Graph Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Build and maintain the security knowledge graph using NetworkX, support graph traversal for all analysis engines |
| **Inputs** | SBOM components, evidence items, asset records, finding records |
| **Outputs** | NetworkX directed graph (DiGraph), serializable node/edge records |
| **Key Technologies** | `networkx`, custom node/edge type schema |

Nodes represent: Repository, Package, Version, Vulnerability, Commit, Maintainer, Service, Container, API, Deployment, Pipeline, Behaviour, RuntimeObservation, Finding, Asset.

Edges represent: CONTAINS, DEPENDS_ON, VERSION_OF, MODIFIED_BY, RELEASED_BY, BUILT_BY, DEPLOYED_AS, USES, CALLS, TRIGGERS, EXHIBITS, AFFECTS, PROPAGATES_TO, OBSERVED_IN.

---

### 3.22 Server-Side Layout Engine

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Compute deterministic x/y coordinates for all graph nodes server-side, so the frontend receives a ready-to-render layout |
| **Inputs** | NetworkX graph |
| **Outputs** | Node position map: `{node_id: {x: float, y: float}}` |
| **Key Technologies** | Topological sort (DAGs), BFS layering (cyclic graphs), custom spacing constants |

**Algorithm**:
1. Attempt topological sort. If successful, use layer-based layout.
2. If graph has cycles, fall back to BFS layering from repository root node.
3. Assign x = layer_index × 280, y = sibling_index × 120.
4. Sibling ordering is deterministic: alphabetical by node ID within each layer.
5. Coordinates are embedded in the serialized graph JSON returned by the API.

---

### 3.23 Supabase/PostgreSQL Persistence

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Persist scan records, graph snapshots, evidence stores, and finding records for retrieval |
| **Inputs** | Completed scan analysis results |
| **Outputs** | Stored scan record, retrievable by scan ID |
| **Key Technologies** | Supabase (managed PostgreSQL), `supabase-py`, `asyncpg`, Row Level Security |

Tables: `scans`, `findings`, `evidence_items`, `graph_snapshots`, `packages`, `vulnerabilities`.

---

### 3.24 Next.js Dashboard

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Provide the primary user interface: scan submission, results display, finding drill-down, and graph visualization |
| **Inputs** | API responses from FastAPI backend |
| **Outputs** | Interactive web dashboard |
| **Key Technologies** | Next.js 14 (App Router), TypeScript, Tailwind CSS, shadcn/ui, React Query |

---

### 3.25 React Flow Visualization

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Render the security knowledge graph as an interactive, pannable, zoomable node-edge diagram |
| **Inputs** | Serialized graph JSON (nodes with pre-computed positions, edges) |
| **Outputs** | Interactive graph visualization in browser |
| **Key Technologies** | React Flow, custom node renderers per node type, custom edge renderers per edge type |

---

## 4. Data Flow

The following describes the complete data flow from GitHub URL input to final dashboard output:

```
Step 1: User Input
  User enters GitHub repository URL in the Next.js dashboard and clicks "Analyze".

Step 2: API Request
  Frontend sends POST /api/v1/analyze with {repo_url, options} to FastAPI backend.
  Backend validates URL, creates a scan record with status=PENDING, returns scan_id.

Step 3: GitHub Ingestion
  GitHub Ingestion Service authenticates with server-side token.
  Fetches repository metadata, file tree, commits, releases, contributors.
  Downloads relevant source files within size and count limits.
  Emits: raw_files[], repo_metadata, commit_history, contributor_list.

Step 4: SBOM Construction
  SBOM Engine parses dependency manifests and lock files.
  PURL Normalization Layer canonicalizes each package.
  Emits: sbom_components[] with (name, version, ecosystem, purl).

Step 5: OSV Query
  OSV Intelligence Engine batches PURL queries to api.osv.dev.
  Caches responses locally.
  Emits: osv_advisories[] per package.

Step 6: Static Analysis (parallel)
  AST Engine analyzes Python source files → ast_findings[].
  Typosquatting Detector checks package names → typosquat_candidates[].
  Dependency Confusion Detector checks registry ambiguity → confusion_risks[].
  Suspicious Update Detector compares version history → update_anomalies[].
  Obfuscation Detector scans AST for encoding patterns → obfuscation_findings[].
  Dormant Logic Detector scans for trigger patterns → dormant_findings[].
  CI/CD Engine analyzes workflow YAML → cicd_findings[].
  Metadata Engine analyzes release/contributor anomalies → metadata_signals[].

Step 7: Simulated Runtime Projection
  Simulated Runtime Signal Engine projects runtime signals from AST capabilities.
  Tags all signals with is_simulated=true, classification=SIMULATED.
  Emits: runtime_signals[].

Step 8: Evidence Correlation
  Evidence Correlation Engine aggregates all evidence items by entity.
  Deduplicates, ranks, produces finding records.
  Emits: correlated_findings[] per entity.

Step 9: Graph Construction
  NetworkX Graph Engine builds the security knowledge graph.
  Adds nodes: Repository, Packages, Versions, Vulnerabilities, Assets, Pipelines.
  Adds edges: DEPENDS_ON (direct + transitive), EXHIBITS, AFFECTS, PROPAGATES_TO.

Step 10: Scoring and Path Analysis
  Origin Engine identifies most likely attack entry point.
  Attack-Path Engine traces propagation through graph.
  Impact Engine computes blast radius score.
  Confidence Engine computes per-finding confidence scores.

Step 11: Containment
  Containment Engine generates recommendations per finding.

Step 12: Gemini Summarization
  Gemini Explanation Layer receives structured finding JSON.
  Returns plain-language summaries and executive overview.

Step 13: Layout and Serialization
  Server-Side Layout Engine computes x/y coordinates for all nodes.
  Graph serialized to JSON: {nodes[], edges[]}.

Step 14: Persistence
  Complete scan result (findings, evidence, graph, recommendations, explanations)
  persisted to Supabase/PostgreSQL.
  Scan status updated to COMPLETE.

Step 15: API Response
  GET /api/v1/scans/{id} returns complete scan result.
  Frontend renders: findings panel, evidence drill-down, React Flow graph.
```

---

## 5. Security Boundaries

The following security boundaries are enforced at all times:

### 5.1 No Code Execution
The platform **never executes** any code from the analyzed repository. All analysis is performed by reading file content through the GitHub API and parsing it using Python's built-in `ast` module or YAML/JSON parsers. No subprocess calls are made with repository content. No shell evaluation occurs.

### 5.2 Server-Side Token Isolation
The GitHub Personal Access Token and all API keys (Gemini, Supabase Service Role) are stored as server-side environment variables only. They are never embedded in frontend code, never returned in API responses, never logged, and never exposed to the browser.

### 5.3 No Secrets in Frontend
The Next.js frontend has access only to `NEXT_PUBLIC_API_URL`. All other configuration is backend-only. The frontend never touches GitHub, Supabase (service role), or Gemini APIs directly.

### 5.4 Read-Only Static Analysis
All repository analysis is read-only. The platform never writes to the analyzed repository, never creates commits, never triggers workflows, and never modifies any external state related to the target repository.

### 5.5 Sandboxing Requirements
For future production deployment: analysis workers should run in isolated containers with no network access to internal infrastructure, with ephemeral filesystems wiped after each scan. File size limits (default 100 MB repo, 1000 files max) prevent resource exhaustion.

### 5.6 OSV Data Integrity
Vulnerability data is sourced exclusively from the OSV API. No internal vulnerability list is maintained. If the OSV API returns no results, no vulnerability findings are reported. The cache stores only real API responses and is never modified by the application to fabricate results.

### 5.7 Gemini Output Constraints
Gemini is used only for natural-language summarization of structured data provided to it in the prompt. The prompt explicitly prohibits Gemini from: inventing CVE IDs, fabricating evidence items, claiming certainty beyond the confidence score, or generating propagation paths not present in the input JSON. Gemini output is displayed as "AI-generated summary" and is not used as evidence input to any scoring system.

### 5.8 Simulated Signal Transparency
All simulated runtime signals are stored with `is_simulated=true` in the database, carry `classification=SIMULATED` in their evidence records, and are displayed with a clearly visible "SIMULATED" badge in the UI. They receive a heavily discounted confidence weight (0.15) to prevent inflated scores.

---

## 6. Deployment Architecture

### 6.1 Frontend — Vercel

- Platform: Vercel (Next.js native host)
- Framework: Next.js 14 with App Router
- Build command: `npm run build`
- Environment variable: `NEXT_PUBLIC_API_URL` (points to Render backend URL)
- Automatic deployments from `main` branch via GitHub integration
- Edge network CDN for static assets

### 6.2 Backend — Render

- Platform: Render Web Service
- Runtime: Python 3.11
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Environment variables: `GITHUB_TOKEN`, `GEMINI_API_KEY`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `ALLOWED_ORIGINS`, `OSV_CACHE_DIR`, `MAX_REPO_SIZE_MB`, `MAX_FILES_PER_SCAN`, `ANALYSIS_TIMEOUT_SECONDS`
- Health check endpoint: `GET /health`
- Auto-deploy from `main` branch

### 6.3 Database — Supabase

- Platform: Supabase (managed PostgreSQL)
- DDL applied via Supabase SQL editor or migration scripts in `supabase/migrations/`
- Row Level Security (RLS) enabled on all tables
- Service role key used by backend only; anon key used for public read operations
- Connection pooling via Supabase connection pooler (PgBouncer)

### 6.4 Environment Variable Management

All secrets are managed as platform-level environment variables (Vercel Dashboard / Render Dashboard). No `.env` files are committed to the repository. A `.env.example` file with placeholder values is committed for developer reference.

### 6.5 CI/CD

- GitHub Actions workflow: `.github/workflows/ci.yml`
- On pull request: run `pytest` (backend), `npm run test` (frontend), `npm run lint`
- On merge to `main`: trigger Vercel and Render auto-deploys
- Action versions are pinned to full SHA for supply-chain safety
- No `curl | bash` patterns in any workflow step

---

## 7. API Architecture

### 7.1 Versioning

All API endpoints are versioned under `/api/v1/`. Breaking changes increment the version to `/api/v2/`. The FastAPI router is structured as:

```
app/
  api/
    v1/
      analyze.py    → /api/v1/analyze
      scans.py      → /api/v1/scans/{id}
      health.py     → /api/v1/health/*
      demo.py       → /api/v1/analyze/demo
```

### 7.2 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/analyze` | Submit a repository for analysis. Returns `scan_id` immediately. Analysis runs asynchronously via background task. |
| `GET` | `/api/v1/scans/{scan_id}` | Retrieve full scan result by ID. Returns status (PENDING/RUNNING/COMPLETE/FAILED) and result payload when complete. |
| `GET` | `/api/v1/scans` | List recent scans (paginated). Query params: `limit`, `offset`. |
| `POST` | `/api/v1/analyze/demo` | Load a pre-built demo scenario. Body: `{"scenario_id": "A"}`. Returns synthetic scan result immediately. |
| `GET` | `/api/v1/health` | Basic health check. Returns `{"status": "ok"}`. |
| `GET` | `/api/v1/health/db` | Database connectivity check. |
| `GET` | `/api/v1/health/osv` | OSV API connectivity check. |

### 7.3 Request/Response Schema

**POST /api/v1/analyze — Request**:
```json
{
  "repo_url": "https://github.com/owner/repo",
  "options": {
    "include_transitive": true,
    "max_depth": 5,
    "include_simulated_runtime": true
  }
}
```

**POST /api/v1/analyze — Response (202 Accepted)**:
```json
{
  "scan_id": "uuid",
  "status": "PENDING",
  "created_at": "2026-09-25T09:00:00Z"
}
```

**GET /api/v1/scans/{id} — Response (200 OK)**:
```json
{
  "scan_id": "uuid",
  "status": "COMPLETE",
  "repo_url": "https://github.com/owner/repo",
  "created_at": "ISO8601",
  "completed_at": "ISO8601",
  "summary": {
    "total_packages": 42,
    "total_findings": 7,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 3,
    "low_count": 1,
    "blast_radius": 94,
    "origin_candidate": "malicious-logger@0.9.1"
  },
  "findings": [],
  "graph": {"nodes": [], "edges": []},
  "gemini_summary": "..."
}
```

### 7.4 Error Responses

All errors return RFC 7807 Problem Details format:
```json
{
  "type": "https://supplygraph.dev/errors/invalid-repo-url",
  "title": "Invalid Repository URL",
  "status": 400,
  "detail": "The provided URL does not resolve to a valid GitHub repository."
}
```

---

## 8. Graph Architecture

### 8.1 Node Types

The security knowledge graph contains the following node types, each with a unique visual style in the React Flow UI:

| Node Type | Color | Role |
|-----------|-------|------|
| `repository` | Blue (#3B82F6) | Root node; the analyzed repository |
| `package` | Green (#10B981) | A software dependency |
| `version` | Teal (#14B8A6) | A specific version of a package |
| `vulnerability` | Red (#EF4444) | A known CVE/GHSA vulnerability |
| `commit` | Purple (#8B5CF6) | A suspicious commit |
| `maintainer` | Indigo (#6366F1) | A package maintainer |
| `service` | Orange (#F97316) | A downstream service |
| `container` | Cyan (#06B6D4) | A container image |
| `api` | Yellow (#EAB308) | An API endpoint |
| `deployment` | Red-Orange (#F43F5E) | A production deployment |
| `pipeline` | Gray (#6B7280) | A CI/CD pipeline |
| `behaviour` | Amber (#D97706) | A detected behavioural capability |
| `runtime_observation` | Pink (#EC4899) | A simulated runtime signal |
| `finding` | Deep Red (#DC2626) | An aggregated security finding |
| `asset` | Slate (#64748B) | A downstream business asset |

### 8.2 Edge Types and Semantics

| Edge Type | Direction | Semantic |
|-----------|-----------|---------|
| `CONTAINS` | repo → package | Repository directly includes this package |
| `DEPENDS_ON` | package → package | Dependency relationship |
| `VERSION_OF` | version → package | Version belongs to package |
| `MODIFIED_BY` | commit → package | Commit modified this package |
| `RELEASED_BY` | version → maintainer | Version was released by maintainer |
| `BUILT_BY` | package → pipeline | Package is built by this pipeline |
| `DEPLOYED_AS` | package → container | Package is deployed in this container |
| `USES` | service → api | Service calls this API |
| `CALLS` | package → api | Package makes API calls |
| `TRIGGERS` | pipeline → deployment | Pipeline triggers this deployment |
| `EXHIBITS` | package → behaviour | Package exhibits this behaviour |
| `AFFECTS` | vulnerability → package | Vulnerability affects this package |
| `PROPAGATES_TO` | finding → asset | Finding propagates to this asset |
| `OBSERVED_IN` | runtime_observation → package | Simulated observation in package |

### 8.3 Layout Strategy

See Section 3.22 (Server-Side Layout Engine) for algorithm details. The layout is computed server-side to ensure determinism and avoid client-side layout jank on large graphs. Pre-computed coordinates are included in the serialized graph JSON and consumed directly by React Flow without any client-side re-layout.

### 8.4 Serialization Format

See Section 4 of `docs/graph-model.md` for full serialization schema.

---

## 9. Terminology Glossary

| Term | Definition |
|------|-----------|
| **Known Vulnerability** | A vulnerability with a confirmed OSV/CVE/GHSA identifier, matched to a specific package version via PURL. Evidence classification: FACT. |
| **Suspicious Component** | A package that exhibits one or more heuristic risk signals (typosquatting, obfuscation, unusual metadata) but has no confirmed CVE. Evidence classification: HEURISTIC. |
| **Suspicious Behaviour** | A capability or code pattern detected by static analysis that is associated with malicious behaviour (e.g., subprocess + outbound network + base64 decode). Evidence classification: HEURISTIC. |
| **Potential Attack Path** | A sequence of graph nodes (packages, services, APIs, deployments) connected by dependency/propagation edges, representing a theoretical route through which a supply-chain compromise could spread. Not confirmed; based on graph topology and finding evidence. |
| **Evidence-backed Propagation** | A propagation path where every edge is supported by at least one evidence item linking the source and destination nodes. Distinguished from speculative paths. |
| **Simulated Runtime Signal** | A synthetic runtime observation projected from static analysis findings for demonstration purposes. Not a real production observation. Always labeled `is_simulated=true` and displayed with a SIMULATED badge. Carries a heavily discounted confidence weight (0.15). |
| **Confirmed Evidence** | An evidence item with classification=FACT: directly verifiable from external authoritative data (e.g., OSV API match, hardcoded credential string). Distinguished from heuristic or simulated evidence. |
