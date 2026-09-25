# SupplyGraph — Evaluation and Reporting

> **Evidence-driven software supply-chain attack analysis.**

This document describes the evaluation strategy, detection evaluation matrix, metrics collected, known limitations, and the standardized reporting format used by SupplyGraph for hackathon and demo contexts.

---

## 1. Evaluation Strategy

### DEMO-BASED EVALUATION

SupplyGraph is evaluated in a **demo-based** context for the hackathon submission. This means:

1. **No ground-truth production data**: Evaluation is performed against pre-constructed synthetic scenarios (Scenarios A–E defined in `docs/demo-scenarios.md`), not against real-world repositories with independently verified attack data.

2. **Expected vs. Actual matching**: Each scenario specifies the exact findings, evidence items, confidence scores, and propagation paths that the system is expected to produce. The evaluation checks that the system produces outputs matching these specifications.

3. **No external benchmarks**: There is no published benchmark dataset for software supply-chain attack detection that the platform is evaluated against. Performance claims are therefore limited to demo scenario accuracy and are not generalized to unknown inputs.

4. **Heuristic metrics, not statistical metrics**: Precision, recall, and F1 scores are not computed because there is no labeled dataset of real supply-chain attacks to evaluate against. Metrics collected are operational and structural.

> [!IMPORTANT]
> All evaluation claims in this document are based on synthetic test scenarios. They do not represent performance guarantees on real-world repositories. Heuristic confidence scores are not probabilities and should not be interpreted as accuracy percentages.

---

## 2. Detection Evaluation Matrix

The following matrix evaluates the system's detection performance for each demo scenario. "Expected Detection" describes what the system should find. "Actual Status" reflects the pre-verified system output.

| Scenario | Name | Expected Detection | Actual Status | Confidence | Notes |
|----------|------|-------------------|--------------|-----------|-------|
| **A** | Vulnerable Transitive Dependency | CVE evidence from OSV (FACT), transitive path resolution from lockfile (FACT), mixin-deep@1.3.1 flagged as VULNERABLE/HIGH | ✅ PASS | 0.75 | Two FACT evidence items confirmed; OSV query returns GHSA-29mw-wpgm-hmr9; lockfile resolves transitive chain correctly |
| **B** | Typosquatting | `reqeusts` detected as TYPOSQUATTING/HIGH with edit distance=1 similarity=0.92, metadata anomalies (new publisher, zero downloads) | ✅ PASS | 0.80 | TyposquattingDetector correctly identifies transposition; MetadataAnomalyDetector signals new publisher account; three HEURISTIC evidence items combined |
| **C** | Compromised Update | `data-parser@1.3.0` flagged as COMPROMISED_UPDATE/CRITICAL; AST finds subprocess + base64; simulated outbound connection to suspicious-c2.example.com | ✅ PASS | 0.85 | Two AST HEURISTIC evidence items; one SIMULATED runtime signal (clearly labeled); simulated signal contributes minimal confidence |
| **D** | Multi-Level Propagation | `malicious-logger@0.9.1` identified as ORIGIN at depth 4; blast radius 94; propagation path through Service X → API Gateway → Production Deployment | ✅ PASS | 0.82 | Origin engine correctly identifies malicious-logger as leaf-direction highest-evidence node; blast radius formula produces 94; propagation path complete |
| **E** | CI/CD Supply-Chain Risk | `deploy.yml` flagged as CICD_RISK/CRITICAL; three FACT/HEURISTIC CI/CD findings; production deployment flagged as affected | ✅ PASS | 0.78 | CICDAnalysisEngine detects curl\|bash (FACT), write-all (FACT), unpinned action (HEURISTIC); inference produces build artifact compromise evidence |

### 2.1 Expected Detection Detail per Scenario

#### Scenario A — Required Outputs

- [ ] `mixin-deep@1.3.1` node present in graph with `is_suspicious=true`
- [ ] `GHSA-29mw-wpgm-hmr9` vulnerability node present and linked via `AFFECTS` edge
- [ ] `DEPENDS_ON` chain: `lodash@4.17.20` → `mixin-deep@1.3.1` present
- [ ] Finding: `finding_type=VULNERABLE`, `severity=HIGH`, `confidence=0.75`
- [ ] Evidence count: 2 items (1 OSV FACT + 1 lockfile FACT)
- [ ] Origin candidate: `mixin-deep@1.3.1`
- [ ] Recommendation: upgrade/pin mixin-deep to ≥2.0.0

#### Scenario B — Required Outputs

- [ ] `reqeusts@2.31.0` node present in graph with `is_suspicious=true`
- [ ] Finding: `finding_type=TYPOSQUATTING`, `severity=HIGH`, `confidence=0.80`
- [ ] Evidence count: 3 items (edit distance + publisher anomaly + zero downloads, all HEURISTIC)
- [ ] Similarity score: 0.92, edit distance: 1
- [ ] `requests@2.31.0` present as clean reference package in graph
- [ ] Recommendation: remove reqeusts, verify requests

#### Scenario C — Required Outputs

- [ ] `data-parser@1.3.0` node present with `is_suspicious=true`
- [ ] Finding: `finding_type=COMPROMISED_UPDATE`, `severity=CRITICAL`, `confidence=0.85`
- [ ] Evidence count: 3 items (AST subprocess + AST obfuscation HEURISTIC + SIMULATED runtime)
- [ ] Simulated signal: `is_simulated=true`, `simulated_label` present
- [ ] `runtime_observation` node: dashed border, SIMULATED badge in UI
- [ ] Capability nodes: `PROCESS_EXECUTION`, `NETWORK_ACCESS` linked via `EXHIBITS`
- [ ] Recommendation: pin to v1.2.0

#### Scenario D — Required Outputs

- [ ] All 5 package nodes present: demo-app, package-a, package-b, package-c, malicious-logger
- [ ] `DEPENDS_ON` chain: demo-app → package-a → package-b → package-c → malicious-logger
- [ ] Origin engine result: `malicious-logger@0.9.1`
- [ ] Propagation path: malicious-logger → Service X → API Gateway → Production Deployment
- [ ] Blast radius: 94 (formula: 2×2 + 15×1 + 25×1 + 50×1)
- [ ] Finding: `severity=CRITICAL`, `confidence=0.82`
- [ ] Service X, API Gateway, Production Deployment nodes present

#### Scenario E — Required Outputs

- [ ] `deploy.yml` pipeline node present with `is_flagged=true`
- [ ] Finding: `finding_type=CICD_RISK`, `severity=CRITICAL`, `confidence=0.78`
- [ ] Evidence count: 4 items (remote exec FACT + write-all FACT + unpinned action HEURISTIC + compromised artifact INFERENCE)
- [ ] Production Deployment node present, linked via `TRIGGERS` edge from pipeline
- [ ] Recommendations: pin actions, remove curl|bash, restrict permissions

---

## 3. Metrics Collected

The following operational metrics are recorded for each scan (demo and live). These metrics are stored in the `scans.summary` JSON field and are available via the API.

### 3.1 Detection Metrics

| Metric | Description | Measurement Method |
|--------|-------------|-------------------|
| **Transitive depth detected** | Maximum transitive dependency depth successfully resolved | Count of `DEPENDS_ON` edge chain length from root to deepest resolved node |
| **Origin identification** | Whether an origin candidate was identified | Boolean: `origin_candidate` field present and non-null |
| **Origin correctness** (demo-only) | Whether origin candidate matches expected origin in scenario spec | Comparison against scenario spec field `expected_origin` |
| **Propagation path completeness** | Whether the identified propagation path includes all expected nodes | Count of expected path nodes present in `propagation_path` / total expected |
| **Affected asset coverage** | Whether all expected assets appear in `affected_assets` | Count of expected assets present / total expected |
| **Evidence count per finding** | Total number of evidence items per finding | Count of items in `evidence[]` array |
| **FACT evidence ratio** | Proportion of evidence items classified as FACT | `count(classification=FACT)` / `count(evidence)` |
| **Simulated evidence ratio** | Proportion of evidence items that are simulated | `count(is_simulated=true)` / `count(evidence)` |

### 3.2 Performance Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Total scan duration** | Time from scan creation to COMPLETE status | < 300 seconds for repositories up to 100 MB |
| **GitHub API call count** | Number of API requests made per scan | Minimized via batching; target < 50 per scan |
| **OSV query count** | Number of PURL queries to OSV API | One per unique package; cached after first call |
| **Graph node count** | Total nodes in the security knowledge graph | Logged in `graph_snapshots.node_count` |
| **Graph edge count** | Total edges in the security knowledge graph | Logged in `graph_snapshots.edge_count` |

### 3.3 Demo-Based False Positive Rate

Since there is no ground-truth dataset, false positive rate is approximated in the demo context as follows:

**Definition**: A false positive in the demo context is a finding produced by the system for a clean entity that the scenario specification marks as clean.

For each scenario, clean packages are included in the SBOM alongside suspicious ones. The system must not flag clean packages as suspicious.

| Scenario | Clean Packages in Scope | Expected False Positives | Demo FP Rate |
|----------|------------------------|------------------------|-------------|
| A | `lodash@4.17.20` | 0 | 0.0% |
| B | `requests@2.31.0` | 0 | 0.0% |
| C | N/A (only data-parser in scope) | 0 | 0.0% |
| D | `package-a@2.0.0`, `package-b@1.5.0` | 0 | 0.0% |
| E | `actions/checkout@v3` (low severity) | 0 for CRITICAL/HIGH | 0.0% for HIGH+ |

> [!NOTE]
> Demo-based FP rate does not generalize to real-world performance. The reference package list and detection thresholds are tuned for these specific scenarios and may produce false positives on other repositories.

---

## 4. Honest Limitations

The following limitations are explicitly acknowledged and must not be obscured in any presentation or documentation.

### 4.1 Confidence Scores Are Heuristics, Not Probabilities

The confidence score produced by `C = 1 - Π(1 - wᵢ × rᵢ)` is a heuristic combination formula. The weights `wᵢ` are manually configured based on intuitive severity of each evidence type, not derived from a statistical analysis of labeled attack data. The reliabilities `rᵢ` are fixed constants per classification type, not learned from data.

**Implication**: A confidence score of 0.82 does not mean there is an 82% probability that the package is malicious. It means that the configured evidence weights and reliabilities combine to produce a score of 0.82 using the defined formula. Manual review is always required before taking action.

### 4.2 Simulated Runtime Signals Are Not Production Telemetry

All runtime signals in the demo context are generated synthetically by projecting static analysis findings through rule-based templates. They represent what the package *might* do based on its code, not what it *has* done in any real environment.

**Implication**: Simulated signals cannot be used as evidence of actual compromise. They exist only to illustrate how the platform would integrate with real runtime monitoring systems in a production deployment.

### 4.3 Typosquatting Detection Is Similarity, Not Intent

The typosquatting detector identifies structural similarity between package names using edit distance and character substitution patterns. It does not query PyPI or npm security teams, does not analyze package contents in detail, and does not determine author intent.

**Implication**: Some legitimate packages may have similar names to popular packages (e.g., a legitimate fork, a plugin named with a prefix). All typosquatting findings require human verification.

### 4.4 OSV Coverage Depends on What Is Indexed

SupplyGraph's vulnerability detection is limited to advisories indexed by the OSV database. Vulnerabilities not yet reported to OSV (zero-days, privately disclosed, ecosystem-specific databases not federated into OSV) will not be detected.

**Implication**: A clean OSV result does not mean a package has no vulnerabilities. It means no known advisory is indexed in OSV for that PURL.

### 4.5 Transitive Resolution Requires Lockfiles

Transitive dependency chains are only fully resolved when lockfiles are present in the repository (`poetry.lock`, `package-lock.json`, `yarn.lock`, `Pipfile.lock`). Without lockfiles, only direct dependencies with explicit version pins can be resolved. Range specifiers without lockfiles produce incomplete dependency graphs.

**Implication**: Scenario A (transitive vulnerability) only works correctly because a `package-lock.json` is present in the demo. Real repositories without lockfiles will have less complete transitive analysis.

### 4.6 Static Analysis Is Python-Only

The AST analysis engine, obfuscation detector, and dormant logic detector currently support only Python source files. Repositories written in JavaScript, TypeScript, Rust, Go, Java, or other languages will not have source-level static analysis applied. Only manifest/lockfile parsing and OSV queries are ecosystem-agnostic.

### 4.7 Gemini Output Is Not Evidence

The Gemini-generated summary is a natural-language description of findings, produced by a large language model. It is not a source of evidence and must not be treated as such. Gemini can hallucinate, and although the prompt constrains it to only reference information in the provided JSON, no output from a language model should be relied upon as ground truth for security decisions.

### 4.8 No Real Network Monitoring

The platform has no integration with real network monitoring infrastructure (SIEM, EDR, IDS/IPS). All "runtime" signals are simulated. In a production deployment, integration with real telemetry sources would significantly increase detection accuracy and evidence quality.

---

## 5. Reporting Format

For each finding produced by SupplyGraph, the following standardized report fields are collected and displayed.

### 5.1 Finding Report Template

| Field | Description | Example |
|-------|-------------|---------|
| **Entity** | Name and version of the entity (package, pipeline, etc.) | `mixin-deep@1.3.1` |
| **Entity Type** | Type of the entity | `Package` |
| **Finding Type** | Type of the finding | `VULNERABLE` |
| **Severity** | Severity level | `HIGH` |
| **Confidence Score** | Heuristic confidence score [0.0, 1.0] | `0.75` |
| **Evidence Count** | Total number of supporting evidence items | `2` |
| **FACT Evidence Count** | Number of evidence items classified as FACT | `2` |
| **HEURISTIC Evidence Count** | Number of evidence items classified as HEURISTIC | `0` |
| **SIMULATED Evidence Count** | Number of evidence items that are simulated | `0` |
| **Origin Candidate** | Most likely attack entry point, if determined | `mixin-deep@1.3.1` |
| **Propagation Path Length** | Number of hops in the propagation path | `3` |
| **Propagation Path** | Ordered list of nodes in the path | `mixin-deep → lodash → demo-app → Web Service` |
| **Affected Asset Count** | Number of downstream assets affected | `1` |
| **Affected Assets** | Names of affected assets | `Web Service` |
| **Blast Radius Score** | Numeric blast radius (formula: 2P+15S+25A+50D) | `17` |
| **Blast Radius Breakdown** | Per-component breakdown | `P=1(2pts) S=1(15pts)` |
| **Recommendation Count** | Number of actionable recommendations | `3` |
| **Recommendations** | List of recommendations with urgency and effort | See below |
| **Is Demo** | Whether this is a demo/synthetic scenario | `true` |
| **Demo Label** | Label for demo findings | `DEMO / SYNTHETIC TEST CASE` |

### 5.2 Recommendation Report Template

For each recommendation within a finding:

| Field | Description | Example |
|-------|-------------|---------|
| **Action** | Action type | `UPGRADE_DEPENDENCY` |
| **Target** | Affected entity | `mixin-deep` |
| **Description** | Full human-readable recommendation | `Upgrade mixin-deep to version >=2.0.0 to resolve GHSA-29mw-wpgm-hmr9` |
| **Urgency** | `IMMEDIATE`, `HIGH`, `MEDIUM`, `LOW` | `HIGH` |
| **Effort** | `LOW`, `MEDIUM`, `HIGH` | `LOW` |

### 5.3 Full Scan Summary Report Template

The following fields are included in every scan summary:

| Field | Description |
|-------|-------------|
| **Scan ID** | UUID of the scan |
| **Repository URL** | Analyzed repository URL |
| **Scan Duration (seconds)** | Time from creation to completion |
| **Total Packages Analyzed** | Count of packages in the SBOM |
| **Total Findings** | Total finding count |
| **Critical Findings** | Count of CRITICAL severity findings |
| **High Findings** | Count of HIGH severity findings |
| **Medium Findings** | Count of MEDIUM severity findings |
| **Low Findings** | Count of LOW severity findings |
| **Max Blast Radius Score** | Highest blast radius score among all findings |
| **Origin Candidate** | Most likely attack entry point (if determined) |
| **Transitive Depth Resolved** | Maximum transitive depth reached by the resolver |
| **Evidence Items Total** | Total evidence items across all findings |
| **Simulated Evidence Items** | Count of simulated evidence items |
| **FACT Evidence Items** | Count of FACT evidence items |
| **Graph Node Count** | Total nodes in the security knowledge graph |
| **Graph Edge Count** | Total edges in the security knowledge graph |
| **OSV Queries Made** | Count of OSV API queries (or cache hits) |
| **Gemini Summary** | AI-generated executive summary |
| **Is Demo** | Whether this is a demo scan |

### 5.4 API Output for Reporting

The full report is available via:

```
GET /api/v1/scans/{scan_id}
```

For programmatic reporting, the structured JSON response contains all fields above. A summary-only view (lighter payload):

```
GET /api/v1/scans/{scan_id}?view=summary
```

Returns only the `summary` object without the full `findings` array and `graph` object.

### 5.5 Evaluation Output for Demo Scenarios

For each demo scenario run, the evaluation output compares expected vs. actual:

```json
{
  "scenario_id": "A",
  "evaluation": {
    "expected_finding_type": "VULNERABLE",
    "actual_finding_type": "VULNERABLE",
    "match": true,
    "expected_severity": "HIGH",
    "actual_severity": "HIGH",
    "match_severity": true,
    "expected_confidence_range": [0.70, 0.80],
    "actual_confidence": 0.75,
    "match_confidence": true,
    "expected_evidence_count_min": 2,
    "actual_evidence_count": 2,
    "match_evidence_count": true,
    "expected_origin": "mixin-deep@1.3.1",
    "actual_origin": "mixin-deep@1.3.1",
    "match_origin": true,
    "expected_path_nodes": ["mixin-deep@1.3.1", "lodash@4.17.20", "demo-app"],
    "actual_path_nodes": ["mixin-deep@1.3.1", "lodash@4.17.20", "demo-app"],
    "path_completeness": 1.0,
    "expected_blast_radius_min": 15,
    "actual_blast_radius": 17,
    "match_blast_radius": true,
    "overall_pass": true
  }
}
```

This evaluation object is returned by:
```
GET /api/v1/scans/{scan_id}/evaluate
```

Available only for demo scans (`is_demo=true`). Not available for live repository scans (no ground truth to compare against).
