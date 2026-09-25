# SupplyGraph — Evidence Model

> **Evidence-driven software supply-chain attack analysis.**

This document defines the evidence philosophy, schema, classification rules, sources, and terminology prohibitions that govern how SupplyGraph discovers, records, and presents security findings.

---

## 1. Evidence Philosophy

SupplyGraph operates under a strict **evidence-first principle**: no security finding is generated, presented, or scored without being anchored to one or more structured, typed evidence items. This principle exists to:

1. **Prevent fabrication**: Every finding must trace back to a real data source (OSV API, GitHub API, AST parse result, lockfile parse result). Invented findings are prohibited.
2. **Enable transparency**: Users must always be able to inspect the exact evidence items that produced a finding, including the raw data they contain.
3. **Support honest uncertainty**: Evidence classification distinguishes between confirmed facts, heuristic inferences, simulated projections, and unknown signals. Confidence scores reflect these distinctions.
4. **Resist overconfidence**: No evidence type, alone or combined, can push a confidence score to 1.0 for heuristic or simulated evidence. The scoring formula is designed to reflect inherent uncertainty.

### Evidence Types

| Classification | Code | Definition |
|---------------|------|-----------|
| **FACT** | `FACT` | Directly verifiable, authoritative data. Example: an OSV advisory match for a known CVE, or a hardcoded credential string found at a specific file location. |
| **HEURISTIC** | `HEURISTIC` | A signal derived from pattern matching or statistical analysis that suggests risk but does not confirm malicious intent. Example: a similarity score between package names, or detection of `subprocess.call()` in source code. |
| **SIMULATED** | `SIMULATED` | A synthetic runtime signal projected from static analysis for demonstration purposes. Not a real observation. Must always be displayed with a "SIMULATED" label and badge. |
| **INFERENCE** | `INFERENCE` | A logical deduction from multiple evidence items. Example: "Package A exhibits NETWORK_ACCESS behaviour AND has a similarity score > 0.85 to a known package, therefore it is likely a typosquatting candidate with network exfiltration capability." Not a direct observation. |
| **UNKNOWN** | `UNKNOWN` | Evidence where the classification cannot be determined. Should be treated as low-confidence and require manual review. |

---

## 2. Evidence Item Schema

Every evidence item is a structured JSON object conforming to the following schema. Evidence items are stored in the `evidence_items` table in Supabase/PostgreSQL and referenced by `finding` records.

### 2.1 Full Schema

```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "entity_id": "uuid",
  "entity_type": "Package | Repository | Pipeline | Version | Maintainer",
  "source": "osv | github | ast | metadata | cicd | runtime | lockfile | sbom",
  "evidence_type": "VULNERABILITY | SUSPICIOUS_BEHAVIOUR | METADATA_ANOMALY | CODE_FINDING | CICD_FINDING | RUNTIME_SIGNAL | TYPOSQUATTING | DEPENDENCY_CONFUSION",
  "classification": "FACT | HEURISTIC | SIMULATED | INFERENCE | UNKNOWN",
  "title": "Short human-readable title of the evidence item",
  "description": "Full description of what was observed and why it is significant",
  "source_location": {
    "file": "path/to/file.py",
    "line": 42,
    "column": 0,
    "snippet": "optional source code snippet (max 200 chars)"
  },
  "confidence_contribution": 0.0,
  "weight": 0.0,
  "reliability": 1.0,
  "is_simulated": false,
  "simulated_label": null,
  "timestamp": "2026-09-25T09:00:00Z",
  "raw_data": {
    "osv_id": "GHSA-xxxx-yyyy-zzzz",
    "cvss_score": 7.4,
    "affected_range": ">=1.0.0,<2.0.0"
  }
}
```

### 2.2 Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes | Unique identifier for this evidence item |
| `scan_id` | UUID | Yes | The scan this evidence belongs to |
| `entity_id` | UUID | Yes | The graph node this evidence is about |
| `entity_type` | string | Yes | Type of the entity (Package, Repository, etc.) |
| `source` | string | Yes | Data source: `osv`, `github`, `ast`, `metadata`, `cicd`, `runtime`, `lockfile`, `sbom` |
| `evidence_type` | string | Yes | Category of evidence (see types below) |
| `classification` | string | Yes | `FACT`, `HEURISTIC`, `SIMULATED`, `INFERENCE`, or `UNKNOWN` |
| `title` | string | Yes | Short (≤100 chars) human-readable summary |
| `description` | string | Yes | Full description of the observation |
| `source_location` | object | No | File and line reference, if applicable |
| `source_location.file` | string | No | Relative file path within the repository |
| `source_location.line` | integer | No | Line number (1-indexed) |
| `source_location.column` | integer | No | Column number (1-indexed), optional |
| `source_location.snippet` | string | No | Code snippet (max 200 characters), sanitized |
| `confidence_contribution` | float | Yes | Pre-computed contribution to the finding's confidence score |
| `weight` | float | Yes | Configured weight wᵢ for this evidence type (0.0–1.0) |
| `reliability` | float | Yes | Reliability multiplier rᵢ based on classification (FACT=1.0, HEURISTIC=0.7, SIMULATED=0.15, INFERENCE=0.5, UNKNOWN=0.3) |
| `is_simulated` | boolean | Yes | Whether this evidence was synthetically generated |
| `simulated_label` | string | No | If simulated, the label string to display: `"SIMULATED — Not real production telemetry"` |
| `timestamp` | ISO8601 | Yes | When this evidence item was created |
| `raw_data` | object | Yes | Source-specific raw data payload (see Section 4 for per-source schemas) |

### 2.3 Evidence Type Definitions

| `evidence_type` | Description |
|----------------|-------------|
| `VULNERABILITY` | A known CVE/GHSA/OSV vulnerability match for a specific package version |
| `SUSPICIOUS_BEHAVIOUR` | A code pattern or capability detected by static analysis that is associated with malicious behaviour |
| `METADATA_ANOMALY` | An anomaly in package metadata (release timing, new maintainer, account age, etc.) |
| `CODE_FINDING` | A static analysis finding at a specific file and line (AST-based) |
| `CICD_FINDING` | A risk pattern detected in a CI/CD workflow configuration |
| `RUNTIME_SIGNAL` | A runtime observation (always simulated in demo context; `is_simulated=true`) |
| `TYPOSQUATTING` | A structural similarity signal between package names |
| `DEPENDENCY_CONFUSION` | A namespace ambiguity signal between internal and public package registries |

---

## 3. Finding Schema

A finding is the primary output unit of the analysis engine. Each finding aggregates one or more evidence items for a single entity and carries the full context needed for both display and remediation.

### 3.1 Full Schema

```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "entity_id": "uuid",
  "entity_type": "Package | Repository | Pipeline | Version | Maintainer",
  "entity_name": "human-readable entity name",
  "finding_type": "VULNERABLE | SUSPICIOUS | TYPOSQUATTING | DEPENDENCY_CONFUSION | COMPROMISED_UPDATE | OBFUSCATION | DORMANT_LOGIC | CICD_RISK",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "confidence": 0.0,
  "evidence": [
    {
      "id": "uuid",
      "evidence_type": "VULNERABILITY",
      "classification": "FACT",
      "title": "Known vulnerability CVE-2021-12345",
      "description": "...",
      "source": "osv",
      "confidence_contribution": 0.85,
      "is_simulated": false
    }
  ],
  "origin_candidate": "malicious-logger@0.9.1",
  "propagation_path": [
    {
      "node_id": "uuid",
      "node_type": "package",
      "node_name": "malicious-logger@0.9.1",
      "edge_type": "DEPENDS_ON",
      "depth": 0
    },
    {
      "node_id": "uuid",
      "node_type": "package",
      "node_name": "package-b@1.0.0",
      "edge_type": "DEPENDS_ON",
      "depth": 1
    }
  ],
  "affected_assets": [
    {
      "asset_id": "uuid",
      "asset_name": "Production API Gateway",
      "asset_type": "api_gateway",
      "criticality": "CRITICAL",
      "is_production": true
    }
  ],
  "impact": {
    "blast_radius_score": 94,
    "affected_packages_count": 2,
    "affected_services_count": 1,
    "affected_apis_count": 1,
    "affected_deployments_count": 1,
    "blast_radius_formula": "2*2 + 15*1 + 25*1 + 50*1 = 94"
  },
  "recommendations": [
    {
      "id": "uuid",
      "action": "REMOVE_PACKAGE",
      "target": "malicious-logger",
      "description": "Remove malicious-logger from all dependency declarations and lock files.",
      "urgency": "IMMEDIATE",
      "effort": "LOW"
    }
  ],
  "gemini_summary": "Plain-language AI-generated summary of this finding.",
  "is_demo": false,
  "demo_label": null,
  "created_at": "2026-09-25T09:00:00Z"
}
```

### 3.2 Finding Type Definitions

| `finding_type` | Description | Default Severity |
|---------------|-------------|-----------------|
| `VULNERABLE` | Package version has a known CVE/GHSA vulnerability confirmed by OSV | Based on CVSS score |
| `SUSPICIOUS` | Package exhibits multiple heuristic risk signals without a confirmed CVE | MEDIUM–HIGH |
| `TYPOSQUATTING` | Package name closely resembles a well-known package; likely impersonation | HIGH |
| `DEPENDENCY_CONFUSION` | Package name exists in both internal and public registries, with ambiguous sourcing | HIGH |
| `COMPROMISED_UPDATE` | A version update introduced suspicious new capabilities not present in the prior version | HIGH–CRITICAL |
| `OBFUSCATION` | Source code contains intentional obfuscation patterns consistent with hiding malicious payloads | HIGH |
| `DORMANT_LOGIC` | Source code contains conditional logic consistent with time-bombs or trigger-based execution | MEDIUM–HIGH |
| `CICD_RISK` | A CI/CD workflow contains patterns that could allow supply-chain compromise of the build | MEDIUM–CRITICAL |

---

## 4. Evidence Sources

### 4.1 OSV (Open Source Vulnerabilities)

**Source identifier**: `osv`

**Description**: The OSV database is the authoritative source for known vulnerability data. Queries are made to `api.osv.dev/v1/querybatch` using canonical PURLs. Responses are cached locally.

**Classification**: Always `FACT` (OSV records are authoritative advisories from the OSV ecosystem).

**Raw data schema**:
```json
{
  "osv_id": "GHSA-29mw-wpgm-hmr9",
  "aliases": ["CVE-2019-20920"],
  "summary": "Prototype pollution in mixin-deep",
  "severity": "HIGH",
  "cvss_score": 8.3,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "affected_range": ">=1.0.0,<2.0.0",
  "fixed_in": "2.0.0",
  "published_at": "2020-09-01T00:00:00Z",
  "purl_queried": "pkg:npm/mixin-deep@1.3.1"
}
```

**Weight**: `0.90` (highest, as OSV data is authoritative)

---

### 4.2 GitHub API

**Source identifier**: `github`

**Description**: Repository metadata, commit history, release history, and contributor information retrieved from the GitHub REST API v3. Used for metadata anomaly detection and suspicious commit identification.

**Classification**: `FACT` for raw API-returned data (e.g., account creation date, contributor list); `HEURISTIC` for anomaly inferences drawn from that data.

**Raw data schema**:
```json
{
  "endpoint": "/repos/owner/repo/releases",
  "github_api_version": "2022-11-28",
  "retrieved_at": "2026-09-25T09:00:00Z",
  "data": {
    "release_id": 123456,
    "tag_name": "v1.3.0",
    "published_at": "2026-09-24T02:00:00Z",
    "author_login": "new-user-xyz",
    "author_created_at": "2026-09-01T00:00:00Z"
  }
}
```

**Weight (metadata anomaly)**: `0.50`

---

### 4.3 AST Analysis

**Source identifier**: `ast`

**Description**: Python Abstract Syntax Tree analysis of source files using the built-in `ast` module. Produces findings at file and line level for suspicious capability patterns.

**Classification**: `HEURISTIC` (pattern matching indicates capability, not confirmed malicious intent).

**Raw data schema**:
```json
{
  "file": "setup.py",
  "line": 42,
  "column": 8,
  "rule_id": "AST-SUBPROCESS-SHELL-TRUE",
  "rule_name": "subprocess.call with shell=True",
  "pattern_matched": "subprocess.call(..., shell=True)",
  "ast_node_type": "Call",
  "snippet": "subprocess.call(['rm', '-rf', '/'], shell=True)",
  "capability_signal": "PROCESS_EXECUTION"
}
```

**Weight (capability signals)**: `0.60`; **Weight (obfuscation patterns)**: `0.70`

---

### 4.4 CI/CD Analysis

**Source identifier**: `cicd`

**Description**: YAML parsing and pattern matching against GitHub Actions workflow files. Identifies supply-chain risks in the build and deployment pipeline.

**Classification**: `HEURISTIC` for pattern-based findings; `FACT` where the pattern is unambiguous (e.g., a `curl | bash` pipeline run step).

**Raw data schema**:
```json
{
  "workflow_file": ".github/workflows/deploy.yml",
  "job_name": "build",
  "step_name": "Install dependencies",
  "line": 18,
  "rule_id": "CICD-REMOTE-EXEC",
  "rule_name": "Remote script execution",
  "pattern_matched": "curl https://example.com/install.sh | bash",
  "raw_step_run": "curl https://example.com/install.sh | bash"
}
```

**Weight**: `0.75`

---

### 4.5 Metadata Analysis

**Source identifier**: `metadata`

**Description**: Anomaly signals derived from package metadata: release timing, account ages, contributor changes, unusual publication patterns.

**Classification**: `HEURISTIC`

**Raw data schema**:
```json
{
  "anomaly_type": "NEW_MAINTAINER_BEFORE_RELEASE",
  "package": "some-package",
  "version": "1.3.0",
  "maintainer_login": "new-user-xyz",
  "maintainer_account_age_days": 24,
  "days_before_release": 5,
  "threshold_days": 30
}
```

**Weight**: `0.50`

---

### 4.6 Lockfile Parsing

**Source identifier**: `lockfile`

**Description**: Parsed lockfile content (poetry.lock, package-lock.json, yarn.lock, Pipfile.lock) providing exact resolved versions for transitive dependency resolution.

**Classification**: `FACT` (lockfiles represent the ground truth of what is installed)

**Raw data schema**:
```json
{
  "lockfile": "poetry.lock",
  "package_name": "mixin-deep",
  "resolved_version": "1.3.1",
  "ecosystem": "pypi",
  "purl": "pkg:pypi/mixin-deep@1.3.1",
  "is_direct": false,
  "depth": 2,
  "resolved_via": ["lodash@4.17.20"]
}
```

**Weight**: `0.80` (lockfile data directly informs OSV queries)

---

### 4.7 Simulated Runtime

**Source identifier**: `runtime`

**Description**: Synthetic runtime signals projected from AST capability findings for demonstration purposes. These are never real production observations. They are generated deterministically from static analysis results.

**Classification**: Always `SIMULATED`

**Raw data schema**:
```json
{
  "signal_type": "OUTBOUND_CONNECTION",
  "target_domain": "suspicious-c2.example.com",
  "target_port": 443,
  "source_package": "data-parser@1.3.0",
  "is_simulated": true,
  "label": "SIMULATED — Not real production telemetry",
  "projected_from_evidence_id": "uuid",
  "projection_rule": "AST-SUBPROCESS + BASE64-DECODE → OUTBOUND_CONNECTION"
}
```

**Weight**: `0.15` (heavily discounted; simulated data must not dominate scoring)

---

## 5. Evidence Classification Rules

### 5.1 When to Use FACT

Use `FACT` when the evidence is:
- Directly returned by an authoritative external API (OSV, GitHub API) without inference
- A literal, unambiguous observation in source code (e.g., a hardcoded secret string matching a known credential pattern)
- A lockfile-resolved package version (no inference required; lockfiles are ground truth)
- A confirmed CVE match returned by the OSV batch query

**FACT evidence has reliability `rᵢ = 1.0`.**

---

### 5.2 When to Use HEURISTIC

Use `HEURISTIC` when the evidence is:
- Derived from pattern matching that could produce false positives (e.g., edit distance comparison for typosquatting detection)
- A static analysis finding that identifies a capability (not confirmed malicious use)
- A metadata anomaly (e.g., new maintainer) that is suspicious but not inherently malicious
- A CI/CD pattern (e.g., script download) that is risky but not necessarily malicious
- A statistical outlier in release timing or contributor behaviour

**HEURISTIC evidence has reliability `rᵢ = 0.7`.**

---

### 5.3 When to Use SIMULATED

Use `SIMULATED` when the evidence is:
- A runtime signal that was not actually observed but was projected from static analysis
- Generated by the Simulated Runtime Signal Engine for demonstration purposes
- Any evidence item where `source = "runtime"` in the demo context

Simulated evidence **must always** carry:
- `is_simulated = true`
- `simulated_label = "SIMULATED — Not real production telemetry"`
- `classification = "SIMULATED"`

**SIMULATED evidence has reliability `rᵢ = 0.15`.**

---

### 5.4 When to Use INFERENCE

Use `INFERENCE` when the evidence is:
- A logical deduction drawn from combining two or more other evidence items
- Not directly observed but reasonably inferred from confirmed or heuristic evidence
- A propagation path conclusion ("Package C is affected because Package B depends on Package C and Package B is confirmed compromised")

**INFERENCE evidence has reliability `rᵢ = 0.5`.**

---

### 5.5 When to Use UNKNOWN

Use `UNKNOWN` when:
- Evidence was retrieved from a source but its classification cannot be determined
- A new detector produces output that has not yet been classified
- The data source itself is of unknown reliability

**UNKNOWN evidence has reliability `rᵢ = 0.3`.**

---

### 5.6 Rules for Combining Evidence

Evidence items are combined using the independent evidence formula in the Confidence Engine:

```
C = 1 - Π(1 - wᵢ × rᵢ)
```

Where the product runs over all evidence items i associated with a finding.

**Combination rules**:

1. **Single FACT item** (e.g., OSV match, w=0.90, r=1.0) → C = 0.90. This is the maximum achievable from a single OSV finding.
2. **Two HEURISTIC items** (w₁=0.60, r₁=0.7; w₂=0.50, r₂=0.7) → C = 1 - (1-0.42)(1-0.35) = 1 - 0.58×0.65 ≈ 0.623.
3. **One FACT + two HEURISTIC items** → C = 1 - (1-0.90)(1-0.42)(1-0.35) ≈ 0.962. Capped at 0.95 for non-all-FACT combinations.
4. **One SIMULATED item alone** (w=0.15, r=0.15) → C = 0.0225. Simulated items alone cannot produce meaningful confidence.
5. **Evidence from different source types is preferred**: If two evidence items of the same type and source are present, they may be deduplicated by the Evidence Correlation Engine before scoring.

**Deduplication rules**:
- Two evidence items with identical `source`, `evidence_type`, `entity_id`, and `source_location.file + line` are considered duplicates. The one with higher `confidence_contribution` is retained.
- Simulated evidence items are never merged with FACT or HEURISTIC items of the same type.

---

### 5.7 Synthetic Evidence Discount Rules

Simulated runtime signals are subject to a mandatory discount:

| Condition | Discount Applied |
|-----------|----------------|
| `classification = SIMULATED` | `reliability` capped at 0.15 |
| `is_simulated = true` | `weight` capped at 0.15 |
| More than 3 simulated signals for one entity | Only top-3 by `confidence_contribution` are included in the formula |
| Any finding where ALL evidence is SIMULATED | `severity` is capped at `MEDIUM`; displayed with "All evidence is simulated" warning |

---

## 6. Terminology Prohibitions

The following language is **explicitly prohibited** in all code, documentation, user interface text, API responses, and Gemini-generated summaries:

### 6.1 Prohibited: Calling a Heuristic Score a Probability

**Prohibited**: "There is an 80% probability that this package is malicious."

**Required**: "This package has a confidence score of 0.80, based on heuristic evidence. This is not a probability; it reflects the aggregate weight of structured evidence items."

The confidence score produced by `C = 1 - Π(1 - wᵢ × rᵢ)` is a heuristic combination formula, not a Bayesian posterior probability. It is presented as a dimensionless score between 0.0 and 1.0.

---

### 6.2 Prohibited: Presenting Simulated Evidence as Production Telemetry

**Prohibited**: "This package was observed connecting to suspicious-c2.example.com."

**Required**: "This package was SIMULATED to connect to suspicious-c2.example.com based on static analysis findings. This is a projected signal, not a real runtime observation."

All UI elements displaying simulated signals must include the badge: `SIMULATED — Not real production telemetry`.

---

### 6.3 Prohibited: Claiming Similarity Proves Malicious Intent

**Prohibited**: "reqeusts is a malicious typosquatting package."

**Required**: "reqeusts has a structural similarity score of 0.92 to the legitimate package requests. This is a heuristic signal suggesting potential typosquatting. Manual verification is required to confirm intent."

The typosquatting detector produces similarity scores, not intent assessments. All typosquatting findings must use language such as "may be a typosquatting candidate", "structurally similar to", "warrants investigation".

---

### 6.4 Additional Prohibitions

| Prohibited | Required Alternative |
|-----------|---------------------|
| "Confirmed malicious package" (for HEURISTIC findings) | "Suspicious package with [N] heuristic signals" |
| "Definitely compromised" | "High-confidence finding (score: X.XX) based on [N] evidence items" |
| "Will exfiltrate data" | "Exhibits NETWORK_ACCESS and CREDENTIAL_ACCESS capability signals" |
| "Our AI detected that..." (for Gemini) | "The analysis engine found..." followed by specific evidence |
| "Zero false positives" | "Heuristic detection; manual verification recommended" |
| Gemini inventing CVE IDs | Gemini must only reference CVEs explicitly provided in the prompt context |
| Gemini inventing propagation paths | Gemini must only describe paths explicitly provided in the prompt context |
