# SupplyGraph — Detection Architecture

> **Evidence-driven software supply-chain attack analysis.**

This document defines the complete detection architecture: the philosophy governing all detectors, the registry of detectors with their algorithms and limitations, capability signal definitions, simulated runtime signal types, evidence correlation, and the scoring architecture.

---

## 1. Detection Philosophy

SupplyGraph follows a **deterministic-first** detection approach:

1. **No fabrication**: Every detector produces structured evidence items traceable to specific source data. No finding is invented.
2. **Explicit limitations**: Every detector's limitations are documented and surfaced in finding metadata.
3. **Classification honesty**: Static analysis findings are classified `HEURISTIC`, not `FACT`, unless the finding is unambiguous (e.g., an OSV match).
4. **Pattern, not intent**: Detectors identify code patterns and statistical anomalies. They do not infer intent. The word "malicious" is used only in recommendations and context, never as a conclusion from a single detector's output.
5. **Independent detectors**: Each detector operates independently on its input data. Correlation is the job of the Evidence Correlation Engine, not individual detectors.
6. **Configurable thresholds**: All detection thresholds are configurable via environment variables or a runtime configuration object. Default values are documented below.

---

## 2. Detector Registry

### Detector A: Typosquatting Detector

**Class**: `TyposquattingDetector`

**Module**: `backend/app/detectors/typosquatting.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `package_names` | `list[str]` | Package names extracted from the SBOM for the analyzed repository |
| `reference_list` | `list[str]` | Curated list of popular legitimate packages (top 1000 PyPI, top 500 npm) |
| `threshold` | `float` | Similarity threshold above which a pair is flagged. Default: `0.85` |

The reference list is stored at `backend/app/data/reference_packages.json` and is bundled with the application. It is not fetched at runtime.

#### Algorithm

```
FOR EACH package_name IN package_names:
  normalized_name = normalize(package_name)
  // Normalize: lowercase, replace hyphens/underscores with empty string
  
  FOR EACH reference_name IN reference_list:
    normalized_ref = normalize(reference_name)
    
    // Skip exact matches (package IS the reference)
    IF normalized_name == normalized_ref: CONTINUE
    
    // Compute normalized edit distance using rapidfuzz
    similarity = rapidfuzz.fuzz.ratio(normalized_name, normalized_ref) / 100.0
    
    // Check character substitution patterns
    substitution_score = check_substitutions(package_name, reference_name)
    
    // Compute final score (weighted average)
    final_score = (0.7 * similarity) + (0.3 * substitution_score)
    
    IF final_score >= threshold:
      EMIT typosquat_candidate(
        package=package_name,
        reference=reference_name,
        similarity_score=final_score,
        edit_distance=levenshtein_distance(normalized_name, normalized_ref)
      )
```

**Character Substitution Patterns Checked**:
- Single character transposition: `reqeusts` → `requests`
- Vowel replacement: `requosts` → `requests`
- Homoglyph substitution: `rn` → `m`, `0` → `o`, `1` → `l`
- Hyphen addition/removal: `requestslib` → `requests-lib`
- Appended suffixes: `-sdk`, `-api`, `-utils`, `-lib`, `-py`, `-python`
- Prepended prefixes: `py-`, `python-`
- Repeated characters: `requestts` → `requests`

#### Outputs

```python
@dataclass
class TyposquatCandidate:
    scan_id: UUID
    package_name: str
    reference_name: str
    similarity_score: float      # [0.0, 1.0]
    edit_distance: int           # Raw Levenshtein distance
    substitution_pattern: str    # Which pattern matched
    evidence: EvidenceItem       # Structured evidence with classification=HEURISTIC
```

#### Confidence Contribution

| Similarity Score | Confidence Contribution |
|----------------|------------------------|
| 0.95 – 1.00 | 0.80 |
| 0.90 – 0.95 | 0.70 |
| 0.85 – 0.90 | 0.55 |

#### Limitations

- **Similarity ≠ malicious intent**: A high similarity score means the package name is structurally close to a known package. It does not mean the package is malicious. The package may be a legitimate wrapper, fork, or plugin.
- **Reference list coverage**: Detection is limited to packages in the reference list. Typosquatting attacks against obscure or internal packages will not be detected.
- **Ecosystem-specific normalization**: The normalization logic is tuned for PyPI and npm. Other ecosystems may produce higher false-positive rates.
- **All findings classified HEURISTIC**: No typosquatting finding is classified FACT. Severity is capped at HIGH.

---

### Detector B: Dependency Confusion Detector

**Class**: `DependencyConfusionDetector`

**Module**: `backend/app/detectors/dependency_confusion.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `packages` | `list[PackageRecord]` | Package records from SBOM with name, version, ecosystem, source_registry |
| `internal_namespace_hints` | `list[str]` | Internal package prefixes hinted from repository configuration (e.g., company name) |

#### Algorithm

```
FOR EACH package IN packages:
  // Step 1: Check if package appears to be internal
  is_internal_looking = (
    package.name starts with any hint in internal_namespace_hints
    OR package.name contains "-internal", "-private", "-corp"
    OR package.version major component >= 100 (internal versioning convention)
  )
  
  IF NOT is_internal_looking: CONTINUE
  
  // Step 2: Check if package is resolvable from public registry
  public_exists = query_public_registry(package.name, package.ecosystem)
  
  IF NOT public_exists:
    CONTINUE  // Not a confusion risk; package doesn't exist publicly
  
  // Step 3: Check for version anomaly (public version > expected)
  public_version = get_latest_public_version(package.name, package.ecosystem)
  
  IF public_version >= package.version:
    risk_type = "PUBLIC_SHADOW_VERSION"
    severity = HIGH
  ELSE:
    risk_type = "NAMESPACE_COLLISION"
    severity = MEDIUM
  
  EMIT confusion_risk(
    package=package,
    risk_type=risk_type,
    public_registry_version=public_version,
    evidence=EvidenceItem(classification=HEURISTIC)
  )
```

#### Outputs

```python
@dataclass
class DependencyConfusionRisk:
    scan_id: UUID
    package_name: str
    risk_type: str              # "PUBLIC_SHADOW_VERSION" | "NAMESPACE_COLLISION"
    internal_version: str
    public_registry_version: str
    source_ambiguity: str       # Which registry would be resolved first
    evidence: EvidenceItem      # classification=HEURISTIC
```

#### Limitations

- **Requires registry access**: Public registry checks require live HTTP requests to PyPI/npm APIs. In offline mode, this detector is disabled.
- **Internal namespace hints are not always available**: Without `internal_namespace_hints`, the detector relies solely on heuristic naming patterns, increasing false-positive rate.
- **Version comparison is approximate**: The detector uses semantic versioning comparison; non-semver packages may produce incorrect results.

---

### Detector C: Suspicious Update Detector

**Class**: `SuspiciousUpdateDetector`

**Module**: `backend/app/detectors/suspicious_update.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `package` | `PackageRecord` | The package to analyze |
| `version_history` | `list[VersionRecord]` | Ordered list of versions (oldest to newest) |
| `source_files_by_version` | `dict[str, list[SourceFile]]` | Source files for each version (where available) |

#### Algorithm

```
FOR EACH consecutive version pair (v_before, v_after) IN version_history:
  
  // Step 1: Extract capability signals for each version via AST
  capabilities_before = extract_capabilities(source_files_by_version[v_before])
  capabilities_after = extract_capabilities(source_files_by_version[v_after])
  
  // Step 2: Identify new capabilities in v_after not in v_before
  new_capabilities = capabilities_after - capabilities_before
  
  // Step 3: Check for suspicious new capabilities
  suspicious_new = [c for c in new_capabilities if c in SUSPICIOUS_CAPABILITIES]
  // SUSPICIOUS_CAPABILITIES = {PROCESS_EXECUTION, NETWORK_ACCESS, CREDENTIAL_ACCESS, DYNAMIC_EXECUTION}
  
  // Step 4: Check for metadata anomalies around this version
  time_since_last_release = v_after.release_date - v_before.release_date
  changelog_available = check_changelog(package, v_after)
  
  // Step 5: Score the suspiciousness
  anomaly_score = compute_update_anomaly_score(
    suspicious_capability_count=len(suspicious_new),
    has_no_changelog=not changelog_available,
    rapid_release=(time_since_last_release.days < 1)
  )
  
  IF anomaly_score >= UPDATE_ANOMALY_THRESHOLD:  // Default: 0.60
    EMIT suspicious_update(
      package=package,
      version_before=v_before.version_string,
      version_after=v_after.version_string,
      new_capabilities=suspicious_new,
      anomaly_score=anomaly_score,
      evidence=EvidenceItem(classification=HEURISTIC)
    )
```

#### Outputs

```python
@dataclass
class SuspiciousUpdateRecord:
    scan_id: UUID
    package_name: str
    version_before: str
    version_after: str
    new_capabilities: list[str]     # Capability signals added in this version
    anomaly_score: float            # [0.0, 1.0]
    has_changelog: bool
    days_since_last_release: int
    evidence: EvidenceItem          # classification=HEURISTIC
```

#### Limitations

- **Source access required**: Comparing capabilities between versions requires access to source code for both versions. If the source is unavailable, the detector falls back to metadata-only analysis (reduced accuracy).
- **Legitimate updates also add capabilities**: Many legitimate updates add new features. The detector uses anomaly scoring, not binary classification. Manual review is required.

---

### Detector D: Obfuscation Detector

**Class**: `ObfuscationDetector`

**Module**: `backend/app/detectors/obfuscation.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `source_files` | `list[SourceFile]` | Python source files with their parsed AST |

#### Algorithm

The obfuscation detector applies a pattern registry to each Python AST. Each pattern is a visitor class that traverses the AST looking for specific node structures.

**Pattern Registry**:

| Pattern ID | Detection Target | AST Pattern |
|-----------|-----------------|-------------|
| `OBF-BASE64-EXEC` | `base64.b64decode()` result passed to `exec()` | `exec(base64.b64decode(...))` chain |
| `OBF-EVAL-NESTED` | Nested `eval()` calls | `eval(eval(...))` |
| `OBF-MARSHAL` | `marshal.loads()` with compiled code | `marshal.loads(...)` → `exec()` |
| `OBF-BUILTINS` | `__builtins__` manipulation | Assignment to `__builtins__` |
| `OBF-COMPILE-EXEC` | `compile()` + `exec()` pattern | `exec(compile(source, ...))` |
| `OBF-CHR-CHAIN` | `chr()` concatenation to build strings | `chr(104)+chr(101)+chr(108)+...` |
| `OBF-ZLIB-EXEC` | `zlib.decompress()` + `exec()` chain | `exec(zlib.decompress(base64.b64decode(...)))` |
| `OBF-IMPORT-MANGLING` | Dynamic import with obfuscated module name | `__import__(chr(111)+chr(115))` |
| `OBF-DYNAMIC-ATTR` | `getattr()` used to access built-ins | `getattr(__builtins__, 'exec')(...)` |

#### Outputs

```python
@dataclass
class ObfuscationFinding:
    scan_id: UUID
    file_path: str
    line_number: int
    column_number: int
    pattern_id: str
    pattern_name: str
    snippet: str                  # Code snippet (max 200 chars, sanitized)
    severity: str                 # HIGH or CRITICAL
    evidence: EvidenceItem        # classification=HEURISTIC
```

#### Confidence Contribution

| Pattern | Confidence Contribution |
|---------|------------------------|
| `OBF-ZLIB-EXEC` | 0.80 |
| `OBF-BASE64-EXEC` | 0.75 |
| `OBF-CHR-CHAIN` | 0.70 |
| `OBF-MARSHAL` | 0.75 |
| `OBF-COMPILE-EXEC` | 0.65 |
| `OBF-EVAL-NESTED` | 0.60 |
| `OBF-BUILTINS` | 0.70 |
| `OBF-DYNAMIC-ATTR` | 0.65 |
| `OBF-IMPORT-MANGLING` | 0.70 |

#### Limitations

- **Not all obfuscation is malicious**: Some legitimate tools (e.g., license enforcement, anti-piracy code) use encoding. The detector flags all obfuscation patterns; human review is required.
- **Python only**: The obfuscation detector currently supports only Python source files. JavaScript, Ruby, and other ecosystems are not analyzed.
- **Minified code**: Highly minified Python (rare) may trip some patterns without obfuscation intent.

---

### Detector E: Dormant Logic Detector

**Class**: `DormantLogicDetector`

**Module**: `backend/app/detectors/dormant_logic.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `source_files` | `list[SourceFile]` | Python source files with their parsed AST |

#### Algorithm

**Pattern Registry**:

| Pattern ID | Detection Target | AST Pattern |
|-----------|-----------------|-------------|
| `DORM-DATETIME-CMP` | Date/time comparison triggering code | `datetime.now() > datetime(YEAR, MONTH, DAY)` in conditional |
| `DORM-ENV-SWITCH` | Environment variable controlling execution path | `if os.environ.get("KEY") == "VALUE": <payload>` |
| `DORM-HOSTNAME-CHECK` | Hostname-based execution branching | `if socket.gethostname() == "target-host": <payload>` |
| `DORM-USER-CHECK` | Username-based execution branching | `if os.getlogin() == "target-user": <payload>` |
| `DORM-SLEEP-PAYLOAD` | Sleep-then-execute pattern | `time.sleep(large_number); <network_call or exec>` |
| `DORM-COUNTER-TRIGGER` | Counter-based trigger | Incrementing counter stored in file/env; execute after N invocations |
| `DORM-RANDOM-TRIGGER` | Probabilistic trigger | `if random.random() < 0.01: <payload>` |

```
FOR EACH source_file IN source_files:
  ast_tree = parse(source_file)
  
  FOR EACH pattern_visitor IN DORMANT_PATTERN_REGISTRY:
    matches = pattern_visitor.visit(ast_tree)
    
    FOR EACH match IN matches:
      // Check if the triggered block contains a suspicious capability
      triggered_capability = extract_capabilities(match.triggered_block)
      
      IF triggered_capability INTERSECTS SUSPICIOUS_CAPABILITIES:
        severity = HIGH
      ELSE:
        severity = MEDIUM
      
      EMIT dormant_finding(
        file=source_file.path,
        line=match.line,
        pattern_id=pattern_visitor.pattern_id,
        trigger_condition=match.trigger_description,
        triggered_capability=triggered_capability,
        severity=severity,
        evidence=EvidenceItem(classification=HEURISTIC)
      )
```

#### Outputs

```python
@dataclass
class DormantLogicFinding:
    scan_id: UUID
    file_path: str
    line_number: int
    pattern_id: str
    trigger_condition: str          # Human-readable description of the trigger
    triggered_capability: list[str] # Capabilities in the triggered block
    severity: str
    evidence: EvidenceItem          # classification=HEURISTIC
```

---

### Detector F: AST/Static Analysis Engine

**Class**: `ASTAnalysisEngine`

**Module**: `backend/app/analysis/ast_engine.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `source_files` | `list[SourceFile]` | Python source files |

#### Pattern Registry

| Rule ID | Pattern | Severity | Capability Signal |
|---------|---------|---------|-----------------|
| `AST-SUBPROCESS-BASIC` | `subprocess.call()`, `subprocess.run()`, `subprocess.Popen()` | MEDIUM | `PROCESS_EXECUTION` |
| `AST-SUBPROCESS-SHELL` | Any subprocess call with `shell=True` | HIGH | `PROCESS_EXECUTION` |
| `AST-OS-SYSTEM` | `os.system()` | HIGH | `PROCESS_EXECUTION` |
| `AST-EXEC` | `exec()` built-in call | HIGH | `DYNAMIC_EXECUTION` |
| `AST-EVAL` | `eval()` built-in call | HIGH | `DYNAMIC_EXECUTION` |
| `AST-DYNAMIC-IMPORT` | `importlib.import_module()`, `__import__()` | MEDIUM | `DYNAMIC_EXECUTION` |
| `AST-SOCKET` | `socket.socket()`, `socket.connect()` | MEDIUM | `NETWORK_ACCESS` |
| `AST-URLLIB` | `urllib.request.urlopen()`, `urllib.request.urlretrieve()` | MEDIUM | `NETWORK_ACCESS` |
| `AST-REQUESTS` | `requests.get()`, `requests.post()`, etc. | LOW | `NETWORK_ACCESS` |
| `AST-ENV-ACCESS` | `os.environ`, `os.getenv()` | LOW | `ENVIRONMENT_ACCESS` |
| `AST-FILE-WRITE` | `open(..., 'w')`, `open(..., 'wb')`, `open(..., 'a')` | LOW | `FILE_WRITE` |
| `AST-FILE-READ` | `open(..., 'r')`, `open(..., 'rb')` in suspicious context | INFO | `FILE_READ` |
| `AST-CREDENTIAL-STR` | String literals matching credential patterns (API keys, tokens) | CRITICAL | `CREDENTIAL_ACCESS` |
| `AST-BASE64` | `base64.b64decode()`, `base64.decodebytes()` | LOW | `DYNAMIC_EXECUTION` |
| `AST-DOWNLOAD-EXEC` | `urllib.request.urlopen()` result passed to `exec()` | CRITICAL | `NETWORK_ACCESS` + `DYNAMIC_EXECUTION` |

#### Output

```python
@dataclass
class ASTFinding:
    scan_id: UUID
    file_path: str
    line_number: int
    column_number: int
    rule_id: str
    rule_name: str
    severity: str
    capability_signal: str          # One of the CAPABILITY SIGNAL types
    snippet: str                    # Sanitized, max 200 chars
    evidence: EvidenceItem          # classification=HEURISTIC (or FACT for AST-CREDENTIAL-STR)
```

---

### Detector G: CI/CD Analysis Engine

**Class**: `CICDAnalysisEngine`

**Module**: `backend/app/analysis/cicd_engine.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `workflow_files` | `list[WorkflowFile]` | GitHub Actions YAML files from `.github/workflows/` |

#### Pattern Registry

| Rule ID | Pattern | Severity | Description |
|---------|---------|---------|-------------|
| `CICD-REMOTE-EXEC` | `curl ... \| bash` or `wget ... \| sh` in run step | CRITICAL | Remote script execution without verification |
| `CICD-UNVERIFIED-DOWNLOAD` | `curl`, `wget` in run steps without checksum verification | HIGH | Downloading external content without integrity check |
| `CICD-UNPINNED-ACTION` | External action without SHA pinning: `uses: owner/action@v1` | HIGH | Action version could be changed maliciously |
| `CICD-WRITE-ALL` | `permissions: write-all` | HIGH | Excessive permissions grant full repository write access |
| `CICD-NO-PERMISSIONS` | No `permissions:` block at workflow or job level | MEDIUM | Permissions not explicitly scoped; default may be too broad |
| `CICD-SUSPICIOUS-SECRET` | Secret name matching patterns: `*_TOKEN`, `*_KEY`, `*_PASSWORD`, `*_CRED` used in external-facing steps | MEDIUM | Secret potentially exposed to external actions |
| `CICD-SELF-HOSTED-RUNNER` | `runs-on: self-hosted` | MEDIUM | Self-hosted runners may not have same security posture as GitHub-hosted |
| `CICD-ARTIFACT-NO-SIGN` | Upload artifact step without signing or digest | LOW | Artifact integrity not verified |
| `CICD-PR-TARGET-EXEC` | `pull_request_target` trigger with code checkout from PR | CRITICAL | Classic supply-chain attack vector via PR workflow |
| `CICD-UNKNOWN-ACTION-ORG` | Action from an organization not in the trusted list | MEDIUM | Unvetted external action source |

#### Outputs

```python
@dataclass
class CICDFinding:
    scan_id: UUID
    workflow_file: str
    job_name: str
    step_name: str
    line_number: int
    rule_id: str
    severity: str
    description: str
    remediation: str
    evidence: EvidenceItem      # classification=HEURISTIC or FACT
```

---

### Detector H: Metadata Anomaly Detector

**Class**: `MetadataAnomalyDetector`

**Module**: `backend/app/detectors/metadata_anomaly.py`

#### Inputs

| Input | Type | Description |
|-------|------|-------------|
| `release_history` | `list[ReleaseRecord]` | Package release history from registry |
| `commit_history` | `list[CommitRecord]` | Repository commit history from GitHub |
| `contributor_list` | `list[ContributorRecord]` | Repository contributor list from GitHub |

#### Pattern Registry

| Anomaly Type | Detection Rule | Severity |
|-------------|---------------|---------|
| `NEW_MAINTAINER_BEFORE_RELEASE` | Maintainer added within 30 days of the release being analyzed | HIGH |
| `NEW_ACCOUNT_MAINTAINER` | Releasing maintainer account is less than 30 days old | HIGH |
| `RAPID_RELEASE_CADENCE` | Multiple releases within 24 hours | MEDIUM |
| `RELEASE_WITHOUT_COMMITS` | Release tag exists but no associated commits were made in the repository | HIGH |
| `SUDDEN_ACTIVITY_SPIKE` | Commit count in last 7 days > 3x average of last 90 days | MEDIUM |
| `OWNERSHIP_TRANSFER` | Package repository was transferred between owners recently | HIGH |
| `ZERO_PRIOR_RELEASES` | Package has exactly one release and that release has suspicious content | MEDIUM |
| `NO_HOMEPAGE_OR_DESCRIPTION` | Package has no description, homepage, or README | LOW |

#### Outputs

```python
@dataclass
class MetadataAnomalySignal:
    scan_id: UUID
    entity_name: str
    entity_type: str
    anomaly_type: str
    severity: str
    description: str
    evidence: EvidenceItem      # classification=HEURISTIC
```

---

## 3. Capability Signals

Capability signals are abstract labels applied to packages based on detected code patterns. They represent what a package is capable of doing, not what it actually does.

| Signal | Code | Description | Severity |
|--------|------|-------------|---------|
| **Network Access** | `NETWORK_ACCESS` | Package can make outbound network connections | MEDIUM |
| **Process Execution** | `PROCESS_EXECUTION` | Package can spawn child processes or execute system commands | HIGH |
| **File Write** | `FILE_WRITE` | Package can write to the filesystem | MEDIUM |
| **File Read** | `FILE_READ` | Package reads files (note: very common; context matters) | LOW |
| **Environment Access** | `ENVIRONMENT_ACCESS` | Package reads environment variables | LOW |
| **Credential Access** | `CREDENTIAL_ACCESS` | Package accesses credential-like strings or files | CRITICAL |
| **Dynamic Execution** | `DYNAMIC_EXECUTION` | Package uses `eval`, `exec`, dynamic imports, or code compilation | HIGH |

**Combination escalation rules**:

| Combination | Escalated Severity |
|-------------|------------------|
| `NETWORK_ACCESS` + `CREDENTIAL_ACCESS` | CRITICAL |
| `PROCESS_EXECUTION` + `NETWORK_ACCESS` | HIGH → CRITICAL |
| `DYNAMIC_EXECUTION` + `NETWORK_ACCESS` | HIGH → CRITICAL |
| `FILE_WRITE` + `CREDENTIAL_ACCESS` | HIGH |
| `PROCESS_EXECUTION` + `FILE_WRITE` + `NETWORK_ACCESS` | CRITICAL |

---

## 4. Simulated Runtime Signals

For demonstration purposes, the Simulated Runtime Signal Engine projects synthetic runtime observations from static analysis findings. All simulated signals are governed by strict labeling requirements.

### 4.1 Signal Types

| Signal Type | Code | Description | Triggering Static Evidence |
|------------|------|-------------|--------------------------|
| **Outbound Connection** | `OUTBOUND_CONNECTION` | Package appears to attempt an outbound network connection | `NETWORK_ACCESS` capability + `PROCESS_EXECUTION` or `DYNAMIC_EXECUTION` |
| **File Modification** | `FILE_MODIFICATION` | Package appears to modify system or configuration files | `FILE_WRITE` + elevated directory paths detected |
| **Subprocess Creation** | `SUBPROCESS_CREATION` | Package spawns a child process | `PROCESS_EXECUTION` capability |
| **Environment Access** | `ENV_ACCESS` | Package reads one or more sensitive environment variables | `ENVIRONMENT_ACCESS` + `CREDENTIAL_ACCESS` |
| **Suspicious Domain Contact** | `SUSPICIOUS_DOMAIN_CONTACT` | Package appears to contact a non-standard domain | `NETWORK_ACCESS` + suspicious domain string literals detected in source |

### 4.2 Projection Rules

```
FOR EACH package WITH capability_signals:
  
  IF NETWORK_ACCESS IN signals AND PROCESS_EXECUTION IN signals:
    EMIT runtime_signal(type=OUTBOUND_CONNECTION, target=infer_domain_from_string_literals())
  
  IF FILE_WRITE IN signals AND path_contains_system_dir(detected_paths):
    EMIT runtime_signal(type=FILE_MODIFICATION, target=detected_path)
  
  IF PROCESS_EXECUTION IN signals:
    EMIT runtime_signal(type=SUBPROCESS_CREATION, target=infer_command())
  
  IF ENVIRONMENT_ACCESS IN signals AND CREDENTIAL_ACCESS IN signals:
    EMIT runtime_signal(type=ENV_ACCESS, target=infer_env_var_name())
  
  IF NETWORK_ACCESS IN signals AND suspicious_domain_detected:
    EMIT runtime_signal(type=SUSPICIOUS_DOMAIN_CONTACT, target=detected_domain)
  
  FOR EACH emitted runtime_signal:
    runtime_signal.is_simulated = True
    runtime_signal.label = "SIMULATED — Not real production telemetry"
    runtime_signal.classification = "SIMULATED"
    runtime_signal.confidence_weight = 0.15  // Capped
```

### 4.3 Mandatory Display Requirements

In the UI, all simulated runtime signal nodes and evidence items **must** display:
1. A pink dashed border on the graph node
2. A badge: `🔴 SIMULATED`
3. Tooltip text: `"This is a projected signal based on static analysis, not a real runtime observation."`
4. The word "SIMULATED" in the evidence panel header

---

## 5. Evidence Correlation

The Evidence Correlation Engine aggregates evidence from all detectors into coherent per-entity findings.

### 5.1 Correlation Process

```
Step 1: GROUP all evidence items by entity_id

Step 2: FOR EACH entity WITH evidence:
  
  // Deduplicate
  deduplicated = deduplicate(evidence_items)
  // Dedup key = (source, evidence_type, source_location.file, source_location.line)
  // When duplicates exist, keep the item with higher confidence_contribution
  
  // Determine finding type
  finding_type = determine_finding_type(deduplicated)
  // Priority: VULNERABLE > TYPOSQUATTING > DEPENDENCY_CONFUSION >
  //            COMPROMISED_UPDATE > OBFUSCATION > DORMANT_LOGIC >
  //            CICD_RISK > SUSPICIOUS
  
  // Determine severity
  severity = max_severity_from_evidence(deduplicated)
  
  // Compute confidence
  confidence = confidence_engine.compute(deduplicated)
  
  // Emit finding
  finding = Finding(
    entity_id=entity_id,
    finding_type=finding_type,
    severity=severity,
    confidence=confidence,
    evidence=deduplicated
  )
  
Step 3: RANK findings by (severity_rank DESC, confidence DESC)

Step 4: RETURN correlated findings
```

### 5.2 Multi-Evidence Escalation

When multiple independent detectors flag the same entity:

| Detector Combination | Escalation |
|---------------------|-----------|
| AST finding + Simulated OUTBOUND_CONNECTION | Severity stays at AST finding severity; confidence increases |
| Typosquatting + AST obfuscation finding | Finding type = SUSPICIOUS; severity escalates to HIGH |
| Suspicious update + Obfuscation + Simulated C2 contact | Finding type = COMPROMISED_UPDATE; severity = CRITICAL |
| CI/CD risk + Compromised artifact | Finding type = CICD_RISK; severity = CRITICAL |
| OSV match + Metadata anomaly | Finding type = VULNERABLE; severity = max(OSV severity, MEDIUM) |

---

## 6. Scoring Architecture

### 6.1 Confidence Formula

```
C = 1 - Π(1 - wᵢ × rᵢ)  for all evidence items i
```

Where:
- `wᵢ` = configured weight for evidence item i (see weight table below)
- `rᵢ` = reliability multiplier based on classification

**Reliability multipliers (rᵢ)**:

| Classification | rᵢ |
|---------------|-----|
| `FACT` | 1.00 |
| `HEURISTIC` | 0.70 |
| `INFERENCE` | 0.50 |
| `SIMULATED` | 0.15 |
| `UNKNOWN` | 0.30 |

**Configured weights (wᵢ)**:

| Evidence Source / Type | Default wᵢ | Configuration Key |
|------------------------|------------|------------------|
| OSV vulnerability match | 0.90 | `WEIGHT_OSV` |
| AST obfuscation pattern | 0.75 | `WEIGHT_AST_OBFUSCATION` |
| CI/CD critical pattern | 0.75 | `WEIGHT_CICD_CRITICAL` |
| AST capability signal (HIGH) | 0.65 | `WEIGHT_AST_CAPABILITY_HIGH` |
| AST capability signal (MEDIUM) | 0.60 | `WEIGHT_AST_CAPABILITY_MEDIUM` |
| Typosquatting (score ≥ 0.95) | 0.80 | `WEIGHT_TYPOSQUAT_HIGH` |
| Typosquatting (score 0.85–0.95) | 0.55 | `WEIGHT_TYPOSQUAT_LOW` |
| Dependency confusion | 0.65 | `WEIGHT_DEP_CONFUSION` |
| Metadata anomaly | 0.50 | `WEIGHT_METADATA` |
| Suspicious update | 0.60 | `WEIGHT_SUSPICIOUS_UPDATE` |
| Lockfile evidence | 0.80 | `WEIGHT_LOCKFILE` |
| Simulated runtime signal | 0.15 | `WEIGHT_SIMULATED` (capped, not configurable above 0.15) |

### 6.2 Blast Radius Formula

```
B = 2P + 15S + 25A + 50D
```

Where:
- `P` = count of affected packages (weight: 2)
- `S` = count of affected services (weight: 15)
- `A` = count of affected APIs (weight: 25)
- `D` = count of affected production deployments (weight: 50)

**Weight rationale**: Production deployments carry the highest weight (50) because a compromised production deployment represents the highest potential business impact. APIs carry weight 25 because public API exposure enables data exfiltration. Services carry weight 15 because internal services are affected but may be isolated. Packages carry weight 2 because package presence alone, without service/deployment context, has limited direct business impact.

### 6.3 Synthetic Discount Rules

| Rule | Effect |
|------|--------|
| All evidence is `SIMULATED` | Overall finding severity capped at `MEDIUM`; warning displayed in UI |
| Any simulated signal used in confidence formula | Simulated item's contribution capped at `wᵢ × rᵢ = 0.15 × 0.15 = 0.0225` |
| More than 3 simulated signals for one entity | Only the top 3 by `confidence_contribution` are included |
| Simulated signal combined with FACT | Simulated item adds minimal confidence increment; FACT item dominates |

### 6.4 Configurable Thresholds

All thresholds are configurable via environment variables:

| Threshold | Default | Configuration Key |
|-----------|---------|------------------|
| Typosquatting similarity | 0.85 | `THRESHOLD_TYPOSQUAT` |
| Update anomaly score | 0.60 | `THRESHOLD_UPDATE_ANOMALY` |
| New maintainer account age (days) | 30 | `THRESHOLD_NEW_MAINTAINER_DAYS` |
| Max transitive depth resolved | 10 | `MAX_TRANSITIVE_DEPTH` |
| Confidence display precision | 2 decimal places | `CONFIDENCE_DISPLAY_PRECISION` |
| Blast radius severity thresholds | CRITICAL ≥100, HIGH ≥50, MEDIUM ≥20 | `BLAST_RADIUS_CRITICAL`, `BLAST_RADIUS_HIGH`, `BLAST_RADIUS_MEDIUM` |
