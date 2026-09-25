# SupplyGraph — Graph Model

> **Evidence-driven software supply-chain attack analysis.**

This document defines the complete data model for the SupplyGraph security knowledge graph: node types, edge types, layout algorithm, serialization format, and filtering/clustering behaviour.

---

## 1. Node Types

Every node in the graph has a globally unique `id` (UUID), a `type` string, pre-computed `position` (x/y), and a `data` object containing type-specific attributes. The following node types are defined.

---

### 1.1 `repository`

**Description**: The root node of every graph. Represents the GitHub repository that was submitted for analysis. There is exactly one repository node per scan.

**UI Color**: `#3B82F6` (Blue)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `url` | string | Full GitHub URL (e.g., `https://github.com/owner/repo`) |
| `name` | string | Repository name |
| `owner` | string | GitHub owner login |
| `default_branch` | string | Default branch name (e.g., `main`) |
| `stars` | integer | GitHub star count at time of scan |
| `last_commit_at` | ISO8601 | Timestamp of most recent commit |
| `is_fork` | boolean | Whether the repository is a fork |
| `language` | string | Primary programming language |
| `open_issues_count` | integer | Number of open issues |

---

### 1.2 `package`

**Description**: A software dependency identified in the repository's SBOM. Represents a logical package (without version specificity). Multiple `version` nodes may be associated with one package node.

**UI Color**: `#10B981` (Green) for clean packages; `#F59E0B` (Amber) for suspicious packages.

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | Package name as declared in manifest |
| `ecosystem` | string | Package ecosystem: `pypi`, `npm`, `cargo`, `go`, `maven`, etc. |
| `purl` | string | Canonical Package URL (e.g., `pkg:pypi/requests@2.31.0`) |
| `normalized_name` | string | Lowercased, canonicalized name for comparison |
| `is_direct` | boolean | Whether this is a direct dependency |
| `is_transitive` | boolean | Whether this is a transitive dependency |
| `depth` | integer | Transitive depth from root (0 = direct) |
| `is_suspicious` | boolean | Whether any suspicious signals are attached |
| `risk_level` | string | Computed: `CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

---

### 1.3 `version`

**Description**: A specific version of a package. A package may have multiple version nodes if multiple versions are referenced in the dependency tree (e.g., version conflicts).

**UI Color**: `#14B8A6` (Teal) for clean versions; `#EF4444` (Red) for versions with known vulnerabilities.

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `package_id` | UUID | Reference to parent package node |
| `version_string` | string | Version as declared (e.g., `2.31.0`) |
| `release_date` | ISO8601 | Date the version was published |
| `is_suspicious` | boolean | Whether this specific version is flagged |
| `is_yanked` | boolean | Whether this version has been yanked from the registry |
| `changelog_url` | string | URL to changelog entry, if available |
| `source_registry` | string | Registry where this version was sourced |
| `has_vulnerabilities` | boolean | Whether OSV reports vulnerabilities for this version |

---

### 1.4 `vulnerability`

**Description**: A known security vulnerability sourced from the OSV database. Linked to one or more `version` nodes via `AFFECTS` edges.

**UI Color**: `#EF4444` (Red) for CRITICAL/HIGH; `#F97316` (Orange) for MEDIUM; `#EAB308` (Yellow) for LOW.

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Internal unique identifier |
| `osv_id` | string | OSV canonical ID (e.g., `GHSA-29mw-wpgm-hmr9`) |
| `aliases` | string[] | Alias IDs (e.g., `["CVE-2021-44228"]`) |
| `summary` | string | Short description from OSV |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `cvss_score` | float | CVSS v3 base score (0.0–10.0), if available |
| `cvss_vector` | string | CVSS v3 vector string, if available |
| `affected_versions` | string[] | Version range strings affected |
| `fixed_in` | string | First fixed version, if available |
| `published_at` | ISO8601 | Date advisory was published |
| `source` | string | Always `"osv"` |

---

### 1.5 `commit`

**Description**: A specific git commit, included in the graph when the commit is associated with a suspicious change (e.g., introducing a new backdoor dependency or malicious capability).

**UI Color**: `#8B5CF6` (Purple)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Internal unique identifier |
| `sha` | string | Full git commit SHA |
| `message` | string | Commit message (first 200 characters) |
| `author` | string | Author login or email |
| `author_date` | ISO8601 | Commit authored date |
| `committer` | string | Committer login or email |
| `is_suspicious` | boolean | Whether this commit is flagged |
| `changed_files` | string[] | List of files changed in this commit |
| `additions` | integer | Number of lines added |
| `deletions` | integer | Number of lines deleted |

---

### 1.6 `maintainer`

**Description**: A package maintainer or contributor, included when metadata anomalies are detected (e.g., new maintainer, suspicious account).

**UI Color**: `#6366F1` (Indigo)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Internal unique identifier |
| `login` | string | GitHub login or registry username |
| `email` | string | Maintainer email, if publicly available |
| `account_age_days` | integer | Age of the account in days at time of scan |
| `is_new` | boolean | Whether this maintainer was added within 30 days of the release |
| `contribution_change` | string | `INCREASED`, `DECREASED`, `STABLE`, `NEW` |
| `is_suspicious` | boolean | Whether this maintainer exhibits anomalies |
| `first_contribution_at` | ISO8601 | Date of first contribution to this package |

---

### 1.7 `service`

**Description**: A downstream service that depends on or is affected by packages in the dependency graph. Included in blast-radius calculations.

**UI Color**: `#F97316` (Orange)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | Service name |
| `type` | string | `web`, `worker`, `database`, `message_queue`, `cache`, etc. |
| `port` | integer | Network port, if applicable |
| `is_external` | boolean | Whether the service is externally accessible |
| `technology` | string | Runtime technology (e.g., `Python/FastAPI`, `Node.js/Express`) |
| `criticality` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |

---

### 1.8 `container`

**Description**: A container image that packages or deploys a service. Included when CI/CD analysis identifies container build steps.

**UI Color**: `#06B6D4` (Cyan)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | Container name |
| `image` | string | Base image name |
| `tag` | string | Image tag |
| `registry` | string | Container registry URL |
| `is_compromised` | boolean | Whether this container is built from a compromised pipeline |
| `build_pipeline_id` | UUID | Reference to the pipeline that builds this container |

---

### 1.9 `api`

**Description**: An API endpoint exposed by a service. Included when downstream impact involves API-level exposure.

**UI Color**: `#EAB308` (Yellow)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | API name or identifier |
| `endpoint` | string | URL path (e.g., `/api/v1/users`) |
| `method` | string | HTTP method: `GET`, `POST`, `PUT`, `DELETE`, etc. |
| `is_public` | boolean | Whether the endpoint is publicly accessible |
| `authentication` | string | Auth mechanism: `none`, `api_key`, `jwt`, `oauth2` |
| `handles_pii` | boolean | Whether this API handles personally identifiable information |

---

### 1.10 `deployment`

**Description**: A production or non-production deployment of a service. Included in blast-radius scoring with a high weight (50 points) due to the direct business impact of compromised production deployments.

**UI Color**: `#F43F5E` (Rose)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | Deployment name |
| `environment` | string | `production`, `staging`, `development`, `preview` |
| `is_production` | boolean | Whether this is a production deployment |
| `platform` | string | Deployment platform (e.g., `Render`, `Vercel`, `AWS ECS`) |
| `url` | string | Deployment URL, if publicly known |
| `container_id` | UUID | Reference to deployed container node, if applicable |

---

### 1.11 `pipeline`

**Description**: A CI/CD pipeline configuration. Included when CI/CD analysis detects supply-chain risks in build or deployment workflows.

**UI Color**: `#6B7280` (Gray) for clean; `#DC2626` (Red) for flagged.

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | Pipeline name (e.g., workflow filename) |
| `platform` | string | `github_actions`, `gitlab_ci`, `circleci`, `jenkins` |
| `config_path` | string | Path to the workflow file (e.g., `.github/workflows/ci.yml`) |
| `is_flagged` | boolean | Whether any CI/CD risks were detected |
| `risk_count` | integer | Number of distinct risks detected |
| `triggers` | string[] | Events that trigger this pipeline |

---

### 1.12 `behaviour`

**Description**: A detected behavioural capability in a package, derived from static analysis. Represents what a package is capable of doing, not what it is confirmed to do.

**UI Color**: `#D97706` (Amber)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `capability` | string | Capability signal: `NETWORK_ACCESS`, `PROCESS_EXECUTION`, `FILE_WRITE`, `FILE_READ`, `ENVIRONMENT_ACCESS`, `CREDENTIAL_ACCESS`, `DYNAMIC_EXECUTION` |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `source` | string | Detection source: `ast`, `cicd`, `metadata` |
| `source_file` | string | Source file where the capability was detected |
| `source_line` | integer | Line number |
| `pattern_matched` | string | Specific pattern that triggered detection |
| `is_simulated` | boolean | Always `false` for behaviour nodes (behaviour is a static finding) |

---

### 1.13 `runtime_observation`

**Description**: A simulated runtime signal projected from static analysis findings. Always carries `is_simulated=true`. Displayed with a prominent SIMULATED badge in the UI. Never represents actual production telemetry.

**UI Color**: `#EC4899` (Pink) with a dashed border to visually distinguish from confirmed nodes.

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `type` | string | Signal type: `OUTBOUND_CONNECTION`, `FILE_MODIFICATION`, `SUBPROCESS_CREATION`, `ENV_ACCESS`, `SUSPICIOUS_DOMAIN_CONTACT` |
| `target` | string | Target of the signal (e.g., domain, file path, env var name) |
| `is_simulated` | boolean | Always `true` |
| `label` | string | Always includes `"SIMULATED"` |
| `source_package_id` | UUID | Package from which this signal was projected |
| `projected_from` | string | Evidence item ID that produced this projection |
| `confidence_weight` | float | Always `0.15` (capped) |

---

### 1.14 `finding`

**Description**: An aggregated security finding node, representing a correlated set of evidence items for a single entity. Findings are the primary output of the analysis engine and the primary source of actionable information.

**UI Color**: `#DC2626` (Deep Red)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `type` | string | Finding type (see evidence model) |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `confidence` | float | Composite confidence score [0.0, 1.0] |
| `entity_id` | UUID | ID of the entity this finding is about |
| `entity_type` | string | Type of the entity |
| `evidence_count` | integer | Number of supporting evidence items |
| `origin_candidate` | string | Most likely origin package, if determined |
| `blast_radius` | integer | Computed blast radius score |
| `recommendation_count` | integer | Number of recommendations generated |

---

### 1.15 `asset`

**Description**: A downstream business asset that is potentially affected by a supply-chain compromise. Assets are the ultimate targets of blast-radius analysis.

**UI Color**: `#64748B` (Slate)

**Key Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | UUID | Unique identifier |
| `name` | string | Asset name |
| `type` | string | `web_service`, `api_gateway`, `database`, `production_deployment`, `customer_data`, `internal_tool` |
| `criticality` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `owner` | string | Team or person responsible for this asset |
| `is_production` | boolean | Whether this is a production asset |
| `blast_radius_weight` | integer | Weight in blast radius formula |

---

## 2. Edge Types

Every edge has a globally unique `id`, `source` (node ID), `target` (node ID), `type` string, and a `data` object with type-specific attributes.

---

### 2.1 `CONTAINS`

| Attribute | Value |
|-----------|-------|
| **Description** | The repository directly contains or declares this package as a dependency |
| **Source Node Types** | `repository` |
| **Target Node Types** | `package` |
| **Direction** | repository → package |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `manifest_file` | string | File where this dependency was declared (e.g., `requirements.txt`) |
| `specifier` | string | Original version specifier (e.g., `>=2.0.0,<3.0.0`) |

---

### 2.2 `DEPENDS_ON`

| Attribute | Value |
|-----------|-------|
| **Description** | One package depends on another package, creating a dependency relationship in the supply chain |
| **Source Node Types** | `package` |
| **Target Node Types** | `package` |
| **Direction** | dependent_package → dependency_package |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_direct` | boolean | Whether this is a direct dependency |
| `is_transitive` | boolean | Whether this is a transitive (indirect) dependency |
| `depth` | integer | Transitive depth from root application |
| `version_constraint` | string | Version constraint declared for this dependency |
| `resolved_version` | string | Actual resolved version from lockfile |
| `is_optional` | boolean | Whether this is an optional dependency |

---

### 2.3 `VERSION_OF`

| Attribute | Value |
|-----------|-------|
| **Description** | A specific version node belongs to a package node |
| **Source Node Types** | `version` |
| **Target Node Types** | `package` |
| **Direction** | version → package |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_pinned` | boolean | Whether this version is exactly pinned |
| `is_latest` | boolean | Whether this is the latest available version |

---

### 2.4 `MODIFIED_BY`

| Attribute | Value |
|-----------|-------|
| **Description** | A suspicious commit modified this package or introduced it |
| **Source Node Types** | `commit` |
| **Target Node Types** | `package`, `version` |
| **Direction** | commit → package/version |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `change_type` | string | `ADDED`, `MODIFIED`, `REMOVED` |
| `files_changed` | string[] | Specific files changed in this package |

---

### 2.5 `RELEASED_BY`

| Attribute | Value |
|-----------|-------|
| **Description** | A version was published/released by a maintainer |
| **Source Node Types** | `version` |
| **Target Node Types** | `maintainer` |
| **Direction** | version → maintainer |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `release_date` | ISO8601 | When the version was released |
| `is_anomalous` | boolean | Whether this release event is flagged as anomalous |

---

### 2.6 `BUILT_BY`

| Attribute | Value |
|-----------|-------|
| **Description** | A package or service is built by a CI/CD pipeline |
| **Source Node Types** | `package`, `service` |
| **Target Node Types** | `pipeline` |
| **Direction** | package/service → pipeline |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `build_step` | string | The specific pipeline step that builds this artifact |
| `is_compromised_pipeline` | boolean | Whether the pipeline has been flagged for CI/CD risks |

---

### 2.7 `DEPLOYED_AS`

| Attribute | Value |
|-----------|-------|
| **Description** | A package or service is deployed as a container or deployment unit |
| **Source Node Types** | `package`, `service` |
| **Target Node Types** | `container`, `deployment` |
| **Direction** | package/service → container/deployment |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `environment` | string | Deployment environment |
| `is_production` | boolean | Whether this is a production deployment |

---

### 2.8 `USES`

| Attribute | Value |
|-----------|-------|
| **Description** | A service uses an API endpoint, either for ingress or egress |
| **Source Node Types** | `service` |
| **Target Node Types** | `api` |
| **Direction** | service → api |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `usage_type` | string | `exposes` (service exposes this API) or `consumes` (service calls this API) |
| `is_authenticated` | boolean | Whether the API interaction is authenticated |

---

### 2.9 `CALLS`

| Attribute | Value |
|-----------|-------|
| **Description** | A package makes API calls, detected via static analysis of network access patterns |
| **Source Node Types** | `package` |
| **Target Node Types** | `api` |
| **Direction** | package → api |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `detected_in_file` | string | Source file where the call was detected |
| `detected_at_line` | integer | Line number |
| `is_simulated` | boolean | Whether this edge was projected from simulation |

---

### 2.10 `TRIGGERS`

| Attribute | Value |
|-----------|-------|
| **Description** | A CI/CD pipeline triggers a deployment (e.g., push to main triggers production deploy) |
| **Source Node Types** | `pipeline` |
| **Target Node Types** | `deployment` |
| **Direction** | pipeline → deployment |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `trigger_event` | string | Event that triggers this pipeline-deployment link (e.g., `push`, `tag`) |
| `is_automatic` | boolean | Whether this is an automatic (not manual approval) trigger |

---

### 2.11 `EXHIBITS`

| Attribute | Value |
|-----------|-------|
| **Description** | A package exhibits a detected behavioural capability, linking the package to its behaviour node |
| **Source Node Types** | `package`, `version` |
| **Target Node Types** | `behaviour` |
| **Direction** | package/version → behaviour |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `evidence_id` | UUID | The evidence item that established this relationship |
| `confidence` | float | Confidence of this specific exhibit relationship |

---

### 2.12 `AFFECTS`

| Attribute | Value |
|-----------|-------|
| **Description** | A known vulnerability affects a specific package version. Source of truth is OSV API data. |
| **Source Node Types** | `vulnerability` |
| **Target Node Types** | `version`, `package` |
| **Direction** | vulnerability → version/package |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `osv_id` | string | The OSV advisory ID that established this relationship |
| `affected_range` | string | Version range from OSV advisory |
| `fixed_in` | string | First version that fixes this vulnerability |
| `is_confirmed` | boolean | Always `true` for OSV-sourced edges |

---

### 2.13 `PROPAGATES_TO`

| Attribute | Value |
|-----------|-------|
| **Description** | A finding or compromise propagates to a downstream asset, tracing the attack path through the dependency graph |
| **Source Node Types** | `finding`, `package`, `service` |
| **Target Node Types** | `asset`, `service`, `deployment` |
| **Direction** | source → downstream_asset |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `propagation_mechanism` | string | `dependency`, `api_call`, `deployment`, `pipeline` |
| `propagation_depth` | integer | Number of hops from origin |
| `is_evidence_backed` | boolean | Whether every hop in this path has supporting evidence |
| `blast_radius_contribution` | integer | Points this edge contributes to the blast radius score |

---

### 2.14 `OBSERVED_IN`

| Attribute | Value |
|-----------|-------|
| **Description** | A simulated runtime observation was projected from analysis of this package |
| **Source Node Types** | `runtime_observation` |
| **Target Node Types** | `package`, `version` |
| **Direction** | runtime_observation → package/version |

**Data Attributes**:

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_simulated` | boolean | Always `true` |
| `projected_from_evidence_id` | UUID | The static analysis evidence item this was projected from |
| `projection_rule` | string | The rule that generated this simulation |

---

## 3. Graph Layout Algorithm

The layout algorithm is executed server-side by the Server-Side Layout Engine. It produces deterministic x/y coordinates for every node, which are embedded in the graph JSON and consumed directly by React Flow without client-side re-layout.

### 3.1 Algorithm Selection

```
INPUT: NetworkX DiGraph G

Step 1: Attempt topological sort of G.
  - If G is a DAG (no cycles): proceed with TOPOLOGICAL LAYERING.
  - If G has cycles: proceed with BFS LAYERING.
```

### 3.2 Topological Layering (for DAGs)

```
Step 2a: Compute topological sort → ordered_nodes[].
Step 2b: Assign layer to each node:
  - layer[root_node] = 0
  - For each node n in topological order:
      layer[n] = max(layer[predecessor] + 1 for all predecessors of n)
Step 2c: Group nodes by layer → layers_dict = {0: [node1, node2], 1: [node3], ...}
Step 2d: Assign coordinates:
  - x = layer_index * H_SPACING  (H_SPACING = 280)
  - y = sibling_index * V_SPACING (V_SPACING = 120)
  - Sibling ordering within a layer: alphabetical by node_id (UUID string sort)
```

### 3.3 BFS Layering (for Cyclic Graphs)

```
Step 2b-alt: Identify root node (type='repository' or highest-degree node).
Step 2c-alt: BFS from root node, assigning layer = BFS discovery level.
  - Nodes not reachable from root are assigned to a separate layer at max_layer + 1.
Step 2d-alt: Same coordinate assignment as topological layering.
  - Back edges (cycle-forming edges) are rendered with a curved style in the UI.
```

### 3.4 Spacing Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `H_SPACING` | 280 | Horizontal pixels between node layers |
| `V_SPACING` | 120 | Vertical pixels between sibling nodes within a layer |

These constants are defined in `backend/app/graph/layout.py` and can be overridden via environment variables `GRAPH_H_SPACING` and `GRAPH_V_SPACING`.

### 3.5 Determinism Guarantees

- Sibling ordering within each layer is **always alphabetical by node ID string**.
- Node IDs are UUIDs generated deterministically from a hash of (scan_id, entity_type, entity_name) using `uuid5(NAMESPACE_DNS, key_string)`.
- For the same repository scan inputs, the graph topology and layout will always be identical, enabling reproducible demos.

---

## 4. Graph Serialization

The graph is serialized to a JSON format compatible with React Flow's node/edge model. Pre-computed positions are embedded so React Flow renders without any client-side layout computation.

### 4.1 Full Serialization Format

```json
{
  "nodes": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "type": "repository",
      "position": {
        "x": 0,
        "y": 0
      },
      "data": {
        "label": "owner/repo",
        "url": "https://github.com/owner/repo",
        "name": "repo",
        "owner": "owner",
        "default_branch": "main",
        "stars": 1240,
        "last_commit_at": "2026-09-20T14:00:00Z",
        "is_fork": false,
        "language": "Python",
        "risk_level": "HIGH"
      }
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "type": "package",
      "position": {
        "x": 280,
        "y": 0
      },
      "data": {
        "label": "requests@2.31.0",
        "name": "requests",
        "ecosystem": "pypi",
        "purl": "pkg:pypi/requests@2.31.0",
        "normalized_name": "requests",
        "is_direct": true,
        "is_transitive": false,
        "depth": 0,
        "is_suspicious": false,
        "risk_level": "CLEAN"
      }
    },
    {
      "id": "770e8400-e29b-41d4-a716-446655440002",
      "type": "vulnerability",
      "position": {
        "x": 560,
        "y": 120
      },
      "data": {
        "label": "CVE-2021-12345",
        "osv_id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-12345"],
        "summary": "Prototype pollution in mixin-deep",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "fixed_in": "2.0.0"
      }
    }
  ],
  "edges": [
    {
      "id": "edge-repo-requests",
      "source": "550e8400-e29b-41d4-a716-446655440000",
      "target": "660e8400-e29b-41d4-a716-446655440001",
      "type": "CONTAINS",
      "animated": false,
      "data": {
        "manifest_file": "requirements.txt",
        "specifier": "requests>=2.28.0"
      }
    },
    {
      "id": "edge-vuln-requests",
      "source": "770e8400-e29b-41d4-a716-446655440002",
      "target": "660e8400-e29b-41d4-a716-446655440001",
      "type": "AFFECTS",
      "animated": true,
      "style": {
        "stroke": "#EF4444",
        "strokeWidth": 2
      },
      "data": {
        "osv_id": "GHSA-xxxx-yyyy-zzzz",
        "affected_range": ">=1.0.0,<2.0.0",
        "fixed_in": "2.0.0",
        "is_confirmed": true
      }
    }
  ],
  "metadata": {
    "scan_id": "uuid",
    "node_count": 3,
    "edge_count": 2,
    "layout_algorithm": "topological",
    "h_spacing": 280,
    "v_spacing": 120,
    "generated_at": "2026-09-25T09:00:00Z"
  }
}
```

### 4.2 Edge Style Conventions

| Edge Type | `animated` | Stroke Color | Stroke Width |
|-----------|-----------|-------------|-------------|
| `CONTAINS` | `false` | `#6B7280` | 1.5 |
| `DEPENDS_ON` | `false` | `#3B82F6` | 1.5 |
| `AFFECTS` | `true` | `#EF4444` | 2.0 |
| `PROPAGATES_TO` | `true` | `#DC2626` | 2.5 |
| `EXHIBITS` | `false` | `#D97706` | 1.5 |
| `OBSERVED_IN` | `true` | `#EC4899` | 1.5 (dashed) |
| `TRIGGERS` | `false` | `#6B7280` | 1.5 |
| `VERSION_OF` | `false` | `#14B8A6` | 1.0 |

---

## 5. Graph Filtering and Clustering

The SupplyGraph UI provides two primary graph views and several filtering options to help analysts focus on relevant information.

### 5.1 Threat-Focused View (Default)

The default view shows only:
- The repository root node
- Packages with `is_suspicious=true` or `risk_level` ∈ {`HIGH`, `CRITICAL`}
- All vulnerability nodes
- All finding nodes
- All runtime observation nodes
- All asset nodes reachable via `PROPAGATES_TO` edges
- All nodes on the identified propagation path (origin → assets)
- Edges: `AFFECTS`, `PROPAGATES_TO`, `EXHIBITS`, `OBSERVED_IN`, and `CONTAINS`/`DEPENDS_ON` edges within the threat subgraph

Clean nodes (no findings, no suspicious signals, not on propagation path) are collapsed into a summary badge: "N clean packages not shown".

### 5.2 Full Graph View

When the user clicks "Show Full Graph", all nodes and edges are displayed. Clean packages are shown in muted green. The layout re-renders from the same pre-computed positions (no re-layout required). A legend in the top-right corner explains all node and edge types.

### 5.3 Node Collapse/Expand Logic

Cluster nodes are used to group large sets of related nodes:

| Cluster Type | Trigger | Cluster Node Label |
|-------------|---------|------------------|
| Clean packages | More than 10 clean packages at the same depth | "N clean packages" |
| Transitive dependencies | Depth ≥ 3 with no findings | "N transitive deps" |
| Unaffected maintainers | Maintainer nodes with no anomalies | "N maintainers" |

Clicking a cluster node expands it into individual nodes. Clicking an expanded group of the same type collapses it back into a cluster node.

### 5.4 Filter Panel

The UI provides a collapsible filter panel with the following controls:

| Filter | Type | Description |
|--------|------|-------------|
| Severity | Checkbox (CRITICAL/HIGH/MEDIUM/LOW) | Show only findings of selected severities |
| Node Type | Checkbox (all node types) | Show/hide specific node types |
| Simulated Signals | Toggle | Show or hide simulated runtime observation nodes |
| Evidence Backed Only | Toggle | Show only nodes with at least one evidence item |
| Propagation Path Only | Toggle | Show only nodes on the identified attack path |

All filters operate client-side on the pre-fetched graph data. No additional API calls are required for filtering.

### 5.5 Search and Highlight

A search box in the top bar allows users to search by:
- Package name (partial match)
- CVE/GHSA ID
- Node ID
- Evidence description substring

Matching nodes are highlighted with a pulsing orange border. Non-matching nodes are dimmed but not hidden, preserving graph topology context.
