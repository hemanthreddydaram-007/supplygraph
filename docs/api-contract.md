# SupplyGraph — API Contract

**Version:** v1.0.0
**Last Updated:** 2026-09-25
**Base URL (Production):** `https://supplygraph-api.onrender.com`
**Base URL (Local):** `http://localhost:8000`
**OpenAPI UI:** `/docs`
**ReDoc UI:** `/redoc`

---

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| Style | RESTful JSON API |
| Versioning | URL prefix `/api/v1` |
| Validation | Pydantic v2 on all request/response bodies |
| Errors | Structured `ErrorEnvelope` on every 4xx/5xx |
| Auth | API Key header `X-API-Key` (MVP: optional/bypass) |
| Content-Type | `application/json` for all endpoints |
| Timestamps | ISO 8601 UTC with `Z` suffix |
| IDs | UUID v4 strings |
| Pagination | `page` (1-indexed) + `page_size` (max 100) |
| CORS | Allowed for frontend origin |
| Envelope | Every response includes `api_version: "v1"` |

---

## Common Response Envelope

All successful responses include:

```json
{
  "api_version": "v1",
  "data": { ... },
  "timestamp": "2026-01-01T00:00:00Z"
}
```

> For list responses, `data` is replaced by a flat structure with pagination fields (see individual endpoints).

---

## Error Response Format

Every error response — regardless of HTTP status code — uses the following envelope:

```json
{
  "api_version": "v1",
  "error": {
    "code": "REPOSITORY_NOT_FOUND",
    "message": "The repository could not be found or is private.",
    "details": null
  },
  "timestamp": "2026-01-01T00:00:00Z"
}
```

### Error Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | `string` | ✅ | Machine-readable error code (see Error Codes table) |
| `message` | `string` | ✅ | Human-readable English description |
| `details` | `object \| null` | ❌ | Additional structured context (field errors, etc.) |

### Validation Error Details Shape

When `code` is `VALIDATION_ERROR`, `details` contains:

```json
{
  "fields": [
    {
      "field": "github_url",
      "message": "String should match pattern '^https://github\\.com/.+/.+$'",
      "input": "not-a-url"
    }
  ]
}
```

---

## Error Code Registry

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_GITHUB_URL` | 422 | URL does not match `https://github.com/{owner}/{repo}` pattern |
| `REPOSITORY_NOT_FOUND` | 404 | Repository does not exist or GitHub returned 404 |
| `REPOSITORY_TOO_LARGE` | 422 | Repository exceeds the 500 MB size limit |
| `REPOSITORY_PRIVATE` | 403 | Repository is private and no valid token was supplied |
| `GITHUB_RATE_LIMITED` | 429 | GitHub API rate limit exhausted; `details.reset_at` gives reset time |
| `GITHUB_UNAVAILABLE` | 502 | GitHub API returned a 5xx error or timed out |
| `OSV_UNAVAILABLE` | 502 | OSV.dev API returned a 5xx error or timed out |
| `ANALYSIS_TIMEOUT` | 504 | Analysis pipeline exceeded the maximum allowed duration (120 s) |
| `SCAN_NOT_FOUND` | 404 | No scan exists with the given `scan_id` |
| `FINDING_NOT_FOUND` | 404 | No finding exists with the given `finding_id` |
| `INVALID_SCENARIO_ID` | 422 | `scenario_id` is not one of `A`, `B`, `C`, `D`, `E` |
| `INTERNAL_ERROR` | 500 | Unhandled server-side exception |
| `DATABASE_UNAVAILABLE` | 503 | Cannot reach Supabase/PostgreSQL |
| `GEMINI_UNAVAILABLE` | 502 | Gemini API returned a non-200 or timed out |
| `VALIDATION_ERROR` | 422 | Request body failed Pydantic validation |
| `SCAN_ALREADY_RUNNING` | 409 | A scan for this repository is already in progress |
| `COMPARISON_MISMATCH` | 422 | The two scans belong to different repositories |

---

## Shared Pydantic Types Reference

These types are used across multiple endpoints. They are defined in `backend/app/models/`.

### `SeverityEnum`
`"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" | "NONE"`

### `ScanStatus`
`"PENDING" | "RUNNING" | "COMPLETE" | "FAILED" | "PARTIAL"`

### `FindingType`
`"TYPOSQUATTING" | "DEPENDENCY_CONFUSION" | "SUSPICIOUS_UPDATE" | "DORMANT_LOGIC" | "OBFUSCATED_BEHAVIOR" | "KNOWN_VULNERABILITY" | "METADATA_ANOMALY" | "CICD_RISK" | "RUNTIME_ANOMALY" | "MAINTAINER_ANOMALY"`

### `FindingStatus`
`"OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "FALSE_POSITIVE"`

### `NodeType`
`"Version" | "Package" | "Repository" | "Service" | "Container" | "API" | "Deployment" | "CICDPipeline" | "Asset"`

### `EdgeType`
`"DEPENDS_ON" | "PROVIDES" | "EXPOSES" | "DEPLOYS" | "TRIGGERS" | "ATTACK_PATH" | "PROPAGATES_TO"`

---

## Endpoint Specifications

---

### 1. POST /api/v1/projects

**Description:** Create a named project to group related scans.

#### Request Body

```json
{
  "name": "string",
  "description": "string | null",
  "github_url": "string | null"
}
```

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `name` | `string` | ✅ | 1–120 characters |
| `description` | `string \| null` | ❌ | Max 1000 characters |
| `github_url` | `string \| null` | ❌ | Must match `https://github.com/{owner}/{repo}` if provided |

#### Response `201 Created`

```json
{
  "api_version": "v1",
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "name": "My Supply Chain Audit",
  "description": "Quarterly audit of all microservices.",
  "github_url": "https://github.com/acme/backend",
  "created_at": "2026-09-25T09:00:00Z",
  "updated_at": "2026-09-25T09:00:00Z",
  "scan_count": 0
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` (UUID) | Project identifier |
| `name` | `string` | Project name |
| `description` | `string \| null` | Project description |
| `github_url` | `string \| null` | Associated repository URL |
| `created_at` | `string` (ISO 8601) | Creation timestamp |
| `updated_at` | `string` (ISO 8601) | Last modification timestamp |
| `scan_count` | `integer` | Number of scans in this project |

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 422 | `VALIDATION_ERROR` | `name` empty or too long; `github_url` invalid format |
| 503 | `DATABASE_UNAVAILABLE` | Cannot persist to database |

#### Example Request

```bash
curl -X POST https://supplygraph-api.onrender.com/api/v1/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Supply Chain Audit",
    "description": "Quarterly audit of all microservices.",
    "github_url": "https://github.com/acme/backend"
  }'
```

#### Example Response (abbreviated)

```json
{
  "api_version": "v1",
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "name": "My Supply Chain Audit",
  "created_at": "2026-09-25T09:00:00Z"
}
```

---

### 2. POST /api/v1/analyze

**Description:** Trigger a full security analysis of a GitHub repository. For MVP simplicity the response is returned **synchronously** (HTTP 200 with the full `AnalysisResponse`). For large repositories the server may return `202 Accepted` with a `scan_id` for polling via `GET /api/v1/scans/{scan_id}`.

#### Request Body

```json
{
  "github_url": "string",
  "branch": "string | null",
  "include_transitive": "boolean",
  "enable_ast_analysis": "boolean",
  "enable_cicd_analysis": "boolean",
  "enable_metadata_analysis": "boolean",
  "enable_simulated_runtime": "boolean",
  "enable_gemini_explanation": "boolean",
  "max_transitive_depth": "integer | null",
  "project_id": "string | null"
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `github_url` | `string` | ✅ | — | Pattern: `^https://github\.com/[^/]+/[^/]+$` |
| `branch` | `string \| null` | ❌ | `null` (uses default branch) | 1–255 chars |
| `include_transitive` | `boolean` | ❌ | `true` | — |
| `enable_ast_analysis` | `boolean` | ❌ | `true` | — |
| `enable_cicd_analysis` | `boolean` | ❌ | `true` | — |
| `enable_metadata_analysis` | `boolean` | ❌ | `true` | — |
| `enable_simulated_runtime` | `boolean` | ❌ | `false` | — |
| `enable_gemini_explanation` | `boolean` | ❌ | `false` | — |
| `max_transitive_depth` | `integer \| null` | ❌ | `5` | 1–10 |
| `project_id` | `string \| null` | ❌ | `null` | Valid project UUID if provided |

#### Response `200 OK` — Full AnalysisResponse (synchronous)

```json
{
  "api_version": "v1",
  "scan_id": "uuid",
  "repository_url": "https://github.com/owner/repo",
  "repository_name": "repo",
  "repository_owner": "owner",
  "branch": "main",
  "commit_sha": "abc123def456...",
  "status": "COMPLETE",
  "is_demo": false,
  "analysis_options": {
    "include_transitive": true,
    "enable_ast_analysis": true,
    "enable_cicd_analysis": true,
    "enable_metadata_analysis": true,
    "enable_simulated_runtime": false,
    "enable_gemini_explanation": false,
    "max_transitive_depth": 5
  },
  "started_at": "2026-09-25T09:00:00Z",
  "completed_at": "2026-09-25T09:00:45Z",
  "duration_seconds": 45.2,
  "summary": {
    "total_packages": 87,
    "total_findings": 4,
    "critical_count": 1,
    "high_count": 1,
    "medium_count": 2,
    "low_count": 0,
    "informational_count": 0,
    "attack_path_count": 2,
    "affected_asset_count": 3,
    "suspicious_package_count": 2,
    "osv_vulnerability_count": 5,
    "overall_risk_score": 87.5,
    "sbom_package_count": 87
  },
  "findings": [ "...FindingModel[]..." ],
  "attack_paths": [ "...AttackPath[]..." ],
  "assets": [ "...AssetModel[]..." ],
  "sbom": { "...CycloneDX SBOM object..." },
  "graph_summary": {
    "node_count": 92,
    "edge_count": 118,
    "layout_version": "v1.0"
  },
  "gemini_explanation": null,
  "errors": []
}
```

#### AnalysisResponse — Full Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `api_version` | `string` | Always `"v1"` |
| `scan_id` | `string` (UUID) | Unique scan identifier |
| `repository_url` | `string` | Canonical repository URL |
| `repository_name` | `string` | Repository name (e.g., `repo`) |
| `repository_owner` | `string` | Repository owner (e.g., `owner`) |
| `branch` | `string` | Branch analyzed |
| `commit_sha` | `string \| null` | HEAD commit SHA at analysis time |
| `status` | `ScanStatus` | `PENDING\|RUNNING\|COMPLETE\|FAILED\|PARTIAL` |
| `is_demo` | `boolean` | `true` if loaded from demo scenario |
| `analysis_options` | `AnalysisOptions` | Flags used for this run |
| `started_at` | `string` (ISO 8601) | Analysis start timestamp |
| `completed_at` | `string \| null` | Analysis completion timestamp |
| `duration_seconds` | `float \| null` | Wall-clock duration |
| `summary` | `ScanSummary` | Aggregate statistics |
| `findings` | `FindingModel[]` | All security findings |
| `attack_paths` | `AttackPath[]` | All traced attack paths |
| `assets` | `AssetModel[]` | All discovered assets |
| `sbom` | `object \| null` | CycloneDX 1.4 SBOM |
| `graph_summary` | `GraphSummary` | High-level graph statistics |
| `gemini_explanation` | `string \| null` | Gemini-generated narrative |
| `errors` | `string[]` | Non-fatal pipeline errors |

#### Response `202 Accepted` — Asynchronous (large repos)

```json
{
  "api_version": "v1",
  "scan_id": "uuid",
  "status": "PENDING",
  "poll_url": "/api/v1/scans/uuid",
  "estimated_duration_seconds": 90,
  "message": "Analysis started. Poll poll_url for results."
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 422 | `INVALID_GITHUB_URL` | URL does not match pattern |
| 404 | `REPOSITORY_NOT_FOUND` | GitHub returns 404 |
| 403 | `REPOSITORY_PRIVATE` | Repository is private |
| 422 | `REPOSITORY_TOO_LARGE` | Repo > 500 MB |
| 429 | `GITHUB_RATE_LIMITED` | Rate limit hit |
| 502 | `GITHUB_UNAVAILABLE` | GitHub 5xx |
| 502 | `OSV_UNAVAILABLE` | OSV.dev 5xx |
| 504 | `ANALYSIS_TIMEOUT` | Pipeline timeout |
| 409 | `SCAN_ALREADY_RUNNING` | Concurrent scan in progress |
| 503 | `DATABASE_UNAVAILABLE` | Cannot persist results |
| 500 | `INTERNAL_ERROR` | Unhandled exception |

#### Example Request

```bash
curl -X POST https://supplygraph-api.onrender.com/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "github_url": "https://github.com/facebookresearch/llama",
    "branch": "main",
    "include_transitive": true,
    "enable_ast_analysis": true,
    "enable_cicd_analysis": true,
    "enable_metadata_analysis": true,
    "enable_simulated_runtime": false,
    "enable_gemini_explanation": true,
    "max_transitive_depth": 5
  }'
```

#### Example Response (abbreviated)

```json
{
  "api_version": "v1",
  "scan_id": "a1b2c3d4-1234-5678-abcd-ef0123456789",
  "status": "COMPLETE",
  "summary": {
    "total_packages": 87,
    "critical_count": 1,
    "overall_risk_score": 87.5
  }
}
```

---

### 3. POST /api/v1/analyze/demo

**Description:** Load a deterministic, pre-built demo scenario. No live network calls to GitHub or OSV are made. Useful for demonstrations and testing. Returns a full `AnalysisResponse` with `is_demo: true`.

#### Request Body

```json
{
  "scenario_id": "A" | "B" | "C" | "D" | "E",
  "include_gemini_explanation": "boolean"
}
```

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| `scenario_id` | `string` | ✅ | — | One of `"A"`, `"B"`, `"C"`, `"D"`, `"E"` |
| `include_gemini_explanation` | `boolean` | ❌ | `false` | — |

#### Demo Scenarios Reference

| ID | Name | Primary Attack Type | Packages | Findings | Risk |
|----|------|---------------------|----------|----------|------|
| `A` | Typosquatting Supply Chain | Typosquatting | 12 | 3 | HIGH |
| `B` | Dependency Confusion | Dependency Confusion | 18 | 4 | CRITICAL |
| `C` | Transitive Backdoor | Dormant Logic (transitive) | 35 | 6 | CRITICAL |
| `D` | CI/CD Pipeline Poisoning | CI/CD Risk + Obfuscation | 24 | 5 | HIGH |
| `E` | Compromised Maintainer | Suspicious Update + Metadata | 20 | 4 | HIGH |

#### Response `200 OK`

Same schema as `POST /api/v1/analyze` response, but with `is_demo: true` and deterministic values.

```json
{
  "api_version": "v1",
  "scan_id": "demo-scenario-a-fixed-uuid-0000",
  "repository_url": "https://github.com/supplygraph-demo/scenario-a",
  "is_demo": true,
  "status": "COMPLETE",
  "summary": {
    "total_packages": 12,
    "total_findings": 3,
    "critical_count": 0,
    "high_count": 2,
    "medium_count": 1,
    "overall_risk_score": 72.0
  },
  "findings": [ "...3 FindingModel objects..." ],
  "attack_paths": [ "...AttackPath objects..." ],
  "assets": [ "...AssetModel objects..." ]
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 422 | `INVALID_SCENARIO_ID` | `scenario_id` not in `{A,B,C,D,E}` |
| 502 | `GEMINI_UNAVAILABLE` | Gemini requested but API unavailable |
| 500 | `INTERNAL_ERROR` | Demo data loading failure |

#### Example Request

```bash
curl -X POST https://supplygraph-api.onrender.com/api/v1/analyze/demo \
  -H "Content-Type: application/json" \
  -d '{"scenario_id": "C", "include_gemini_explanation": false}'
```

---

### 4. POST /api/v1/reanalyze/{scan_id}

**Description:** Re-run the analysis pipeline using the same repository URL and options as the original scan identified by `scan_id`. The new analysis produces a new `scan_id` with a fresh timestamp. Useful for detecting regressions or improvements after dependency updates.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `string` (UUID) | ID of the scan to re-run |

#### Request Body

Optional. Override options from the original scan.

```json
{
  "enable_gemini_explanation": "boolean | null",
  "enable_simulated_runtime": "boolean | null",
  "max_transitive_depth": "integer | null"
}
```

All fields default to `null` (inherit from original scan).

#### Response `200 OK`

Full `AnalysisResponse` with new `scan_id`. The `previous_scan_id` field is populated to link the chain.

```json
{
  "api_version": "v1",
  "scan_id": "new-uuid",
  "previous_scan_id": "original-scan-uuid",
  "repository_url": "https://github.com/owner/repo",
  "status": "COMPLETE",
  "summary": { "..." }
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `SCAN_NOT_FOUND` | No scan with the given `scan_id` |
| 422 | `REPOSITORY_NOT_FOUND` | Repository was deleted/renamed since original scan |
| 429 | `GITHUB_RATE_LIMITED` | Rate limit hit |
| 409 | `SCAN_ALREADY_RUNNING` | Another scan for this repo is running |
| 500 | `INTERNAL_ERROR` | Unhandled exception |

#### Example Request

```bash
curl -X POST https://supplygraph-api.onrender.com/api/v1/reanalyze/a1b2c3d4-1234-5678-abcd-ef0123456789
```

---

### 5. GET /api/v1/scans

**Description:** List scans with optional filtering and pagination.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | `integer` | `1` | Page number (1-indexed) |
| `page_size` | `integer` | `20` | Results per page (1–100) |
| `repository_url` | `string \| null` | `null` | Filter by exact repository URL |
| `status` | `ScanStatus \| null` | `null` | Filter by scan status |
| `is_demo` | `boolean \| null` | `null` | Include/exclude demo scans |
| `project_id` | `string \| null` | `null` | Filter by project UUID |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "scans": [
    {
      "scan_id": "uuid",
      "repository_url": "https://github.com/owner/repo",
      "repository_name": "repo",
      "repository_owner": "owner",
      "branch": "main",
      "commit_sha": "abc123",
      "status": "COMPLETE",
      "is_demo": false,
      "started_at": "2026-09-25T09:00:00Z",
      "completed_at": "2026-09-25T09:00:45Z",
      "duration_seconds": 45.2,
      "summary": {
        "total_packages": 87,
        "total_findings": 4,
        "critical_count": 1,
        "overall_risk_score": 87.5
      }
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 20,
  "total_pages": 3
}
```

| Field | Type | Description |
|-------|------|-------------|
| `scans` | `ScanListItem[]` | Page of scan summaries |
| `total` | `integer` | Total matching records |
| `page` | `integer` | Current page number |
| `page_size` | `integer` | Items per page |
| `total_pages` | `integer` | Total number of pages |

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 422 | `VALIDATION_ERROR` | `page < 1`, `page_size > 100`, invalid `status` |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/scans?page=1&page_size=10&status=COMPLETE"
```

---

### 6. GET /api/v1/scans/{scan_id}

**Description:** Retrieve the complete scan result including all findings, attack paths, assets, and SBOM for the specified scan.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `string` (UUID) | Scan identifier |

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `include_sbom` | `boolean` | `false` | Include full CycloneDX SBOM in response |
| `include_graph` | `boolean` | `false` | Include graph payload inline |

#### Response `200 OK`

Full `AnalysisResponse` object (same schema as `POST /api/v1/analyze`).

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `SCAN_NOT_FOUND` | No scan with the given ID |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/scans/a1b2c3d4-1234-5678-abcd-ef0123456789"
```

---

### 7. GET /api/v1/findings

**Description:** List findings across all scans or for a specific scan, with rich filtering.

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_id` | `string \| null` | `null` | Filter by scan UUID |
| `severity` | `SeverityEnum \| null` | `null` | Filter by severity level |
| `finding_type` | `FindingType \| null` | `null` | Filter by detection category |
| `status` | `FindingStatus \| null` | `null` | Filter by triage status |
| `is_confirmed` | `boolean \| null` | `null` | Filter confirmed/unconfirmed |
| `package_name` | `string \| null` | `null` | Filter by package name substring |
| `page` | `integer` | `1` | Page number |
| `page_size` | `integer` | `20` | Results per page (max 100) |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "findings": [
    {
      "finding_id": "uuid",
      "scan_id": "uuid",
      "finding_type": "TYPOSQUATTING",
      "severity": "HIGH",
      "status": "OPEN",
      "title": "Typosquatting: 'requets' mimics 'requests'",
      "description": "Package 'requets==2.31.0' closely resembles the popular 'requests' library...",
      "package_name": "requets",
      "package_version": "2.31.0",
      "purl": "pkg:pypi/requets@2.31.0",
      "is_confirmed": true,
      "confidence_score": 0.92,
      "impact_score": 0.75,
      "risk_score": 88.0,
      "created_at": "2026-09-25T09:00:45Z"
    }
  ],
  "total": 4,
  "page": 1,
  "page_size": 20,
  "total_pages": 1
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 422 | `VALIDATION_ERROR` | Invalid enum value or page params |
| 404 | `SCAN_NOT_FOUND` | `scan_id` provided but not found |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/findings?scan_id=uuid&severity=HIGH&page=1"
```

---

### 8. GET /api/v1/findings/{finding_id}

**Description:** Retrieve a single finding in complete detail, including all evidence items, propagation chain, and containment recommendations.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `finding_id` | `string` (UUID) | Finding identifier |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "finding_id": "uuid",
  "scan_id": "uuid",
  "finding_type": "TYPOSQUATTING",
  "severity": "HIGH",
  "status": "OPEN",
  "title": "Typosquatting: 'requets' mimics 'requests'",
  "description": "Detailed human-readable description of the finding.",
  "package_name": "requets",
  "package_version": "2.31.0",
  "purl": "pkg:pypi/requets@2.31.0",
  "ecosystem": "PyPI",
  "is_confirmed": true,
  "is_transitive": false,
  "transitive_depth": 0,
  "confidence_score": 0.92,
  "confidence_breakdown": {
    "name_similarity": 0.97,
    "metadata_anomaly": 0.88,
    "behavioral": 0.80,
    "osv_match": 0.0,
    "cicd_signal": 0.0
  },
  "impact_score": 0.75,
  "impact_breakdown": {
    "exploitability": 0.90,
    "blast_radius": 0.70,
    "operational_impact": 0.65,
    "business_impact": 0.80
  },
  "risk_score": 88.0,
  "evidence": [
    {
      "evidence_id": "uuid",
      "evidence_type": "NAME_SIMILARITY",
      "source": "typosquatting_detector",
      "summary": "Edit distance of 1 between 'requets' and 'requests'",
      "raw_data": {
        "target_name": "requests",
        "edit_distance": 1,
        "similarity_score": 0.97,
        "algorithm": "levenshtein"
      },
      "severity_contribution": "HIGH",
      "weight": 0.4,
      "collected_at": "2026-09-25T09:00:20Z"
    }
  ],
  "propagation_chain": [
    {
      "node_id": "pkg:pypi/requets@2.31.0",
      "node_type": "Version",
      "label": "requets@2.31.0",
      "depth": 0,
      "relationship": "ORIGIN"
    },
    {
      "node_id": "app-node",
      "node_type": "Repository",
      "label": "owner/repo",
      "depth": 1,
      "relationship": "DEPENDS_ON"
    }
  ],
  "affected_assets": [
    {
      "asset_id": "uuid",
      "asset_type": "Service",
      "name": "api-service",
      "is_critical": true
    }
  ],
  "recommendations": [
    {
      "recommendation_id": "uuid",
      "action_type": "REPLACE_PACKAGE",
      "priority": "IMMEDIATE",
      "title": "Replace 'requets' with 'requests'",
      "description": "Remove 'requets==2.31.0' from your lockfile and install 'requests>=2.31.0'.",
      "implementation_steps": [
        "Run: pip uninstall requets",
        "Run: pip install requests>=2.31.0",
        "Update requirements.txt or poetry.lock"
      ],
      "estimated_effort": "LOW",
      "references": ["https://pypi.org/project/requests/"]
    }
  ],
  "osv_vulnerabilities": [],
  "created_at": "2026-09-25T09:00:45Z",
  "updated_at": "2026-09-25T09:00:45Z"
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `FINDING_NOT_FOUND` | No finding with the given ID |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/findings/b2c3d4e5-2345-6789-bcde-f01234567890"
```

---

### 9. GET /api/v1/graph/{scan_id}

**Description:** Retrieve the security graph payload for a scan. This is the primary data source for the React Flow visualization. Includes pre-computed layout positions (server-side layout via NetworkX + a force-directed or hierarchical algorithm).

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `string` (UUID) | Scan identifier |

#### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `layout` | `string` | `"hierarchical"` | Layout algorithm: `"hierarchical"`, `"force"`, `"radial"` |
| `highlight_attack_paths` | `boolean` | `true` | Annotate attack-path edges with `is_attack_path: true` |
| `filter_severity` | `SeverityEnum \| null` | `null` | Only show nodes/edges involved in findings at this severity or above |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "scan_id": "uuid",
  "nodes": [
    {
      "id": "pkg:pypi/requests@2.31.0",
      "type": "packageNode",
      "position": {"x": 280.0, "y": 120.0},
      "data": {
        "label": "requests@2.31.0",
        "node_type": "Version",
        "ecosystem": "PyPI",
        "is_suspicious": false,
        "is_origin_candidate": false,
        "is_affected": false,
        "severity": null,
        "purl": "pkg:pypi/requests@2.31.0",
        "package_name": "requests",
        "version": "2.31.0",
        "vulnerability_count": 0,
        "finding_count": 0,
        "is_transitive": false,
        "transitive_depth": 1,
        "metadata": {
          "pypi_url": "https://pypi.org/project/requests/",
          "author": "Kenneth Reitz",
          "license": "Apache-2.0"
        }
      }
    },
    {
      "id": "app-node",
      "type": "repositoryNode",
      "position": {"x": 0.0, "y": 0.0},
      "data": {
        "label": "owner/repo",
        "node_type": "Repository",
        "is_suspicious": false,
        "is_origin_candidate": false,
        "is_affected": true,
        "severity": "HIGH",
        "vulnerability_count": 0,
        "finding_count": 4
      }
    }
  ],
  "edges": [
    {
      "id": "dep-app-requests",
      "source": "app-node",
      "target": "pkg:pypi/requests@2.31.0",
      "type": "dependencyEdge",
      "animated": false,
      "data": {
        "edge_type": "DEPENDS_ON",
        "is_direct": true,
        "depth": 1,
        "is_attack_path": false,
        "constraint_type": "==",
        "constraint_version": "2.31.0"
      }
    }
  ],
  "layout_version": "v1.0",
  "layout_algorithm": "hierarchical",
  "node_count": 92,
  "edge_count": 118
}
```

#### Node Object Schema

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique node ID (PURL for packages) |
| `type` | `string` | React Flow node type (`packageNode`, `repositoryNode`, `serviceNode`, `pipelineNode`) |
| `position` | `{x: float, y: float}` | Pre-computed layout position |
| `data.label` | `string` | Display label |
| `data.node_type` | `NodeType` | Semantic type |
| `data.is_suspicious` | `boolean` | Has at least one active finding |
| `data.is_origin_candidate` | `boolean` | Identified as possible attack origin |
| `data.is_affected` | `boolean` | Reachable from an attack origin |
| `data.severity` | `SeverityEnum \| null` | Highest severity finding on this node |
| `data.purl` | `string \| null` | Package URL (packages only) |
| `data.vulnerability_count` | `integer` | OSV vulnerability count |
| `data.finding_count` | `integer` | SupplyGraph finding count |

#### Edge Object Schema

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique edge ID |
| `source` | `string` | Source node ID |
| `target` | `string` | Target node ID |
| `type` | `string` | React Flow edge type (`dependencyEdge`, `attackEdge`) |
| `animated` | `boolean` | Animated in React Flow (true for attack paths) |
| `data.edge_type` | `EdgeType` | Semantic edge type |
| `data.is_direct` | `boolean` | True for depth-1 dependencies |
| `data.depth` | `integer` | Dependency depth from root |
| `data.is_attack_path` | `boolean` | Part of a traced attack path |

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `SCAN_NOT_FOUND` | No scan with the given ID |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/graph/a1b2c3d4-1234-5678-abcd-ef0123456789?layout=hierarchical"
```

---

### 10. GET /api/v1/attack-paths/{scan_id}

**Description:** Retrieve all attack paths traced for a scan. Each path is an ordered sequence of nodes from the suspected origin to an affected asset, with edge metadata.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `string` (UUID) | Scan identifier |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "scan_id": "uuid",
  "attack_paths": [
    {
      "path_id": "uuid",
      "finding_id": "uuid",
      "origin_node_id": "pkg:pypi/requets@2.31.0",
      "origin_label": "requets@2.31.0",
      "target_asset_id": "asset-uuid",
      "target_asset_label": "api-service",
      "severity": "HIGH",
      "confidence": 0.92,
      "path_length": 3,
      "nodes": [
        {
          "node_id": "pkg:pypi/requets@2.31.0",
          "label": "requets@2.31.0",
          "node_type": "Version",
          "depth": 0,
          "is_origin": true,
          "is_target": false
        },
        {
          "node_id": "app-node",
          "label": "owner/repo",
          "node_type": "Repository",
          "depth": 1,
          "is_origin": false,
          "is_target": false
        },
        {
          "node_id": "asset-service-api",
          "label": "api-service",
          "node_type": "Service",
          "depth": 2,
          "is_origin": false,
          "is_target": true
        }
      ],
      "edges": [
        {
          "from_node_id": "pkg:pypi/requets@2.31.0",
          "to_node_id": "app-node",
          "edge_type": "DEPENDS_ON",
          "depth": 1
        },
        {
          "from_node_id": "app-node",
          "to_node_id": "asset-service-api",
          "edge_type": "DEPLOYS",
          "depth": 2
        }
      ],
      "narrative": "The malicious package 'requets' is a direct dependency of owner/repo, which deploys the api-service. An attacker who controls 'requets' can execute arbitrary code in the api-service runtime."
    }
  ],
  "total_paths": 2
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `SCAN_NOT_FOUND` | No scan with the given ID |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/attack-paths/a1b2c3d4-1234-5678-abcd-ef0123456789"
```

---

### 11. GET /api/v1/assets/{scan_id}

**Description:** Retrieve all assets (services, containers, deployments, APIs, CI/CD pipelines) discovered during a scan.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | `string` (UUID) | Scan identifier |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "scan_id": "uuid",
  "assets": [
    {
      "asset_id": "uuid",
      "scan_id": "uuid",
      "asset_type": "Service",
      "name": "api-service",
      "description": "Main REST API service for the application.",
      "is_critical": true,
      "is_affected": true,
      "affected_by_finding_ids": ["finding-uuid-1"],
      "blast_radius_score": 0.75,
      "operational_impact": "HIGH",
      "business_impact": "HIGH",
      "discovery_source": "docker-compose.yml",
      "metadata": {
        "image": "python:3.11-slim",
        "port": 8000,
        "environment": "production"
      }
    },
    {
      "asset_id": "uuid-2",
      "asset_type": "CICDPipeline",
      "name": ".github/workflows/deploy.yml",
      "description": "GitHub Actions deployment workflow.",
      "is_critical": true,
      "is_affected": false,
      "blast_radius_score": 0.90,
      "operational_impact": "CRITICAL",
      "business_impact": "CRITICAL",
      "discovery_source": ".github/workflows/deploy.yml",
      "metadata": {
        "triggers": ["push", "workflow_dispatch"],
        "jobs": ["build", "deploy"],
        "uses_secrets": true
      }
    }
  ],
  "total": 2
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `SCAN_NOT_FOUND` | No scan with the given ID |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/assets/a1b2c3d4-1234-5678-abcd-ef0123456789"
```

---

### 12. GET /api/v1/compare/{scan_a_id}/{scan_b_id}

**Description:** Compare two scans of the same repository, producing a delta analysis showing new/resolved findings, package changes, and risk score evolution.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_a_id` | `string` (UUID) | ID of the older (baseline) scan |
| `scan_b_id` | `string` (UUID) | ID of the newer (target) scan |

#### Response `200 OK`

```json
{
  "api_version": "v1",
  "comparison_id": "uuid",
  "scan_a_id": "uuid",
  "scan_b_id": "uuid",
  "repository_url": "https://github.com/owner/repo",
  "scan_a_timestamp": "2026-09-24T09:00:00Z",
  "scan_b_timestamp": "2026-09-25T09:00:45Z",
  "risk_delta": {
    "scan_a_risk_score": 72.0,
    "scan_b_risk_score": 87.5,
    "delta": 15.5,
    "trend": "WORSENED"
  },
  "finding_delta": {
    "new_findings": [
      {
        "finding_id": "uuid",
        "title": "New typosquatting finding",
        "severity": "HIGH",
        "finding_type": "TYPOSQUATTING"
      }
    ],
    "resolved_findings": [],
    "persisted_findings": [
      {
        "finding_id_a": "uuid-in-a",
        "finding_id_b": "uuid-in-b",
        "title": "Existing CVE",
        "severity": "MEDIUM"
      }
    ],
    "new_count": 1,
    "resolved_count": 0,
    "persisted_count": 3
  },
  "package_delta": {
    "added_packages": [
      {"purl": "pkg:pypi/requets@2.31.0", "name": "requets", "version": "2.31.0"}
    ],
    "removed_packages": [],
    "updated_packages": [
      {
        "purl_a": "pkg:pypi/requests@2.30.0",
        "purl_b": "pkg:pypi/requests@2.31.0",
        "name": "requests",
        "version_a": "2.30.0",
        "version_b": "2.31.0"
      }
    ],
    "added_count": 1,
    "removed_count": 0,
    "updated_count": 1
  },
  "attack_path_delta": {
    "new_paths": 1,
    "resolved_paths": 0
  }
}
```

#### Error Responses

| HTTP | Code | Condition |
|------|------|-----------|
| 404 | `SCAN_NOT_FOUND` | Either scan ID does not exist |
| 422 | `COMPARISON_MISMATCH` | The two scans are for different repositories |
| 503 | `DATABASE_UNAVAILABLE` | Cannot query database |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/api/v1/compare/scan-a-uuid/scan-b-uuid"
```

---

### 13. GET /health

**Description:** Health check endpoint for uptime monitoring and deployment readiness probes. Does not require authentication.

#### Response `200 OK` — Healthy

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "api_version": "v1",
  "services": {
    "database": {
      "status": "healthy",
      "latency_ms": 12
    },
    "osv_api": {
      "status": "healthy",
      "latency_ms": 45
    },
    "github_api": {
      "status": "healthy",
      "rate_limit_remaining": 4850,
      "rate_limit_reset_at": "2026-09-25T10:00:00Z"
    },
    "gemini_api": {
      "status": "healthy"
    }
  },
  "timestamp": "2026-09-25T09:00:00Z"
}
```

#### Response `503 Service Unavailable` — Degraded

```json
{
  "status": "degraded",
  "version": "1.0.0",
  "api_version": "v1",
  "services": {
    "database": {
      "status": "unhealthy",
      "error": "Connection timeout"
    },
    "osv_api": {"status": "healthy", "latency_ms": 45},
    "github_api": {"status": "healthy", "rate_limit_remaining": 4850},
    "gemini_api": {"status": "unknown"}
  },
  "timestamp": "2026-09-25T09:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | `"healthy" \| "degraded" \| "unhealthy"` | Overall system health |
| `version` | `string` | Application version |
| `api_version` | `string` | API version |
| `services` | `object` | Per-service health objects |
| `timestamp` | `string` | Check timestamp |

#### Example Request

```bash
curl "https://supplygraph-api.onrender.com/health"
```

---

## Graph Payload Format (Complete Reference)

The graph payload returned by `GET /api/v1/graph/{scan_id}` is the canonical data format consumed by the React Flow frontend.

```json
{
  "api_version": "v1",
  "scan_id": "uuid",
  "nodes": [
    {
      "id": "pkg:pypi/requests@2.31.0",
      "type": "packageNode",
      "position": {"x": 280.0, "y": 120.0},
      "data": {
        "label": "requests@2.31.0",
        "node_type": "Version",
        "ecosystem": "PyPI",
        "is_suspicious": false,
        "is_origin_candidate": false,
        "is_affected": false,
        "severity": null,
        "purl": "pkg:pypi/requests@2.31.0",
        "package_name": "requests",
        "version": "2.31.0",
        "vulnerability_count": 0,
        "finding_count": 0,
        "is_transitive": false,
        "transitive_depth": 1,
        "metadata": {}
      }
    },
    {
      "id": "app-root",
      "type": "repositoryNode",
      "position": {"x": 0.0, "y": 0.0},
      "data": {
        "label": "owner/repo",
        "node_type": "Repository",
        "is_suspicious": false,
        "is_origin_candidate": false,
        "is_affected": true,
        "severity": "HIGH",
        "vulnerability_count": 0,
        "finding_count": 4,
        "metadata": {}
      }
    },
    {
      "id": "asset-svc-api",
      "type": "serviceNode",
      "position": {"x": 560.0, "y": 240.0},
      "data": {
        "label": "api-service",
        "node_type": "Service",
        "is_suspicious": false,
        "is_origin_candidate": false,
        "is_affected": true,
        "severity": "HIGH",
        "vulnerability_count": 0,
        "finding_count": 0,
        "metadata": {}
      }
    },
    {
      "id": "pipeline-deploy",
      "type": "pipelineNode",
      "position": {"x": 840.0, "y": 0.0},
      "data": {
        "label": ".github/workflows/deploy.yml",
        "node_type": "CICDPipeline",
        "is_suspicious": true,
        "is_origin_candidate": false,
        "is_affected": false,
        "severity": "MEDIUM",
        "vulnerability_count": 0,
        "finding_count": 1,
        "metadata": {}
      }
    }
  ],
  "edges": [
    {
      "id": "dep-root-requests",
      "source": "app-root",
      "target": "pkg:pypi/requests@2.31.0",
      "type": "dependencyEdge",
      "animated": false,
      "data": {
        "edge_type": "DEPENDS_ON",
        "is_direct": true,
        "depth": 1,
        "is_attack_path": false,
        "constraint_type": "==",
        "constraint_version": "2.31.0"
      }
    },
    {
      "id": "deploy-root-svc",
      "source": "app-root",
      "target": "asset-svc-api",
      "type": "deployEdge",
      "animated": false,
      "data": {
        "edge_type": "DEPLOYS",
        "is_direct": true,
        "depth": 1,
        "is_attack_path": true
      }
    },
    {
      "id": "pipeline-root-deploy",
      "source": "pipeline-deploy",
      "target": "app-root",
      "type": "pipelineEdge",
      "animated": false,
      "data": {
        "edge_type": "TRIGGERS",
        "is_direct": true,
        "depth": 1,
        "is_attack_path": false
      }
    }
  ],
  "layout_version": "v1.0",
  "layout_algorithm": "hierarchical",
  "node_count": 4,
  "edge_count": 3
}
```

### Node Types and React Flow Component Mapping

| `node_type` value | React Flow `type` | Description |
|---|---|---|
| `Version` | `packageNode` | A specific versioned package |
| `Package` | `packageNode` | A package without specific version |
| `Repository` | `repositoryNode` | Root GitHub repository node |
| `Service` | `serviceNode` | Deployed microservice or application |
| `Container` | `serviceNode` | Docker container |
| `API` | `serviceNode` | External API endpoint |
| `Deployment` | `serviceNode` | Deployment artifact |
| `CICDPipeline` | `pipelineNode` | CI/CD workflow file |
| `Asset` | `serviceNode` | Generic infrastructure asset |

### Edge Types and React Flow Component Mapping

| `edge_type` | React Flow `type` | `animated` | Description |
|---|---|---|---|
| `DEPENDS_ON` | `dependencyEdge` | `false` normally, `true` if attack path | Package dependency |
| `PROVIDES` | `dependencyEdge` | `false` | Package provides a service |
| `EXPOSES` | `deployEdge` | `false` | Service exposes an API |
| `DEPLOYS` | `deployEdge` | `false` normally, `true` if attack path | Repository deploys service |
| `TRIGGERS` | `pipelineEdge` | `false` | CI/CD triggers action |
| `ATTACK_PATH` | `attackEdge` | `true` | Explicit attack path edge |
| `PROPAGATES_TO` | `attackEdge` | `true` | Threat propagation |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v1.0.0 | 2026-09-25 | Initial API — HackFusion 2026, Theme 6 |

---

*SupplyGraph API Contract — HackFusion 2026 — Theme 6: Software Supply-Chain Attack Graph Engine*
