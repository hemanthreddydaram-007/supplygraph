# SupplyGraph — Testing Strategy
HackFusion 2026 | Theme 6

---

## Testing Philosophy

1. Test working behavior, not just happy paths.
2. Every security module must have at least one automated test.
3. Integration tests verify the full pipeline end-to-end.
4. Demo scenarios A-E serve as acceptance tests.
5. Never claim a feature works until a test proves it.
6. Partial analysis is acceptable; silent failure is not.

---

## Test Tooling

### Backend
- **Framework:** pytest 8+
- **Async:** pytest-asyncio
- **HTTP client:** httpx (FastAPI TestClient)
- **Type checking:** mypy
- **Linting:** ruff
- **Coverage:** pytest-cov

### Frontend
- **Framework:** Jest + React Testing Library
- **Type checking:** tsc --noEmit
- **Linting:** eslint

---

## Backend Unit Tests

Location: `backend/tests/unit/`

### test_purl.py
- `test_pypi_purl_canonical` — requests@2.31.0 → pkg:pypi/requests@2.31.0
- `test_npm_purl_with_namespace` — @scope/pkg@1.0.0 → pkg:npm/%40scope/pkg@1.0.0
- `test_purl_from_string` — parse pkg:pypi/requests@2.31.0
- `test_invalid_purl_raises_value_error`
- `test_purl_without_version`
- `test_purl_ecosystem_normalization`

### test_lockfile.py
- `test_parse_poetry_lock_direct_deps`
- `test_parse_poetry_lock_transitive_deps`
- `test_parse_package_lock_json_v3`
- `test_parse_requirements_txt_pinned`
- `test_parse_requirements_txt_range_spec`
- `test_missing_lockfile_returns_empty_transitive`
- `test_lockfile_warning_when_missing`

### test_sbom.py
- `test_sbom_has_cyclonedx_format`
- `test_sbom_serial_number_is_urn_uuid`
- `test_sbom_components_have_purl`
- `test_sbom_dependencies_reference_bom_refs`
- `test_sbom_generated_at_is_recent`

### test_osv.py
- `test_batch_query_builds_correct_payload`
- `test_cache_hit_returns_cached_record`
- `test_cache_miss_triggers_fetch`
- `test_stale_osv_record_refreshed_by_modified_ts`
- `test_osv_network_failure_returns_gracefully`
- `test_version_within_affected_range`
- `test_version_after_fix_not_affected`

### test_graph.py
- `test_graph_adds_repository_node`
- `test_graph_adds_package_nodes`
- `test_graph_adds_depends_on_edges`
- `test_transitive_dependency_path_found`
- `test_cycle_in_graph_detected_and_handled`
- `test_ancestor_packages_of_vulnerable_found`
- `test_graph_edge_semantics_consistent`

### test_layout.py
- `test_dag_layout_assigns_positions`
- `test_dag_layout_no_position_overlap`
- `test_cyclic_graph_layout_does_not_crash`
- `test_layout_positions_are_deterministic`
- `test_horizontal_spacing_correct`
- `test_vertical_spacing_correct`

### test_typosquatting.py
- `test_reqeusts_vs_requests_flagged`
- `test_numpyy_vs_numpy_flagged`
- `test_requests_vs_requests_not_flagged`
- `test_similarity_score_range_0_to_1`
- `test_threshold_configurable`

### test_ast_analysis.py
- `test_subprocess_shell_true_detected`
- `test_eval_string_detected`
- `test_exec_string_detected`
- `test_base64_decode_pattern_detected`
- `test_clean_file_no_findings`
- `test_finding_has_file_and_line`
- `test_finding_has_severity`

### test_confidence.py
- `test_zero_evidence_yields_zero_confidence`
- `test_single_evidence_low_confidence`
- `test_multiple_evidence_increases_confidence`
- `test_simulated_evidence_discounted`
- `test_confidence_capped_at_1_0`
- `test_score_percent_computed_correctly`

### test_blast_radius.py
- `test_empty_assets_zero_score`
- `test_one_production_deployment_score_50`
- `test_one_api_score_25`
- `test_one_service_score_15`
- `test_composite_score_correct`
- `test_weights_configurable`

### test_containment.py
- `test_vulnerable_gets_pin_version_recommendation`
- `test_typosquat_gets_remove_dependency_recommendation`
- `test_cicd_risk_gets_audit_workflow_recommendation`
- `test_recommendation_has_why_field`
- `test_recommendation_has_expected_effect`

---

## Backend Integration Tests

Location: `backend/tests/integration/`

### test_analyze_endpoint.py

#### MILESTONE 2A GATE TEST
```python
def test_demo_scenario_a_returns_valid_graph_payload():
    """
    This test MUST pass before Milestone 2A is declared complete.
    """
    response = client.post("/api/v1/analyze/demo", json={"scenario_id": "A"})
    assert response.status_code == 200
    data = response.json()
    assert data["api_version"] == "v1"
    assert data["scan"]["status"] == "completed"
    assert len(data["graph"]["nodes"]) > 0
    assert len(data["graph"]["edges"]) > 0
    for node in data["graph"]["nodes"]:
        assert "position" in node
        assert "x" in node["position"]
        assert "y" in node["position"]
    assert len(data["findings"]) > 0
    assert len(data["vulnerabilities"]) > 0
```

### test_full_pipeline.py
- `test_demo_d_transitive_path_found` — verify 4-level propagation path
- `test_demo_d_origin_identified`
- `test_demo_d_affected_assets_not_empty`
- `test_demo_d_blast_radius_score_positive`
- `test_demo_d_containment_recommendations_present`
- `test_health_endpoint_returns_200`
- `test_invalid_github_url_returns_422`

---

## Frontend Tests

Location: `frontend/src/**/__tests__/`

- `GraphCanvas.test.tsx` — nodes render with correct positions
- `FindingsList.test.tsx` — severity filter works
- `AnalysisForm.test.tsx` — invalid URL shows error

---

## Demo Scenario Acceptance Tests

For each scenario A-E, manually verify:

| Check | Scenario A | B | C | D | E |
|---|---|---|---|---|---|
| Graph renders | ✓ | ✓ | ✓ | ✓ | ✓ |
| Origin identified | ✓ | ✓ | ✓ | ✓ | ✓ |
| Attack path shown | ✓ | ✓ | ✓ | ✓ | ✓ |
| Affected assets shown | ✓ | ✓ | ✓ | ✓ | ✓ |
| Confidence displayed | ✓ | ✓ | ✓ | ✓ | ✓ |
| Containment shown | ✓ | ✓ | ✓ | ✓ | ✓ |
| DEMO label visible | ✓ | ✓ | ✓ | ✓ | ✓ |
| SIMULATED labels (where applicable) | - | - | ✓ | ✓ | - |

---

## Test Fixtures

Location: `backend/tests/fixtures/`

- `poetry.lock` — sample Poetry lockfile
- `package-lock.json` — sample npm lockfile
- `requirements.txt` — sample pip requirements
- `malicious_sample.py` — Python file with suspicious patterns (subprocess, eval, base64)
- `clean_sample.py` — Python file with no suspicious patterns
- `suspicious_workflow.yml` — GitHub Actions with suspicious patterns
- `clean_workflow.yml` — GitHub Actions clean workflow

---

## Test Commands

```bash
# Run all backend tests
cd backend && pytest tests/ -v

# Run with coverage
cd backend && pytest tests/ -v --cov=app --cov-report=html

# Run only unit tests
cd backend && pytest tests/unit/ -v

# Run only integration tests
cd backend && pytest tests/integration/ -v

# Type check
cd backend && mypy app/

# Lint
cd backend && ruff check app/ tests/

# Frontend type check
cd frontend && npx tsc --noEmit

# Frontend lint
cd frontend && npm run lint

# Frontend tests
cd frontend && npm test
```
