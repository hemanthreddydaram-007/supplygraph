"""
Unit tests for the heuristic confidence engine.
Tests verify scoring logic, synthetic discount, and disclaimer presence.
"""

import pytest
from app.engines.confidence import (
    ConfidenceFactor,
    compute_confidence,
    compute_blast_radius,
    DEFAULT_SYNTHETIC_DISCOUNT,
)


class TestConfidenceEngine:

    def test_zero_evidence_yields_zero_confidence(self):
        result = compute_confidence([])
        assert result["score"] == 0.0
        assert result["score_percent"] == 0.0

    def test_label_is_heuristic(self):
        result = compute_confidence([])
        assert result["label"] == "Heuristic Confidence Score"

    def test_disclaimer_present(self):
        result = compute_confidence([])
        assert "heuristic" in result["disclaimer"].lower()
        assert "NOT a probability" in result["disclaimer"]

    def test_single_evidence_low_confidence(self):
        factor = ConfidenceFactor(
            evidence_type="metadata_anomaly",
            source="metadata",
            raw_weight=0.40,
            reliability=0.5,
        )
        result = compute_confidence([factor])
        # C = 1 - (1 - 0.40 * 0.5) = 1 - 0.8 = 0.2
        assert abs(result["score"] - 0.20) < 0.01

    def test_multiple_evidence_increases_confidence(self):
        factors = [
            ConfidenceFactor("osv_vulnerability", "osv", 0.80, 1.0),
            ConfidenceFactor("ast_finding", "ast", 0.60, 0.7),
        ]
        result = compute_confidence(factors)
        # Multiple factors should produce higher score than single
        single = compute_confidence([factors[0]])
        assert result["score"] > single["score"]

    def test_simulated_evidence_discounted(self):
        real_factor = ConfidenceFactor(
            "ast_finding", "ast", 0.60, 0.7, is_simulated=False
        )
        sim_factor = ConfidenceFactor(
            "simulated_runtime", "runtime", 0.60, 0.7, is_simulated=True
        )
        real_result = compute_confidence([real_factor])
        sim_result = compute_confidence([sim_factor])
        # Simulated evidence must produce lower confidence
        assert sim_result["score"] < real_result["score"]

    def test_confidence_capped_at_1_0(self):
        # Many high-weight factors should not exceed 1.0
        factors = [
            ConfidenceFactor(f"type_{i}", "osv", 0.99, 1.0)
            for i in range(10)
        ]
        result = compute_confidence(factors)
        assert result["score"] <= 1.0

    def test_score_percent_computed_correctly(self):
        factor = ConfidenceFactor("osv_vulnerability", "osv", 0.80, 1.0)
        result = compute_confidence([factor])
        assert abs(result["score_percent"] - result["score"] * 100) < 0.1

    def test_simulated_count_tracked(self):
        factors = [
            ConfidenceFactor("osv_vulnerability", "osv", 0.80, 1.0, is_simulated=False),
            ConfidenceFactor("simulated_runtime", "runtime", 0.30, 0.3, is_simulated=True),
        ]
        result = compute_confidence(factors)
        assert result["simulated_evidence_count"] == 1
        assert result["evidence_count"] == 2


class TestBlastRadius:

    def test_empty_assets_zero_score(self):
        result = compute_blast_radius()
        assert result["score"] == 0.0

    def test_label_is_heuristic(self):
        result = compute_blast_radius()
        assert "Heuristic" in result["label"]

    def test_one_production_deployment_score_50(self):
        result = compute_blast_radius(production_deployment_count=1)
        assert result["score"] == 50.0

    def test_one_api_score_25(self):
        result = compute_blast_radius(api_count=1)
        assert result["score"] == 25.0

    def test_one_service_score_15(self):
        result = compute_blast_radius(service_count=1)
        assert result["score"] == 15.0

    def test_one_package_score_2(self):
        result = compute_blast_radius(package_count=1)
        assert result["score"] == 2.0

    def test_composite_score_correct(self):
        # 2 packages + 2 services + 1 API + 1 production deployment
        # = 2*2 + 2*15 + 1*25 + 1*50 = 4 + 30 + 25 + 50 = 109
        result = compute_blast_radius(
            package_count=2,
            service_count=2,
            api_count=1,
            production_deployment_count=1,
        )
        assert result["score"] == 109.0

    def test_weights_configurable(self):
        result = compute_blast_radius(
            package_count=1,
            package_weight=5.0,  # custom weight
        )
        assert result["score"] == 5.0

    def test_breakdown_present(self):
        result = compute_blast_radius(package_count=2, api_count=1)
        assert "breakdown" in result
        assert "packages" in result["breakdown"]
        assert "apis" in result["breakdown"]
