"""
SupplyGraph Confidence Engine
Version: 1.0.0

Purpose:
    Compute a heuristic confidence score for each security finding.

Formula:
    C = 1 - Π(1 - wi × ri)

    where:
        wi = configurable evidence weight (0.0 to 1.0)
        ri = configurable evidence source reliability (0.0 to 1.0)

    Synthetic/simulated evidence is discounted by synthetic_discount factor.

IMPORTANT DISCLAIMER:
    This is a HEURISTIC scoring model.
    It is NOT a probability of compromise.
    It is NOT scientifically validated.
    All weights are configurable and subjective.
    The UI must clearly label this as "Heuristic Confidence Score".

Evidence Weights (default, all configurable):
    OSV vulnerability match:        0.80
    AST suspicious finding:         0.60
    Typosquatting similarity:       0.50
    Dependency confusion:           0.65
    Suspicious update:              0.55
    CI/CD risk:                     0.60
    Metadata anomaly:               0.40
    Simulated runtime signal:       0.30 × (1 - synthetic_discount)

Source Reliability (default, all configurable):
    OSV:                    1.0 (authoritative database)
    GitHub API:             0.9 (authoritative for repo data)
    AST analysis:           0.7 (heuristic)
    Typosquatting:          0.6 (heuristic, similarity ≠ malicious)
    Metadata:               0.5 (heuristic)
    Simulated runtime:      0.3 (controlled synthetic)

Full implementation in Milestone 2B.
This module defines the interface and scoring constants.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any

# ============================================================
# DEFAULT EVIDENCE WEIGHTS
# ============================================================
DEFAULT_WEIGHTS: Dict[str, float] = {
    "osv_vulnerability": 0.80,
    "ast_finding": 0.60,
    "typosquatting": 0.50,
    "dependency_confusion": 0.65,
    "suspicious_update": 0.55,
    "cicd_risk": 0.60,
    "metadata_anomaly": 0.40,
    "obfuscation": 0.55,
    "dormant_logic": 0.45,
    "simulated_runtime": 0.30,
    "dependency_reachability": 0.35,
    "service_exposure": 0.50,
}

# ============================================================
# DEFAULT SOURCE RELIABILITY
# ============================================================
DEFAULT_RELIABILITY: Dict[str, float] = {
    "osv": 1.0,
    "github": 0.9,
    "ast": 0.7,
    "lockfile": 0.9,
    "sbom": 0.8,
    "typosquatting": 0.6,
    "dependency_confusion": 0.65,
    "cicd": 0.7,
    "metadata": 0.5,
    "runtime": 0.3,  # simulated
}

DEFAULT_SYNTHETIC_DISCOUNT = 0.15


@dataclass
class ConfidenceFactor:
    """A single factor contributing to the confidence score."""
    evidence_type: str
    source: str
    raw_weight: float
    reliability: float
    is_simulated: bool = False
    synthetic_discount: float = DEFAULT_SYNTHETIC_DISCOUNT
    description: str = ""

    @property
    def effective_weight(self) -> float:
        """Apply synthetic discount if evidence is simulated."""
        w = self.raw_weight * self.reliability
        if self.is_simulated:
            w = w * (1.0 - self.synthetic_discount)
        return min(w, 1.0)

    @property
    def contribution(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "source": self.source,
            "raw_weight": round(self.raw_weight, 3),
            "reliability": round(self.reliability, 3),
            "effective_weight": round(self.effective_weight, 3),
            "is_simulated": self.is_simulated,
            "description": self.description,
        }


def compute_confidence(
    factors: List[ConfidenceFactor],
    synthetic_discount: float = DEFAULT_SYNTHETIC_DISCOUNT,
) -> Dict[str, Any]:
    """
    Compute heuristic confidence score from a list of evidence factors.

    Formula: C = 1 - Π(1 - wi × ri)
    where wi = effective weight (post synthetic discount)

    Returns:
        {
            "score": float (0.0 to 1.0),
            "score_percent": float (0.0 to 100.0),
            "evidence_count": int,
            "simulated_evidence_count": int,
            "contributing_factors": List[dict],
            "label": "Heuristic Confidence Score",
            "disclaimer": str
        }
    """
    if not factors:
        return {
            "score": 0.0,
            "score_percent": 0.0,
            "evidence_count": 0,
            "simulated_evidence_count": 0,
            "contributing_factors": [],
            "label": "Heuristic Confidence Score",
            "disclaimer": (
                "This is a heuristic score and NOT a probability of compromise. "
                "All weights are configurable and subjective."
            ),
        }

    # C = 1 - Π(1 - wi)
    product = 1.0
    for factor in factors:
        product *= (1.0 - factor.effective_weight)

    score = min(1.0 - product, 1.0)
    simulated_count = sum(1 for f in factors if f.is_simulated)

    return {
        "score": round(score, 4),
        "score_percent": round(score * 100, 1),
        "evidence_count": len(factors),
        "simulated_evidence_count": simulated_count,
        "synthetic_discount_applied": synthetic_discount,
        "contributing_factors": [f.contribution for f in factors],
        "label": "Heuristic Confidence Score",
        "disclaimer": (
            "This is a heuristic score and NOT a probability of compromise. "
            "All weights are configurable and subjective."
        ),
    }


def compute_blast_radius(
    package_count: int = 0,
    service_count: int = 0,
    api_count: int = 0,
    production_deployment_count: int = 0,
    package_weight: float = 2.0,
    service_weight: float = 15.0,
    api_weight: float = 25.0,
    deployment_weight: float = 50.0,
) -> Dict[str, Any]:
    """
    Compute heuristic blast-radius score.

    Formula: B = 2P + 15S + 25A + 50D

    IMPORTANT: This is a heuristic estimate, not a universal business-impact metric.
    Always show underlying asset counts alongside the score.
    Weights are configurable and documented.
    """
    score = (
        package_count * package_weight
        + service_count * service_weight
        + api_count * api_weight
        + production_deployment_count * deployment_weight
    )
    return {
        "score": round(score, 2),
        "label": "Heuristic Blast-Radius Score",
        "breakdown": {
            "packages": {"count": package_count, "weight": package_weight, "subtotal": package_count * package_weight},
            "services": {"count": service_count, "weight": service_weight, "subtotal": service_count * service_weight},
            "apis": {"count": api_count, "weight": api_weight, "subtotal": api_count * api_weight},
            "deployments": {
                "count": production_deployment_count,
                "weight": deployment_weight,
                "subtotal": production_deployment_count * deployment_weight,
            },
        },
        "disclaimer": (
            "Heuristic Blast-Radius Score. Weights: "
            f"Package={package_weight}, Service={service_weight}, "
            f"API={api_weight}, Deployment={deployment_weight}. "
            "Do not use as an objective business-impact metric."
        ),
    }
