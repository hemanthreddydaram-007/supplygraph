# Tests for DependencyConfusionDetector
import pytest
from app.detectors.confusion_detector import DependencyConfusionDetector
from app.models.core import SBOMComponent, Ecosystem


@pytest.fixture
def detector():
    return DependencyConfusionDetector()


def make_component(name: str, ecosystem: str = "npm") -> SBOMComponent:
    eco = Ecosystem.NPM if ecosystem == "npm" else Ecosystem.PYPI
    return SBOMComponent(
        bom_ref=f"{name}-ref",
        name=name,
        version="1.0.0",
        ecosystem=eco,
        purl=f"pkg:{ecosystem}/{name}@1.0.0",
        is_direct=True,
        is_transitive=False
    )


def test_clean_public_package_no_finding(detector):
    """Well-known public packages should not be flagged."""
    comps = [make_component("express"), make_component("lodash"), make_component("react")]
    results = detector.detect(comps)
    assert len(results) == 0


def test_internal_scoped_package_flagged(detector):
    """Packages with @internal scope should be flagged."""
    comps = [make_component("@internal/auth-utils")]
    results = detector.detect(comps)
    assert len(results) == 1
    assert results[0].evidence_type == "DEPENDENCY-CONFUSION-RISK"


def test_corp_scoped_package_flagged(detector):
    """Packages with @corp scope should be flagged."""
    comps = [make_component("@corp/shared-components")]
    results = detector.detect(comps)
    assert len(results) == 1


def test_internal_suffix_package_flagged(detector):
    """Packages ending in -internal should be flagged."""
    comps = [make_component("my-app-internal")]
    results = detector.detect(comps)
    assert len(results) == 1


def test_private_suffix_package_flagged(detector):
    """Packages ending in -private should be flagged."""
    comps = [make_component("auth-service-private")]
    results = detector.detect(comps)
    assert len(results) == 1


def test_create_finding_from_evidence(detector):
    """create_finding_from_evidence should return a FindingModel."""
    comps = [make_component("@internal/logging")]
    evidence = detector.detect(comps)
    finding = detector.create_finding_from_evidence(evidence, "scan-abc", "@internal/logging")
    assert finding is not None
    assert finding.finding_type.value == "DEPENDENCY_CONFUSION"
    assert finding.severity.value == "HIGH"


def test_empty_component_list(detector):
    """Empty component list should return empty results."""
    results = detector.detect([])
    assert results == []
