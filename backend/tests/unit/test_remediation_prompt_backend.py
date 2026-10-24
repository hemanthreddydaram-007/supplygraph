# SupplyGraph - Backend Tests for Evidence-Based Remediation & Action Pinning
import pytest
from app.services.code_reviewer import CodeReviewerService, resolve_action_pin, ACTION_SHA_REGISTRY
from app.services.osv_client import resolve_best_fixed_version


def test_verified_action_resolves_official_sha():
    """Authoritative actions in registry must resolve to verified 40-char commit SHA."""
    sha, comment = resolve_action_pin("actions/checkout", "v4")
    assert sha == "11bd71901bbe5b1630ceea73d27597364c9af683"
    assert "v4.2.2" in comment

    sha_py, comment_py = resolve_action_pin("actions/setup-python", "v5")
    assert sha_py == "42375524e23c412d93fb67b49958b491fce71c38"
    assert "v5.4.0" in comment_py


def test_unverified_third_party_action_never_fabricates_sha():
    """Unverified third-party actions must return None for SHA, never a fabricated pseudo-hash."""
    sha, comment = resolve_action_pin("untrusted-org/malicious-or-custom-action", "v1.0.0")
    assert sha is None, "Must never return a fabricated SHA for unverified actions"
    assert "Verify" in comment or "v1.0.0" in comment


def test_code_reviewer_handles_unverified_action_without_broken_syntax():
    """Code reviewer must output an action-required directive instead of a fake SHA."""
    reviewer = CodeReviewerService()
    workflow_yaml = """name: Deploy
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: custom-org/custom-action@v2
"""
    reviews = reviewer.review_snippet(workflow_yaml, language="yaml", file_path=".github/workflows/deploy.yml")
    assert len(reviews) == 2

    # Verified action
    checkout_rev = next(r for r in reviews if "checkout" in r.title)
    assert "11bd71901bbe5b1630ceea73d27597364c9af683" in checkout_rev.corrected_code

    # Unverified action
    custom_rev = next(r for r in reviews if "custom-action" in r.title)
    assert "VERIFY_40_CHAR_COMMIT_SHA" in custom_rev.corrected_code
    assert "https://github.com/custom-org/custom-action/releases" in custom_rev.error_explanation


def test_semver_resolver_least_disruptive_patch():
    """SemVer resolver must select highest patch in same major to cover all CVEs without major bump."""
    # Installed 1.2.0, available fixes: 1.1.0, 1.2.3, 1.4.0, 2.0.0
    # When prefer_highest is True, picks 1.4.0 (highest patch in same major)
    fixed = resolve_best_fixed_version("1.2.0", ["1.1.0", "1.4.0", "1.2.3", "2.0.0"], prefer_highest=True)
    assert fixed == "1.4.0"


def test_semver_resolver_never_downgrades():
    """SemVer resolver must never downgrade major versions or invent fabricated versions."""
    fixed = resolve_best_fixed_version("2.5.0", ["1.8.2"])
    assert fixed is None
