# Tests for CICDAnalyzer
import pytest
from app.detectors.cicd_analyzer import CICDAnalyzer

@pytest.fixture
def analyzer():
    return CICDAnalyzer()


STANDARD_WORKFLOW = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - name: Run tests
        run: npm test
"""

UNPINNED_WORKFLOW = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: third-party/action@v2
      - uses: another-org/risky-action@main
"""

INJECTION_WORKFLOW = """
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Greet
        run: echo "Hello ${{ github.event.pull_request.title }}"
"""

PERMISSIONS_WORKFLOW = """
name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""


def test_clean_workflow_no_findings(analyzer):
    """A standard workflow using only first-party actions should produce no findings."""
    findings = analyzer.analyze("ci.yml", STANDARD_WORKFLOW)
    assert len(findings) == 0


def test_detects_unpinned_third_party_action(analyzer):
    """Unpinned third-party actions should be flagged."""
    findings = analyzer.analyze("ci.yml", UNPINNED_WORKFLOW)
    types = [f.evidence_type for f in findings]
    assert "CICD-UNPINNED-ACTION" in types


def test_detects_multiple_unpinned_actions(analyzer):
    """Both third-party@v2 and third-party@main should be flagged."""
    findings = analyzer.analyze("ci.yml", UNPINNED_WORKFLOW)
    unpinned = [f for f in findings if f.evidence_type == "CICD-UNPINNED-ACTION"]
    assert len(unpinned) >= 2


def test_detects_script_injection(analyzer):
    """PR title interpolation into run: should be flagged."""
    findings = analyzer.analyze("ci.yml", INJECTION_WORKFLOW)
    types = [f.evidence_type for f in findings]
    assert "CICD-SCRIPT-INJECTION" in types


def test_detects_excessive_permissions(analyzer):
    """write-all permissions should be flagged."""
    findings = analyzer.analyze("ci.yml", PERMISSIONS_WORKFLOW)
    types = [f.evidence_type for f in findings]
    assert "CICD-EXCESSIVE-PERMISSIONS" in types


def test_create_finding_from_evidence(analyzer):
    """create_finding_from_evidence should produce a FindingModel."""
    findings_ev = analyzer.analyze("ci.yml", UNPINNED_WORKFLOW)
    finding = analyzer.create_finding_from_evidence(findings_ev, "scan-123", "ci.yml")
    assert finding is not None
    assert finding.finding_type.value == "CICD_RISK"
    assert len(finding.evidence) > 0


def test_empty_content_produces_no_findings(analyzer):
    """Empty workflow should produce no findings."""
    findings = analyzer.analyze("empty.yml", "")
    assert len(findings) == 0


def test_detects_curl_pipe_bash(analyzer):
    """curl piped to bash should be detected."""
    content = """
    name: Build
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - run: curl -sSL https://install.example.com/setup.sh | bash
    """
    findings = analyzer.analyze("ci.yml", content)
    types = [f.evidence_type for f in findings]
    assert "CICD-CURL-PIPE-BASH" in types


def test_detects_gitlab_ci_unpinned_image(analyzer):
    """GitLab CI configuration using unpinned :latest image should be flagged."""
    content = """
    image: node:latest
    stages:
      - test
    test_job:
      stage: test
      script:
        - npm test
    """
    findings = analyzer.analyze(".gitlab-ci.yml", content)
    types = [f.evidence_type for f in findings]
    assert "CICD-UNPINNED-IMAGE" in types


def test_pinned_sha_with_comment_not_flagged(analyzer):
    """An action pinned to a 40-character commit SHA with a comment should not be flagged."""
    content = """
    name: CI
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: third-party/action@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    """
    findings = analyzer.analyze("ci.yml", content)
    unpinned = [f for f in findings if f.evidence_type == "CICD-UNPINNED-ACTION"]
    assert len(unpinned) == 0

