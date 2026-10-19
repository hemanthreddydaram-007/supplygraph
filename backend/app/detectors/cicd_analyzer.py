# SupplyGraph - CI/CD Workflow Analyzer
# Detects security risks in GitHub Actions workflows
from app.models.core import (
    EvidenceItem, EvidenceClassification, EvidenceSource,
    FindingModel, FindingType, Severity, SourceLocation
)
from app.engines.confidence import compute_confidence, ConfidenceFactor, compute_blast_radius
import re
import uuid
import datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Patterns for detecting unpinned 3rd party actions (mutable refs)
_UNPINNED_ACTION_PATTERN = re.compile(
    r'uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(v[\d.]+|main|master|latest|develop|HEAD)',
    re.IGNORECASE
)

# Trusted first-party action prefixes that are OK to use with tags
_FIRST_PARTY_PREFIXES = (
    "actions/",
    "github/",
)

# Dangerous context interpolation patterns (script injection vectors)
_INJECTION_PATTERN = re.compile(
    r'\$\{\{\s*github\.event\.(?:pull_request\.[a-z_]+|issue\.[a-z_]+|comment\.[a-z_]+|head_commit\.[a-z_]+)\s*\}\}',
    re.IGNORECASE
)

_HEAD_REF_PATTERN = re.compile(
    r'\$\{\{\s*github\.head_ref\s*\}\}',
    re.IGNORECASE
)

# Insecure curl/wget piped to shell
_CURL_BASH_PATTERN = re.compile(
    r'(?:curl|wget)\s+[^|\n]+(?:\|\s*(?:bash|sh|sudo\s+bash|sudo\s+sh))',
    re.IGNORECASE
)

# Unpinned container images (e.g., in GitLab CI or Docker steps)
_UNPINNED_IMAGE_PATTERN = re.compile(
    r'(?:image:\s*|FROM\s+)([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*):(latest|main|master|dev|develop)\b',
    re.IGNORECASE
)

# Patterns for over-permissive permissions
_WRITE_ALL_PATTERN = re.compile(
    r'permissions:\s*write-all',
    re.IGNORECASE
)

# High-entropy string heuristic (potential hardcoded secret)
_HIGH_ENTROPY_PATTERN = re.compile(
    r'(?:token|secret|key|password|passwd|api_key)\s*[:=]\s*["\']?([A-Za-z0-9+/=_-]{20,})["\']?',
    re.IGNORECASE
)


class CICDAnalyzer:
    """Scans GitHub Actions and GitLab CI workflow YAML content for security risks."""

    def analyze(self, workflow_name: str, workflow_content: str) -> List[EvidenceItem]:
        """
        Analyze a single workflow file and return a list of EvidenceItems.

        Args:
            workflow_name: The filename of the workflow (e.g. 'ci.yml', '.gitlab-ci.yml')
            workflow_content: Raw YAML string content of the workflow file

        Returns:
            List of EvidenceItem findings
        """
        findings: List[EvidenceItem] = []

        try:
            findings.extend(self._detect_unpinned_actions(workflow_name, workflow_content))
            findings.extend(self._detect_script_injection(workflow_name, workflow_content))
            findings.extend(self._detect_curl_bash(workflow_name, workflow_content))
            findings.extend(self._detect_unpinned_images(workflow_name, workflow_content))
            findings.extend(self._detect_excessive_permissions(workflow_name, workflow_content))
        except Exception as e:
            logger.warning(f"CICDAnalyzer error on {workflow_name}: {e}")

        return findings

    def _detect_unpinned_actions(self, workflow_name: str, content: str) -> List[EvidenceItem]:
        """Detect third-party GitHub Actions using mutable version tags instead of pinned SHAs."""
        results = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            match = _UNPINNED_ACTION_PATTERN.search(line)
            if match:
                action_ref = match.group(1)
                version_ref = match.group(2)
                # Skip first-party GitHub/actions owned actions
                if any(action_ref.startswith(p) for p in _FIRST_PARTY_PREFIXES):
                    continue
                results.append(EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.CICD,
                    evidence_type="CICD-UNPINNED-ACTION",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Unpinned third-party GitHub Action '{action_ref}@{version_ref}' in "
                        f"'{workflow_name}'. Mutable tags can be redirected to inject malicious code. "
                        f"Pin to a full 40-character commit SHA instead."
                    ),
                    source_location=SourceLocation(file=workflow_name, line=line_num),
                    confidence_contribution=0.7,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "action": action_ref,
                        "ref": version_ref,
                        "rule": "CICD-UNPINNED-ACTION",
                        "remediation": f"Pin to a commit SHA: {action_ref}@<40-char-sha>"
                    }
                ))
        return results

    def _detect_script_injection(self, workflow_name: str, content: str) -> List[EvidenceItem]:
        """Detect untrusted GitHub context interpolation in run: shell blocks (script injection)."""
        results = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            matched = False
            if _INJECTION_PATTERN.search(line):
                matched = True
                pattern_name = "CICD-SCRIPT-INJECTION"
                desc = (
                    f"Untrusted GitHub event context interpolated directly into shell script in "
                    f"'{workflow_name}' at line {line_num}. An attacker can craft a PR title or "
                    f"issue body to inject arbitrary shell commands."
                )
            elif _HEAD_REF_PATTERN.search(line):
                matched = True
                pattern_name = "CICD-SCRIPT-INJECTION"
                desc = (
                    f"github.head_ref interpolated into run: block in '{workflow_name}' at line {line_num}. "
                    f"Branch names are attacker-controlled and enable command injection."
                )
            if matched:
                results.append(EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.CICD,
                    evidence_type="CICD-SCRIPT-INJECTION",
                    classification=EvidenceClassification.HEURISTIC,
                    description=desc,
                    source_location=SourceLocation(file=workflow_name, line=line_num),
                    confidence_contribution=0.8,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "rule": pattern_name,
                        "line": line.strip(),
                        "remediation": "Use an intermediate env var: env: VAR: ${{ github.event... }} then reference $VAR in run:"
                    }
                ))
        return results

    def _detect_curl_bash(self, workflow_name: str, content: str) -> List[EvidenceItem]:
        """Detect risky curl or wget commands piped directly to a shell interpreter."""
        results = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            if _CURL_BASH_PATTERN.search(line):
                results.append(EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.CICD,
                    evidence_type="CICD-CURL-PIPE-BASH",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Insecure shell execution via pipe ('curl | bash' or 'wget | sh') detected in "
                        f"'{workflow_name}' at line {line_num}. Executing untrusted remote scripts directly "
                        f"bypasses integrity verification and enables supply-chain RCE."
                    ),
                    source_location=SourceLocation(file=workflow_name, line=line_num),
                    confidence_contribution=0.85,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "rule": "CICD-CURL-PIPE-BASH",
                        "line": line.strip(),
                        "remediation": "Download script, verify SHA-256 checksum, then execute locally."
                    }
                ))
        return results

    def _detect_unpinned_images(self, workflow_name: str, content: str) -> List[EvidenceItem]:
        """Detect mutable container image tags (e.g., :latest, :main) in CI workflows/GitLab CI."""
        results = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            match = _UNPINNED_IMAGE_PATTERN.search(line)
            if match:
                img_name = match.group(1)
                tag = match.group(2)
                results.append(EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.CICD,
                    evidence_type="CICD-UNPINNED-IMAGE",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Unpinned container image '{img_name}:{tag}' in '{workflow_name}' at line {line_num}. "
                        f"Mutable image tags can be replaced in registries without verification. "
                        f"Pin image to an immutable digest (e.g., image@sha256:...)."
                    ),
                    source_location=SourceLocation(file=workflow_name, line=line_num),
                    confidence_contribution=0.65,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "image": img_name,
                        "tag": tag,
                        "rule": "CICD-UNPINNED-IMAGE",
                        "remediation": f"Pin container image to sha256 digest: {img_name}@sha256:<digest>"
                    }
                ))
        return results

    def _detect_excessive_permissions(self, workflow_name: str, content: str) -> List[EvidenceItem]:
        """Detect write-all permissions and hardcoded high-entropy secrets."""
        results = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            if _WRITE_ALL_PATTERN.search(line):
                results.append(EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.CICD,
                    evidence_type="CICD-EXCESSIVE-PERMISSIONS",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Workflow '{workflow_name}' uses 'permissions: write-all' at line {line_num}. "
                        f"This grants the workflow token write access to all repository resources. "
                        f"Use least-privilege specific permission grants instead."
                    ),
                    source_location=SourceLocation(file=workflow_name, line=line_num),
                    confidence_contribution=0.6,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "rule": "CICD-EXCESSIVE-PERMISSIONS",
                        "remediation": "Replace write-all with explicit per-resource permissions (e.g., contents: read)"
                    }
                ))
            secret_match = _HIGH_ENTROPY_PATTERN.search(line)
            if secret_match:
                secret_preview = secret_match.group(1)[:6] + "***"
                results.append(EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.CICD,
                    evidence_type="CICD-EXCESSIVE-PERMISSIONS",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Potential hardcoded secret detected in '{workflow_name}' at line {line_num} "
                        f"(preview: {secret_preview}). Hardcoded secrets in workflows are exposed in "
                        f"repository history and build logs."
                    ),
                    source_location=SourceLocation(file=workflow_name, line=line_num),
                    confidence_contribution=0.75,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "rule": "CICD-HARDCODED-SECRET",
                        "remediation": "Use GitHub Actions Secrets (${{ secrets.MY_SECRET }}) instead of hardcoding values."
                    }
                ))
        return results

    def create_finding_from_evidence(
        self,
        evidence_items: List[EvidenceItem],
        scan_id: str,
        workflow_name: str
    ) -> Optional[FindingModel]:
        """
        Convert a list of CI/CD evidence items into a single FindingModel.
        Returns None if no evidence.
        """
        if not evidence_items:
            return None

        severity = Severity.MEDIUM
        for e in evidence_items:
            if e.evidence_type == "CICD-SCRIPT-INJECTION":
                severity = Severity.HIGH
                break

        confidence = compute_confidence([
            ConfidenceFactor(
                evidence_type=e.evidence_type,
                source="cicd",
                raw_weight=e.confidence_contribution,
                reliability=0.85
            ) for e in evidence_items
        ])

        return FindingModel(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            entity_type="Pipeline",
            finding_type=FindingType.CICD_RISK,
            severity=severity,
            title=f"CI/CD Risk: {len(evidence_items)} issue(s) in {workflow_name}",
            description=f"Security issues detected in GitHub Actions workflow '{workflow_name}': " +
                        "; ".join(set(e.evidence_type for e in evidence_items)),
            confidence=confidence,
            impact=compute_blast_radius(package_count=0, service_count=1, api_count=0, production_deployment_count=1),
            evidence=evidence_items,
            recommendations=[]
        )
