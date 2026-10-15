# SupplyGraph - Dependency Confusion Detector
# Detects potential dependency confusion / namespace collision attacks
from app.models.core import (
    EvidenceItem, EvidenceClassification, EvidenceSource,
    FindingModel, FindingType, Severity, SBOMComponent
)
from app.engines.confidence import compute_confidence, ConfidenceFactor, compute_blast_radius
import re
import uuid
import datetime
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

# Internal/private naming patterns that suggest a package is meant to be internal
_INTERNAL_PATTERNS = [
    re.compile(r'^@(?:internal|corp|private|company|org)/', re.IGNORECASE),
    re.compile(r'[-_](?:internal|private|corp|auth|common|shared|utils|core)$', re.IGNORECASE),
    re.compile(r'^(?:internal|private|corp)-', re.IGNORECASE),
]

# Scoped packages that look like internal tooling namespaces
_SUSPICIOUS_SCOPES = {
    "@internal", "@corp", "@private", "@company",
    "@myapp", "@myorg", "@enterprise", "@local",
}


class DependencyConfusionDetector:
    """
    Detects dependency confusion risk in a list of SBOM components.

    Dependency confusion attacks occur when an internal package name is also
    registered publicly on npm/PyPI, causing package managers to fetch the
    public (potentially malicious) version instead of the internal one.
    """

    def detect(self, components: List[SBOMComponent]) -> List[EvidenceItem]:
        """
        Analyze a list of SBOM components for dependency confusion indicators.

        Args:
            components: List of parsed SBOMComponent objects

        Returns:
            List of EvidenceItem findings
        """
        evidence_list: List[EvidenceItem] = []

        try:
            for comp in components:
                evidence = self._check_component(comp)
                if evidence:
                    evidence_list.append(evidence)
        except Exception as e:
            logger.warning(f"DependencyConfusionDetector error: {e}")

        return evidence_list

    def _check_component(self, comp: SBOMComponent) -> Optional[EvidenceItem]:
        """Check a single component for confusion indicators."""
        name = comp.name or ""
        purl = comp.purl or ""

        # Check for scoped npm packages with internal-looking scopes
        if name.startswith("@"):
            scope = name.split("/")[0].lower() if "/" in name else name.lower()
            if scope in _SUSPICIOUS_SCOPES:
                return EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.DEPENDENCY_CONFUSION,
                    evidence_type="DEPENDENCY-CONFUSION-RISK",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Package '{name}' uses a suspicious internal-looking npm scope '{scope}'. "
                        f"If this is a private internal package, a public package with the same name "
                        f"on npm could be substituted by the package manager (dependency confusion attack). "
                        f"Ensure your .npmrc pins the registry for this scope."
                    ),
                    confidence_contribution=0.65,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "package": name,
                        "purl": purl,
                        "scope": scope,
                        "rule": "DEPENDENCY-CONFUSION-RISK",
                        "remediation": (
                            f'Add to .npmrc: \'{scope}:registry=https://your-private-registry\'. '
                            f'Or for pip: add to pip.conf: [install] index-url = https://your-private-pypi'
                        )
                    }
                )

        # Check for internal naming patterns in non-scoped packages
        for pattern in _INTERNAL_PATTERNS:
            if pattern.search(name):
                return EvidenceItem(
                    id=str(uuid.uuid4()),
                    source=EvidenceSource.DEPENDENCY_CONFUSION,
                    evidence_type="DEPENDENCY-CONFUSION-RISK",
                    classification=EvidenceClassification.HEURISTIC,
                    description=(
                        f"Package '{name}' matches internal naming convention patterns "
                        f"(e.g., '-internal', '-private', '-corp'). "
                        f"If this is not published to the public registry, an attacker could register "
                        f"a malicious package with the same name to execute code during `npm install`."
                    ),
                    confidence_contribution=0.55,
                    is_simulated=False,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw_data={
                        "package": name,
                        "purl": purl,
                        "rule": "DEPENDENCY-CONFUSION-RISK",
                        "remediation": (
                            "Pin the registry scope in .npmrc or use a private registry. "
                            "For Python: use --index-url with your private PyPI in pip.conf."
                        )
                    }
                )

        return None

    def create_finding_from_evidence(
        self,
        evidence_items: List[EvidenceItem],
        scan_id: str,
        package_name: str
    ) -> Optional[FindingModel]:
        """Convert evidence items into a FindingModel."""
        if not evidence_items:
            return None

        confidence = compute_confidence([
            ConfidenceFactor(
                evidence_type=e.evidence_type,
                source="dependency_confusion",
                raw_weight=e.confidence_contribution,
                reliability=0.7
            ) for e in evidence_items
        ])

        return FindingModel(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            entity_type="Package",
            finding_type=FindingType.DEPENDENCY_CONFUSION,
            severity=Severity.HIGH,
            title=f"Dependency Confusion Risk: {package_name}",
            description=(
                f"Package '{package_name}' may be vulnerable to a dependency confusion attack. "
                f"If this is an internal package and a public package with the same name exists, "
                f"your package manager could fetch the malicious public version."
            ),
            origin_candidate=package_name,
            confidence=confidence,
            impact=compute_blast_radius(package_count=1, service_count=1, api_count=0, production_deployment_count=0),
            evidence=evidence_items,
            recommendations=[]
        )
