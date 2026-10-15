from app.models.core import FindingModel, ContainmentRecommendation, ContainmentActionType, FindingType
from typing import List, Optional
import uuid

class ContainmentEngine:
    def generate_recommendations(self, finding: FindingModel, fixed_version: Optional[str] = None) -> List[ContainmentRecommendation]:
        recommendations = []
        
        # Check for Vulnerable
        if finding.finding_type == FindingType.VULNERABLE:
            # Check if fixed_version is provided, or extract from evidence
            resolved_fixed = fixed_version
            if not resolved_fixed:
                for ev in finding.evidence:
                    if ev.raw_data and ev.raw_data.get("fixed_version"):
                        resolved_fixed = ev.raw_data.get("fixed_version")
                        break
            
            # If still None, check if origin_candidate has version to compute next major
            if not resolved_fixed:
                origin = finding.origin_candidate or ""
                if "@" in origin:
                    cur_ver = origin.split("@")[-1]
                    import re
                    match = re.match(r"^(\d+)", cur_ver)
                    if match:
                        next_major = int(match.group(1)) + 1
                        resolved_fixed = f">={next_major}.0.0"
            
            resolved_fixed = resolved_fixed or "latest"
            
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.PIN_VERSION,
                    title="Pin or Upgrade Dependency",
                    description=f"Upgrade or pin {finding.origin_candidate} to safe version {resolved_fixed}.",
                    why="To mitigate known vulnerabilities by upgrading to a patched release.",
                    expected_effect="Eliminates the vulnerability.",
                    priority="high",
                    fixed_version=resolved_fixed
                )
            )
            
        # Check for Typosquatting or Dependency Confusion
        if finding.finding_type in (FindingType.TYPOSQUATTING, FindingType.DEPENDENCY_CONFUSION):
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.REMOVE_DEPENDENCY,
                    title="Remove Malicious Dependency",
                    description=f"Remove the malicious dependency {finding.origin_candidate} immediately.",
                    why="High confidence malicious component detected.",
                    expected_effect="Prevents execution of malicious code.",
                    priority="critical"
                )
            )
            
        return recommendations
