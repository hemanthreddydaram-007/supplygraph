from app.models.core import FindingModel, ContainmentRecommendation, ContainmentActionType, FindingType
from typing import List
import uuid

class ContainmentEngine:
    def generate_recommendations(self, finding: FindingModel) -> List[ContainmentRecommendation]:
        recommendations = []
        
        # Check for Vulnerable
        if finding.finding_type == FindingType.VULNERABLE:
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.PIN_VERSION,
                    title="Pin or Upgrade Dependency",
                    description=f"Upgrade or pin the version of the vulnerable dependency {finding.origin_candidate}.",
                    why="To mitigate known vulnerabilities.",
                    expected_effect="Eliminates the vulnerability.",
                    priority="high"
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
