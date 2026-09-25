# SupplyGraph - Containment Engine
from app.models.core import FindingModel, ContainmentRecommendation, ContainmentActionType, FindingType
from typing import List
import uuid

class ContainmentEngine:
    def generate_recommendations(self, finding: FindingModel) -> List[ContainmentRecommendation]:
        recommendations = []
        
        # Check for Vulnerable
        if finding.type == FindingType.VULNERABLE:
            recommendations.append(
                ContainmentRecommendation(
                    id=str(uuid.uuid4()),
                    action=ContainmentActionType.PIN_VERSION,
                    description=f"Upgrade or pin the version of the vulnerable dependency {finding.component_id}.",
                    target_component=finding.component_id,
                    effort="low",
                    impact="high"
                )
            )
            
        # Check for Typosquatting or Dependency Confusion
        if finding.type in (FindingType.TYPOSQUATTING, FindingType.DEPENDENCY_CONFUSION):
            recommendations.append(
                ContainmentRecommendation(
                    id=str(uuid.uuid4()),
                    action=ContainmentActionType.REMOVE_DEPENDENCY,
                    description=f"Remove the malicious dependency {finding.component_id} immediately.",
                    target_component=finding.component_id,
                    effort="low",
                    impact="critical"
                )
            )
            
        # Check for Blast Radius > 50
        if finding.blast_radius is not None and finding.blast_radius > 50:
            recommendations.append(
                ContainmentRecommendation(
                    id=str(uuid.uuid4()),
                    action=ContainmentActionType.ISOLATE_SERVICE,
                    description=f"Isolate the affected service to prevent lateral movement (Blast Radius: {finding.blast_radius}).",
                    target_component=finding.component_id,
                    effort="high",
                    impact="high"
                )
            )
            
        return recommendations
