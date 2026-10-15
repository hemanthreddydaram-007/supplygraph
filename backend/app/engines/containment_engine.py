# SupplyGraph - Context-Aware Containment Engine v3.0
# Generates actionable, context-aware remediation recommendations across all threat types.
from app.models.core import FindingModel, ContainmentRecommendation, ContainmentActionType, FindingType
from typing import List, Optional
import uuid

class ContainmentEngine:
    def generate_recommendations(self, finding: FindingModel, fixed_version: Optional[str] = None) -> List[ContainmentRecommendation]:
        recommendations = []
        
        # 1. Vulnerable dependency -> Pin or upgrade to safe version
        if finding.finding_type == FindingType.VULNERABLE:
            resolved_fixed = fixed_version
            if not resolved_fixed:
                for ev in finding.evidence:
                    if ev.raw_data and ev.raw_data.get("fixed_version"):
                        resolved_fixed = ev.raw_data.get("fixed_version")
                        break
            
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
                    description=f"Upgrade or pin {finding.origin_candidate or 'package'} to safe version {resolved_fixed}.",
                    why="To mitigate known vulnerabilities by upgrading to a patched release.",
                    expected_effect="Eliminates the vulnerability and closes known attack paths.",
                    priority="high",
                    fixed_version=resolved_fixed
                )
            )
            
        # 2. Typosquatting -> Remove package immediately
        elif finding.finding_type == FindingType.TYPOSQUATTING:
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.REMOVE_DEPENDENCY,
                    title=f"Remove Typosquatted Package {finding.origin_candidate or ''}".strip(),
                    description=f"Immediately uninstall and remove {finding.origin_candidate or 'package'} from lockfiles and requirements.",
                    why="High-confidence typosquatting attack detected impersonating a legitimate package.",
                    expected_effect="Eliminates untrusted rogue code from the dependency graph.",
                    priority="critical"
                )
            )
            
        # 3. Dependency Confusion -> Enforce registry scoping
        elif finding.finding_type == FindingType.DEPENDENCY_CONFUSION:
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.RESTRICT_REGISTRY,
                    title=f"Restrict Registry Scope for {finding.origin_candidate or 'Internal Package'}",
                    description=f"Configure strict registry scoping in .npmrc or pip.conf to restrict {finding.origin_candidate or 'internal package'} to private registries.",
                    why="Prevent public package registry namespace squatting and substitution attacks.",
                    expected_effect="Ensures package manager fetches internal dependencies exclusively from authorized registries.",
                    priority="critical"
                )
            )

        # 4. CI/CD Risk -> Least-privilege permissions and pinned action SHAs
        elif finding.finding_type == FindingType.CICD_RISK:
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.AUDIT_WORKFLOW,
                    title="Harden CI/CD Workflow & Pin Action SHAs",
                    description="Audit GitHub Actions workflows to enforce least-privilege permissions and pin actions to immutable 40-character commit SHAs.",
                    why="Unpinned tags or blanket write permissions allow malicious upstream modifications to compromise the pipeline.",
                    expected_effect="Guarantees reproducible, immutable builds immune to tag hijacking.",
                    priority="high"
                )
            )

        # 5. Suspicious / Obfuscation / Dormant Logic -> Isolate and audit
        elif finding.finding_type in (FindingType.SUSPICIOUS, FindingType.OBFUSCATION, FindingType.DORMANT_LOGIC):
            recommendations.append(
                ContainmentRecommendation(
                    action_type=ContainmentActionType.ISOLATE_SERVICE,
                    title="Isolate Component & Audit Code Patterns",
                    description=f"Quarantine {finding.origin_candidate or 'component'} and inspect flagged AST patterns (eval, dynamic subprocess, secrets).",
                    why="Static analysis identified high-risk capabilities or obfuscated execution paths.",
                    expected_effect="Prevents potential backdoor execution or sensitive credential leakage.",
                    priority="high"
                )
            )
            
        return recommendations
