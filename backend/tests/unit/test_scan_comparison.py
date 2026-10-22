# SupplyGraph - Scan Comparison Unit Test
import pytest
from app.models.core import (
    AnalysisResponse, ScanMetadata, ScanStatus, SecurityGraph,
    SBOMComponent, FindingModel, FindingType, Severity,
    ConfidenceModel, ImpactModel
)
from app.api.endpoints import compare_scans, CompareRequest


def test_compare_scans_delta():
    scan_a = AnalysisResponse(
        api_version="v1",
        scan=ScanMetadata(
            id="11111111-1111-1111-1111-111111111111",
            repository_url="https://github.com/test/repo",
            status=ScanStatus.COMPLETED,
            blast_radius_score=40.0
        ),
        components=[
            SBOMComponent(bom_ref="pkg:npm/lodash@4.17.20", name="lodash", version="4.17.20", ecosystem="npm", purl="pkg:npm/lodash@4.17.20"),
            SBOMComponent(bom_ref="pkg:npm/old-lib@1.0.0", name="old-lib", version="1.0.0", ecosystem="npm", purl="pkg:npm/old-lib@1.0.0"),
        ],
        findings=[
            FindingModel(
                scan_id="11111111-1111-1111-1111-111111111111",
                entity_type="Package",
                finding_type=FindingType.VULNERABLE,
                severity=Severity.HIGH,
                confidence=ConfidenceModel(score=0.8),
                title="Prototype Pollution in old-lib",
                description="test vuln",
                impact=ImpactModel()
            )
        ],
        graph=SecurityGraph(scan_id="11111111-1111-1111-1111-111111111111", nodes=[], edges=[])
    )

    scan_b = AnalysisResponse(
        api_version="v1",
        scan=ScanMetadata(
            id="22222222-2222-2222-2222-222222222222",
            repository_url="https://github.com/test/repo",
            status=ScanStatus.COMPLETED,
            blast_radius_score=15.0
        ),
        components=[
            SBOMComponent(bom_ref="pkg:npm/lodash@4.17.20", name="lodash", version="4.17.20", ecosystem="npm", purl="pkg:npm/lodash@4.17.20"),
            SBOMComponent(bom_ref="pkg:npm/axios@1.6.0", name="axios", version="1.6.0", ecosystem="npm", purl="pkg:npm/axios@1.6.0"),
        ],
        findings=[],
        graph=SecurityGraph(scan_id="22222222-2222-2222-2222-222222222222", nodes=[], edges=[])
    )

    comp = compare_scans(CompareRequest(scan_a=scan_a, scan_b=scan_b))
    assert comp.blast_radius_delta == -25.0
    assert any(dc.change_type == "added" and dc.package_name == "axios" for dc in comp.dependency_changes)
    assert any(dc.change_type == "removed" and dc.package_name == "old-lib" for dc in comp.dependency_changes)
    assert any(fc.change_type == "resolved" for fc in comp.finding_changes)
