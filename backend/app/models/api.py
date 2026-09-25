# SupplyGraph API Models - v1.0
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any
from uuid import UUID
from datetime import datetime
from .core import ScanStatus, Severity, FindingType


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class APIError(BaseModel):
    api_version: str = "v1"
    error: ErrorDetail
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    status: str
    version: str = "1.0.0"
    database: str = "unknown"
    osv_api: str = "unknown"
    github_api: str = "unknown"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    repository_url: str
    status: ScanStatus
    scan_type: str
    total_findings: int
    total_vulnerabilities: int
    blast_radius_score: float
    max_confidence: float
    started_at: datetime
    completed_at: Optional[datetime] = None


class ScanListResponse(BaseModel):
    api_version: str = "v1"
    scans: List[ScanListItem]
    total: int
    page: int = 1
    page_size: int = 20


class FindingListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    scan_id: UUID
    entity_type: str
    finding_type: FindingType
    severity: Severity
    confidence_percent: float
    title: str
    origin_candidate: Optional[str] = None
    affected_asset_count: int = 0
    status: str = "open"
    created_at: datetime


class FindingListResponse(BaseModel):
    api_version: str = "v1"
    findings: List[FindingListItem]
    total: int
    filters_applied: dict = Field(default_factory=dict)


class ProjectCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    github_url: str


class ProjectResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str] = None
    github_url: str
    created_at: datetime
