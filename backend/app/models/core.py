# SupplyGraph Core Pydantic v2 Models
# Version: 1.0.0
# HackFusion 2026 - Theme 6

from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing import Optional, List, Dict, Any, Literal, Union
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum
import re


# ============================================================
# ENUMERATIONS
# ============================================================

class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    GOLANG = "golang"
    CARGO = "cargo"
    NUGET = "nuget"
    GITHUB_ACTIONS = "github-actions"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class FindingType(str, Enum):
    VULNERABLE = "VULNERABLE"
    SUSPICIOUS = "SUSPICIOUS"
    TYPOSQUATTING = "TYPOSQUATTING"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    COMPROMISED_UPDATE = "COMPROMISED_UPDATE"
    OBFUSCATION = "OBFUSCATION"
    DORMANT_LOGIC = "DORMANT_LOGIC"
    CICD_RISK = "CICD_RISK"
    METADATA_ANOMALY = "METADATA_ANOMALY"


class EvidenceClassification(str, Enum):
    FACT = "FACT"
    HEURISTIC = "HEURISTIC"
    SIMULATED = "SIMULATED"
    INFERENCE = "INFERENCE"
    UNKNOWN = "UNKNOWN"


class EvidenceSource(str, Enum):
    OSV = "osv"
    GITHUB = "github"
    AST = "ast"
    METADATA = "metadata"
    CICD = "cicd"
    RUNTIME = "runtime"
    LOCKFILE = "lockfile"
    SBOM = "sbom"
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"


class NodeType(str, Enum):
    REPOSITORY = "Repository"
    PACKAGE = "Package"
    VERSION = "Version"
    VULNERABILITY = "Vulnerability"
    COMMIT = "Commit"
    MAINTAINER = "Maintainer"
    SERVICE = "Service"
    CONTAINER = "Container"
    API = "API"
    DEPLOYMENT = "Deployment"
    PIPELINE = "Pipeline"
    BEHAVIOUR = "Behaviour"
    RUNTIME_OBSERVATION = "RuntimeObservation"
    FINDING = "Finding"
    ASSET = "Asset"


class EdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    DEPENDS_ON = "DEPENDS_ON"
    VERSION_OF = "VERSION_OF"
    MODIFIED_BY = "MODIFIED_BY"
    RELEASED_BY = "RELEASED_BY"
    BUILT_BY = "BUILT_BY"
    DEPLOYED_AS = "DEPLOYED_AS"
    USES = "USES"
    CALLS = "CALLS"
    TRIGGERS = "TRIGGERS"
    EXHIBITS = "EXHIBITS"
    AFFECTS = "AFFECTS"
    PROPAGATES_TO = "PROPAGATES_TO"
    OBSERVED_IN = "OBSERVED_IN"


class AssetType(str, Enum):
    SERVICE = "service"
    CONTAINER = "container"
    API = "api"
    DEPLOYMENT = "deployment"
    PIPELINE = "pipeline"
    REPOSITORY = "repository"


class ContainmentActionType(str, Enum):
    PIN_VERSION = "PIN_VERSION"
    ROLLBACK = "ROLLBACK"
    REPLACE_DEPENDENCY = "REPLACE_DEPENDENCY"
    REMOVE_DEPENDENCY = "REMOVE_DEPENDENCY"
    ISOLATE_SERVICE = "ISOLATE_SERVICE"
    PIPELINE_CONTROL = "PIPELINE_CONTROL"
    RESTRICT_REGISTRY = "RESTRICT_REGISTRY"
    REBUILD = "REBUILD"
    REANALYZE = "REANALYZE"
    ROTATE_CREDENTIALS = "ROTATE_CREDENTIALS"
    AUDIT_WORKFLOW = "AUDIT_WORKFLOW"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


# ============================================================
# PURL NORMALIZATION
# ============================================================

class PURL(BaseModel):
    """Package URL (PURL) following the PURL specification."""
    model_config = ConfigDict(frozen=True)

    ecosystem: Ecosystem
    name: str
    version: Optional[str] = None
    namespace: Optional[str] = None
    qualifiers: Optional[str] = None
    subpath: Optional[str] = None

    @property
    def canonical(self) -> str:
        """Return the canonical PURL string."""
        base = f"pkg:{self.ecosystem.value}/"
        if self.namespace:
            base += f"{self.namespace}/"
        base += self.name
        if self.version:
            base += f"@{self.version}"
        return base

    @classmethod
    def from_string(cls, purl_str: str) -> "PURL":
        """Parse a PURL string into a PURL object."""
        pattern = r"pkg:(?P<ecosystem>[^/]+)/(?:(?P<namespace>[^/]+)/)?(?P<name>[^@]+)(?:@(?P<version>[^?#]+))?"
        match = re.match(pattern, purl_str)
        if not match:
            raise ValueError(f"Invalid PURL: {purl_str}")
        eco = match.group("ecosystem")
        try:
            ecosystem = Ecosystem(eco)
        except ValueError:
            ecosystem = Ecosystem.UNKNOWN
        return cls(
            ecosystem=ecosystem,
            name=match.group("name"),
            version=match.group("version"),
            namespace=match.group("namespace"),
        )


# ============================================================
# REPOSITORY MODELS
# ============================================================

class RepositoryModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    github_url: str
    owner: str
    name: str
    default_branch: str = "main"
    description: Optional[str] = None
    stars: int = 0
    forks: int = 0
    is_private: bool = False
    language: Optional[str] = None
    topics: List[str] = Field(default_factory=list)
    last_commit_sha: Optional[str] = None
    last_commit_at: Optional[datetime] = None
    size_kb: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator('github_url')
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        if not v.startswith('https://github.com/'):
            raise ValueError(f"Not a valid GitHub URL: {v}")
        return v.rstrip('/')


# ============================================================
# COMPONENT MODELS
# ============================================================

class ComponentModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    name: str
    ecosystem: Ecosystem
    purl: str  # canonical PURL without version
    normalized_name: str
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    license: Optional[str] = None


class ComponentVersionModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    component_id: UUID
    version_string: str
    purl: str  # canonical PURL with version
    bom_ref: Optional[str] = None
    release_date: Optional[datetime] = None
    is_suspicious: bool = False
    is_latest: bool = False
    published_by: Optional[str] = None
    checksum_sha256: Optional[str] = None


# ============================================================
# SBOM MODELS
# ============================================================

class SBOMComponent(BaseModel):
    """A single component in a CycloneDX SBOM."""
    bom_ref: str
    name: str
    version: Optional[str] = None
    ecosystem: Ecosystem
    purl: str
    description: Optional[str] = None
    licenses: List[str] = Field(default_factory=list)
    hashes: Dict[str, str] = Field(default_factory=dict)
    is_direct: bool = True
    is_transitive: bool = False
    depth: int = 0


class SBOMDependency(BaseModel):
    """A dependency relationship in the SBOM."""
    from_bom_ref: str
    to_bom_ref: str
    is_direct: bool = True


class SBOM(BaseModel):
    """CycloneDX Software Bill of Materials."""
    spec_version: str = "1.5"
    bom_format: str = "CycloneDX"
    serial_number: str = Field(default_factory=lambda: f"urn:uuid:{uuid4()}")
    version: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    components: List[SBOMComponent] = Field(default_factory=list)
    dependencies: List[SBOMDependency] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    lockfile_used: Optional[str] = None
    transitive_resolved: bool = False


# ============================================================
# VULNERABILITY MODELS
# ============================================================

class OSVAffectedRange(BaseModel):
    """An affected version range from OSV."""
    range_type: str  # SEMVER, ECOSYSTEM, GIT
    events: List[Dict[str, str]] = Field(default_factory=list)
    fixed: Optional[str] = None


class VulnerabilityModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    osv_id: str
    aliases: List[str] = Field(default_factory=list)
    summary: str
    details: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_ids: List[str] = Field(default_factory=list)
    affected_ecosystems: List[str] = Field(default_factory=list)
    fixed_versions: Dict[str, Any] = Field(default_factory=dict)
    references: List[Dict[str, str]] = Field(default_factory=list)
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    osv_modified: Optional[str] = None
    fetched_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# EVIDENCE MODELS
# ============================================================

class SourceLocation(BaseModel):
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    function: Optional[str] = None


class EvidenceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    source: EvidenceSource
    evidence_type: str
    classification: EvidenceClassification
    description: str
    source_location: Optional[SourceLocation] = None
    confidence_contribution: float = Field(default=0.0, ge=0.0, le=1.0)
    is_simulated: bool = False
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# FINDING MODELS
# ============================================================

class ImpactModel(BaseModel):
    """Heuristic blast-radius impact model."""
    package_count: int = 0
    service_count: int = 0
    api_count: int = 0
    production_deployment_count: int = 0
    blast_radius_score: float = 0.0
    affected_asset_ids: List[str] = Field(default_factory=list)

    # Weights (configurable)
    package_weight: float = 2.0
    service_weight: float = 15.0
    api_weight: float = 25.0
    deployment_weight: float = 50.0

    @model_validator(mode='after')
    def compute_blast_radius(self) -> 'ImpactModel':
        self.blast_radius_score = (
            self.package_count * self.package_weight +
            self.service_count * self.service_weight +
            self.api_count * self.api_weight +
            self.production_deployment_count * self.deployment_weight
        )
        return self

    model_config = ConfigDict(from_attributes=True)


class ConfidenceModel(BaseModel):
    """Heuristic confidence score. NOT a probability of compromise."""
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    score_percent: float = 0.0
    evidence_count: int = 0
    simulated_evidence_count: int = 0
    synthetic_discount_applied: float = 0.15
    contributing_factors: List[Dict[str, Any]] = Field(default_factory=list)
    label: str = "Heuristic Confidence Score"
    disclaimer: str = "This is a heuristic score and NOT a probability of compromise."

    @model_validator(mode='after')
    def compute_percent(self) -> 'ConfidenceModel':
        self.score_percent = round(self.score * 100, 1)
        return self

    model_config = ConfigDict(from_attributes=True)


class PropagationStep(BaseModel):
    node_id: str
    node_type: NodeType
    label: str
    edge_type: EdgeType
    evidence: List[str] = Field(default_factory=list)


class ContainmentRecommendation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    action_type: ContainmentActionType
    title: str
    description: str
    why: str
    expected_effect: str
    priority: Literal["critical", "high", "medium", "low"] = "medium"
    triggering_evidence_description: Optional[str] = None


class FindingModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    entity_id: Optional[UUID] = None
    entity_type: str
    finding_type: FindingType
    severity: Severity
    confidence: ConfidenceModel
    title: str
    description: str
    origin_candidate: Optional[str] = None
    propagation_path: List[PropagationStep] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    impact: ImpactModel
    evidence: List[EvidenceItem] = Field(default_factory=list)
    recommendations: List[ContainmentRecommendation] = Field(default_factory=list)
    status: str = "open"
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# GRAPH MODELS
# ============================================================

class GraphPosition(BaseModel):
    x: float
    y: float


class GraphNodeData(BaseModel):
    label: str
    node_type: NodeType
    entity_id: Optional[str] = None
    is_suspicious: bool = False
    is_origin_candidate: bool = False
    is_affected: bool = False
    severity: Optional[Severity] = None
    purl: Optional[str] = None
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    confidence: Optional[float] = None
    finding_count: int = 0
    vulnerability_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphNode(BaseModel):
    id: str
    type: str  # React Flow node type
    position: GraphPosition
    data: GraphNodeData
    is_collapsed: bool = False


class GraphEdgeData(BaseModel):
    edge_type: EdgeType
    label: Optional[str] = None
    is_attack_path: bool = False
    is_direct: bool = True
    depth: Optional[int] = None
    evidence: List[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str = "default"
    animated: bool = False
    data: GraphEdgeData


class SecurityGraph(BaseModel):
    """The complete security graph for a scan."""
    scan_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    layout_version: str = "v1.0"
    node_count: int = 0
    edge_count: int = 0
    has_cycles: bool = False
    suspicious_node_count: int = 0
    attack_path_count: int = 0

    @model_validator(mode='after')
    def compute_counts(self) -> 'SecurityGraph':
        self.node_count = len(self.nodes)
        self.edge_count = len(self.edges)
        self.suspicious_node_count = sum(1 for n in self.nodes if n.data.is_suspicious)
        return self


# ============================================================
# ATTACK PATH MODELS
# ============================================================

class AttackPath(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    finding_id: Optional[UUID] = None
    origin_node_id: str
    target_node_id: str
    path_nodes: List[str]  # ordered list of node IDs
    path_edges: List[str]  # ordered list of edge IDs
    path_length: int
    confidence: ConfidenceModel
    is_direct: bool = False
    is_transitive: bool = False
    blast_radius: ImpactModel
    affected_asset_count: int = 0
    explanation: Optional[str] = None
    label: str = "Potential Attack Path"


# ============================================================
# ASSET MODELS
# ============================================================

class AssetModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    name: str
    asset_type: AssetType
    criticality: Literal["critical", "high", "medium", "low"] = "medium"
    environment: Optional[str] = None
    is_production: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
    connected_components: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)


# ============================================================
# SCAN MODELS
# ============================================================

class ScanMetadata(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_url: str
    status: ScanStatus
    scan_type: str = "full"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    commit_sha: Optional[str] = None
    lockfile_detected: bool = False
    lockfile_types: List[str] = Field(default_factory=list)
    sbom_generated: bool = False
    osv_queried: bool = False
    analysis_version: str = "v1.0"
    total_components: int = 0
    total_direct_dependencies: int = 0
    total_transitive_dependencies: int = 0
    total_vulnerabilities: int = 0
    total_findings: int = 0
    total_attack_paths: int = 0
    blast_radius_score: float = 0.0
    max_confidence: float = 0.0
    warnings: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    partial_analysis: bool = False


class AnalysisRequest(BaseModel):
    """Request to analyze a GitHub repository."""
    github_url: str
    branch: Optional[str] = None
    include_transitive: bool = True
    enable_ast_analysis: bool = True
    enable_cicd_analysis: bool = True
    enable_metadata_analysis: bool = True
    enable_simulated_runtime: bool = False
    enable_gemini_explanation: bool = True
    max_transitive_depth: int = Field(default=10, ge=1, le=20)

    @field_validator('github_url')
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        if not v.startswith('https://github.com/'):
            raise ValueError(f"Must be a public GitHub URL. Got: {v}")
        return v.rstrip('/')


class DemoRequest(BaseModel):
    """Request to load a deterministic demo scenario."""
    scenario_id: Literal["A", "B", "C", "D", "E"]
    include_gemini_explanation: bool = True


class AnalysisResponse(BaseModel):
    """Complete analysis response including graph, findings, paths."""
    api_version: str = "v1"
    scan: ScanMetadata
    sbom: Optional[SBOM] = None
    components: List[SBOMComponent] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityModel] = Field(default_factory=list)
    findings: List[FindingModel] = Field(default_factory=list)
    graph: SecurityGraph
    attack_paths: List[AttackPath] = Field(default_factory=list)
    assets: List[AssetModel] = Field(default_factory=list)
    gemini_explanation: Optional[str] = None
    gemini_available: bool = False
    is_demo: bool = False
    demo_label: Optional[str] = None
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================
# COMPARISON MODELS
# ============================================================

class DependencyChange(BaseModel):
    change_type: Literal["added", "removed", "version_changed"]
    package_name: str
    ecosystem: str
    version_before: Optional[str] = None
    version_after: Optional[str] = None
    purl_before: Optional[str] = None
    purl_after: Optional[str] = None


class FindingChange(BaseModel):
    change_type: Literal["new", "resolved", "confidence_changed"]
    finding_id: str
    finding_type: FindingType
    severity: Severity
    entity_name: str
    confidence_before: Optional[float] = None
    confidence_after: Optional[float] = None


class ScanComparison(BaseModel):
    scan_a_id: str
    scan_b_id: str
    scan_a_timestamp: datetime
    scan_b_timestamp: datetime
    dependency_changes: List[DependencyChange] = Field(default_factory=list)
    vulnerability_changes: List[FindingChange] = Field(default_factory=list)
    finding_changes: List[FindingChange] = Field(default_factory=list)
    blast_radius_delta: float = 0.0
    confidence_delta: float = 0.0
    attack_path_changes: List[str] = Field(default_factory=list)
    summary: str = ""
