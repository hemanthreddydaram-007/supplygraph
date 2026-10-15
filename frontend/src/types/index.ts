export interface GraphPosition {
  x: number;
  y: number;
}

export interface GraphNodeData {
  label: string;
  node_type: string;
  is_suspicious?: boolean;
  is_origin_candidate?: boolean;
  is_affected?: boolean;
  severity?: string;
  finding_count?: number;
  vulnerability_count?: number;
  purl?: string;
  [key: string]: any;
}

export interface GraphNode {
  id: string;
  type: string;
  position: GraphPosition;
  data: GraphNodeData;
}

export interface GraphEdgeData {
  edge_type: string;
  is_direct?: boolean;
  depth?: number;
  is_attack_path?: boolean;
  label?: string;
  [key: string]: any;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  animated?: boolean;
  data: GraphEdgeData;
}

export interface SecurityGraph {
  scan_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  layout_version: string;
  node_count: number;
  edge_count: number;
  has_cycles: boolean;
}

export interface SBOMComponent {
  bom_ref: string;
  name: string;
  version?: string;
  ecosystem: string;
  purl: string;
  is_direct?: boolean;
  is_transitive?: boolean;
}

export interface SBOM {
  spec_version: string;
  bom_format: string;
  components: SBOMComponent[];
  metadata?: Record<string, any>;
  generated_at?: string;
}

export interface PolygonAttestation {
  network: string;
  contract_address: string;
  repository: string;
  sbom_sha256: string;
  merkle_root: string;
  blast_radius_score: number;
  payload_hash: string;
  attestation_timestamp: string;
  status: string;
  verification_note: string;
  solidity_verification: string;
}

export interface DetectorBreakdown {
  osv_count: number;
  typosquat_count: number;
  ast_count: number;
  cicd_count: number;
  confusion_count: number;
  sbom_sha256?: string;
  merkle_root?: string;
  polygon_attestation?: PolygonAttestation;
  model_provider?: string;
}

export interface CodeReviewItem {
  id: string;
  file_path: string;
  line_number: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: "Security Vulnerability" | "Bug / Logic Error" | "Code Quality / Best Practice";
  title: string;
  error_explanation: string;
  buggy_code: string;
  corrected_code: string;
}

export interface AnalysisResponse {
  api_version: string;
  scan: any;
  graph: SecurityGraph;
  findings: any[];
  vulnerabilities: any[];
  attack_paths: any[];
  assets: any[];
  sbom?: SBOM;
  components?: SBOMComponent[];
  is_demo?: boolean;
  gemini_explanation?: string;
  gemini_available?: boolean;
  detector_breakdown?: DetectorBreakdown;
  code_reviews?: CodeReviewItem[];
}
