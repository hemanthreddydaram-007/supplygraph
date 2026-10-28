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
  is_dev?: boolean;
  declared_in?: string;
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
  historic_attack_count?: number;
  historic_attacks_detected?: string[];
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
  category: "Security Vulnerability" | "Bug / Logic Error" | "Code Quality / Best Practice" | "CI/CD Security Hardening";
  title: string;
  error_explanation: string;
  buggy_code: string;
  corrected_code: string;
  unified_diff?: string;
}

export interface FirstPartyGHSA {
  ghsa_id: string;
  cve_id?: string;
  title: string;
  summary?: string;
  severity: string;
  html_url?: string;
}

export interface DependabotBenchmark {
  dependabot_configured: boolean;
  has_dependabot_config?: boolean;
  dependabot_file_path?: string | null;
  open_dependabot_prs: number;
  first_party_ghsas_count: number;
  first_party_ghsas: FirstPartyGHSA[];
  supplygraph_advantage_summary: string;
  supplygraph_advantage?: string;
  additional_findings_caught: number;
  github_dependency_graph_enabled?: boolean;
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
  demo_label?: string;
  gemini_explanation?: string;
  gemini_available?: boolean;
  detector_breakdown?: DetectorBreakdown;
  code_reviews?: CodeReviewItem[];
  dependabot_benchmark?: DependabotBenchmark;
}

export interface SandboxExecutionRequest {
  files?: { path: string; content: string }[];
  target_file?: string;
  mode?: "auto" | "detonate" | "test" | "inspect_manifest" | "extract_strings";
  timeout_seconds?: number;
  archive_base64?: string;
  archive_filename?: string;
}

export interface SandboxExecutionResponse {
  api_version: string;
  execution_id: string;
  status: "success" | "warning" | "error" | "violation";
  isolation_mode: "docker" | "restricted_subprocess" | "static_safe";
  target_type: string;
  exit_code: number;
  duration_seconds: number;
  logs: string;
  security_violations: string[];
  extracted_strings: string[];
  manifest_summary?: Record<string, any>;
  test_results?: Record<string, any>;
  detonation_alerts: string[];
  timestamp?: string;
}

export interface ScanHistoryRecord {
  id: string;
  timestamp: string;
  target: string;
  total_components: number;
  total_findings: number;
  blast_radius_score: number;
  data: AnalysisResponse;
}


