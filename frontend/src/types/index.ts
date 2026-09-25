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
  type: string; // The React Flow custom node type (e.g. repositoryNode)
  position: GraphPosition;
  data: GraphNodeData;
}

export interface GraphEdgeData {
  edge_type: string;
  is_direct?: boolean;
  depth?: number;
  is_attack_path?: boolean;
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

export interface AnalysisResponse {
  api_version: string;
  scan: any;
  graph: SecurityGraph;
  findings: any[];
  vulnerabilities: any[];
  attack_paths: any[];
  assets: any[];
  is_demo?: boolean;
  gemini_explanation?: string;
}
