-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- SupplyGraph Database Schema v1.0
-- Created for HackFusion 2026 - Theme 6

-- PROJECTS
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    github_url TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- REPOSITORIES
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    github_url TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    description TEXT,
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    is_private BOOLEAN DEFAULT FALSE,
    language TEXT,
    topics TEXT[],
    last_commit_sha TEXT,
    last_commit_at TIMESTAMPTZ,
    size_kb INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- SCANS
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','partial')),
    scan_type TEXT NOT NULL DEFAULT 'full' CHECK (scan_type IN ('full','demo','reanalysis')),
    scenario_id TEXT,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    commit_sha TEXT,
    lockfile_detected BOOLEAN DEFAULT FALSE,
    sbom_generated BOOLEAN DEFAULT FALSE,
    osv_queried BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    analysis_version TEXT DEFAULT 'v1.0',
    total_components INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_attack_paths INTEGER DEFAULT 0,
    blast_radius_score NUMERIC(10,2) DEFAULT 0,
    max_confidence NUMERIC(5,4) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- COMPONENTS (canonical packages)
CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    purl TEXT UNIQUE NOT NULL,
    normalized_name TEXT NOT NULL,
    description TEXT,
    homepage TEXT,
    repository_url TEXT,
    license TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(name, ecosystem)
);

-- COMPONENT VERSIONS
CREATE TABLE component_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    component_id UUID REFERENCES components(id) ON DELETE CASCADE,
    version_string TEXT NOT NULL,
    purl TEXT UNIQUE NOT NULL,
    bom_ref TEXT,
    release_date TIMESTAMPTZ,
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_latest BOOLEAN DEFAULT FALSE,
    published_by TEXT,
    checksum_sha256 TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(component_id, version_string)
);

-- SCAN COMPONENTS (components found in a specific scan)
CREATE TABLE scan_components (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    component_version_id UUID REFERENCES component_versions(id),
    is_direct BOOLEAN DEFAULT TRUE,
    is_transitive BOOLEAN DEFAULT FALSE,
    depth INTEGER DEFAULT 0,
    declared_in TEXT,
    lockfile_source TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- DEPENDENCIES
CREATE TABLE dependencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    from_version_id UUID REFERENCES component_versions(id),
    to_version_id UUID REFERENCES component_versions(id),
    is_direct BOOLEAN DEFAULT FALSE,
    is_transitive BOOLEAN DEFAULT FALSE,
    depth INTEGER DEFAULT 1,
    constraint_spec TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- VULNERABILITIES
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    osv_id TEXT UNIQUE NOT NULL,
    aliases TEXT[],
    summary TEXT,
    details TEXT,
    severity TEXT CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
    cvss_score NUMERIC(4,2),
    cvss_vector TEXT,
    cwe_ids TEXT[],
    affected_ecosystems TEXT[],
    fixed_versions JSONB,
    references JSONB,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    osv_modified TEXT,
    fetched_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- COMPONENT VERSION VULNERABILITIES
CREATE TABLE version_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    component_version_id UUID REFERENCES component_versions(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    is_affected BOOLEAN DEFAULT TRUE,
    fixed_in_version TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(component_version_id, vulnerability_id)
);

-- ASSETS
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('service','container','api','deployment','pipeline','repository')),
    criticality TEXT DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
    environment TEXT,
    is_production BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- FINDINGS
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    entity_id UUID,
    entity_type TEXT NOT NULL,
    finding_type TEXT NOT NULL CHECK (finding_type IN (
        'VULNERABLE','SUSPICIOUS','TYPOSQUATTING','DEPENDENCY_CONFUSION',
        'COMPROMISED_UPDATE','OBFUSCATION','DORMANT_LOGIC','CICD_RISK','METADATA_ANOMALY'
    )),
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    confidence NUMERIC(5,4) DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
    title TEXT NOT NULL,
    description TEXT,
    origin_candidate TEXT,
    status TEXT DEFAULT 'open' CHECK (status IN ('open','reviewed','dismissed','resolved')),
    blast_radius_score NUMERIC(10,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- EVIDENCE
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('osv','github','ast','metadata','cicd','runtime','lockfile','sbom','typosquatting','dependency_confusion')),
    evidence_type TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('FACT','HEURISTIC','SIMULATED','INFERENCE','UNKNOWN')),
    description TEXT NOT NULL,
    source_file TEXT,
    source_line INTEGER,
    confidence_contribution NUMERIC(5,4) DEFAULT 0,
    is_simulated BOOLEAN DEFAULT FALSE,
    raw_data JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ATTACK PATHS
CREATE TABLE attack_paths (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id),
    origin_node_id TEXT,
    target_node_id TEXT,
    path_nodes JSONB NOT NULL,
    path_edges JSONB NOT NULL,
    path_length INTEGER NOT NULL,
    confidence NUMERIC(5,4) DEFAULT 0,
    is_direct BOOLEAN DEFAULT FALSE,
    is_transitive BOOLEAN DEFAULT FALSE,
    blast_radius_score NUMERIC(10,2) DEFAULT 0,
    affected_asset_count INTEGER DEFAULT 0,
    explanation TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- GRAPH NODES (stored positions)
CREATE TABLE graph_nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    position_x NUMERIC(10,2) DEFAULT 0,
    position_y NUMERIC(10,2) DEFAULT 0,
    entity_id UUID,
    metadata JSONB,
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_origin_candidate BOOLEAN DEFAULT FALSE,
    is_affected BOOLEAN DEFAULT FALSE,
    severity TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(scan_id, node_id)
);

-- GRAPH EDGES
CREATE TABLE graph_edges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    edge_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    label TEXT,
    is_attack_path BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(scan_id, edge_id)
);

-- RUNTIME OBSERVATIONS
CREATE TABLE runtime_observations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    component_version_id UUID REFERENCES component_versions(id),
    observation_type TEXT NOT NULL CHECK (observation_type IN (
        'OUTBOUND_CONNECTION','FILE_MODIFICATION','SUBPROCESS_CREATION',
        'ENV_ACCESS','SUSPICIOUS_DOMAIN_CONTACT','PROCESS_SPAWN'
    )),
    target TEXT,
    description TEXT,
    is_simulated BOOLEAN DEFAULT TRUE,
    severity TEXT DEFAULT 'MEDIUM',
    metadata JSONB,
    observed_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- CONTAINMENT ACTIONS
CREATE TABLE containment_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK (action_type IN (
        'PIN_VERSION','ROLLBACK','REPLACE_DEPENDENCY','REMOVE_DEPENDENCY',
        'ISOLATE_SERVICE','PIPELINE_CONTROL','RESTRICT_REGISTRY',
        'REBUILD','REANALYZE','ROTATE_CREDENTIALS','AUDIT_WORKFLOW'
    )),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    why TEXT NOT NULL,
    expected_effect TEXT NOT NULL,
    triggering_evidence_id UUID REFERENCES evidence(id),
    priority TEXT DEFAULT 'medium' CHECK (priority IN ('critical','high','medium','low')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- SCAN COMPARISONS
CREATE TABLE scan_comparisons (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_a_id UUID REFERENCES scans(id),
    scan_b_id UUID REFERENCES scans(id),
    new_dependencies JSONB,
    removed_dependencies JSONB,
    version_changes JSONB,
    new_vulnerabilities JSONB,
    resolved_vulnerabilities JSONB,
    new_findings JSONB,
    resolved_findings JSONB,
    blast_radius_delta NUMERIC(10,2),
    confidence_delta NUMERIC(5,4),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- INDEXES
CREATE INDEX idx_scans_repository_id ON scans(repository_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scan_components_scan_id ON scan_components(scan_id);
CREATE INDEX idx_dependencies_scan_id ON dependencies(scan_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_type ON findings(finding_type);
CREATE INDEX idx_evidence_finding_id ON evidence(finding_id);
CREATE INDEX idx_attack_paths_scan_id ON attack_paths(scan_id);
CREATE INDEX idx_graph_nodes_scan_id ON graph_nodes(scan_id);
CREATE INDEX idx_graph_edges_scan_id ON graph_edges(scan_id);
CREATE INDEX idx_components_purl ON components(purl);
CREATE INDEX idx_component_versions_purl ON component_versions(purl);
CREATE INDEX idx_vulnerabilities_osv_id ON vulnerabilities(osv_id);

-- ROW LEVEL SECURITY (enable for production)
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
