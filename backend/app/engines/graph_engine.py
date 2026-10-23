# SupplyGraph - Graph Engine
from app.models.core import SecurityGraph, GraphNode, GraphEdge, GraphNodeData, GraphEdgeData, GraphPosition, NodeType, EdgeType, RepositoryModel, SBOM, VulnerabilityModel, FindingModel, AssetModel, FindingType
from app.graph.layout import compute_layout, get_graph_statistics
import networkx as nx
from typing import List

class GraphEngine:
    def build_graph(self, repo: RepositoryModel, sbom: SBOM, vulnerabilities: List[VulnerabilityModel], findings: List[FindingModel], assets: List[AssetModel]) -> SecurityGraph:
        G = nx.DiGraph()
        
        # 1. Add repository node
        repo_id = str(repo.id)
        G.add_node(repo_id, type="repository", data=GraphNodeData(
            label=repo.name,
            node_type=NodeType.REPOSITORY,
            entity_id=repo_id
        ))
        
        # 2. Add package/version nodes from SBOM
        if sbom and sbom.components:
            for comp in sbom.components:
                comp_id = comp.bom_ref
                G.add_node(comp_id, type="component", data=GraphNodeData(
                    label=f"{comp.name}@{comp.version}" if comp.version else comp.name,
                    node_type=NodeType.VERSION,
                    entity_id=comp_id,
                    purl=comp.purl,
                    version=comp.version,
                    ecosystem=comp.ecosystem.value if comp.ecosystem else None,
                    metadata={
                        "declared_in": getattr(comp, "declared_in", None),
                        "is_direct": comp.is_direct,
                        "is_dev": getattr(comp, "is_dev", False)
                    }
                ))
                # Add CONTAINS edge from repo to direct dependencies
                if comp.is_direct:
                    G.add_edge(repo_id, comp_id, data=GraphEdgeData(
                        edge_type=EdgeType.CONTAINS,
                        is_direct=True
                    ))
                    
        # 3. Add DEPENDS_ON edges
        if sbom and sbom.dependencies:
            for dep in sbom.dependencies:
                if G.has_node(dep.from_bom_ref) and G.has_node(dep.to_bom_ref):
                    G.add_edge(dep.from_bom_ref, dep.to_bom_ref, data=GraphEdgeData(
                        edge_type=EdgeType.DEPENDS_ON,
                        is_direct=dep.is_direct
                    ))
                    
        # 4. Add vulnerability nodes and AFFECTS edges
        for vuln in vulnerabilities:
            vuln_id = vuln.osv_id or str(vuln.id)
            if not G.has_node(vuln_id):
                G.add_node(vuln_id, type="vulnerability", data=GraphNodeData(
                    label=vuln.osv_id or "Vulnerability",
                    node_type=NodeType.VULNERABILITY,
                    entity_id=str(vuln.id),
                    severity=vuln.severity,
                    vulnerability_count=1,
                    metadata={"summary": vuln.summary, "aliases": vuln.aliases}
                ))
                
        # Link vulnerabilities to packages via findings
        for finding in findings:
            if finding.finding_type == FindingType.VULNERABLE:
                vuln_node_ids = []
                for vuln in vulnerabilities:
                    if vuln.osv_id:
                        if (vuln.osv_id in finding.title or 
                            (finding.description and vuln.osv_id in finding.description) or
                            any(vuln.osv_id in ev.description or (ev.raw_data and ev.raw_data.get("vuln_id") == vuln.osv_id) for ev in finding.evidence)):
                            vuln_node_ids.append(vuln.osv_id)
                        
                target_node_id = str(finding.entity_id) if finding.entity_id else finding.origin_candidate
                
                for vuln_node_id in vuln_node_ids:
                    if target_node_id and G.has_node(vuln_node_id) and G.has_node(target_node_id):
                        if not G.has_edge(vuln_node_id, target_node_id):
                            G.add_edge(vuln_node_id, target_node_id, data=GraphEdgeData(
                                edge_type=EdgeType.AFFECTS,
                                label="AFFECTS",
                                is_attack_path=True
                            ))
            
        # 5. Add asset nodes and DEPLOYED_AS / USES edges
        for asset in assets:
            asset_id = str(asset.id)
            G.add_node(asset_id, type="asset", data=GraphNodeData(
                label=asset.name,
                node_type=NodeType.ASSET,
                entity_id=asset_id,
                metadata={"asset_type": asset.asset_type.value}
            ))
            
            G.add_edge(repo_id, asset_id, data=GraphEdgeData(
                edge_type=EdgeType.DEPLOYED_AS
            ))
            
            for comp_ref in asset.connected_components:
                if G.has_node(comp_ref):
                    G.add_edge(asset_id, comp_ref, data=GraphEdgeData(
                        edge_type=EdgeType.USES
                    ))
                    
        # 6. Compute Layout and Build Pydantic Model with threat node prioritization
        threat_node_ids = set()
        for vuln in vulnerabilities:
            if vuln.osv_id:
                threat_node_ids.add(vuln.osv_id)
        for f in findings:
            if f.origin_candidate:
                threat_node_ids.add(f.origin_candidate)
            if f.entity_id:
                threat_node_ids.add(str(f.entity_id))

        positions = compute_layout(G, threat_node_ids=threat_node_ids)
        stats = get_graph_statistics(G)
        
        nodes = []
        for node_id, node_data in G.nodes(data=True):
            pos_dict = positions.get(node_id, {"x": 0.0, "y": 0.0})
            nodes.append(GraphNode(
                id=str(node_id),
                type=node_data.get("type", "default"),
                position=GraphPosition(x=pos_dict["x"], y=pos_dict["y"]),
                data=node_data["data"]
            ))
            
        # Prioritize vulnerable and threat nodes first in the visualization array to maintain 60 FPS in React Flow
        def node_priority(node: GraphNode) -> int:
            if node.data.node_type == NodeType.VULNERABILITY:
                return 0
            if node.data.node_type in (NodeType.REPOSITORY, NodeType.ASSET):
                return 1
            if node.id in threat_node_ids or node.data.is_suspicious or node.data.is_origin_candidate or node.data.is_affected:
                return 2
            if getattr(node.data, "metadata", {}) and node.data.metadata.get("is_direct"):
                return 3
            return 4

        nodes.sort(key=node_priority)

        edges = []
        for u, v, edge_data in G.edges(data=True):
            edges.append(GraphEdge(
                id=f"{u}-{v}",
                source=str(u),
                target=str(v),
                data=edge_data["data"]
            ))
            
        return SecurityGraph(
            scan_id=repo_id,
            nodes=nodes,
            edges=edges,
            has_cycles=stats.get("has_cycles", False)
        )

