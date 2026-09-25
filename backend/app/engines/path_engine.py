# SupplyGraph - Attack Path Engine
from app.models.core import AttackPath, ConfidenceModel, ImpactModel, SecurityGraph
import networkx as nx
from typing import List, Union
import uuid

class PathEngine:
    def find_attack_paths(self, graph: Union[SecurityGraph, nx.DiGraph], origin_node_ids: List[str], target_node_ids: List[str]) -> List[AttackPath]:
        if isinstance(graph, SecurityGraph):
            scan_id_str = graph.scan_id
            G = nx.DiGraph()
            for node in graph.nodes:
                G.add_node(node.id)
            for edge in graph.edges:
                G.add_edge(edge.source, edge.target, id=edge.id)
        else:
            scan_id_str = str(uuid.uuid4())
            G = graph
            
        try:
            scan_id = uuid.UUID(scan_id_str)
        except ValueError:
            scan_id = uuid.uuid4()
            
        paths = []
        cutoff = 6
        
        for origin in origin_node_ids:
            if not G.has_node(origin):
                continue
            for target in target_node_ids:
                if not G.has_node(target):
                    continue
                if origin == target:
                    continue
                    
                try:
                    simple_paths = list(nx.all_simple_paths(G, origin, target, cutoff=cutoff))
                except nx.NetworkXNoPath:
                    continue
                    
                for path_nodes in simple_paths:
                    path_edges = []
                    for i in range(len(path_nodes) - 1):
                        u = path_nodes[i]
                        v = path_nodes[i+1]
                        edge_data = G.get_edge_data(u, v) or {}
                        edge_id = edge_data.get("id", f"{u}-{v}")
                        path_edges.append(edge_id)
                        
                    is_direct = len(path_edges) == 1
                    is_transitive = len(path_edges) > 1
                    
                    paths.append(AttackPath(
                        scan_id=scan_id,
                        origin_node_id=origin,
                        target_node_id=target,
                        path_nodes=path_nodes,
                        path_edges=path_edges,
                        path_length=len(path_edges),
                        confidence=ConfidenceModel(score=0.7),
                        blast_radius=ImpactModel(package_count=len(path_nodes)),
                        is_direct=is_direct,
                        is_transitive=is_transitive
                    ))
                    
        return paths
