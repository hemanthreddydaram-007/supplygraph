from app.models.core import AttackPath, ConfidenceModel, ImpactModel, SecurityGraph, EdgeType
import networkx as nx
from typing import List, Union
import uuid

class PathEngine:
    def find_attack_paths(self, graph: Union[SecurityGraph, nx.DiGraph], origin_node_ids: List[str], target_node_ids: List[str]) -> List[AttackPath]:
        if isinstance(graph, SecurityGraph):
            scan_id_str = str(graph.scan_id) if graph.scan_id else str(uuid.uuid4())
            G = nx.DiGraph()
            for node in graph.nodes:
                G.add_node(node.id)
            for edge in graph.edges:
                # Attack path propagates backwards up the dependency tree, but forwards into assets
                etype = edge.data.edge_type if edge.data else None
                if etype in (EdgeType.CONTAINS, EdgeType.DEPENDS_ON):
                    # Reverse dependency edges so attack flows from child to parent
                    G.add_edge(edge.target, edge.source, id=edge.id)
                else:
                    # Keep AFFECTS, DEPLOYED_AS, etc in forward direction
                    G.add_edge(edge.source, edge.target, id=edge.id)
        else:
            scan_id_str = str(uuid.uuid4())
            G = graph
            
        try:
            scan_id = uuid.UUID(scan_id_str)
        except ValueError:
            scan_id = uuid.uuid4()
            
        paths = []
        cutoff = 10
        
        for origin in origin_node_ids:
            if not G.has_node(origin):
                continue
            for target in target_node_ids:
                if not G.has_node(target):
                    continue
                    
                try:
                    simple_paths = list(nx.all_simple_paths(G, origin, target, cutoff=cutoff))
                except nx.NetworkXNoPath:
                    continue
                    
                for p in simple_paths:
                    path_edges = []
                    is_direct = False
                    is_transitive = False
                    
                    for i in range(len(p) - 1):
                        u = p[i]
                        v = p[i+1]
                        edge_data = G.get_edge_data(u, v)
                        edge_id = edge_data.get('id', str(uuid.uuid4())) if edge_data else str(uuid.uuid4())
                        path_edges.append(edge_id)
                        
                        # Just heuristic approximations for demo
                        if len(p) == 3:
                            is_direct = True
                        else:
                            is_transitive = True
                            
                    paths.append(AttackPath(
                        scan_id=scan_id,
                        origin_node_id=origin,
                        target_node_id=target,
                        path_nodes=p,
                        path_edges=path_edges,
                        path_length=len(path_edges),
                        confidence=ConfidenceModel(score=0.7),
                        blast_radius=ImpactModel(package_count=len(p)),
                        is_direct=is_direct,
                        is_transitive=is_transitive
                    ))
                    
        return paths
