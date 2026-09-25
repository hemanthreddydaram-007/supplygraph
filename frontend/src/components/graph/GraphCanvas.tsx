"use client";

import React, { useMemo } from "react";
import { 
  ReactFlow, 
  Controls, 
  Background, 
  MiniMap,
  MarkerType,
  Edge,
  Node,
  useNodesState,
  useEdgesState
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { nodeTypes } from "./CustomNodes";
import { SecurityGraph } from "@/types";

interface GraphCanvasProps {
  graph: SecurityGraph;
}

export function GraphCanvas({ graph }: GraphCanvasProps) {
  // Map our generic nodes to React Flow nodes
  const initialNodes: Node[] = useMemo(() => {
    return graph.nodes.map((n) => ({
      id: n.id,
      type: n.type || "default",
      position: n.position,
      data: n.data,
    }));
  }, [graph.nodes]);

  // Map our generic edges to React Flow edges
  const initialEdges: Edge[] = useMemo(() => {
    return graph.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      animated: e.data?.is_attack_path || e.animated,
      style: {
        stroke: e.data?.is_attack_path ? "#dc2626" : "#94a3b8",
        strokeWidth: e.data?.is_attack_path ? 3 : 2,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: e.data?.is_attack_path ? "#dc2626" : "#94a3b8",
      },
    }));
  }, [graph.edges]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Update state when graph prop changes
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  return (
    <div className="w-full h-full bg-slate-50 rounded-xl overflow-hidden border border-slate-200">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.1}
        maxZoom={1.5}
      >
        <Background color="#cbd5e1" gap={20} size={1} />
        <Controls showInteractive={false} />
        <MiniMap 
          nodeColor={(n) => {
            if (n.data?.is_suspicious) return '#ef4444';
            if (n.data?.is_affected) return '#fb923c';
            return '#cbd5e1';
          }}
          maskColor="rgba(248, 250, 252, 0.7)"
        />
      </ReactFlow>
    </div>
  );
}
