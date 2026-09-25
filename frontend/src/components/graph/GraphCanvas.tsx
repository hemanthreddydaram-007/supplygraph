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
    return graph.nodes.map(n => ({
      id: n.id,
      position: { x: n.position.x, y: n.position.y },
      data: n.data as any,
      type: "default", // We use default and map it to BaseNode in nodeTypes
    }));
  }, [graph.nodes]);

  // Map our generic edges to React Flow edges
  const initialEdges: Edge[] = useMemo(() => {
    return graph.edges.map(e => ({
      id: e.id,
      source: e.source,
      target: e.target,
      animated: e.animated || e.data.is_attack_path,
      label: e.data.label,
      style: { 
        stroke: e.data.is_attack_path ? "#ef4444" : "#3f3f46", 
        strokeWidth: e.data.is_attack_path ? 2 : 1 
      },
      labelStyle: { fill: "#a1a1aa", fontSize: 10, fontWeight: 500 },
      labelBgStyle: { fill: "transparent" },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 15,
        height: 15,
        color: e.data.is_attack_path ? "#ef4444" : "#3f3f46",
      },
    }));
  }, [graph.edges]);

  return (
    <ReactFlow
      nodes={initialNodes}
      edges={initialEdges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      className="bg-[#0a0a0a]"
      colorMode="dark"
    >
      <Background color="#27272a" gap={20} size={1} />
      <Controls 
        className="bg-card border border-border fill-muted-foreground shadow-lg rounded-md overflow-hidden" 
        showInteractive={false}
      />
    </ReactFlow>
  );
}
