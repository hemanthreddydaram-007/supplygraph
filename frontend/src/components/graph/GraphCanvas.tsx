"use client";

import React, { useMemo } from "react";
import { 
  ReactFlow, 
  Controls, 
  Background, 
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
  const initialNodes: Node[] = useMemo(() => {
    return graph.nodes.map(n => ({
      id: n.id,
      position: { x: n.position.x, y: n.position.y },
      data: n.data as any,
      type: "default",
    }));
  }, [graph.nodes]);

  const initialEdges: Edge[] = useMemo(() => {
    return graph.edges.map(e => {
      const isAttack = Boolean(e.data?.is_attack_path);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: isAttack || Boolean(e.animated),
        label: e.data?.label,
        style: { 
          stroke: isAttack ? "#ef4444" : "#27272a", 
          strokeWidth: isAttack ? 2.5 : 1.2,
          filter: isAttack ? "drop-shadow(0 0 6px rgba(239, 68, 68, 0.6))" : "none"
        },
        labelStyle: { fill: isAttack ? "#fca5a5" : "#71717a", fontSize: 9, fontFamily: "monospace" },
        labelBgStyle: { fill: "#09090b", fillOpacity: 0.8 },
        labelBgPadding: [4, 2],
        labelBgBorderRadius: 4,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 14,
          height: 14,
          color: isAttack ? "#ef4444" : "#3f3f46",
        },
      };
    });
  }, [graph.edges]);

  return (
    <div className="w-full h-full bg-[#09090b]">
      <ReactFlow
        nodes={initialNodes}
        edges={initialEdges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        colorMode="dark"
      >
        <Background color="#18181b" gap={24} size={1} />
        <Controls 
          className="!bg-zinc-950/90 !border !border-zinc-800 !fill-zinc-400 !shadow-2xl !rounded-lg overflow-hidden" 
          showInteractive={false}
        />
      </ReactFlow>
    </div>
  );
}