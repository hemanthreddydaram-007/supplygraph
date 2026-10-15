"use client";

import React, { useMemo, useCallback, useEffect, useState, useRef } from "react";
import {
  ReactFlow,
  Controls,
  Background,
  MarkerType,
  Edge,
  Node,
  useReactFlow,
  ReactFlowProvider,
  FitViewOptions,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { nodeTypes } from "./CustomNodes";
import { SecurityGraph } from "@/types";

interface GraphCanvasProps {
  graph: SecurityGraph;
  focusNodeId?: string | null;
  onNodeClick?: (nodeId: string) => void;
}

type GraphFilter = "attack" | "all";

function GraphCanvasInner({ graph, focusNodeId, onNodeClick }: GraphCanvasProps) {
  const { fitView, setCenter } = useReactFlow();
  const [filter, setFilter] = useState<GraphFilter>("attack");

  // Determine if we should default to attack-path-only view
  const totalNodes = graph.nodes.length;
  const defaultFilter: GraphFilter = totalNodes > 35 ? "attack" : "all";
  
  // Set default filter based on graph size on mount
  useEffect(() => {
    setFilter(defaultFilter);
  }, [graph.scan_id, defaultFilter]);

  // Identify attack-path and threat nodes with bi-directional reachability
  const threatNodeIds = useMemo(() => {
    const directThreats = new Set<string>();

    // 1. Identify all Vulnerability / finding nodes and any node marked as compromised
    graph.nodes.forEach(n => {
      const type = n.data?.node_type;
      if (
        type === "Vulnerability" ||
        type === "Finding" ||
        n.data?.is_suspicious ||
        n.data?.is_origin_candidate ||
        n.data?.is_affected ||
        (n.data?.vulnerability_count && n.data?.vulnerability_count > 0) ||
        (n.data?.finding_count && n.data?.finding_count > 0)
      ) {
        directThreats.add(n.id);
      }
    });

    // Also any edge explicitly marked as attack path
    graph.edges.forEach(e => {
      if (e.data?.is_attack_path) {
        directThreats.add(e.source);
        directThreats.add(e.target);
      }
    });

    if (directThreats.size === 0) {
      // If no threats identified, include all nodes
      return new Set(graph.nodes.map(n => n.id));
    }

    // 2. Build bi-directional adjacency map
    const neighbors = new Map<string, Set<string>>();
    graph.edges.forEach(e => {
      if (!neighbors.has(e.source)) neighbors.set(e.source, new Set());
      if (!neighbors.has(e.target)) neighbors.set(e.target, new Set());
      neighbors.get(e.source)!.add(e.target);
      neighbors.get(e.target)!.add(e.source);
    });

    // 3. Traverse in BOTH directions (1 to 3 hops) to keep parents, intermediate packages, assets, and repo
    const kept = new Set<string>(directThreats);
    let frontier = Array.from(directThreats);

    for (let hop = 0; hop < 3; hop++) {
      const nextFrontier: string[] = [];
      frontier.forEach(curr => {
        const adjacent = neighbors.get(curr);
        if (adjacent) {
          adjacent.forEach(nbr => {
            if (!kept.has(nbr)) {
              kept.add(nbr);
              nextFrontier.push(nbr);
            }
          });
        }
      });
      frontier = nextFrontier;
      if (frontier.length === 0) break;
    }

    // Always keep root Repository node
    graph.nodes.forEach(n => {
      if (
        n.data?.node_type === "Repository" ||
        n.type === "repositoryNode" ||
        n.id.startsWith("repo-")
      ) {
        kept.add(n.id);
      }
    });

    return kept;
  }, [graph]);

  // Compute layout positions with multi-column grid wrapping (max 8 per column)
  const visibleNodes: Node[] = useMemo(() => {
    const rawNodes = filter === "all"
      ? graph.nodes
      : graph.nodes.filter(n => threatNodeIds.has(n.id));

    // Group nodes by X coordinate to detect columns with > 8 nodes
    const colGroups = new Map<number, typeof rawNodes>();
    rawNodes.forEach(n => {
      const xKey = Math.round(n.position.x);
      if (!colGroups.has(xKey)) colGroups.set(xKey, []);
      colGroups.get(xKey)!.push(n);
    });

    const adjustedPositions = new Map<string, { x: number; y: number }>();

    colGroups.forEach((nodesInCol, baseX) => {
      if (nodesInCol.length <= 8) {
        nodesInCol.forEach(n => {
          adjustedPositions.set(n.id, { x: n.position.x, y: n.position.y });
        });
      } else {
        // Multi-column grid wrapping: 8 rows per column
        const maxRows = 8;
        const vSpacing = 115;
        const hSpacing = 320;
        const totalRows = Math.min(maxRows, nodesInCol.length);
        const startY = -((totalRows - 1) * vSpacing) / 2;

        nodesInCol.forEach((n, idx) => {
          const subCol = Math.floor(idx / maxRows);
          const row = idx % maxRows;
          adjustedPositions.set(n.id, {
            x: baseX + subCol * hSpacing,
            y: startY + row * vSpacing,
          });
        });
      }
    });

    return rawNodes.map(n => {
      const pos = adjustedPositions.get(n.id) || { x: n.position.x, y: n.position.y };
      return {
        id: n.id,
        position: pos,
        data: n.data as any,
        type: "default",
      };
    });
  }, [graph.nodes, filter, threatNodeIds]);

  const visibleEdges: Edge[] = useMemo(() => {
    const visibleNodeIds = new Set(visibleNodes.map(n => n.id));

    return graph.edges
      .filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target))
      .map(e => {
        // Edge is on an attack path if explicitly marked or if either end connects to a vulnerability
        const isAttack =
          Boolean(e.data?.is_attack_path) ||
          e.data?.edge_type === "AFFECTS" ||
          (threatNodeIds.has(e.source) && threatNodeIds.has(e.target));

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          animated: isAttack,
          label: e.data?.label,
          style: {
            stroke: isAttack ? "#ef4444" : "#475569",
            strokeWidth: isAttack ? 2.5 : 1.6,
            filter: isAttack ? "drop-shadow(0 0 8px rgba(239,68,68,0.7))" : "none",
          },
          labelStyle: {
            fill: isAttack ? "#fca5a5" : "#71717a",
            fontSize: 9,
            fontFamily: "monospace",
          },
          labelBgStyle: { fill: "#09090b", fillOpacity: 0.85 },
          labelBgPadding: [4, 2] as [number, number],
          labelBgBorderRadius: 4,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            width: isAttack ? 16 : 12,
            height: isAttack ? 16 : 12,
            color: isAttack ? "#ef4444" : "#475569",
          },
        };
      });
  }, [graph.edges, visibleNodes, threatNodeIds]);

  // Focus on a specific node when focusNodeId changes
  useEffect(() => {
    if (!focusNodeId) return;
    const node = graph.nodes.find(n => n.id === focusNodeId ||
      n.id.includes(focusNodeId) ||
      focusNodeId.includes(n.id));
    if (node) {
      // Switch to all-nodes view if the target node is not visible
      if (!threatNodeIds.has(node.id)) {
        setFilter("all");
      }
      setTimeout(() => {
        fitView({ nodes: [{ id: node.id }], duration: 600, padding: 0.3 });
      }, 100);
    }
  }, [focusNodeId, fitView, graph.nodes, threatNodeIds]);

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    onNodeClick?.(node.id);
  }, [onNodeClick]);

  const attackCount = threatNodeIds.size;
  const allCount = graph.nodes.length;

  return (
    <div className="w-full h-full bg-[#09090b] relative">
      {/* Filter Control — floating segmented control */}
      <div className="absolute top-3 right-3 z-20 flex items-center bg-zinc-950/90 border border-zinc-800 rounded-lg overflow-hidden shadow-xl backdrop-blur-md">
        <button
          onClick={() => setFilter("attack")}
          className={`px-3 py-1.5 text-[10px] font-mono font-semibold transition-all ${
            filter === "attack"
              ? "bg-red-950/60 text-red-300 border-r border-red-800/40"
              : "text-zinc-500 hover:text-zinc-300 border-r border-zinc-800"
          }`}
        >
          ⚡ Attack Paths Only
          {filter === "attack" && (
            <span className="ml-1.5 px-1 py-0.5 bg-red-900/40 text-red-400 rounded text-[9px]">
              {attackCount}
            </span>
          )}
        </button>
        <button
          onClick={() => setFilter("all")}
          className={`px-3 py-1.5 text-[10px] font-mono font-semibold transition-all ${
            filter === "all"
              ? "bg-zinc-800/60 text-zinc-100"
              : "text-zinc-500 hover:text-zinc-300"
          }`}
        >
          All Nodes ({allCount})
        </button>
      </div>

      <ReactFlow
        nodes={visibleNodes}
        edges={visibleEdges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        colorMode="dark"
        onNodeClick={handleNodeClick}
        minZoom={0.05}
        maxZoom={2}
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

export function GraphCanvas(props: GraphCanvasProps) {
  return (
    <ReactFlowProvider>
      <GraphCanvasInner {...props} />
    </ReactFlowProvider>
  );
}