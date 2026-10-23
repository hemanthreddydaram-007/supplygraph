"use client";

import React, { useMemo, useCallback, useEffect, useState } from "react";
import {
  ReactFlow,
  Controls,
  Background,
  MarkerType,
  Edge,
  Node,
  useReactFlow,
  ReactFlowProvider,
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

const GraphCanvasInner = React.memo(function GraphCanvasInner({
  graph,
  focusNodeId,
  onNodeClick,
}: GraphCanvasProps) {
  const { fitView, setCenter } = useReactFlow();
  const [filter, setFilter] = useState<GraphFilter>("attack");
  const [ecoFilter, setEcoFilter] = useState<string>("all");
  const [sevFilter, setSevFilter] = useState<string>("all");

  const safeNodes = useMemo(() => (Array.isArray(graph?.nodes) ? graph.nodes : []), [graph?.nodes]);
  const safeEdges = useMemo(() => (Array.isArray(graph?.edges) ? graph.edges : []), [graph?.edges]);
  const scanId = graph?.scan_id || "default";

  // Determine if we should default to attack-path-only view
  const totalNodes = safeNodes.length;
  const defaultFilter: GraphFilter = totalNodes > 35 ? "attack" : "all";

  // Set default filter based on graph size on mount
  useEffect(() => {
    setFilter(defaultFilter);
  }, [scanId, defaultFilter]);

  // Identify attack-path and threat nodes with bi-directional reachability
  const threatNodeIds = useMemo(() => {
    const directThreats = new Set<string>();

    // 1. Identify all Vulnerability / finding nodes and any node marked as compromised
    safeNodes.forEach(n => {
      const type = n?.data?.node_type;
      if (
        type === "Vulnerability" ||
        type === "Finding" ||
        n?.data?.is_suspicious ||
        n?.data?.is_origin_candidate ||
        n?.data?.is_affected ||
        (n?.data?.vulnerability_count && n.data.vulnerability_count > 0) ||
        (n?.data?.finding_count && n.data.finding_count > 0)
      ) {
        directThreats.add(n.id);
      }
    });

    // Also any edge explicitly marked as attack path
    safeEdges.forEach(e => {
      if (e?.data?.is_attack_path) {
        directThreats.add(e.source);
        directThreats.add(e.target);
      }
    });

    if (directThreats.size === 0) {
      return new Set(safeNodes.map(n => n.id));
    }

    // 2. Build bi-directional adjacency map
    const neighbors = new Map<string, Set<string>>();
    safeEdges.forEach(e => {
      if (!neighbors.has(e.source)) neighbors.set(e.source, new Set());
      if (!neighbors.has(e.target)) neighbors.set(e.target, new Set());
      neighbors.get(e.source)!.add(e.target);
      neighbors.get(e.target)!.add(e.source);
    });

    // 3. Traverse in BOTH directions (1 to 3 hops)
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
    safeNodes.forEach(n => {
      if (
        n?.data?.node_type === "Repository" ||
        n?.type === "repositoryNode" ||
        n?.id?.startsWith("repo-")
      ) {
        kept.add(n.id);
      }
    });

    return kept;
  }, [safeNodes, safeEdges]);

  // Collect unique ecosystems and severities from graph nodes
  const ecosystems = useMemo(() => {
    const ecoSet = new Set<string>();
    safeNodes.forEach(n => {
      const eco = n?.data?.ecosystem as string | undefined;
      if (eco && eco !== "unknown") ecoSet.add(eco);
    });
    return Array.from(ecoSet).sort();
  }, [safeNodes]);

  const severities = useMemo(() => {
    const sevSet = new Set<string>();
    safeNodes.forEach(n => {
      const sev = n?.data?.severity as string | undefined;
      if (sev) sevSet.add(sev);
    });
    // Return in severity order
    return ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].filter(s => sevSet.has(s));
  }, [safeNodes]);

  // Hard-cap nodes in "All Nodes" mode: top 180 prioritized nodes if > 200 nodes
  const isCapped = filter === "all" && safeNodes.length > 200;

  const prioritizedAllNodes = useMemo(() => {
    if (!isCapped) return safeNodes;

    // Prioritize:
    // 1. Threat / affected nodes
    // 2. Services, APIs, Repositories, Deployments
    // 3. Direct dependencies
    // 4. Remaining nodes
    const threats: typeof safeNodes = [];
    const assets: typeof safeNodes = [];
    const directDeps: typeof safeNodes = [];
    const others: typeof safeNodes = [];

    safeNodes.forEach(n => {
      if (threatNodeIds.has(n.id)) {
        threats.push(n);
      } else if (
        n?.data?.node_type === "Repository" ||
        n?.data?.node_type === "Service" ||
        n?.data?.node_type === "API" ||
        n?.data?.node_type === "Deployment" ||
        n?.data?.node_type === "Pipeline"
      ) {
        assets.push(n);
      } else if (n?.data?.metadata?.is_direct) {
        directDeps.push(n);
      } else {
        others.push(n);
      }
    });

    const combined = [...threats, ...assets, ...directDeps, ...others];
    return combined.slice(0, 180);
  }, [safeNodes, isCapped, threatNodeIds]);

  // Compute layout positions with multi-column grid wrapping (max 8 per column)
  const visibleNodes: Node[] = useMemo(() => {
    let rawNodes: typeof safeNodes = filter === "all"
      ? prioritizedAllNodes
      : safeNodes.filter(n => threatNodeIds.has(n.id));

    // Apply ecosystem filter
    if (ecoFilter !== "all") {
      rawNodes = rawNodes.filter(n => {
        const eco = n.data?.ecosystem as string | undefined;
        return eco === ecoFilter || n.data?.node_type === "Repository" || n.data?.node_type === "Service";
      });
    }

    // Apply severity filter
    if (sevFilter !== "all") {
      rawNodes = rawNodes.filter(n => {
        const sev = n.data?.severity as string | undefined;
        return sev === sevFilter || n.data?.node_type === "Repository";
      });
    }

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
      const pos = adjustedPositions.get(n.id) || { x: n.position?.x ?? 0, y: n.position?.y ?? 0 };
      return {
        id: n.id,
        position: pos,
        data: n.data as any,
        type: "default",
      };
    });
  }, [safeNodes, filter, prioritizedAllNodes, threatNodeIds, ecoFilter, sevFilter]);

  const visibleEdges: Edge[] = useMemo(() => {
    const visibleNodeIds = new Set(visibleNodes.map(n => n.id));
    let animatedCount = 0;

    return safeEdges
      .filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target))
      .map(e => {
        const isAttack =
          Boolean(e.data?.is_attack_path) ||
          e.data?.edge_type === "AFFECTS" ||
          (threatNodeIds.has(e.source) && threatNodeIds.has(e.target));

        let animate = false;
        if (isAttack) {
          if (filter === "attack") {
            if (animatedCount < 40) {
              animate = true;
              animatedCount++;
            }
          } else {
            // "all" view - disable if > 100 edges, otherwise cap at 40
            if (safeEdges.length <= 100 && animatedCount < 40) {
              animate = true;
              animatedCount++;
            }
          }
        }

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          animated: animate,
          label: e.data?.label,
          style: {
            stroke: isAttack ? "#ef4444" : "#334155",
            strokeWidth: isAttack ? 2.5 : 1.2,
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
            width: isAttack ? 14 : 10,
            height: isAttack ? 14 : 10,
            color: isAttack ? "#ef4444" : "#334155",
          },
        };
      });
  }, [safeEdges, visibleNodes, threatNodeIds, filter]);

  // Focus on a specific node when focusNodeId changes — smooth zoom to center
  useEffect(() => {
    if (!focusNodeId) return;
    const node = safeNodes.find(n =>
      n.id === focusNodeId ||
      n.id.includes(focusNodeId) ||
      focusNodeId.includes(n.id)
    );
    if (node) {
      // Switch to "all" view if node is not in attack path subset
      if (!threatNodeIds.has(node.id)) {
        setFilter("all");
      }
      // Use setCenter for precise, smooth zoom to the node
      setTimeout(() => {
        const x = (node.position?.x ?? 0) + 80; // offset to center of node card
        const y = (node.position?.y ?? 0) + 20;
        setCenter(x, y, { zoom: 1.4, duration: 800 });
      }, 150);
    }
  }, [focusNodeId, setCenter, safeNodes, threatNodeIds]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      onNodeClick?.(node.id);
    },
    [onNodeClick]
  );

  const attackCount = threatNodeIds.size;
  const allCount = safeNodes.length;

  return (
    <div className="w-full h-full bg-[#09090b] relative">
      {/* Filter Control — floating segmented control */}
      <div className="absolute top-3 right-3 z-20 flex flex-col items-end gap-1.5">
        <div className="flex items-center bg-zinc-950/90 border border-zinc-800 rounded-lg overflow-hidden shadow-lg">
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

        {/* 60 FPS Node Capping Badge */}
        {isCapped && (
          <div className="px-2.5 py-0.5 bg-amber-500/10 border border-amber-500/30 rounded text-[9px] font-mono text-amber-300">
            Showing top 180 of {allCount} nodes for 60 FPS performance
          </div>
        )}

        {/* Ecosystem Filter Pills */}
        {ecosystems.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap justify-end max-w-[200px]">
            <button
              onClick={() => setEcoFilter("all")}
              className={`px-2 py-0.5 rounded text-[9px] font-mono border transition-all ${
                ecoFilter === "all"
                  ? "bg-zinc-700/80 text-zinc-100 border-zinc-600"
                  : "bg-zinc-950/80 text-zinc-500 border-zinc-800 hover:text-zinc-300"
              }`}
            >
              All Ecosystems
            </button>
            {ecosystems.map(eco => (
              <button
                key={eco}
                onClick={() => setEcoFilter(ecoFilter === eco ? "all" : eco)}
                className={`px-2 py-0.5 rounded text-[9px] font-mono border transition-all ${
                  ecoFilter === eco
                    ? "bg-indigo-700/60 text-indigo-100 border-indigo-600/60"
                    : "bg-zinc-950/80 text-zinc-500 border-zinc-800 hover:text-zinc-300"
                }`}
              >
                {eco}
              </button>
            ))}
          </div>
        )}

        {/* Severity Filter Pills */}
        {severities.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap justify-end max-w-[200px]">
            {severities.map(sev => {
              const sevColors: Record<string, string> = {
                CRITICAL: "bg-red-900/60 text-red-300 border-red-700/60",
                HIGH: "bg-orange-900/60 text-orange-300 border-orange-700/60",
                MEDIUM: "bg-amber-900/60 text-amber-300 border-amber-700/60",
                LOW: "bg-blue-900/60 text-blue-300 border-blue-700/60",
                INFO: "bg-zinc-800/60 text-zinc-400 border-zinc-700/60",
              };
              const inactiveStyle = "bg-zinc-950/80 text-zinc-600 border-zinc-800 hover:text-zinc-300";
              return (
                <button
                  key={sev}
                  onClick={() => setSevFilter(sevFilter === sev ? "all" : sev)}
                  className={`px-2 py-0.5 rounded text-[9px] font-mono border transition-all ${
                    sevFilter === sev ? sevColors[sev] || inactiveStyle : inactiveStyle
                  }`}
                >
                  {sev}
                </button>
              );
            })}
          </div>
        )}
      </div>

      <ReactFlow
        nodes={visibleNodes}
        edges={visibleEdges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        colorMode="dark"
        onNodeClick={handleNodeClick}
        minZoom={0.15}
        maxZoom={2}
        onlyRenderVisibleElements={true}
        elevateNodesOnSelect={false}
        elevateEdgesOnSelect={false}
      >
        <Background color="#18181b" gap={24} size={1} />
        <Controls
          className="!bg-zinc-950/90 !border !border-zinc-800 !fill-zinc-400 !shadow-lg !rounded-lg overflow-hidden"
          showInteractive={false}
        />
      </ReactFlow>
    </div>
  );
});

GraphCanvasInner.displayName = "GraphCanvasInner";

export const GraphCanvas = React.memo(function GraphCanvas(props: GraphCanvasProps) {
  return (
    <ReactFlowProvider>
      <GraphCanvasInner {...props} />
    </ReactFlowProvider>
  );
});

GraphCanvas.displayName = "GraphCanvas";