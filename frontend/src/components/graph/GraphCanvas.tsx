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

export interface FocusTarget {
  id?: string;
  finding?: any;
  packageKey?: string;
  timestamp: number;
}

export interface GraphCanvasProps {
  graph: SecurityGraph;
  focusNodeId?: string | null;
  focusTarget?: FocusTarget | null;
  onNodeClick?: (nodeId: string) => void;
}

type GraphFilter = "package" | "detailed" | "all";

export function findMatchingNode(
  target: { id?: string; finding?: any; packageKey?: string },
  nodes: Node[]
): Node | null {
  if (!nodes || nodes.length === 0) return null;
  const finding = target.finding;
  const rawId = (target.id || "").trim();
  const pkgKey = (target.packageKey || "").trim();

  const candidates: string[] = [];

  if (rawId) candidates.push(rawId);
  if (pkgKey) candidates.push(pkgKey);

  // Extract from finding fields
  if (finding) {
    if (finding.origin_candidate) candidates.push(finding.origin_candidate);
    if (finding.entity_id) candidates.push(String(finding.entity_id));

    // Extract CVE/GHSA IDs from title or description
    const titleMatch = (finding.title || "").match(/(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+|PYSEC-\d{4}-\d+|SNYK-[A-Z0-9-]+)/i);
    if (titleMatch) candidates.push(titleMatch[1]);

    const descMatch = (finding.description || "").match(/(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+|PYSEC-\d{4}-\d+|SNYK-[A-Z0-9-]+)/i);
    if (descMatch) candidates.push(descMatch[1]);

    // Check evidence
    if (Array.isArray(finding.evidence)) {
      finding.evidence.forEach((ev: any) => {
        if (ev?.raw_data?.vuln_id) candidates.push(ev.raw_data.vuln_id);
        if (ev?.raw_data?.package) candidates.push(ev.raw_data.package);
        if (ev?.raw_data?.purl) candidates.push(ev.raw_data.purl);
      });
    }

    // Check propagation steps
    if (Array.isArray(finding.propagation_path)) {
      finding.propagation_path.forEach((step: any) => {
        if (step?.node_id) candidates.push(step.node_id);
      });
    }

    // Special finding types:
    // CI/CD risk -> look for pipeline node
    if (
      finding.finding_type === "CICD_RISK" ||
      finding.title?.includes("CI/CD") ||
      (finding.description && finding.description.includes("GitHub Actions"))
    ) {
      candidates.push("pipeline", "Pipeline");
    }

    // AST / Repo-level finding -> look for repository node
    if (
      finding.entity_type === "Repository" ||
      finding.title?.includes("AST") ||
      finding.finding_type === "SUSPICIOUS"
    ) {
      candidates.push("repository", "Repository", "demo-app", "app");
    }
  }

  // Variant generator for package names / versions
  const generateVariants = (input: string) => {
    if (!input) return [];
    const res: string[] = [input];
    // Strip pkg:xxx/
    const noPurl = input.replace(/^pkg:[^/]+\//, "").replace(/^@/, "");
    res.push(noPurl);
    if (noPurl.includes("@")) {
      const [name, ver] = noPurl.split("@");
      res.push(name);
      res.push(`${name}-${ver}`);
      res.push(`${name}@${ver}`);
    } else if (noPurl.includes("-")) {
      const lastHyphen = noPurl.lastIndexOf("-");
      const name = noPurl.substring(0, lastHyphen);
      const ver = noPurl.substring(lastHyphen + 1);
      if (/\d/.test(ver)) {
        res.push(name);
        res.push(`${name}@${ver}`);
      }
    }
    return res;
  };

  const allVariants: string[] = [];
  candidates.forEach(c => {
    allVariants.push(...generateVariants(c));
  });

  const uniqueCandidates = Array.from(new Set(allVariants.map(s => s.trim()).filter(Boolean)));

  // Helper for alpha-numeric normalization
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

  // Priority 1: Exact node.id match
  for (const c of uniqueCandidates) {
    const match = nodes.find(n => n.id === c);
    if (match) return match;
  }

  // Priority 2: Exact node.data.purl, label, or entity_id match
  for (const c of uniqueCandidates) {
    const match = nodes.find(n => 
      (n.data as any)?.purl === c ||
      (n.data as any)?.label === c ||
      (n.data as any)?.entity_id === c
    );
    if (match) return match;
  }

  // Priority 3: Alpha-numeric normalized match (ignoring hyphens, @, pkg:)
  for (const c of uniqueCandidates) {
    const cleanC = norm(c);
    if (cleanC.length < 3) continue;
    const match = nodes.find(n => {
      const cleanId = norm(n.id);
      const cleanLabel = norm((n.data as any)?.label || "");
      const cleanPurl = norm((n.data as any)?.purl || "");
      return cleanId === cleanC || cleanLabel === cleanC || cleanPurl === cleanC;
    });
    if (match) return match;
  }

  // Priority 4: Substring match (e.g. "mixin-deep" in "mixin-deep-1.3.1")
  for (const c of uniqueCandidates) {
    const cleanC = norm(c);
    if (cleanC.length < 4) continue;
    const match = nodes.find(n => {
      const cleanId = norm(n.id);
      const cleanLabel = norm((n.data as any)?.label || "");
      return cleanId.includes(cleanC) || cleanC.includes(cleanId) ||
             cleanLabel.includes(cleanC) || cleanC.includes(cleanLabel);
    });
    if (match) return match;
  }

  // Priority 5: By node_type fallback for CI/CD or Repository
  if (
    finding?.finding_type === "CICD_RISK" ||
    finding?.title?.includes("CI/CD") ||
    rawId.endsWith(".yml") ||
    rawId.endsWith(".yaml")
  ) {
    const pipeNode = nodes.find(n => (n.data as any)?.node_type === "Pipeline" || n.id.toLowerCase().includes("pipeline"));
    if (pipeNode) return pipeNode;
  }

  if (
    finding?.entity_type === "Repository" ||
    finding?.title?.includes("AST")
  ) {
    const repoNode = nodes.find(n => (n.data as any)?.node_type === "Repository" || n.type === "repositoryNode" || n.id.toLowerCase().includes("app") || n.id.toLowerCase().includes("repo"));
    if (repoNode) return repoNode;
  }

  return null;
}

const GraphCanvasInner = React.memo(function GraphCanvasInner({
  graph,
  focusNodeId,
  focusTarget,
  onNodeClick,
}: GraphCanvasProps) {
  const { fitView, setCenter } = useReactFlow();
  const [filter, setFilter] = useState<GraphFilter>("package");
  const [ecoFilter, setEcoFilter] = useState<string>("all");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [activeFocusedId, setActiveFocusedId] = useState<string | null>(null);
  const visibleNodesRef = React.useRef<Node[]>([]);

  const safeNodes = useMemo(() => (Array.isArray(graph?.nodes) ? graph.nodes : []), [graph?.nodes]);
  const safeEdges = useMemo(() => (Array.isArray(graph?.edges) ? graph.edges : []), [graph?.edges]);
  const scanId = graph?.scan_id || "default";

  // Set default filter based on graph on mount
  useEffect(() => {
    setFilter("package");
  }, [scanId]);

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

  const packageOnlyNodes = useMemo(() => {
    return safeNodes.filter(n => {
      const type = n?.data?.node_type;
      return type !== "Vulnerability" && type !== "Finding";
    });
  }, [safeNodes]);

  // Compute layout positions with multi-column grid wrapping (max 8 per column)
  const visibleNodes: Node[] = useMemo(() => {
    let rawNodes: typeof safeNodes;
    if (filter === "package") {
      rawNodes = packageOnlyNodes;
    } else if (filter === "detailed") {
      rawNodes = safeNodes.filter(n => threatNodeIds.has(n.id));
    } else {
      rawNodes = prioritizedAllNodes;
    }

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
      const isFocused = n.id === activeFocusedId;
      return {
        id: n.id,
        position: pos,
        data: {
          ...(n.data as any),
          is_focused: isFocused,
        },
        selected: isFocused,
        type: "default",
      };
    });
  }, [safeNodes, filter, packageOnlyNodes, prioritizedAllNodes, threatNodeIds, ecoFilter, sevFilter, activeFocusedId]);

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
          if (filter === "detailed" || filter === "package") {
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

  // Keep visibleNodesRef in sync on every render
  useEffect(() => {
    visibleNodesRef.current = visibleNodes;
  });

  // Focus on a specific node when focusTarget or focusNodeId changes — smooth zoom to center
  useEffect(() => {
    if (!focusTarget && !focusNodeId) return;

    const payload: FocusTarget = focusTarget || {
      id: focusNodeId || undefined,
      timestamp: Date.now(),
    };

    const node = findMatchingNode(payload, safeNodes);
    if (!node) return;

    setActiveFocusedId(node.id);

    // Auto-adjust view mode if node is filtered out:
    // If it's a Vulnerability node and filter is "package", switch to "detailed" (exploded CVEs)
    if (node.data?.node_type === "Vulnerability" && filter === "package") {
      setFilter("detailed");
    } else if (!threatNodeIds.has(node.id) && filter === "detailed") {
      setFilter("all");
    }

    // Reset ecosystem or severity filter if they hide this node
    if (ecoFilter !== "all" && node.data?.ecosystem && node.data.ecosystem !== ecoFilter) {
      setEcoFilter("all");
    }
    if (sevFilter !== "all" && node.data?.severity && node.data.severity !== sevFilter) {
      setSevFilter("all");
    }

    // Use setCenter with slight delay to ensure React Flow has layout & correct on-screen position
    const timer = setTimeout(() => {
      const onScreen = visibleNodesRef.current.find(vn => vn.id === node.id) || node;
      const x = (onScreen.position?.x ?? 0) + 105;
      const y = (onScreen.position?.y ?? 0) + 35;
      setCenter(x, y, { zoom: 1.45, duration: 650 });
    }, 180);

    return () => clearTimeout(timer);
  }, [focusTarget, focusNodeId, safeNodes, threatNodeIds, setCenter, filter, ecoFilter, sevFilter]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setActiveFocusedId(node.id);
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
        <div className="flex items-center bg-zinc-950/90 border border-zinc-800 rounded-lg overflow-hidden shadow-lg backdrop-blur-md">
          <button
            onClick={() => setFilter("package")}
            className={`px-3 py-1.5 text-[10px] font-mono font-semibold transition-all ${
              filter === "package"
                ? "bg-indigo-950/70 text-indigo-300 border-r border-indigo-800/40"
                : "text-zinc-500 hover:text-zinc-300 border-r border-zinc-800"
            }`}
            title="Clean, executive package dependency DAG without individual CVE clutter"
          >
            📦 Package Flow ({packageOnlyNodes.length})
          </button>
          <button
            onClick={() => setFilter("detailed")}
            className={`px-3 py-1.5 text-[10px] font-mono font-semibold transition-all ${
              filter === "detailed"
                ? "bg-red-950/60 text-red-300 border-r border-red-800/40"
                : "text-zinc-500 hover:text-zinc-300 border-r border-zinc-800"
            }`}
            title="Exploded forensic tree showing every individual CVE node"
          >
            🔍 Exploded CVEs ({attackCount})
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