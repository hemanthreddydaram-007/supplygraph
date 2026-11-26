import { AnalysisResponse, GraphNode, SecurityGraph } from "@/types";
import { getFindingPackage, resolveHighestSafeVersion } from "@/lib/remediationPromptGenerator";
import { GroupedPackageFindings } from "@/components/scanner/FindingsPanel";

const DEV_PACKAGES = new Set([
  "streamlit",
  "watchdog",
  "pytest",
  "pytest-cov",
  "pytest-asyncio",
  "black",
  "flake8",
  "mypy",
  "coverage",
  "pylint",
  "isort",
  "bandit",
  "mock",
  "pre-commit",
  "tox",
  "sphinx",
  "mkdocs",
  "eslint",
  "jest",
  "mocha",
  "typescript",
  "actionlint",
]);

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function isKnownDevPackage(pkgName: string): boolean {
  const clean = pkgName.toLowerCase();
  for (const dev of DEV_PACKAGES) {
    if (clean === dev || clean.startsWith(`${dev}@`) || clean.endsWith(`/${dev}`)) {
      return true;
    }
  }
  return false;
}

export function computeNodeDepths(data: AnalysisResponse | null): Map<string, number> {
  if (!data?.graph?.nodes || data.graph.nodes.length === 0) return new Map();
  const nodes = data.graph.nodes;
  const edges = data.graph.edges || [];
  const depths = new Map<string, number>();

  const compDepthMap = new Map<string, number>();
  const compList: any[] = data.components || data.sbom?.components || [];
  compList.forEach((c) => {
    const d = c.depth ?? (c.is_direct ? 1 : 2);
    if (c.bom_ref) compDepthMap.set(c.bom_ref.toLowerCase(), d);
    if (c.name) compDepthMap.set(c.name.toLowerCase(), d);
    if (c.purl) compDepthMap.set(c.purl.toLowerCase(), d);
  });

  let roots = nodes
    .filter((n) => (n.data?.node_type || n.type || "").toLowerCase() === "repository")
    .map((n) => n.id);

  if (roots.length === 0) {
    const targetIds = new Set(edges.map((e) => e.target));
    roots = nodes
      .filter((n) => {
        const type = (n.data?.node_type || n.type || "").toLowerCase();
        const isVuln = type === "vulnerability" || n.id.startsWith("GHSA-") || n.id.startsWith("CVE-");
        return !isVuln && !targetIds.has(n.id);
      })
      .map((n) => n.id);
  }

  if (roots.length === 0 && nodes.length > 0) {
    roots = [nodes[0].id];
  }

  roots.forEach((r) => depths.set(r, 0));

  const depAdj = new Map<string, { target: string; edgeDepth?: number }[]>();
  nodes.forEach((n) => depAdj.set(n.id, []));

  edges.forEach((e) => {
    const edgeType = (e.data?.edge_type || e.type || e.data?.label || "").toLowerCase();
    if (edgeType !== "affects" && depAdj.has(e.source)) {
      depAdj.get(e.source)!.push({ target: e.target, edgeDepth: e.data?.depth });
    }
  });

  const queue: string[] = [...roots];
  while (queue.length > 0) {
    const curr = queue.shift()!;
    const currD = depths.get(curr)!;
    for (const next of depAdj.get(curr) || []) {
      const targetNode = nodes.find((n) => n.id === next.target);
      const metaDepth = (targetNode?.data as any)?.metadata?.depth ?? (targetNode?.data as any)?.depth;
      const cleanName = (targetNode?.data?.label || "").split("@")[0].toLowerCase();
      const compD = targetNode
        ? compDepthMap.get(targetNode.id.toLowerCase()) || compDepthMap.get(cleanName)
        : undefined;

      const candidateDepth =
        next.edgeDepth ?? metaDepth ?? compD ?? currD + 1;

      if (!depths.has(next.target) || depths.get(next.target)! > candidateDepth) {
        depths.set(next.target, candidateDepth);
        queue.push(next.target);
      }
    }
  }

  nodes.forEach((n) => {
    const type = (n.data?.node_type || n.type || "").toLowerCase();
    const isVuln = type === "vulnerability" || n.id.startsWith("GHSA-") || n.id.startsWith("CVE-");
    if (!isVuln && !depths.has(n.id)) {
      const metaDepth = (n.data as any)?.metadata?.depth ?? (n.data as any)?.depth;
      const cleanName = (n.data?.label || "").split("@")[0].toLowerCase();
      const compD = compDepthMap.get(n.id.toLowerCase()) || compDepthMap.get(cleanName);
      depths.set(n.id, metaDepth ?? compD ?? 1);
    }
  });

  nodes.forEach((n) => {
    const type = (n.data?.node_type || n.type || "").toLowerCase();
    const isVuln = type === "vulnerability" || n.id.startsWith("GHSA-") || n.id.startsWith("CVE-");
    if (!isVuln) return;

    const metaDepth = (n.data as any)?.metadata?.depth ?? (n.data as any)?.depth;
    const connectedEdges = edges.filter((e) => e.source === n.id || e.target === n.id);
    let pkgDepth: number | null = null;

    for (const ce of connectedEdges) {
      const otherId = ce.source === n.id ? ce.target : ce.source;
      if (depths.has(otherId)) {
        const d = depths.get(otherId)!;
        if (pkgDepth === null || d < pkgDepth) pkgDepth = d;
      } else if (ce.data?.depth !== undefined && ce.data?.depth !== null) {
        if (pkgDepth === null || ce.data.depth < pkgDepth) pkgDepth = ce.data.depth;
      }
    }

    if (pkgDepth === null && data.findings) {
      const finding = data.findings.find(
        (f: any) =>
          f.title?.includes(n.id) ||
          f.description?.includes(n.id) ||
          (f.evidence &&
            f.evidence.some(
              (ev: any) => ev.description?.includes(n.id) || ev.raw_data?.vuln_id === n.id
            ))
      );
      if (finding) {
        const { pkgName } = getFindingPackage(finding);
        if (pkgName) {
          const matched = compDepthMap.get(pkgName.toLowerCase());
          if (matched !== undefined) pkgDepth = matched;
        }
      }
    }

    depths.set(n.id, pkgDepth ?? metaDepth ?? 1);
  });

  return depths;
}

export function isNodeDevDependency(
  node: GraphNode,
  data: AnalysisResponse | null
): boolean {
  if (node.data?.is_dev === true || node.data?.metadata?.is_dev === true) return true;
  const type = (node.data?.node_type || node.type || "").toLowerCase();
  if (type === "devdependency") return true;

  const rawLabel = (node.data?.label || node.id || "").toLowerCase();
  const pkgNameFromLabel = rawLabel.split("@")[0].replace(/^pkg:(pypi|npm|cargo|golang)\//, "");
  if (isKnownDevPackage(pkgNameFromLabel)) return true;

  const comp = (data?.components || data?.sbom?.components || []).find(
    (c: any) =>
      c.bom_ref === node.id ||
      c.name?.toLowerCase() === pkgNameFromLabel ||
      c.purl === node.data?.purl
  );
  if (comp && comp.is_dev) return true;

  const isVuln = type === "vulnerability" || node.id.startsWith("GHSA-") || node.id.startsWith("CVE-");
  if (isVuln && data?.graph?.edges) {
    const connectedEdges = data.graph.edges.filter(
      (e) => e.source === node.id || e.target === node.id
    );
    for (const ce of connectedEdges) {
      const targetId = ce.source === node.id ? ce.target : ce.source;
      const targetNode = data.graph.nodes.find((n) => n.id === targetId);
      if (targetNode && isNodeDevDependency(targetNode, data)) return true;
    }

    if (data?.findings) {
      const vulnFinding = data.findings.find(
        (f: any) =>
          f.title?.includes(node.id) ||
          f.description?.includes(node.id) ||
          (f.evidence &&
            f.evidence.some(
              (ev: any) => ev.description?.includes(node.id) || ev.raw_data?.vuln_id === node.id
            ))
      );
      if (vulnFinding) {
        const { pkgName } = getFindingPackage(vulnFinding);
        if (pkgName && isKnownDevPackage(pkgName)) return true;
      }
    }
  }

  return false;
}

export function countDevDependencies(data: AnalysisResponse | null): number {
  const compList: any[] = data?.components || data?.sbom?.components || [];
  const compDevCount = compList.filter(
    (c) => c.is_dev || (c.name && DEV_PACKAGES.has(c.name.toLowerCase()))
  ).length;

  if (!data?.graph?.nodes) return compDevCount;

  const devNodes = data.graph.nodes.filter((n) => {
    const type = (n.data?.node_type || n.type || "").toLowerCase();
    const isVuln = type === "vulnerability" || n.id.startsWith("GHSA-") || n.id.startsWith("CVE-");
    if (isVuln || type === "repository") return false;
    return isNodeDevDependency(n, data);
  });

  return Math.max(devNodes.length, compDevCount);
}

export function filterGraph(
  data: AnalysisResponse | null,
  nodeDepths: Map<string, number>,
  prodOnly: boolean,
  transitiveDepth: number
): SecurityGraph | null {
  if (!data?.graph?.nodes) return null;

  const visibleNodes = data.graph.nodes.filter((node) => {
    const type = (node.data?.node_type || node.type || "").toLowerCase();
    if (type === "repository") return true;
    if (prodOnly && isNodeDevDependency(node, data)) return false;
    const depth = nodeDepths.get(node.id) ?? 1;
    return depth <= transitiveDepth;
  });

  const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
  const visibleEdges = (data.graph.edges || []).filter(
    (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
  );

  return {
    ...data.graph,
    nodes: visibleNodes,
    edges: visibleEdges,
    node_count: visibleNodes.length,
    edge_count: visibleEdges.length,
  };
}

export function filterActiveFindings(
  data: AnalysisResponse | null,
  currentGraph: SecurityGraph | null,
  nodeDepths: Map<string, number>,
  prodOnly: boolean,
  transitiveDepth: number
): any[] {
  if (!data?.findings) return [];

  return data.findings.filter((f) => {
    const { pkgName } = getFindingPackage(f);
    if (!pkgName) return true;

    if (prodOnly) {
      const cleanPkg = pkgName.toLowerCase();
      const isDevComp = (data.components || data.sbom?.components || []).some(
        (c: any) =>
          (c.name?.toLowerCase() === cleanPkg || c.bom_ref?.toLowerCase().includes(cleanPkg)) &&
          c.is_dev
      );
      if (isKnownDevPackage(cleanPkg) || isDevComp) return false;
    }

    if (data.graph?.nodes) {
      let pkgDepth: number | null = null;
      const cleanPkg = pkgName.toLowerCase();
      nodeDepths.forEach((depth, nodeId) => {
        const rawId = nodeId.toLowerCase();
        if (rawId.includes(cleanPkg) || rawId.split("@")[0].endsWith(cleanPkg)) {
          if (pkgDepth === null || depth < pkgDepth) pkgDepth = depth;
        }
      });

      if (pkgDepth !== null && pkgDepth > transitiveDepth) return false;

      if (currentGraph?.nodes) {
        const matchingRawNodes = data.graph.nodes.filter((n) => {
          const label = (n.data?.label || "").toLowerCase();
          return n.id.toLowerCase().includes(cleanPkg) || label.includes(cleanPkg);
        });
        if (matchingRawNodes.length > 0) {
          const isVisible = matchingRawNodes.some((rn) =>
            currentGraph.nodes.some((vn) => vn.id === rn.id)
          );
          if (!isVisible) return false;
        }
      }
    }

    return true;
  });
}

export function groupFindingsByPackage(activeFindings: any[]): GroupedPackageFindings[] {
  if (!activeFindings || activeFindings.length === 0) return [];
  const groups: Record<string, GroupedPackageFindings> = {};

  activeFindings.forEach((f) => {
    const { pkgName, version, ecosystem, key } = getFindingPackage(f);
    if (!groups[key]) {
      groups[key] = {
        key,
        pkgName,
        version,
        ecosystem,
        findings: [],
        highestSeverity: "LOW",
        fixVersion: "",
      };
    }
    groups[key].findings.push(f);

    const currentSev = f.severity?.toUpperCase() || "LOW";
    const groupSevIdx = SEVERITY_ORDER.indexOf(groups[key].highestSeverity);
    const curSevIdx = SEVERITY_ORDER.indexOf(currentSev);
    if (curSevIdx !== -1 && (groupSevIdx === -1 || curSevIdx < groupSevIdx)) {
      groups[key].highestSeverity = currentSev;
    }
  });

  Object.values(groups).forEach((g) => {
    const candidateFixes: string[] = [];
    g.findings.forEach((f) => {
      f.recommendations?.forEach((r: any) => {
        if (r?.fixed_version) candidateFixes.push(r.fixed_version);
      });
      f.evidence?.forEach((e: any) => {
        if (e?.raw_data?.fixed_version) candidateFixes.push(e.raw_data.fixed_version);
        if (e?.raw_data?.fixed) candidateFixes.push(e.raw_data.fixed);
      });
    });

    const bestFix = resolveHighestSafeVersion(g.version, candidateFixes);
    if (bestFix) g.fixVersion = bestFix;
    else if (candidateFixes.length > 0) g.fixVersion = candidateFixes[0];
  });

  return Object.values(groups).sort((a, b) => {
    const aIdx = SEVERITY_ORDER.indexOf(a.highestSeverity);
    const bIdx = SEVERITY_ORDER.indexOf(b.highestSeverity);
    if (aIdx !== bIdx) return aIdx - bIdx;
    return b.findings.length - a.findings.length;
  });
}
