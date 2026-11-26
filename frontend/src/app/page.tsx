"use client";

import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  fetchRepositoryAnalysis,
  fetchDemoAnalysis,
  fetchFolderAnalysis,
  compareScans,
} from "@/lib/api";
import { AnalysisResponse, CodeReviewItem, ScanHistoryRecord } from "@/types";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { OverviewDashboard } from "@/components/dashboard/OverviewDashboard";
import { CodeReviewerPanel } from "@/components/reviewer/CodeReviewerPanel";
import { SandboxPanel } from "@/components/sandbox/SandboxPanel";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";
import { SbomModal } from "@/components/modals/SbomModal";
import { ScanHistoryModal } from "@/components/modals/ScanHistoryModal";
import { TelemetryHud } from "@/components/scanner/TelemetryHud";
import { FindingsPanel } from "@/components/scanner/FindingsPanel";
import { SCENARIOS, ScenarioId } from "@/lib/executiveSummary";
import {
  downloadAIPrompt,
  downloadAuditReport,
  downloadExecutiveHtml,
  downloadPatchedManifest,
  downloadSbomJson,
} from "@/lib/reportExporters";
import {
  computeNodeDepths,
  countDevDependencies,
  filterActiveFindings,
  filterGraph,
  groupFindingsByPackage,
} from "@/lib/graphFiltering";
import {
  ArrowLeft,
  ChevronDown,
  Cpu,
  FileCode2,
  FolderUp,
  Loader2,
  Search,
  ShieldAlert,
  Sparkles,
  X,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

type WorkspaceView = "overview" | "scanner" | "reviewer" | "sandbox";

export default function Dashboard() {
  const [currentView, setCurrentView] = useState<WorkspaceView>("overview");
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUploadedFiles, setLastUploadedFiles] = useState<{ path: string; content: string }[]>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | string | null>(null);
  const [activeScenario, setActiveScenario] = useState<ScenarioId | null>(null);
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [focusTarget, setFocusTarget] = useState<{
    id?: string;
    finding?: any;
    packageKey?: string;
    timestamp: number;
  } | null>(null);
  const [showSbomModal, setShowSbomModal] = useState(false);
  const [showAllFindings, setShowAllFindings] = useState(false);
  const [prodOnly, setProdOnly] = useState(false);
  const [transitiveDepth, setTransitiveDepth] = useState<number>(10);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [selectedHistoryScan, setSelectedHistoryScan] = useState<ScanHistoryRecord | null>(null);
  const [comparisonResult, setComparisonResult] = useState<any | null>(null);
  const [comparingLoading, setComparingLoading] = useState(false);
  const [showScenariosDropdown, setShowScenariosDropdown] = useState(false);
  const [hudCollapsed, setHudCollapsed] = useState(false);
  const [expandedPackageKeys, setExpandedPackageKeys] = useState<Record<string, boolean>>({});
  const [scanElapsedSeconds, setScanElapsedSeconds] = useState(0);
  const [computedSbomSha, setComputedSbomSha] = useState<string>("");

  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const scanAbortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!loading) {
      setScanElapsedSeconds(0);
      return;
    }
    setScanElapsedSeconds(0);
    const timer = setInterval(() => setScanElapsedSeconds((prev) => prev + 1), 1000);
    return () => clearInterval(timer);
  }, [loading]);

  useEffect(() => {
    if (!data) {
      setComputedSbomSha("");
      return;
    }
    if (data?.detector_breakdown?.sbom_sha256) {
      setComputedSbomSha(data.detector_breakdown.sbom_sha256);
      return;
    }

    const components = data.sbom?.components || data.components || [];
    const rawPayload = JSON.stringify(components);

    const computeFallbackHash = () => {
      let hash = 0;
      for (let i = 0; i < rawPayload.length; i++) {
        hash = (hash << 5) - hash + rawPayload.charCodeAt(i);
        hash |= 0;
      }
      setComputedSbomSha(`0x${Math.abs(hash).toString(16).padStart(64, "0")}`);
    };

    if (typeof window !== "undefined" && window.crypto?.subtle) {
      const dataBuffer = new TextEncoder().encode(rawPayload);
      window.crypto.subtle
        .digest("SHA-256", dataBuffer)
        .then((hashBuffer) => {
          const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          setComputedSbomSha(`0x${hashHex}`);
        })
        .catch(computeFallbackHash);
    } else {
      computeFallbackHash();
    }
  }, [data]);

  useEffect(() => {
    try {
      const savedHistory = localStorage.getItem("supplygraph_scan_history");
      if (!savedHistory) return;
      const parsed = JSON.parse(savedHistory);
      if (Array.isArray(parsed)) {
        const sanitized: ScanHistoryRecord[] = parsed
          .filter((item): item is ScanHistoryRecord => Boolean(item && typeof item === "object"))
          .map((item) => ({
            id: String(item.id || `scan-${Date.now()}`),
            timestamp: String(item.timestamp || "Recently"),
            target: String(item.target || "Project"),
            total_components: Number(item.total_components) || 0,
            total_findings: Number(item.total_findings) || 0,
            blast_radius_score: Number(item.blast_radius_score) || 0,
            data: item.data || undefined,
          }));
        setScanHistory(sanitized);
      } else {
        localStorage.removeItem("supplygraph_scan_history");
      }
    } catch (_) {
      try {
        localStorage.removeItem("supplygraph_scan_history");
      } catch (_) {}
    }
  }, []);

  useEffect(() => {
    if (!data || !data.scan) return;
    try {
      const scanId = data.scan.id || `scan-${Date.now()}`;
      const target =
        data.scan.repository_url?.replace("https://github.com/", "") ||
        (activeScenario ? `Scenario ${activeScenario}` : "Uploaded Project");

      const record: ScanHistoryRecord = {
        id: scanId,
        timestamp: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        target,
        total_components:
          Number(data.scan.total_components) || Number(data.components?.length) || 0,
        total_findings: Number(data.scan.total_findings) || Number(data.findings?.length) || 0,
        blast_radius_score: Number(data.scan.blast_radius_score) || 0,
        data,
      };

      setScanHistory((prev) => {
        const currentList = Array.isArray(prev) ? prev : [];
        if (currentList.length > 0 && currentList[0]?.id === scanId) return currentList;
        const filtered = currentList.filter((item) => item?.id !== scanId);
        const updated = [record, ...filtered].slice(0, 10);
        try {
          localStorage.setItem("supplygraph_scan_history", JSON.stringify(updated));
        } catch (_) {}
        return updated;
      });
    } catch (_) {}
  }, [data, activeScenario]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleSelectHistoryScan = useCallback(
    async (record: ScanHistoryRecord) => {
      setSelectedHistoryScan(record);
      if (!data) return;
      setComparingLoading(true);
      try {
        if (!record?.data) throw new Error("Missing snapshot data");
        const res = await compareScans(record.data, data);
        setComparisonResult(res);
      } catch (e) {
        console.warn("Backend comparison fallback:", e);
        const currentComps = new Set((data.components || []).map((c: any) => c.name));
        const oldComps = new Set((record?.data?.components || []).map((c: any) => c.name));
        const added = (data.components || [])
          .filter((c: any) => !oldComps.has(c.name))
          .map((c: any) => ({
            change_type: "added",
            package_name: c.name,
            ecosystem: c.ecosystem,
            version_after: c.version,
          }));
        const removed = (record?.data?.components || [])
          .filter((c: any) => !currentComps.has(c.name))
          .map((c: any) => ({
            change_type: "removed",
            package_name: c.name,
            ecosystem: c.ecosystem,
            version_before: c.version,
          }));

        const curBlast = Number(data.scan?.blast_radius_score) || 0;
        const oldBlast =
          Number(record?.blast_radius_score ?? record?.data?.scan?.blast_radius_score) || 0;
        const blastShift = curBlast - oldBlast;

        setComparisonResult({
          blast_radius_delta: blastShift,
          dependency_changes: [...added, ...removed],
          finding_changes: [],
          summary: `Delta comparison between ${record.target} and current active scan. Blast shift: ${
            blastShift >= 0 ? "+" : ""
          }${blastShift.toFixed(1)}.`,
        });
      } finally {
        setComparingLoading(false);
      }
    },
    [data]
  );

  const handleLoadHistoryScan = useCallback((record: ScanHistoryRecord) => {
    if (record?.data) setData(record.data);
    setSelectedHistoryScan(null);
    setComparisonResult(null);
    setShowHistoryModal(false);
  }, []);

  const handleClearHistory = useCallback(() => {
    try {
      localStorage.removeItem("supplygraph_scan_history");
    } catch (_) {}
    setScanHistory([]);
    setSelectedHistoryScan(null);
    setComparisonResult(null);
  }, []);

  const handleCancelScan = useCallback(() => {
    scanAbortControllerRef.current?.abort();
    setLoading(false);
    setError("Scan cancelled by user.");
  }, []);

  const executeAnalysis = useCallback(
    async (urlToScan: string, overrideProdOnly?: boolean) => {
      const trimmed = urlToScan.trim();
      if (!trimmed) return;
      if (!/^https:\/\/github\.com\/[^\/]+\/[^\/]+/.test(trimmed)) {
        setError("Please enter a valid GitHub repository URL (e.g., https://github.com/org/repo)");
        return;
      }

      scanAbortControllerRef.current?.abort();
      const controller = new AbortController();
      scanAbortControllerRef.current = controller;

      setLoading(true);
      setError(null);
      setData(null);
      setActiveScenario(null);
      setFocusNodeId(null);
      setFocusTarget(null);
      setShowAllFindings(false);
      setCurrentView("scanner");
      const useProd = overrideProdOnly !== undefined ? overrideProdOnly : prodOnly;

      try {
        const result = await fetchRepositoryAnalysis(
          trimmed,
          useProd,
          transitiveDepth,
          controller.signal
        );
        setData(result);
      } catch (err: any) {
        setError(
          err.name === "AbortError"
            ? "Scan cancelled by user."
            : err.message || "Failed to establish secure handshake with analysis engine."
        );
      } finally {
        setLoading(false);
      }
    },
    [prodOnly, transitiveDepth]
  );

  const executeScenario = useCallback(async (scenarioId: ScenarioId) => {
    setLoading(true);
    setError(null);
    setData(null);
    setActiveScenario(scenarioId);
    setFocusNodeId(null);
    setFocusTarget(null);
    setShowAllFindings(false);
    setCurrentView("scanner");
    try {
      const result = await fetchDemoAnalysis(scenarioId);
      setData(result);
    } catch (err: any) {
      setError(err.message || `Failed to load Scenario ${scenarioId}.`);
      setActiveScenario(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setLoading(true);
    setError(null);
    setData(null);
    setActiveScenario(null);
    setFocusNodeId(null);
    setFocusTarget(null);
    setShowAllFindings(false);
    setCurrentView("scanner");

    try {
      const firstPath = fileList[0].webkitRelativePath || fileList[0].name;
      const folderName = firstPath.split("/")[0] || "Local Project";
      const maxFileSize = 60 * 1024;
      const skipDirs = [
        "node_modules/", ".git/", ".next/", "dist/", "build/",
        "venv/", ".venv/", "__pycache__/", "coverage/", ".vscode/",
      ];
      const skipExts = [
        ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".pdf", ".lockb", ".gif", ".webp", ".zip", ".tar",
        ".gz", ".exe", ".bin",
      ];

      const lockfileCandidates: File[] = [];
      const sourceCandidates: File[] = [];

      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const lowerPath = (file.webkitRelativePath || file.name).toLowerCase();
        if (skipDirs.some((dir) => lowerPath.includes(dir))) continue;
        if (skipExts.some((ext) => lowerPath.endsWith(ext))) continue;
        if (file.size > maxFileSize) continue;

        const fileName = lowerPath.split("/").pop() || "";
        const isLockfileOrWorkflow =
          fileName === "package.json" ||
          fileName === "package-lock.json" ||
          fileName === "requirements.txt" ||
          fileName === "poetry.lock" ||
          fileName === "pipfile.lock" ||
          lowerPath.includes(".github/workflows/");

        if (isLockfileOrWorkflow) {
          lockfileCandidates.push(file);
        } else if (
          [".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml"].some((ext) =>
            lowerPath.endsWith(ext)
          ) ||
          fileName === "dockerfile"
        ) {
          sourceCandidates.push(file);
        }
      }

      const selectedFiles = [
        ...lockfileCandidates.slice(0, 15),
        ...sourceCandidates.slice(0, 25),
      ].slice(0, 40);

      if (selectedFiles.length === 0) {
        throw new Error("No source code or lockfiles found in uploaded folder.");
      }

      const readFiles = await Promise.all(
        selectedFiles.map(async (file) => ({
          path: file.webkitRelativePath || file.name,
          content: await file.text(),
        }))
      );

      const result = await fetchFolderAnalysis(folderName, readFiles, prodOnly, transitiveDepth);
      setLastUploadedFiles(readFiles);
      setData(result);
    } catch (err: any) {
      setError(err.message || "Failed to analyze uploaded project folder.");
    } finally {
      setLoading(false);
      if (folderInputRef.current) folderInputRef.current.value = "";
    }
  };

  const copyToClipboard = useCallback((text: string, index: number | string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1800);
  }, []);

  const handleFindingClick = useCallback((finding: any) => {
    const titleMatch = (finding?.title || "").match(
      /(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+|PYSEC-\d{4}-\d+|SNYK-[A-Z0-9-]+)/i
    );
    const targetId =
      (titleMatch ? titleMatch[1] : null) ||
      finding?.origin_candidate ||
      finding?.entity_id ||
      finding?.title ||
      "";
    setFocusTarget({ id: targetId, finding, timestamp: Date.now() });
    setFocusNodeId(targetId);
  }, []);

  const handlePackageFocus = useCallback((packageKey: string, sampleFinding?: any) => {
    setFocusTarget({ id: packageKey, packageKey, finding: sampleFinding, timestamp: Date.now() });
    setFocusNodeId(packageKey);
  }, []);

  const handleGetStarted = useCallback(() => setCurrentView("scanner"), []);
  const handleSelectScenario = useCallback((id: ScenarioId) => executeScenario(id), [executeScenario]);
  const handleNodeClick = useCallback((nodeId: string) => {
    setFocusTarget({ id: nodeId, timestamp: Date.now() });
    setFocusNodeId(nodeId);
  }, []);

  const nodeDepths = useMemo(() => computeNodeDepths(data), [data]);
  const maxGraphDepth = useMemo(() => {
    if (nodeDepths.size === 0) return 10;
    return Math.max(Math.max(...Array.from(nodeDepths.values()), 1), 1);
  }, [nodeDepths]);

  useEffect(() => {
    if (data?.scan?.id && maxGraphDepth > 0) {
      setTransitiveDepth(maxGraphDepth);
    } else if (data?.graph && maxGraphDepth > 0) {
      setTransitiveDepth((prev) => (prev > maxGraphDepth ? maxGraphDepth : prev));
    }
  }, [data?.scan?.id, data?.graph, maxGraphDepth]);

  const devDepsCount = useMemo(() => countDevDependencies(data), [data]);
  const currentGraph = useMemo(
    () => filterGraph(data, nodeDepths, prodOnly, transitiveDepth),
    [data, nodeDepths, prodOnly, transitiveDepth]
  );
  const activeFindings = useMemo(
    () => filterActiveFindings(data, currentGraph, nodeDepths, prodOnly, transitiveDepth),
    [data, currentGraph, nodeDepths, prodOnly, transitiveDepth]
  );
  const currentCodeReviews = useMemo(() => data?.code_reviews || [], [data?.code_reviews]);
  const handleReviewsUpdated = useCallback((updated: CodeReviewItem[]) => {
    setData((prev) => (prev ? { ...prev, code_reviews: updated } : null));
  }, []);
  const displayedFindings = useMemo(
    () => (showAllFindings ? activeFindings : activeFindings.slice(0, 25)),
    [activeFindings, showAllFindings]
  );
  const groupedFindings = useMemo(() => groupFindingsByPackage(activeFindings), [activeFindings]);

  useEffect(() => {
    if (groupedFindings.length > 0) {
      setExpandedPackageKeys((prev) =>
        Object.keys(prev).length === 0 && groupedFindings[0]
          ? { [groupedFindings[0].key]: true }
          : prev
      );
    }
  }, [groupedFindings]);

  const togglePackageExpanded = useCallback((key: string) => {
    setExpandedPackageKeys((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  const toggleAllPackages = useCallback(
    (expand: boolean) => {
      if (!expand) {
        setExpandedPackageKeys({});
        return;
      }
      const all: Record<string, boolean> = {};
      groupedFindings.forEach((g) => {
        all[g.key] = true;
      });
      setExpandedPackageKeys(all);
    },
    [groupedFindings]
  );

  const targetSummary =
    data?.scan?.repository_url?.replace("https://github.com/", "") ||
    (activeScenario ? `Scenario ${activeScenario}` : "Active Project");

  return (
    <ErrorBoundary fallbackTitle="SupplyGraph Session Recovered">
      <div className="flex flex-col h-screen w-screen bg-[#070b13] text-zinc-100 overflow-hidden font-sans select-none">
        <header className="h-14 border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-xl flex items-center justify-between px-6 sticky top-0 z-40 shrink-0">
          <div className="flex items-center space-x-6">
            <button
              type="button"
              onClick={() => setCurrentView("overview")}
              aria-label="SupplyGraph Overview"
              className="flex items-center space-x-2.5 cursor-pointer group text-left focus:outline-none focus:ring-2 focus:ring-indigo-500/60 rounded-lg pr-1"
            >
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-red-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-red-500/20 group-hover:scale-105 transition-transform">
                <ShieldAlert className="w-4 h-4 text-white" aria-hidden="true" />
              </div>
              <span className="text-sm font-bold tracking-tight text-zinc-100">SupplyGraph</span>
            </button>

            <nav aria-label="Primary navigation" className="hidden md:flex items-center space-x-1">
              <button
                type="button"
                onClick={() => setCurrentView("overview")}
                aria-current={currentView === "overview" ? "page" : undefined}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                  currentView === "overview"
                    ? "bg-zinc-800 text-zinc-100 font-semibold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
                )}
              >
                <span>Overview</span>
              </button>

              <button
                type="button"
                onClick={() => setCurrentView("scanner")}
                aria-current={currentView === "scanner" ? "page" : undefined}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                  currentView === "scanner"
                    ? "bg-zinc-800 text-zinc-100 font-semibold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
                )}
              >
                <span>Scanner & Graph</span>
              </button>

              <button
                type="button"
                onClick={() => setCurrentView("reviewer")}
                aria-current={currentView === "reviewer" ? "page" : undefined}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                  currentView === "reviewer"
                    ? "bg-zinc-800 text-zinc-100 font-semibold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
                )}
              >
                <Sparkles className="w-3 h-3 text-amber-400" aria-hidden="true" />
                <span>Code Reviewer</span>
                {data?.code_reviews && data.code_reviews.length > 0 && (
                  <span className="ml-1 px-1.5 py-0.2 rounded-full text-[9px] bg-amber-500/20 text-amber-300 font-mono font-bold">
                    {data.code_reviews.length}
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setCurrentView("sandbox")}
                aria-current={currentView === "sandbox" ? "page" : undefined}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                  currentView === "sandbox"
                    ? "bg-zinc-800 text-zinc-100 font-semibold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
                )}
              >
                <Zap className="w-3 h-3 text-red-400" aria-hidden="true" />
                <span>Sandbox Execution</span>
              </button>
            </nav>
          </div>

          <div className="flex items-center space-x-3">
            {currentView === "overview" && (
              <button
                type="button"
                onClick={() => setCurrentView("scanner")}
                className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white text-xs font-semibold shadow-md shadow-red-600/20 transition-all flex items-center space-x-1.5 hover:scale-105 active:scale-95"
              >
                <span>Get Started →</span>
              </button>
            )}

            {currentView === "scanner" && (
              <div className="hidden lg:flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => setShowSbomModal(true)}
                  disabled={!data}
                  className="px-2.5 py-1 rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-850 text-zinc-300 disabled:opacity-40 text-xs font-mono flex items-center space-x-1.5 transition-colors"
                >
                  <FileCode2 className="w-3.5 h-3.5 text-blue-400" aria-hidden="true" />
                  <span>CycloneDX SBOM</span>
                </button>
              </div>
            )}
          </div>
        </header>

        <main className="flex-1 flex flex-col overflow-hidden">
          {currentView === "overview" && (
            <div className="flex-1 overflow-y-auto">
              <OverviewDashboard
                onGetStarted={handleGetStarted}
                onSelectScenario={handleSelectScenario}
              />
            </div>
          )}

          {currentView === "scanner" && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="border-b border-zinc-800/80 bg-zinc-950/90 px-6 py-2.5 shrink-0">
                <div className="flex flex-wrap items-center gap-2.5">
                  <div className="relative flex-1 min-w-[280px]">
                    <Search
                      className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400"
                      aria-hidden="true"
                    />
                    <input
                      ref={inputRef}
                      type="text"
                      aria-label="GitHub repository URL"
                      value={githubUrl}
                      onChange={(e) => setGithubUrl(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && executeAnalysis(githubUrl)}
                      placeholder="https://github.com/owner/repository — Press Enter to scan"
                      className="w-full pl-10 pr-24 py-1.5 rounded-xl bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:ring-1 focus:ring-red-500/50 transition-all"
                    />
                    <button
                      type="button"
                      onClick={() => executeAnalysis(githubUrl)}
                      disabled={loading}
                      className="absolute right-1 top-1/2 -translate-y-1/2 px-3 py-1 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center space-x-1 transition-colors shadow-sm"
                    >
                      {loading ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                      ) : (
                        <Zap className="w-3.5 h-3.5" aria-hidden="true" />
                      )}
                      <span>Scan</span>
                    </button>
                  </div>

                  <input
                    type="file"
                    aria-label="Upload local project folder"
                    ref={folderInputRef}
                    onChange={handleFolderUpload}
                    {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
                    className="hidden"
                  />

                  <button
                    type="button"
                    onClick={() => folderInputRef.current?.click()}
                    disabled={loading}
                    className="px-3 py-1.5 rounded-xl bg-indigo-600/15 hover:bg-indigo-600/25 border border-indigo-500/30 hover:border-indigo-500/50 text-indigo-300 hover:text-indigo-200 text-xs font-semibold flex items-center space-x-1.5 transition-all shrink-0 shadow-sm"
                    title="Upload and scan a local project directory from your computer"
                  >
                    <FolderUp className="w-3.5 h-3.5 text-indigo-400" aria-hidden="true" />
                    <span>Upload Folder</span>
                  </button>

                  <div className="relative shrink-0">
                    <button
                      type="button"
                      onClick={() => setShowScenariosDropdown((prev) => !prev)}
                      aria-expanded={showScenariosDropdown}
                      aria-haspopup="menu"
                      className={cn(
                        "px-3 py-1.5 rounded-xl text-xs font-mono font-medium flex items-center space-x-1.5 border transition-all shadow-sm",
                        activeScenario
                          ? "bg-red-500/15 border-red-500/40 text-red-300 font-semibold"
                          : "bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700"
                      )}
                      title="Test deterministic evaluation scenarios (A–E)"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />
                      <span>{activeScenario ? `Scenario ${activeScenario}` : "Demo Scenarios"}</span>
                      <ChevronDown
                        className={cn(
                          "w-3.5 h-3.5 text-zinc-400 transition-transform",
                          showScenariosDropdown && "rotate-180"
                        )}
                        aria-hidden="true"
                      />
                    </button>

                    {showScenariosDropdown && (
                      <div
                        role="menu"
                        className="absolute left-0 sm:right-0 sm:left-auto top-full mt-2 w-80 bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl z-50 p-2 space-y-1 backdrop-blur-2xl"
                      >
                        <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase text-zinc-400 border-b border-zinc-800/80 flex items-center justify-between">
                          <span>Deterministic Scenarios</span>
                          <span className="text-[9px] text-zinc-500">5 Evaluator Modes</span>
                        </div>
                        {SCENARIOS.map((s) => (
                          <button
                            key={s.id}
                            type="button"
                            role="menuitem"
                            onClick={() => {
                              setShowScenariosDropdown(false);
                              executeScenario(s.id);
                            }}
                            className={cn(
                              "w-full text-left px-3 py-2 rounded-xl text-xs font-mono flex items-center space-x-2.5 transition-colors",
                              activeScenario === s.id
                                ? "bg-red-500/20 text-red-200 border border-red-500/30"
                                : "hover:bg-zinc-900 text-zinc-300"
                            )}
                          >
                            <span className="text-base" aria-hidden="true">
                              {s.icon}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="font-semibold text-zinc-100">Scenario {s.id}</div>
                              <div className="text-[10px] text-zinc-400 truncate">{s.label}</div>
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => setProdOnly((prev) => !prev)}
                    aria-pressed={prodOnly}
                    className={cn(
                      "px-2.5 py-1.5 rounded-xl text-xs font-mono font-medium flex items-center space-x-1.5 border transition-all shrink-0 shadow-sm cursor-pointer",
                      prodOnly
                        ? "bg-emerald-950/60 border-emerald-500/70 text-emerald-300 shadow-emerald-950/30"
                        : "bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-zinc-100 hover:border-zinc-700"
                    )}
                    title={
                      prodOnly
                        ? `Filtering: Production Only (${devDepsCount} Dev Dependenc${
                            devDepsCount === 1 ? "y" : "ies"
                          } Omitted)`
                        : "Filtering: All Dependencies (Including Dev Dependencies)"
                    }
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        "w-2 h-2 rounded-full",
                        prodOnly ? "bg-emerald-400 animate-pulse" : "bg-zinc-600"
                      )}
                    />
                    <span>{prodOnly ? "Prod Only" : "All Deps"}</span>
                    {devDepsCount > 0 && (
                      <span
                        className={cn(
                          "px-1.5 py-0.2 rounded-full text-[9px] font-bold font-mono transition-colors",
                          prodOnly
                            ? "bg-emerald-500/25 text-emerald-300 border border-emerald-500/30"
                            : "bg-zinc-800 text-zinc-400"
                        )}
                      >
                        {prodOnly ? `-${devDepsCount}` : `${devDepsCount} dev`}
                      </span>
                    )}
                  </button>

                  <div
                    className={cn(
                      "flex items-center space-x-1.5 px-2.5 py-1.5 rounded-xl border text-xs font-mono transition-all shrink-0 shadow-sm",
                      transitiveDepth < maxGraphDepth
                        ? "bg-indigo-950/40 border-indigo-500/60 text-indigo-200"
                        : "bg-zinc-900/80 border-zinc-800 text-zinc-300"
                    )}
                    title={`Max Transitive Dependency Depth Filter: ${transitiveDepth} of ${maxGraphDepth} hops`}
                  >
                    <span className="text-zinc-400 text-[10px] uppercase">Depth:</span>
                    <span className="text-indigo-400 font-semibold">{transitiveDepth}</span>
                    <span className="text-zinc-500 text-[10px]">/{maxGraphDepth}</span>
                    <div className="flex items-center space-x-1 ml-0.5">
                      <button
                        type="button"
                        aria-label="Decrease transitive depth filter"
                        onClick={() =>
                          setTransitiveDepth((prev) =>
                            Math.max(1, Math.min(prev, maxGraphDepth) - 1)
                          )
                        }
                        disabled={transitiveDepth <= 1}
                        className="w-4 h-4 rounded flex items-center justify-center bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-zinc-300 text-[10px] transition-colors active:scale-90"
                        title="Decrease depth (hide deeper transitive hops)"
                      >
                        -
                      </button>
                      <button
                        type="button"
                        aria-label="Increase transitive depth filter"
                        onClick={() =>
                          setTransitiveDepth((prev) =>
                            Math.min(Math.max(maxGraphDepth, 20), prev + 1)
                          )
                        }
                        disabled={transitiveDepth >= Math.max(maxGraphDepth, 20)}
                        className="w-4 h-4 rounded flex items-center justify-center bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-zinc-300 text-[10px] transition-colors active:scale-90"
                        title="Increase depth (reveal deeper transitive hops)"
                      >
                        +
                      </button>
                    </div>
                  </div>
                </div>

                {error && (
                  <div
                    role="alert"
                    className="mt-2 p-2.5 rounded-lg bg-red-950/40 border border-red-800/40 text-red-300 text-xs font-mono flex items-center justify-between"
                  >
                    <span>{error}</span>
                    <button
                      type="button"
                      aria-label="Dismiss error message"
                      onClick={() => setError(null)}
                      className="text-zinc-400 hover:text-white"
                    >
                      <X className="w-3.5 h-3.5" aria-hidden="true" />
                    </button>
                  </div>
                )}
              </div>

              <div className="flex-1 flex overflow-hidden relative">
                {!data && !loading ? (
                  <div className="m-auto flex flex-col items-center justify-center text-center p-8 max-w-md space-y-4">
                    <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-500 shadow-xl">
                      <ShieldAlert className="w-8 h-8 text-red-400" aria-hidden="true" />
                    </div>
                    <div>
                      <h2 className="text-base font-bold text-zinc-100">
                        Ready to Analyze Supply Chain
                      </h2>
                      <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                        Paste any public GitHub repository URL, upload a local project folder from
                        your computer, or select one of the demo scenarios above.
                      </p>
                    </div>
                    <div className="flex items-center space-x-2 pt-2">
                      <button
                        type="button"
                        onClick={() => executeScenario("A")}
                        className="px-3.5 py-1.5 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-xs font-mono text-zinc-300 transition-colors"
                      >
                        Load Scenario A
                      </button>
                      <button
                        type="button"
                        onClick={() => folderInputRef.current?.click()}
                        className="px-3.5 py-1.5 rounded-xl bg-indigo-600/15 hover:bg-indigo-600/25 border border-indigo-500/30 text-xs font-mono text-indigo-300 transition-colors"
                      >
                        Upload Folder
                      </button>
                    </div>
                  </div>
                ) : loading ? (
                  <div
                    role="status"
                    aria-live="polite"
                    className="m-auto flex flex-col items-center justify-center text-center p-8 space-y-4 max-w-md"
                  >
                    <div className="relative">
                      <div className="w-16 h-16 rounded-full border-2 border-red-500/20 border-t-red-500 animate-spin" />
                      <div className="absolute inset-0 flex items-center justify-center">
                        <Cpu className="w-6 h-6 text-zinc-400 animate-pulse" aria-hidden="true" />
                      </div>
                    </div>
                    <div>
                      <p className="text-xs font-mono text-zinc-200 tracking-wider uppercase font-semibold">
                        Traversing Multi-Hop Attack DAG...{" "}
                        {scanElapsedSeconds > 0 && `(${scanElapsedSeconds}s)`}
                      </p>
                      <p className="text-[11px] font-mono text-zinc-400 mt-1">
                        Parsing Lockfiles → OSV Batch Intel → Heuristic Detectors → Code Reviewer
                      </p>
                    </div>
                    <div className="flex items-center space-x-2 pt-1">
                      <button
                        type="button"
                        onClick={handleCancelScan}
                        className="px-3.5 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 text-zinc-300 text-xs font-mono transition-all flex items-center space-x-1.5 shadow-sm active:scale-95"
                      >
                        <X className="w-3.5 h-3.5 text-zinc-400" aria-hidden="true" />
                        <span>Cancel Scan</span>
                      </button>
                      {scanElapsedSeconds >= 6 && (
                        <button
                          type="button"
                          onClick={() => {
                            handleCancelScan();
                            folderInputRef.current?.click();
                          }}
                          className="px-3.5 py-1.5 rounded-lg bg-indigo-950/70 hover:bg-indigo-900/80 border border-indigo-700/60 text-indigo-300 text-xs font-mono transition-all flex items-center space-x-1.5 shadow-sm"
                        >
                          <FolderUp className="w-3.5 h-3.5 text-indigo-400" aria-hidden="true" />
                          <span>Switch to Folder Upload</span>
                        </button>
                      )}
                    </div>
                  </div>
                ) : data ? (
                  <>
                    <div className="flex-1 flex flex-col h-full relative">
                      <div className="absolute top-4 left-4 z-20">
                        <TelemetryHud
                          data={data}
                          activeScenario={activeScenario}
                          currentGraph={currentGraph}
                          activeFindingsCount={activeFindings.length}
                          scanHistoryCount={scanHistory.length}
                          prodOnly={prodOnly}
                          transitiveDepth={transitiveDepth}
                          maxGraphDepth={maxGraphDepth}
                          hudCollapsed={hudCollapsed}
                          onToggleCollapse={setHudCollapsed}
                          onOpenHistory={() => {
                            setSelectedHistoryScan(null);
                            setComparisonResult(null);
                            setShowHistoryModal(true);
                          }}
                        />
                      </div>

                      {currentGraph && (
                        <GraphCanvas
                          graph={currentGraph}
                          focusNodeId={focusNodeId}
                          focusTarget={focusTarget}
                          onNodeClick={handleNodeClick}
                        />
                      )}
                    </div>

                    <FindingsPanel
                      data={data}
                      activeScenario={activeScenario}
                      activeFindings={activeFindings}
                      displayedFindings={displayedFindings}
                      groupedFindings={groupedFindings}
                      currentCodeReviews={currentCodeReviews}
                      copiedIndex={copiedIndex}
                      prodOnly={prodOnly}
                      transitiveDepth={transitiveDepth}
                      maxGraphDepth={maxGraphDepth}
                      showAllFindings={showAllFindings}
                      expandedPackageKeys={expandedPackageKeys}
                      onCopy={copyToClipboard}
                      onFindingClick={handleFindingClick}
                      onPackageFocus={handlePackageFocus}
                      onTogglePackageExpanded={togglePackageExpanded}
                      onToggleAllPackages={toggleAllPackages}
                      onToggleShowAllFindings={() => setShowAllFindings((prev) => !prev)}
                      onResetFilters={() => {
                        setTransitiveDepth(maxGraphDepth);
                        setProdOnly(false);
                      }}
                      onDownloadAIPrompt={() => downloadAIPrompt(data)}
                      onDownloadPatchedManifest={() => downloadPatchedManifest(data)}
                      onDownloadExecutiveHtml={() => downloadExecutiveHtml(data, activeScenario)}
                      onDownloadReport={() => downloadAuditReport(data)}
                      onNavigateView={(view) => setCurrentView(view)}
                    />
                  </>
                ) : null}
              </div>
            </div>
          )}

          {currentView === "reviewer" && (
            <div className="flex-1 flex flex-col overflow-y-auto bg-zinc-950">
              <div className="max-w-7xl mx-auto w-full px-6 py-6 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-zinc-800/80">
                  <div className="flex items-center space-x-3">
                    <button
                      type="button"
                      onClick={() => setCurrentView("scanner")}
                      className="p-2 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 hover:text-white transition-colors flex items-center space-x-1.5 text-xs font-mono shadow-sm"
                      title="Return to Dependency Graph & Findings"
                    >
                      <ArrowLeft className="w-4 h-4" aria-hidden="true" />
                      <span>Graph & Findings</span>
                    </button>
                    <div>
                      <h1 className="text-lg font-bold text-zinc-100 flex items-center space-x-2">
                        <Sparkles className="w-4 h-4 text-amber-400" aria-hidden="true" />
                        <span>Code Reviewer & AI Patches</span>
                      </h1>
                      <p className="text-xs text-zinc-400 mt-0.5">
                        High-resolution static AST analysis, vulnerable code snippets, and automated
                        git patch generators.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <div className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400">
                      Target: <span className="text-zinc-200 font-semibold">{targetSummary}</span>
                    </div>
                    <div className="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 font-semibold">
                      {currentCodeReviews.length} Patches Ready
                    </div>
                  </div>
                </div>

                <CodeReviewerPanel
                  codeReviews={currentCodeReviews}
                  onReviewsUpdated={handleReviewsUpdated}
                />
              </div>
            </div>
          )}

          {currentView === "sandbox" && (
            <div className="flex-1 flex flex-col overflow-y-auto bg-zinc-950">
              <div className="max-w-7xl mx-auto w-full px-6 py-6 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-zinc-800/80">
                  <div className="flex items-center space-x-3">
                    <button
                      type="button"
                      onClick={() => setCurrentView("scanner")}
                      className="p-2 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 hover:text-white transition-colors flex items-center space-x-1.5 text-xs font-mono shadow-sm"
                      title="Return to Dependency Graph & Findings"
                    >
                      <ArrowLeft className="w-4 h-4" aria-hidden="true" />
                      <span>Graph & Findings</span>
                    </button>
                    <div>
                      <h1 className="text-lg font-bold text-zinc-100 flex items-center space-x-2">
                        <Zap className="w-4 h-4 text-red-400" aria-hidden="true" />
                        <span>Dynamic Detonation Sandbox</span>
                      </h1>
                      <p className="text-xs text-zinc-400 mt-0.5">
                        Isolated runtime container: execute suspect lifecycle scripts, observe
                        network beacons, and verify evasion payloads.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <div className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400">
                      Target: <span className="text-zinc-200 font-semibold">{targetSummary}</span>
                    </div>
                    <div className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 font-semibold">
                      Isolated Container
                    </div>
                  </div>
                </div>

                <SandboxPanel
                  files={lastUploadedFiles}
                  projectName={data?.scan?.repository_url || "Active Workspace"}
                />
              </div>
            </div>
          )}
        </main>

        <SbomModal
          open={showSbomModal}
          onClose={() => setShowSbomModal(false)}
          data={data}
          computedSbomSha={computedSbomSha}
          copiedIndex={copiedIndex}
          onCopy={copyToClipboard}
          onDownloadSbom={() => downloadSbomJson(data, computedSbomSha)}
        />

        <ScanHistoryModal
          open={showHistoryModal}
          onClose={() => {
            setShowHistoryModal(false);
            setSelectedHistoryScan(null);
            setComparisonResult(null);
          }}
          data={data}
          activeScenario={activeScenario}
          scanHistory={scanHistory}
          selectedHistoryScan={selectedHistoryScan}
          comparisonResult={comparisonResult}
          comparingLoading={comparingLoading}
          onResetSelected={() => {
            setSelectedHistoryScan(null);
            setComparisonResult(null);
          }}
          onSelectHistoryScan={handleSelectHistoryScan}
          onLoadHistoryScan={handleLoadHistoryScan}
          onClearHistory={handleClearHistory}
        />
      </div>
    </ErrorBoundary>
  );
}
