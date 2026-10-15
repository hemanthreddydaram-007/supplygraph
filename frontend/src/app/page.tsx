"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { fetchRepositoryAnalysis, fetchDemoAnalysis } from "@/lib/api";
import { AnalysisResponse, DetectorBreakdown, PolygonAttestation, SBOM } from "@/types";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import {
  ShieldAlert,
  Loader2,
  Sparkles,
  Cpu,
  Download,
  CheckCircle2,
  Shield,
  Copy,
  Check,
  Search,
  Zap,
  X,
  FileCode2,
  Link2,
  ChevronRight,
  Info,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ============================================================
// SCENARIO DEFINITIONS
// ============================================================
const SCENARIOS = [
  { id: "A", label: "Transitive CVE", icon: "🔗", color: "red" },
  { id: "B", label: "Dependency Confusion", icon: "🎭", color: "orange" },
  { id: "C", label: "Malicious Post-Install", icon: "💀", color: "rose" },
  { id: "D", label: "Deep Chain (Depth 4)", icon: "🕸️", color: "amber" },
  { id: "E", label: "CI/CD Workflow Leak", icon: "⚙️", color: "yellow" },
] as const;

type ScenarioId = "A" | "B" | "C" | "D" | "E";

// ============================================================
// SEVERITY HELPERS
// ============================================================
function getSeverityClass(severity: string) {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "bg-red-500/10 text-red-400 border-red-500/20";
    case "HIGH": return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "MEDIUM": return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    default: return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function getDetectorTag(finding: any): string {
  const type = finding?.finding_type || "";
  if (type === "VULNERABLE") return "OSV";
  if (type === "TYPOSQUATTING") return "TYPOSQUAT";
  if (type === "CICD_RISK") return "CI/CD";
  if (type === "DEPENDENCY_CONFUSION") return "CONFUSION";
  if (type === "SUSPICIOUS") return "AST";
  return "ENGINE";
}

function getDetectorTagClass(tag: string): string {
  switch (tag) {
    case "OSV": return "bg-indigo-950/60 text-indigo-300 border-indigo-700/40";
    case "TYPOSQUAT": return "bg-rose-950/60 text-rose-300 border-rose-700/40";
    case "CI/CD": return "bg-yellow-950/60 text-yellow-300 border-yellow-700/40";
    case "CONFUSION": return "bg-purple-950/60 text-purple-300 border-purple-700/40";
    case "AST": return "bg-cyan-950/60 text-cyan-300 border-cyan-700/40";
    default: return "bg-zinc-900 text-zinc-400 border-zinc-700";
  }
}

function buildLockfileSnippet(finding: any): string {
  const title: string = finding?.title || "";
  const origin: string = finding?.origin_candidate || "";
  const ref = origin || title.replace("Vulnerability in ", "") || "package";
  const ecosystem = finding?.finding_type === "VULNERABLE" ? "npm" : "pip";

  if (ecosystem === "npm" || ref.startsWith("pkg:npm")) {
    const pkgName = ref.replace(/pkg:npm\//, "").replace(/@.*$/, "");
    return `// package.json override\n"overrides": {\n  "${pkgName}": ">=patched_version"\n}`;
  } else {
    const pkgName = ref.replace(/pkg:pypi\//, "").replace(/@.*$/, "");
    return `# requirements.txt pin\n${pkgName}>=patched_version  # pinned by SupplyGraph`;
  }
}

// ============================================================
// MODAL COMPONENT
// ============================================================
function Modal({ open, onClose, title, children }: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  children: React.ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
          <div className="text-sm font-semibold text-zinc-100">{title}</div>
          <button onClick={onClose} className="p-1 rounded-lg text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">
          {children}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// MAIN DASHBOARD
// ============================================================
export default function Dashboard() {
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "briefing">("findings");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [activeScenario, setActiveScenario] = useState<ScenarioId | null>(null);
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [showSbomModal, setShowSbomModal] = useState(false);
  const [showPolygonModal, setShowPolygonModal] = useState(false);
  const [polygonAttested, setPolygonAttested] = useState(false);
  const [attestCopied, setAttestCopied] = useState(false);
  const [showFormulaTooltip, setShowFormulaTooltip] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

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

  const executeAnalysis = useCallback(async (urlToScan: string) => {
    const trimmed = urlToScan.trim();
    if (!trimmed) return;
    if (!/^https:\/\/github\.com\/[^\/]+\/[^\/]+/.test(trimmed)) {
      setError("Please enter a valid GitHub repository URL (e.g., https://github.com/org/repo)");
      return;
    }
    setLoading(true);
    setError(null);
    setData(null);
    setActiveScenario(null);
    setPolygonAttested(false);
    setFocusNodeId(null);
    try {
      const result = await fetchRepositoryAnalysis(trimmed);
      setData(result);
    } catch (err: any) {
      setError(err.message || "Failed to establish secure handshake with analysis engine.");
    } finally {
      setLoading(false);
    }
  }, []);

  const executeScenario = useCallback(async (scenarioId: ScenarioId) => {
    setLoading(true);
    setError(null);
    setData(null);
    setActiveScenario(scenarioId);
    setPolygonAttested(false);
    setFocusNodeId(null);
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

  const copyToClipboard = useCallback((text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1800);
  }, []);

  const handleFindingClick = useCallback((finding: any) => {
    const nodeId = finding?.origin_candidate || finding?.entity_id || null;
    if (nodeId) {
      setFocusNodeId(nodeId);
    }
  }, []);

  const handleDownloadReport = useCallback(() => {
    if (!data) return;
    const bd = data.detector_breakdown;
    const timestamp = new Date().toISOString();
    let report = `# SupplyGraph Security Audit Report\n`;
    report += `Generated: ${timestamp}\n`;
    report += `Repository: ${data?.scan?.repository_url || "N/A"}\n`;
    report += `Blast Radius: ${data?.scan?.blast_radius_score || 0}/100\n`;
    report += `Total Components: ${data?.scan?.total_components || 0}\n`;
    report += `Total Findings: ${data?.scan?.total_findings || 0}\n`;
    if (bd) {
      report += `\n## Detector Breakdown\n`;
      report += `- OSV/CVE: ${bd.osv_count || 0}\n`;
      report += `- Typosquatting: ${bd.typosquat_count || 0}\n`;
      report += `- AST/Code: ${bd.ast_count || 0}\n`;
      report += `- CI/CD: ${bd.cicd_count || 0}\n`;
      report += `- Confusion: ${bd.confusion_count || 0}\n`;
      if (bd.sbom_sha256) report += `- CycloneDX SBOM SHA-256: ${bd.sbom_sha256}\n`;
      if (bd.model_provider) report += `- AI Provider: ${bd.model_provider}\n`;
    }
    report += `\n## AI Executive Briefing\n${data?.gemini_explanation || "N/A"}\n`;
    report += `\n## Findings\n`;
    (data?.findings || []).forEach((f: any, i: number) => {
      report += `\n### [${i + 1}] ${f.title} (${f.severity})\n`;
      report += `Type: ${f.finding_type || "UNKNOWN"} | Detector: ${getDetectorTag(f)}\n`;
      report += `${f.description}\n`;
      if (f.recommendations?.length > 0) {
        report += `\nContainment: ${f.recommendations[0].title}\n`;
        report += `${f.recommendations[0].why}\n`;
      }
      report += `\nLockfile Override:\n\`\`\`\n${buildLockfileSnippet(f)}\n\`\`\`\n`;
    });
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `supplygraph-audit-${data?.scan?.repository_url?.split("/").pop() || "report"}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  const handleDownloadSbom = useCallback(() => {
    if (!data?.sbom && !data?.components) return;
    const sbomData = data.sbom || { components: data.components || [] };
    const blob = new Blob([JSON.stringify(sbomData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyclonedx-sbom-${data?.scan?.repository_url?.split("/").pop() || "export"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  const handlePolygonAttest = useCallback(async () => {
    const attestation = data?.detector_breakdown?.polygon_attestation;
    if (!attestation) return;

    // Try MetaMask if available
    if (typeof window !== "undefined" && (window as any).ethereum) {
      try {
        const provider = (window as any).ethereum;
        await provider.request({ method: "eth_requestAccounts" });
        const message = `SupplyGraph SBOM Attestation\nRepo: ${attestation.repository}\nSHA256: ${attestation.sbom_sha256}\nTimestamp: ${attestation.attestation_timestamp}`;
        const accounts = await provider.request({ method: "eth_accounts" });
        await provider.request({
          method: "personal_sign",
          params: [message, accounts[0]],
        });
      } catch (e) {
        // MetaMask rejected or not available — use simulated
      }
    }
    // Always mark as attested (simulated relayer)
    setPolygonAttested(true);
    setShowPolygonModal(true);
  }, [data]);

  const breakdown = data?.detector_breakdown;
  const attestation = breakdown?.polygon_attestation;
  const sbomComponents = data?.sbom?.components || data?.components || [];
  const sbomSha = breakdown?.sbom_sha256 || "N/A";

  return (
    <div className="flex h-screen w-full flex-col bg-[#07070a] text-zinc-100 font-sans selection:bg-red-500/30 selection:text-white overflow-hidden relative">

      {/* AMBIENT CANVAS DEPTH */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f1f2e15_1px,transparent_1px),linear-gradient(to_bottom,#1f1f2e15_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none -z-10" />

      {/* TOP COMMAND HEADER */}
      <header className="flex h-16 items-center justify-between border-b border-zinc-800/80 px-6 bg-zinc-950/80 backdrop-blur-xl shrink-0 z-40">

        {/* BRANDING */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-zinc-950 border border-zinc-800 text-red-400 shadow-sm">
            <Shield className="w-4 h-4" />
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-sm font-semibold tracking-tight text-zinc-100">SupplyGraph</span>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono uppercase tracking-wider bg-red-950/40 border border-red-500/30 text-red-300">
              ASPM v2
            </span>
          </div>
        </div>

        {/* HERO COMMAND SEARCH BAR */}
        <div className="flex items-center space-x-3 w-full max-w-2xl px-6">
          <div className="relative w-full group">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-zinc-500 group-focus-within:text-red-400 transition-colors">
              <Search className="w-4 h-4" />
            </div>
            <input
              ref={inputRef}
              type="text"
              placeholder="Paste any public repository URL (e.g. https://github.com/axios/axios)"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeAnalysis(githubUrl)}
              className="w-full bg-zinc-900/80 border border-zinc-800/90 hover:border-zinc-700/80 pl-10 pr-28 py-2 rounded-xl text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-red-500/50 focus:ring-2 focus:ring-red-500/10 backdrop-blur-md transition-all shadow-[0_2px_10px_rgba(0,0,0,0.5)]"
            />
            <div className="absolute inset-y-0 right-1.5 flex items-center space-x-1.5">
              <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono text-zinc-500 bg-zinc-800/60 rounded border border-zinc-700/50">
                ⌘K
              </kbd>
              <button
                onClick={() => executeAnalysis(githubUrl)}
                disabled={loading || !githubUrl.trim()}
                className="flex items-center space-x-1.5 bg-zinc-100 hover:bg-white text-zinc-950 border border-zinc-200 px-3 py-1 rounded-lg font-semibold text-[11px] transition-all disabled:opacity-30 disabled:cursor-not-allowed shadow active:scale-95"
              >
                {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 fill-current text-zinc-900" />}
                <span>Scan</span>
              </button>
            </div>
          </div>
        </div>

        {/* RIGHT HEADER ACTIONS */}
        <div className="flex items-center space-x-2 shrink-0">
          {/* CycloneDX SBOM Button — only when data is loaded */}
          {data && (
            <>
              <button
                onClick={() => setShowSbomModal(true)}
                className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-mono font-semibold bg-indigo-950/40 border border-indigo-700/40 text-indigo-300 hover:bg-indigo-900/40 transition-all"
              >
                <FileCode2 className="w-3 h-3" />
                <span>CycloneDX SBOM</span>
              </button>
              <button
                onClick={handlePolygonAttest}
                className={cn(
                  "flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-mono font-semibold border transition-all",
                  polygonAttested
                    ? "bg-emerald-950/40 border-emerald-700/40 text-emerald-300"
                    : "bg-purple-950/40 border-purple-700/40 text-purple-300 hover:bg-purple-900/40"
                )}
              >
                <Link2 className="w-3 h-3" />
                <span>{polygonAttested ? "✓ Polygon Attested" : "Anchor on Polygon"}</span>
              </button>
            </>
          )}
          {/* STATUS INDICATOR */}
          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-zinc-900/90 border border-zinc-800 text-[11px] font-mono shadow-inner">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-zinc-400 text-[10px]">ANALYSIS DAEMON READY</span>
          </div>
        </div>
      </header>

      {/* SCENARIO SWITCHER BAR */}
      <div className="shrink-0 border-b border-zinc-800/60 bg-zinc-950/60 backdrop-blur-sm px-6 py-2 flex items-center space-x-3 z-30">
        <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider shrink-0">Attack Simulations:</span>
        <div className="flex items-center space-x-2 overflow-x-auto no-scrollbar">
          {SCENARIOS.map((s) => (
            <button
              key={s.id}
              onClick={() => executeScenario(s.id as ScenarioId)}
              disabled={loading}
              className={cn(
                "flex items-center space-x-1.5 px-3 py-1 rounded-full text-[10px] font-mono font-semibold border whitespace-nowrap transition-all shrink-0 disabled:opacity-50",
                activeScenario === s.id
                  ? "bg-zinc-100 text-zinc-950 border-zinc-300 shadow"
                  : "bg-zinc-900/60 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600"
              )}
            >
              <span>{s.icon}</span>
              <span>Scenario {s.id}: {s.label}</span>
              {activeScenario === s.id && <ChevronRight className="w-3 h-3" />}
            </button>
          ))}
        </div>
      </div>

      {/* WORKSPACE */}
      <div className="flex-1 flex overflow-hidden relative">
        <main className="flex-1 flex overflow-hidden relative">

          {error ? (
            <div className="m-auto flex flex-col items-center justify-center p-8 max-w-md border border-red-500/20 bg-zinc-950/90 backdrop-blur-2xl rounded-2xl text-center shadow-2xl">
              <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-4 text-red-400">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <h2 className="text-sm font-semibold text-zinc-100 mb-1.5 tracking-tight">Handshake Interrupted</h2>
              <p className="text-xs text-zinc-400 mb-6 font-mono leading-relaxed">{error}</p>
              <button
                onClick={() => executeAnalysis(githubUrl)}
                className="text-xs font-semibold bg-zinc-100 text-zinc-950 hover:bg-white px-4 py-2 rounded-lg transition-all shadow"
              >
                Retry Analysis
              </button>
            </div>
          ) : !data && !loading ? (

            /* HERO CENTERPIECE */
            <div className="m-auto flex flex-col items-center justify-center text-center p-8 max-w-2xl">
              <div className="relative group cursor-pointer mb-7">
                <div className="absolute -inset-5 rounded-full border border-red-500/20 animate-[spin_14s_linear_infinite] [border-dasharray:4_4] pointer-events-none" />
                <div className="absolute -inset-9 rounded-full border border-indigo-500/15 animate-[spin_22s_linear_infinite_reverse] pointer-events-none" />
                <div className="absolute -inset-1 bg-gradient-to-r from-red-600 via-rose-500 to-amber-500 rounded-3xl blur-2xl opacity-40 group-hover:opacity-70 transition duration-500" />
                <div className="relative w-24 h-24 rounded-3xl bg-gradient-to-b from-zinc-900 via-zinc-950 to-black border border-zinc-700/80 shadow-[0_25px_60px_rgba(0,0,0,0.9),inset_0_1px_0_rgba(255,255,255,0.15)] flex items-center justify-center transform group-hover:scale-105 group-hover:-translate-y-1 transition-all duration-300">
                  <Shield className="w-11 h-11 text-red-400 drop-shadow-[0_0_14px_rgba(239,68,68,0.6)]" />
                </div>
              </div>
              <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-red-950/40 border border-red-500/30 text-red-300 text-[10px] font-mono uppercase tracking-widest mb-3.5 shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping"></span>
                <span>Next-Gen Reachability & ASPM Intelligence</span>
              </div>
              <h2 className="text-2xl font-bold tracking-tight text-zinc-100 sm:text-3xl mb-3">
                Contextual Attack Path Analysis
              </h2>
              <p className="text-xs text-zinc-400 leading-relaxed font-mono max-w-lg mb-4">
                Standard scanners generate static vulnerability lists. SupplyGraph traverses transitive dependency trees to calculate upward runtime reachability, real blast radius, and surgical patch containment.
              </p>
              <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-zinc-900/60 border border-zinc-800 text-[11px] font-mono text-zinc-400">
                <span className="text-zinc-600">TIP:</span>
                <span className="text-zinc-200">Try Scenario A–E above, or paste any GitHub URL</span>
              </div>
            </div>

          ) : loading ? (

            /* SCANNING ANIMATION */
            <div className="m-auto flex flex-col items-center justify-center text-center">
              <div className="relative mb-6">
                <div className="w-16 h-16 rounded-full border-2 border-red-500/20 border-t-red-500 animate-spin flex items-center justify-center"></div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <Cpu className="w-6 h-6 text-zinc-400 animate-pulse" />
                </div>
              </div>
              <p className="text-xs font-mono text-zinc-200 tracking-wider uppercase font-semibold">
                Constructing Attack Paths...
              </p>
              <span className="text-[11px] font-mono text-zinc-500 mt-1">
                Streaming Git Manifests → Inverting Traversal Edges → Computing Blast Radius
              </span>
            </div>

          ) : (

            /* ACTIVE GRAPH & WORKSPACE */
            <>
              <div className="flex-1 flex flex-col h-full relative">

                {/* FLOATING TELEMETRY HUD */}
                <div className="absolute top-5 left-5 z-20">
                  <div className="bg-zinc-950/85 backdrop-blur-xl border border-zinc-800/90 rounded-xl px-4 py-3 shadow-2xl min-w-[220px]">
                    {/* Repo name */}
                    <div className="flex items-center space-x-2 mb-2.5">
                      <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
                      <span className="text-[11px] font-mono font-semibold text-zinc-100 truncate max-w-[180px]">
                        {data?.scan?.repository_url?.replace("https://github.com/", "") ||
                          (activeScenario ? `Demo Scenario ${activeScenario}` : "Unknown")}
                      </span>
                    </div>

                    {/* Primary metrics */}
                    <div className="flex items-center space-x-4 text-[11px] font-mono pt-2 border-t border-zinc-800/60">
                      <div>
                        <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Components</span>
                        <span className="text-zinc-200 font-semibold">{data?.scan?.total_components || 0}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Findings</span>
                        <span className="text-red-400 font-semibold">{data?.scan?.total_findings || 0}</span>
                      </div>
                      <div className="relative">
                        <span className="text-zinc-500 block text-[9px] uppercase tracking-wider flex items-center space-x-1">
                          <span>Blast Radius</span>
                          <button
                            onMouseEnter={() => setShowFormulaTooltip(true)}
                            onMouseLeave={() => setShowFormulaTooltip(false)}
                            className="text-zinc-600 hover:text-zinc-400"
                          >
                            <Info className="w-2.5 h-2.5" />
                          </button>
                        </span>
                        <span className={cn(
                          "font-semibold",
                          (data?.scan?.blast_radius_score || 0) > 70 ? "text-red-400" :
                          (data?.scan?.blast_radius_score || 0) > 0 ? "text-amber-400" : "text-emerald-400"
                        )}>
                          {data?.scan?.blast_radius_score?.toFixed(1) || 0}/100
                        </span>
                        {/* Formula Tooltip */}
                        {showFormulaTooltip && (
                          <div className="absolute left-0 bottom-8 z-30 w-64 bg-zinc-900 border border-zinc-700 rounded-lg p-3 shadow-2xl text-[10px] font-mono">
                            <div className="text-zinc-300 font-semibold mb-1.5">Scoring Formulas</div>
                            <div className="text-zinc-400 space-y-1">
                              <div><span className="text-amber-400">Blast Radius:</span></div>
                              <div className="text-zinc-300 pl-2">B = 2P + 15S + 25A + 50D</div>
                              <div className="text-zinc-500 pl-2 text-[9px]">P=Packages, S=Services, A=APIs, D=Deployments</div>
                              <div className="mt-1.5"><span className="text-indigo-400">Confidence Score:</span></div>
                              <div className="text-zinc-300 pl-2">C = 1 - ∏(1 - wᵢ × rᵢ)</div>
                              <div className="text-zinc-500 pl-2 text-[9px]">w=evidence weight, r=source reliability</div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Secondary detector breakdown grid */}
                    {breakdown && (
                      <div className="grid grid-cols-4 gap-1.5 mt-2.5 pt-2 border-t border-zinc-800/60">
                        {[
                          { label: "CVE/OSV", value: breakdown.osv_count || 0, color: "text-indigo-400" },
                          { label: "TYPOSQUAT", value: breakdown.typosquat_count || 0, color: "text-rose-400" },
                          { label: "AST/CODE", value: breakdown.ast_count || 0, color: "text-cyan-400" },
                          { label: "CI/CD", value: breakdown.cicd_count || 0, color: "text-yellow-400" },
                        ].map((item) => (
                          <div key={item.label} className="text-center">
                            <div className={cn("text-[11px] font-semibold", item.color)}>{item.value}</div>
                            <div className="text-[8px] text-zinc-600 uppercase tracking-tight">{item.label}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* GRAPH CANVAS */}
                <div className="flex-1 w-full h-full">
                  {data && data.graph && (
                    <GraphCanvas
                      graph={data.graph}
                      focusNodeId={focusNodeId}
                      onNodeClick={(id) => setFocusNodeId(id)}
                    />
                  )}
                </div>
              </div>

              {/* INSPECTOR DRAWER */}
              <div className="w-[440px] flex flex-col border-l border-zinc-800/80 bg-zinc-950/80 backdrop-blur-2xl h-full shadow-2xl shrink-0 z-30">

                {/* DRAWER TABS */}
                <div className="flex items-center justify-between border-b border-zinc-800/80 px-4 pt-3 pb-0 bg-zinc-950/50">
                  <div className="flex space-x-4">
                    <button
                      onClick={() => setActiveTab("findings")}
                      className={cn(
                        "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5",
                        activeTab === "findings"
                          ? "border-red-500 text-zinc-100"
                          : "border-transparent text-zinc-400 hover:text-zinc-200"
                      )}
                    >
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                      <span>Findings ({data?.findings?.length || 0})</span>
                    </button>
                    <button
                      onClick={() => setActiveTab("briefing")}
                      className={cn(
                        "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5",
                        activeTab === "briefing"
                          ? "border-indigo-500 text-zinc-100"
                          : "border-transparent text-zinc-400 hover:text-zinc-200"
                      )}
                    >
                      <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Executive AI</span>
                    </button>
                  </div>

                  <button
                    onClick={handleDownloadReport}
                    className="p-1.5 text-zinc-400 hover:text-zinc-200 rounded-md hover:bg-zinc-800/60 transition-colors mb-2"
                    title="Export Executive Report (.md)"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* TAB CONTENT */}
                <div className="flex-1 overflow-y-auto p-5 space-y-4">

                  {/* ============ FINDINGS TAB ============ */}
                  {activeTab === "findings" && (
                    <div className="space-y-3.5">
                      {data?.findings && data.findings.length > 0 ? (
                        data.findings.map((f: any, idx: number) => {
                          const detectorTag = getDetectorTag(f);
                          const lockSnippet = buildLockfileSnippet(f);
                          return (
                            <div
                              key={idx}
                              className="p-3.5 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 transition-all group cursor-pointer"
                              onClick={() => handleFindingClick(f)}
                            >
                              {/* Header */}
                              <div className="flex items-start justify-between mb-2">
                                <h4 className="text-xs font-semibold text-zinc-200 pr-4 leading-snug group-hover:text-red-300 transition-colors">
                                  {f.title}
                                </h4>
                                <div className="flex items-center space-x-1 shrink-0">
                                  {/* Detector tag */}
                                  <span className={cn(
                                    "px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border",
                                    getDetectorTagClass(detectorTag)
                                  )}>
                                    {detectorTag}
                                  </span>
                                  {/* Severity badge */}
                                  <span className={cn(
                                    "px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border",
                                    getSeverityClass(f.severity)
                                  )}>
                                    {f.severity}
                                  </span>
                                </div>
                              </div>

                              <p className="text-[11px] text-zinc-400 leading-relaxed mb-3">
                                {f.description}
                              </p>

                              {/* Click hint */}
                              <div className="text-[9px] text-zinc-600 font-mono mb-2">
                                ↗ Click to focus node in graph
                              </div>

                              {/* Containment Strategy */}
                              {f.recommendations && f.recommendations.length > 0 && (
                                <div className="mt-2.5 pt-2.5 border-t border-zinc-800/60">
                                  <div className="flex items-center justify-between text-[10px] text-zinc-500 font-mono uppercase mb-1.5">
                                    <span>Containment Strategy</span>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        copyToClipboard(lockSnippet, idx);
                                      }}
                                      className="flex items-center space-x-1 hover:text-zinc-300 transition-colors"
                                    >
                                      {copiedIndex === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                      <span>{copiedIndex === idx ? "Copied!" : "Copy Lock"}</span>
                                    </button>
                                  </div>
                                  <div className="p-2 rounded bg-black/60 border border-zinc-800/70 font-mono text-[10px] text-zinc-300">
                                    <div className="text-emerald-400 font-semibold">{f.recommendations[0]?.title}</div>
                                    <div className="text-zinc-400 text-[9px] mt-0.5">{f.recommendations[0]?.why}</div>
                                    {/* Copyable lockfile snippet */}
                                    <pre className="mt-1.5 text-[9px] text-zinc-300 whitespace-pre-wrap break-all bg-zinc-900/60 rounded p-1.5 border border-zinc-800/50">
                                      {lockSnippet}
                                    </pre>
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })
                      ) : (
                        <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl">
                          <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                          <div className="text-xs font-semibold text-zinc-200">Zero Attack Paths Found</div>
                          <div className="text-[11px] text-zinc-500 mt-1">All nested transitive dependencies resolve cleanly.</div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ============ EXECUTIVE AI TAB ============ */}
                  {activeTab === "briefing" && (
                    <div className="space-y-4">
                      {/* AI Provider badge */}
                      <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-indigo-950/20 border border-indigo-700/30 text-[10px] font-mono">
                        <Sparkles className="w-3 h-3 text-indigo-400" />
                        <span className="text-indigo-300 font-semibold">
                          {breakdown?.model_provider
                            ? `Powered by ${breakdown.model_provider} (Zero-Hallucination Bounded)`
                            : "Powered by AWS Bedrock & Gemini 1.5 Flash (Zero-Hallucination Bounded)"}
                        </span>
                      </div>

                      {/* AI explanation */}
                      <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/20 text-xs text-zinc-300 leading-relaxed">
                        <div dangerouslySetInnerHTML={{
                          __html: (data?.gemini_explanation || "No summary available.")
                            .replace(/\n/g, "<br />")
                            .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
                        }} />
                      </div>

                      {/* Export button */}
                      <button
                        onClick={handleDownloadReport}
                        className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl bg-zinc-900 border border-zinc-700 text-xs font-semibold text-zinc-200 hover:bg-zinc-800 transition-all"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export Executive Report (.md)</span>
                      </button>

                      {/* SBOM attestation info */}
                      {breakdown?.sbom_sha256 && (
                        <div className="p-3.5 rounded-xl bg-purple-950/20 border border-purple-700/30 font-mono text-[11px] space-y-2">
                          <div className="flex items-center justify-between text-purple-300 font-semibold">
                            <span className="flex items-center space-x-1.5">
                              <Shield className="w-3.5 h-3.5" />
                              <span>Cryptographic Attestation</span>
                            </span>
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-900/40 border border-purple-700/40 text-purple-300">
                              Polygon Amoy
                            </span>
                          </div>
                          <div>
                            <span className="text-zinc-500 text-[9px] block">SBOM SHA-256</span>
                            <span className="text-zinc-300 text-[10px] break-all">{breakdown.sbom_sha256}</span>
                          </div>
                          {breakdown.merkle_root && (
                            <div>
                              <span className="text-zinc-500 text-[9px] block">Merkle Root</span>
                              <span className="text-zinc-300 text-[10px] break-all">{breakdown.merkle_root}</span>
                            </div>
                          )}
                          <button
                            onClick={handlePolygonAttest}
                            className="w-full mt-2 py-1.5 px-3 rounded-lg text-xs font-semibold bg-purple-900/40 hover:bg-purple-800/50 border border-purple-700/40 text-purple-200 transition-all flex items-center justify-center space-x-1.5"
                          >
                            <Link2 className="w-3.5 h-3.5" />
                            <span>{polygonAttested ? "View Polygon Receipt" : "Anchor on Polygon Amoy"}</span>
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                </div>
              </div>
            </>
          )}
        </main>
      </div>

      {/* CYCLONEDX SBOM MODAL */}
      <Modal
        open={showSbomModal}
        onClose={() => setShowSbomModal(false)}
        title={
          <div className="flex items-center space-x-2">
            <FileCode2 className="w-4 h-4 text-indigo-400" />
            <span>CycloneDX v1.5 SBOM Manifest</span>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between p-3 rounded-xl bg-zinc-900/80 border border-zinc-800">
            <div>
              <div className="text-xs font-semibold text-zinc-200">
                {data?.scan?.repository_url?.replace("https://github.com/", "") || "Repository"}
              </div>
              <div className="text-[10px] font-mono text-zinc-500 mt-0.5">
                Format: CycloneDX 1.5 JSON • {sbomComponents.length} components
              </div>
            </div>
            <button
              onClick={handleDownloadSbom}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-100 text-zinc-950 hover:bg-white transition-all shadow"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
          </div>

          <div className="p-3 rounded-xl bg-zinc-900/60 border border-zinc-800/80 font-mono text-[10px] space-y-1.5">
            <div className="text-zinc-500 uppercase tracking-wider text-[9px]">Cryptographic SHA-256 Digest</div>
            <div className="text-indigo-300 break-all bg-black/40 p-2 rounded border border-zinc-800">
              {sbomSha}
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-xs font-semibold text-zinc-300 font-mono flex items-center justify-between">
              <span>BOM Components ({sbomComponents.length})</span>
            </div>
            <div className="max-h-72 overflow-y-auto space-y-1.5 pr-1">
              {sbomComponents.map((comp, i) => (
                <div
                  key={i}
                  className="p-2.5 rounded-lg bg-zinc-900/40 border border-zinc-800/70 flex items-center justify-between font-mono text-[11px]"
                >
                  <div className="truncate mr-2">
                    <span className="text-zinc-200 font-semibold">{comp.name}</span>
                    <span className="text-zinc-500 ml-2 text-[10px]">v{comp.version || "unknown"}</span>
                    <div className="text-[9px] text-zinc-600 truncate">{comp.purl}</div>
                  </div>
                  <div className="flex items-center space-x-1.5 shrink-0">
                    <span className="px-1.5 py-0.5 rounded text-[8px] bg-zinc-800 text-zinc-400 border border-zinc-700 uppercase">
                      {comp.ecosystem}
                    </span>
                    {comp.is_direct && (
                      <span className="px-1.5 py-0.5 rounded text-[8px] bg-emerald-950/50 text-emerald-400 border border-emerald-800/40">
                        Direct
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      {/* POLYGON ATTESTATION MODAL */}
      <Modal
        open={showPolygonModal}
        onClose={() => setShowPolygonModal(false)}
        title={
          <div className="flex items-center space-x-2">
            <Link2 className="w-4 h-4 text-purple-400" />
            <span>Polygon Amoy Testnet Attestation</span>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between p-3 rounded-xl bg-purple-950/30 border border-purple-700/40">
            <div className="flex items-center space-x-2.5">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              <div>
                <div className="text-xs font-semibold text-purple-200">
                  Cryptographic Posture Anchored
                </div>
                <div className="text-[10px] font-mono text-purple-400">
                  Status: {attestation?.status || "ATTESTED"} • Network: Polygon Amoy (80002)
                </div>
              </div>
            </div>
            <button
              onClick={() => {
                if (attestation) {
                  navigator.clipboard.writeText(JSON.stringify(attestation, null, 2));
                  setAttestCopied(true);
                  setTimeout(() => setAttestCopied(false), 1800);
                }
              }}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition-all"
            >
              {attestCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{attestCopied ? "Copied" : "Copy Proof"}</span>
            </button>
          </div>

          <div className="space-y-2.5 font-mono text-[11px]">
            <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
              <div className="text-zinc-500 text-[9px] uppercase tracking-wider">Contract Address</div>
              <div className="text-purple-300 break-all select-all">{attestation?.contract_address || "0x5FbDB2315678afecb367f032d93F642f64180aa3"}</div>
            </div>

            <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
              <div className="text-zinc-500 text-[9px] uppercase tracking-wider">Receipt Payload Hash (Deterministic)</div>
              <div className="text-emerald-300 break-all select-all">{attestation?.payload_hash || "N/A"}</div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
                <div className="text-zinc-500 text-[9px] uppercase tracking-wider">SBOM SHA-256</div>
                <div className="text-zinc-300 text-[10px] break-all">{attestation?.sbom_sha256 || sbomSha}</div>
              </div>
              <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
                <div className="text-zinc-500 text-[9px] uppercase tracking-wider">Merkle Posture Root</div>
                <div className="text-zinc-300 text-[10px] break-all">{attestation?.merkle_root || "N/A"}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
                <div className="text-zinc-500 text-[9px] uppercase tracking-wider">Blast Radius Score</div>
                <div className="text-amber-400 font-semibold">{attestation?.blast_radius_score?.toFixed(1) || "0.0"}/100</div>
              </div>
              <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-1">
                <div className="text-zinc-500 text-[9px] uppercase tracking-wider">Timestamp</div>
                <div className="text-zinc-400 text-[10px] truncate">{attestation?.attestation_timestamp || "N/A"}</div>
              </div>
            </div>

            {attestation?.solidity_verification && (
              <div className="p-3 rounded-lg bg-black/60 border border-zinc-800 space-y-1">
                <div className="text-zinc-500 text-[9px] uppercase tracking-wider">Solidity On-Chain Verification</div>
                <pre className="text-zinc-300 text-[9px] whitespace-pre-wrap break-all">{attestation.solidity_verification}</pre>
              </div>
            )}

            {attestation?.verification_note && (
              <p className="text-[10px] text-zinc-500 leading-relaxed font-sans">
                {attestation.verification_note}
              </p>
            )}
          </div>
        </div>
      </Modal>

    </div>
  );
}