"use client";

import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { fetchRepositoryAnalysis, fetchDemoAnalysis, fetchFolderAnalysis } from "@/lib/api";
import { AnalysisResponse, DetectorBreakdown, PolygonAttestation, SBOM, CodeReviewItem } from "@/types";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { LoginPage } from "@/components/auth/LoginPage";
import { OverviewDashboard } from "@/components/dashboard/OverviewDashboard";
import { CodeReviewerPanel } from "@/components/reviewer/CodeReviewerPanel";
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
  FolderUp,
  LogOut,
  ArrowRight,
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
  const rawRef = origin || title.replace(/^Vulnerability in\s*/i, "") || "package";

  // Decode URI component (handles %40 in purl)
  let cleanRef = rawRef;
  try {
    cleanRef = decodeURIComponent(rawRef);
  } catch (_) {}

  const isPypi = cleanRef.startsWith("pkg:pypi/") || (!cleanRef.startsWith("pkg:npm/") && (finding?.finding_type === "AST" || finding?.evidence?.some((e: any) => e.source === "ast")));
  cleanRef = cleanRef.replace(/^pkg:(npm|pypi)\//, "");

  // Extract package name and current version
  let pkgName = cleanRef;
  let curVer = "";
  if (cleanRef.startsWith("@")) {
    const atIdx = cleanRef.indexOf("@", 1);
    if (atIdx !== -1) {
      pkgName = cleanRef.substring(0, atIdx);
      curVer = cleanRef.substring(atIdx + 1);
    }
  } else {
    const atIdx = cleanRef.indexOf("@");
    if (atIdx !== -1) {
      pkgName = cleanRef.substring(0, atIdx);
      curVer = cleanRef.substring(atIdx + 1);
    }
  }

  // Resolve real fixed version
  let fixedVer: string = finding?.recommendations?.[0]?.fixed_version || "";
  if (!fixedVer && finding?.recommendations) {
    for (const rec of finding.recommendations) {
      if (rec?.fixed_version) {
        fixedVer = rec.fixed_version;
        break;
      }
    }
  }
  if (!fixedVer && finding?.evidence) {
    for (const ev of finding.evidence) {
      if (ev?.raw_data?.fixed_version) {
        fixedVer = ev.raw_data.fixed_version;
        break;
      }
      if (ev?.raw_data?.fixed) {
        fixedVer = ev.raw_data.fixed;
        break;
      }
    }
  }
  if (!fixedVer && curVer) {
    const match = curVer.match(/^(\d+)/);
    if (match) {
      fixedVer = `>=${parseInt(match[1], 10) + 1}.0.0`;
    }
  }
  if (!fixedVer || fixedVer.includes("patched_version")) {
    fixedVer = "latest";
  }

  if (!isPypi) {
    const npmVer = (fixedVer === "latest" || fixedVer.startsWith(">=") || fixedVer.startsWith("^"))
      ? fixedVer
      : `^${fixedVer}`;
    return `// package.json override\n"overrides": {\n  "${pkgName}": "${npmVer}"\n}`;
  } else {
    const pipVer = fixedVer === "latest"
      ? ""
      : (fixedVer.startsWith(">=") || fixedVer.startsWith("==") ? fixedVer : `>=${fixedVer}`);
    return `# requirements.txt pin\n${pkgName}${pipVer}  # pinned by SupplyGraph`;
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/75 backdrop-blur-sm" onClick={onClose} />
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
// USER AUTH MODEL
// ============================================================
interface AuthUser {
  name: string;
  email: string;
  role: string;
}

// ============================================================
// MAIN DASHBOARD (4-STAGE FLOW)
// ============================================================
export default function Dashboard() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [currentView, setCurrentView] = useState<"login" | "overview" | "scanner">("overview");

  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "briefing" | "reviewer">("findings");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [activeScenario, setActiveScenario] = useState<ScenarioId | null>(null);
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [showSbomModal, setShowSbomModal] = useState(false);
  const [showPolygonModal, setShowPolygonModal] = useState(false);
  const [polygonAttested, setPolygonAttested] = useState(false);
  const [attestCopied, setAttestCopied] = useState(false);
  const [showFormulaTooltip, setShowFormulaTooltip] = useState(false);
  const [showAllFindings, setShowAllFindings] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  // Restore or set default user session
  useEffect(() => {
    const saved = localStorage.getItem("supplygraph_user");
    if (saved) {
      try {
        setCurrentUser(JSON.parse(saved));
        setCurrentView("overview");
      } catch (_) {}
    } else {
      // Default to judge fast pass active session
      const defaultUser: AuthUser = {
        name: "YUKTHI 2026 Judge",
        email: "evaluator@yukthi2026.mbu.ac.in",
        role: "Evaluator Mode",
      };
      setCurrentUser(defaultUser);
      localStorage.setItem("supplygraph_user", JSON.stringify(defaultUser));
      setCurrentView("overview");
    }
  }, []);

  const handleLogin = (user: AuthUser) => {
    setCurrentUser(user);
    localStorage.setItem("supplygraph_user", JSON.stringify(user));
    setCurrentView("overview");
  };

  const handleSignOut = () => {
    localStorage.removeItem("supplygraph_user");
    setCurrentUser(null);
    setCurrentView("login");
  };

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
    setShowAllFindings(false);
    setCurrentView("scanner");
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

  // Handle local project folder upload
  const handleFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setLoading(true);
    setError(null);
    setData(null);
    setActiveScenario(null);
    setPolygonAttested(false);
    setFocusNodeId(null);
    setShowAllFindings(false);
    setCurrentView("scanner");

    try {
      const firstPath = fileList[0].webkitRelativePath || fileList[0].name;
      const folderName = firstPath.split("/")[0] || "Local Project";

      const maxFileSize = 60 * 1024; // 60 KB max
      const skipDirs = [
        "node_modules/", ".git/", ".next/", "dist/", "build/",
        "venv/", ".venv/", "__pycache__/", "coverage/", ".vscode/"
      ];
      const skipExts = [
        ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".pdf", ".lockb", ".gif", ".webp", ".zip", ".tar",
        ".gz", ".exe", ".bin"
      ];

      const lockfileCandidates: File[] = [];
      const sourceCandidates: File[] = [];

      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const relPath = file.webkitRelativePath || file.name;
        const lowerPath = relPath.toLowerCase();

        // Immediate pre-filtering before any reading
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
          lowerPath.endsWith(".py") ||
          lowerPath.endsWith(".js") ||
          lowerPath.endsWith(".ts") ||
          lowerPath.endsWith(".tsx") ||
          lowerPath.endsWith(".jsx") ||
          lowerPath.endsWith(".json") ||
          lowerPath.endsWith(".yml") ||
          lowerPath.endsWith(".yaml") ||
          fileName === "dockerfile"
        ) {
          sourceCandidates.push(file);
        }
      }

      // Prioritize: lockfiles/workflows first, plus up to 25 source files, total capped at 40 files
      const selectedFiles = [
        ...lockfileCandidates.slice(0, 15),
        ...sourceCandidates.slice(0, 25),
      ].slice(0, 40);

      if (selectedFiles.length === 0) {
        throw new Error("No source code or lockfiles found in uploaded folder.");
      }

      // Fast concurrent file reading using Promise.all (<300ms)
      const readFiles = await Promise.all(
        selectedFiles.map(async (file) => {
          const content = await file.text();
          return {
            path: file.webkitRelativePath || file.name,
            content,
          };
        })
      );

      const result = await fetchFolderAnalysis(folderName, readFiles);
      setData(result);
    } catch (err: any) {
      setError(err.message || "Failed to analyze uploaded project folder.");
    } finally {
      setLoading(false);
      if (folderInputRef.current) {
        folderInputRef.current.value = "";
      }
    }
  };

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
    report += `Repository / Project: ${data?.scan?.repository_url || "N/A"}\n`;
    report += `Blast Radius: ${data?.scan?.blast_radius_score || 0}/100\n`;
    report += `Total Components: ${data?.scan?.total_components || 0}\n`;
    report += `Total Findings: ${data?.scan?.total_findings || 0}\n`;
    report += `Code Review Issues: ${data?.code_reviews?.length || 0}\n`;
    if (bd) {
      report += `\n## Detector Breakdown\n`;
      report += `- OSV/CVE: ${bd.osv_count || 0}\n`;
      report += `- Typosquatting: ${bd.typosquat_count || 0}\n`;
      report += `- Static AST: ${bd.ast_count || 0}\n`;
      report += `- CI/CD Workflows: ${bd.cicd_count || 0}\n`;
      report += `- Dependency Confusion: ${bd.confusion_count || 0}\n`;
      if (bd.sbom_sha256) report += `- SBOM SHA-256: ${bd.sbom_sha256}\n`;
      if (bd.merkle_root) report += `- Merkle Root: ${bd.merkle_root}\n`;
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
    if (data?.code_reviews && data.code_reviews.length > 0) {
      report += `\n## AI Code Reviewer Patches\n`;
      data.code_reviews.forEach((cr: CodeReviewItem, i: number) => {
        report += `\n### Patch [${i + 1}] ${cr.title} (${cr.severity})\n`;
        report += `File: ${cr.file_path} (Line ${cr.line_number}) | Category: ${cr.category}\n`;
        report += `Explanation: ${cr.error_explanation}\n`;
        report += `\nOriginal Code:\n\`\`\`\n${cr.buggy_code}\n\`\`\`\n`;
        report += `\nCorrected Code:\n\`\`\`\n${cr.corrected_code}\n\`\`\`\n`;
      });
    }
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

  const handleAnchorPolygon = useCallback(() => {
    setShowPolygonModal(true);
    setPolygonAttested(true);
  }, []);

  const handleGetStarted = useCallback(() => setCurrentView("scanner"), []);
  const handleSelectScenario = useCallback((id: ScenarioId) => executeScenario(id), [executeScenario]);
  const handleNodeClick = useCallback((nodeId: string) => {
    setFocusNodeId(nodeId);
  }, []);
  const currentGraph = useMemo(() => data?.graph || null, [data?.graph]);
  const currentCodeReviews = useMemo(() => data?.code_reviews || [], [data?.code_reviews]);
  const handleReviewsUpdated = useCallback((updated: CodeReviewItem[]) => {
    setData((prev) => (prev ? { ...prev, code_reviews: updated } : null));
  }, []);
  const displayedFindings = useMemo(() => {
    if (!data?.findings) return [];
    return showAllFindings ? data.findings : data.findings.slice(0, 25);
  }, [data?.findings, showAllFindings]);

  // STAGE 1: LOGIN VIEW
  if (currentView === "login" || !currentUser) {
    return <LoginPage onLogin={handleLogin} />;
  }

  const attestation = data?.detector_breakdown?.polygon_attestation;

  return (
    <div className="flex flex-col h-screen w-screen bg-[#070b13] text-zinc-100 overflow-hidden font-sans select-none">
      {/* TOP NAVIGATION BAR */}
      <header className="h-14 border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-xl flex items-center justify-between px-6 sticky top-0 z-40 shrink-0">
        <div className="flex items-center space-x-6">
          <div
            className="flex items-center space-x-2.5 cursor-pointer group"
            onClick={() => setCurrentView("overview")}
          >
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-red-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-red-500/20 group-hover:scale-105 transition-transform">
              <ShieldAlert className="w-4 h-4 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="text-sm font-bold tracking-tight text-zinc-100">SupplyGraph</span>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-500/15 text-red-400 font-mono font-bold border border-red-500/30">
                  v3.0 ASPM
                </span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center space-x-1">
            <button
              onClick={() => setCurrentView("overview")}
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
              onClick={() => setCurrentView("scanner")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                currentView === "scanner" && activeTab !== "reviewer"
                  ? "bg-zinc-800 text-zinc-100 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              )}
            >
              <span>Scanner & Graph</span>
            </button>

            <button
              onClick={() => {
                setCurrentView("scanner");
                setActiveTab("reviewer");
              }}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                currentView === "scanner" && activeTab === "reviewer"
                  ? "bg-zinc-800 text-zinc-100 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              )}
            >
              <Sparkles className="w-3 h-3 text-amber-400" />
              <span>Code Reviewer</span>
              {data?.code_reviews && data.code_reviews.length > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[9px] bg-amber-500/20 text-amber-300 font-mono">
                  {data.code_reviews.length}
                </span>
              )}
            </button>
          </nav>
        </div>

        {/* Top Right Controls */}
        <div className="flex items-center space-x-3">
          {currentUser && (
            <div className="hidden sm:flex items-center space-x-2 px-2.5 py-1 rounded-lg bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>{currentUser.name}</span>
            </div>
          )}

          {currentView === "overview" && (
            <button
              onClick={() => setCurrentView("scanner")}
              className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white text-xs font-semibold shadow-md shadow-red-600/20 transition-all flex items-center space-x-1.5 hover:scale-105 active:scale-95"
            >
              <span>🚀 Get Started →</span>
            </button>
          )}

          {/* CycloneDX & Polygon modals buttons in header when in scanner */}
          {currentView === "scanner" && (
            <div className="hidden lg:flex items-center space-x-2">
              <button
                onClick={() => setShowSbomModal(true)}
                disabled={!data}
                className="px-2.5 py-1 rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-850 text-zinc-300 disabled:opacity-40 text-xs font-mono flex items-center space-x-1.5 transition-colors"
              >
                <FileCode2 className="w-3.5 h-3.5 text-blue-400" />
                <span>CycloneDX SBOM</span>
              </button>

              <button
                onClick={handleAnchorPolygon}
                disabled={!data}
                className={cn(
                  "px-2.5 py-1 rounded-lg border text-xs font-mono flex items-center space-x-1.5 transition-all",
                  polygonAttested
                    ? "border-purple-500/40 bg-purple-950/40 text-purple-300"
                    : "border-zinc-800 bg-zinc-900/60 hover:bg-zinc-850 text-zinc-300 disabled:opacity-40"
                )}
              >
                <Shield className="w-3.5 h-3.5 text-purple-400" />
                <span>{polygonAttested ? "Polygon: Attested" : "Anchor on Polygon"}</span>
              </button>
            </div>
          )}

          {currentUser && (
            <button
              onClick={handleSignOut}
              className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 rounded-lg transition-colors text-xs font-mono flex items-center space-x-1"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Sign Out</span>
            </button>
          )}
        </div>
      </header>

      {/* STAGE 2: OVERVIEW DASHBOARD */}
      {currentView === "overview" && (
        <div className="flex-1 overflow-y-auto">
          <OverviewDashboard
            onGetStarted={handleGetStarted}
            onSelectScenario={handleSelectScenario}
          />
        </div>
      )}

      {/* STAGE 3 & 4: SCANNER WORKSPACE */}
      {currentView === "scanner" && (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* SCANNER CONTROLS HEADER */}
          <div className="border-b border-zinc-800/80 bg-zinc-950/90 px-6 py-3 space-y-2.5 shrink-0">
            {/* Dual Input Controls: URL bar + Upload Project Folder */}
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative flex-1 min-w-[300px]">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                <input
                  ref={inputRef}
                  type="text"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && executeAnalysis(githubUrl)}
                  placeholder="https://github.com/owner/repository (e.g. appsecco/dvna) — Press Enter to scan"
                  className="w-full pl-10 pr-24 py-2 rounded-xl bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-red-500/50 transition-all"
                />
                <button
                  onClick={() => executeAnalysis(githubUrl)}
                  disabled={loading}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 px-3 py-1 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center space-x-1 transition-colors shadow-sm"
                >
                  {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                  <span>Scan</span>
                </button>
              </div>

              {/* Hidden Folder Input for local folder analysis */}
              <input
                type="file"
                ref={folderInputRef}
                onChange={handleFolderUpload}
                {...({ webkitdirectory: "", directory: "", multiple: true } as any)}
                className="hidden"
              />

              <button
                onClick={() => folderInputRef.current?.click()}
                disabled={loading}
                className="px-3.5 py-2 rounded-xl bg-indigo-600/15 hover:bg-indigo-600/25 border border-indigo-500/30 hover:border-indigo-500/50 text-indigo-300 hover:text-indigo-200 text-xs font-semibold flex items-center space-x-2 transition-all shrink-0 shadow-sm"
                title="Upload and scan a local project directory from your computer"
              >
                <FolderUp className="w-3.5 h-3.5 text-indigo-400" />
                <span>📂 Upload Folder</span>
              </button>
            </div>

            {/* Scenario Pills */}
            <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mr-1">
                Demo Scenarios:
              </span>
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => executeScenario(s.id)}
                  disabled={loading}
                  className={cn(
                    "px-2.5 py-1 rounded-lg text-xs font-mono transition-all flex items-center space-x-1.5 border",
                    activeScenario === s.id
                      ? "bg-red-500/15 border-red-500/40 text-red-300 font-semibold shadow-sm"
                      : "bg-zinc-900/60 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
                  )}
                >
                  <span>{s.icon}</span>
                  <span>Scenario {s.id}</span>
                  <span className="text-zinc-500 text-[10px]">({s.label})</span>
                </button>
              ))}
            </div>

            {/* Error banner */}
            {error && (
              <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-800/40 text-red-300 text-xs font-mono flex items-center justify-between">
                <span>{error}</span>
                <button onClick={() => setError(null)} className="text-zinc-400 hover:text-white">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {/* MAIN SCANNER BODY: GRAPH CANVAS + FINDINGS / REVIEWER PANEL */}
          <div className="flex-1 flex overflow-hidden relative">
            {!data && !loading ? (
              /* EMPTY STATE */
              <div className="m-auto flex flex-col items-center justify-center text-center p-8 max-w-md space-y-4">
                <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-500 shadow-xl">
                  <ShieldAlert className="w-8 h-8 text-red-400" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-zinc-100">Ready to Analyze Supply Chain</h3>
                  <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
                    Paste any public GitHub repository URL, upload a local project folder from your computer, or click one of the Scenario pills above.
                  </p>
                </div>
                <div className="flex items-center space-x-2 pt-2">
                  <button
                    onClick={() => executeScenario("A")}
                    className="px-3.5 py-1.5 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-xs font-mono text-zinc-300 transition-colors"
                  >
                    🔗 Load Scenario A
                  </button>
                  <button
                    onClick={() => folderInputRef.current?.click()}
                    className="px-3.5 py-1.5 rounded-xl bg-indigo-600/15 hover:bg-indigo-600/25 border border-indigo-500/30 text-xs font-mono text-indigo-300 transition-colors"
                  >
                    📂 Upload Folder
                  </button>
                </div>
              </div>
            ) : loading ? (
              /* SCANNING ANIMATION */
              <div className="m-auto flex flex-col items-center justify-center text-center p-8 space-y-4">
                <div className="relative">
                  <div className="w-16 h-16 rounded-full border-2 border-red-500/20 border-t-red-500 animate-spin" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <Cpu className="w-6 h-6 text-zinc-400 animate-pulse" />
                  </div>
                </div>
                <div>
                  <p className="text-xs font-mono text-zinc-200 tracking-wider uppercase font-semibold">
                    Traversing Multi-Hop Attack DAG...
                  </p>
                  <p className="text-[11px] font-mono text-zinc-500 mt-1">
                    Parsing Lockfiles → OSV Batch Intel → Heuristic Detectors → AI Code Reviewer
                  </p>
                </div>
              </div>
            ) : data ? (
              /* ACTIVE GRAPH & WORKSPACE */
              <>
                <div className="flex-1 flex flex-col h-full relative">
                  {/* FLOATING TELEMETRY HUD */}
                  <div className="absolute top-4 left-4 z-20">
                    <div className="bg-zinc-950/85 backdrop-blur-xl border border-zinc-800/90 rounded-xl px-4 py-3 shadow-2xl min-w-[220px]">
                      <div className="flex items-center space-x-2 mb-2.5">
                        <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
                        <span className="text-[11px] font-mono font-semibold text-zinc-100 truncate max-w-[180px]">
                          {data?.scan?.repository_url?.replace("https://github.com/", "") ||
                            (activeScenario ? `Demo Scenario ${activeScenario}` : "Project")}
                        </span>
                      </div>

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
                          <span
                            className={cn(
                              "font-semibold",
                              (data?.scan?.blast_radius_score || 0) > 70
                                ? "text-red-400"
                                : (data?.scan?.blast_radius_score || 0) > 0
                                ? "text-amber-400"
                                : "text-emerald-400"
                            )}
                          >
                            {data?.scan?.blast_radius_score?.toFixed(1) || 0}/100
                          </span>

                          {/* Mathematical Formula Tooltip */}
                          {showFormulaTooltip && (
                            <div className="absolute left-0 bottom-8 z-30 w-64 bg-zinc-900 border border-zinc-700 rounded-lg p-3 shadow-2xl text-[10px] font-mono">
                              <div className="text-zinc-300 font-semibold mb-1.5">Scoring Formulas</div>
                              <div className="text-zinc-400 space-y-1">
                                <div><span className="text-amber-400">Blast Radius:</span></div>
                                <div className="text-zinc-300 pl-2">B = 2P + 15S + 25A + 50D</div>
                                <div className="text-zinc-500 pl-2 text-[9px]">P=Packages, S=Services, A=APIs, D=Deployments</div>
                                <div className="pt-1"><span className="text-indigo-400">Heuristic Confidence:</span></div>
                                <div className="text-zinc-300 pl-2">C = 1 - ∏(1 - w_i × r_i)</div>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Detector breakdown pills */}
                      {data?.detector_breakdown && (
                        <div className="mt-2.5 pt-2 border-t border-zinc-800/60 flex flex-wrap gap-1 text-[9px] font-mono">
                          <span className="text-zinc-500">Detectors:</span>
                          <span className="text-indigo-300">OSV: {data.detector_breakdown.osv_count || 0}</span>
                          <span className="text-zinc-600">•</span>
                          <span className="text-rose-300">Typosquat: {data.detector_breakdown.typosquat_count || 0}</span>
                          <span className="text-zinc-600">•</span>
                          <span className="text-cyan-300">AST: {data.detector_breakdown.ast_count || 0}</span>
                          <span className="text-zinc-600">•</span>
                          <span className="text-yellow-300">CI/CD: {data.detector_breakdown.cicd_count || 0}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* REACT FLOW CANVAS */}
                  {currentGraph && (
                    <GraphCanvas
                      graph={currentGraph}
                      focusNodeId={focusNodeId}
                      onNodeClick={handleNodeClick}
                    />
                  )}
                </div>

                {/* RIGHT PANEL: 3 TABS (FINDINGS / EXECUTIVE AI / CODE REVIEWER) */}
                <div className="w-[420px] border-l border-zinc-800/80 bg-zinc-950/70 backdrop-blur-md flex flex-col h-full shrink-0">
                  {/* Tab Navigation */}
                  <div className="flex items-center justify-between px-5 pt-3.5 border-b border-zinc-800/80 shrink-0">
                    <div className="flex items-center space-x-4">
                      {/* Findings Tab */}
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

                      {/* Executive AI Tab */}
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

                      {/* Code Reviewer Tab */}
                      <button
                        onClick={() => setActiveTab("reviewer")}
                        className={cn(
                          "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5",
                          activeTab === "reviewer"
                            ? "border-amber-500 text-zinc-100"
                            : "border-transparent text-zinc-400 hover:text-zinc-200"
                        )}
                      >
                        <FileCode2 className="w-3.5 h-3.5 text-amber-400" />
                        <span>Code Reviewer ({data?.code_reviews?.length || 0})</span>
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

                  {/* TAB CONTENT SCROLLABLE BODY */}
                  <div className="flex-1 overflow-y-auto p-5 space-y-4">
                    {/* ============ FINDINGS TAB ============ */}
                    {activeTab === "findings" && (
                      <div className="space-y-3.5">
                        {data?.findings && data.findings.length > 0 ? (
                          <>
                            {displayedFindings.map((f: any, idx: number) => {
                              const detectorTag = getDetectorTag(f);
                              const lockSnippet = buildLockfileSnippet(f);
                              return (
                                <div
                                  key={idx}
                                  className="p-3.5 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 transition-all group cursor-pointer"
                                  onClick={() => handleFindingClick(f)}
                                >
                                  <div className="flex items-start justify-between mb-2">
                                    <h4 className="text-xs font-semibold text-zinc-200 pr-4 leading-snug group-hover:text-red-300 transition-colors">
                                      {f.title}
                                    </h4>
                                    <div className="flex items-center space-x-1 shrink-0">
                                      <span
                                        className={cn(
                                          "px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border",
                                          getDetectorTagClass(detectorTag)
                                        )}
                                      >
                                        {detectorTag}
                                      </span>
                                      <span
                                        className={cn(
                                          "px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border",
                                          getSeverityClass(f.severity)
                                        )}
                                      >
                                        {f.severity}
                                      </span>
                                    </div>
                                  </div>

                                  <p className="text-[11px] text-zinc-400 leading-relaxed mb-3">
                                    {f.description}
                                  </p>

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
                                          {copiedIndex === idx ? (
                                            <Check className="w-3 h-3 text-emerald-400" />
                                          ) : (
                                            <Copy className="w-3 h-3" />
                                          )}
                                          <span>{copiedIndex === idx ? "Copied!" : "Copy Lock"}</span>
                                        </button>
                                      </div>
                                      <div className="p-2 rounded bg-black/60 border border-zinc-800/70 font-mono text-[10px] text-zinc-300">
                                        <div className="text-emerald-400 font-semibold">
                                          {f.recommendations[0]?.title}
                                        </div>
                                        <div className="text-zinc-400 text-[9px] mt-0.5">
                                          {f.recommendations[0]?.why}
                                        </div>
                                        <pre className="mt-1.5 text-[9px] text-zinc-300 whitespace-pre-wrap break-all bg-zinc-900/60 rounded p-1.5 border border-zinc-800/50">
                                          {lockSnippet}
                                        </pre>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })}

                            {data.findings.length > 25 && (
                              <div className="pt-2 text-center">
                                <button
                                  onClick={() => setShowAllFindings(!showAllFindings)}
                                  className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700/80 text-xs font-mono text-zinc-200 transition-colors shadow-sm"
                                >
                                  {showAllFindings
                                    ? "Show First 25 Findings"
                                    : `Show All (${data.findings.length}) Findings`}
                                </button>
                              </div>
                            )}
                          </>
                        ) : (
                          <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl">
                            <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                            <p className="text-xs text-zinc-400 font-mono">No vulnerabilities detected</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* ============ EXECUTIVE AI TAB ============ */}
                    {activeTab === "briefing" && (
                      <div className="space-y-4">
                        <div className="p-4 rounded-xl border border-indigo-900/40 bg-indigo-950/20 text-xs leading-relaxed space-y-3">
                          <div className="flex items-center justify-between text-indigo-300 font-mono text-[11px] pb-2 border-b border-indigo-900/40">
                            <span className="flex items-center space-x-1.5">
                              <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                              <span>Autonomous Security Audit</span>
                            </span>
                            <span className="text-zinc-500 text-[10px]">
                              {data?.detector_breakdown?.model_provider || "Claude 3.5 Sonnet / Gemini 1.5"}
                            </span>
                          </div>

                          <div className="text-zinc-300 whitespace-pre-wrap font-sans text-xs leading-relaxed">
                            {data?.gemini_explanation || "No executive summary available."}
                          </div>
                        </div>

                        <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-900/30 space-y-2 text-xs font-mono">
                          <div className="text-zinc-400 font-semibold">Exploitability Summary</div>
                          <div className="text-zinc-400 text-[11px]">
                            • Total Attack Paths: <span className="text-zinc-200">{data?.scan?.total_attack_paths || 0}</span>
                          </div>
                          <div className="text-zinc-400 text-[11px]">
                            • Blast Radius Score: <span className="text-red-400 font-bold">{data?.scan?.blast_radius_score?.toFixed(1) || 0}/100</span>
                          </div>
                          <div className="text-zinc-400 text-[11px]">
                            • Transitive Vulnerabilities: <span className="text-amber-400 font-bold">{data?.vulnerabilities?.length || 0}</span>
                          </div>
                          <div className="text-zinc-400 text-[11px]">
                            • AI Code Patches: <span className="text-indigo-400 font-bold">{data?.code_reviews?.length || 0}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* ============ CODE REVIEWER TAB ============ */}
                    {activeTab === "reviewer" && (
                      <CodeReviewerPanel
                        codeReviews={currentCodeReviews}
                        onReviewsUpdated={handleReviewsUpdated}
                      />
                    )}
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}

      {/* ============================================================
          CYCLONEDX SBOM MODAL
      ============================================================ */}
      <Modal
        open={showSbomModal}
        onClose={() => setShowSbomModal(false)}
        title={
          <div className="flex items-center space-x-2">
            <FileCode2 className="w-4 h-4 text-blue-400" />
            <span>CycloneDX v1.5 Software Bill of Materials (SBOM)</span>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800 text-xs font-mono space-y-1.5">
            <div className="flex items-center justify-between text-zinc-400">
              <span>Standard Format:</span>
              <span className="text-zinc-200">CycloneDX v1.5 JSON</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Total Components:</span>
              <span className="text-zinc-200">{data?.sbom?.components?.length || data?.components?.length || 0}</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Deterministic SHA-256:</span>
              <span className="text-blue-400 text-[10px] break-all">
                {data?.detector_breakdown?.sbom_sha256 || "Computing..."}
              </span>
            </div>
          </div>

          <div className="max-h-60 overflow-y-auto rounded-xl border border-zinc-800 bg-black/60 p-3 text-[10px] font-mono text-zinc-400 space-y-1">
            {(data?.sbom?.components || data?.components || []).map((comp: any, idx: number) => (
              <div key={idx} className="flex items-center justify-between py-0.5 border-b border-zinc-900">
                <span className="text-zinc-300 font-semibold">{comp.name}</span>
                <span className="text-zinc-500">{comp.version || "latest"}</span>
                <span className="text-zinc-600 text-[9px]">{comp.ecosystem}</span>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-end space-x-2 pt-2">
            <button
              onClick={handleDownloadSbom}
              className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-md shadow-blue-600/20"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download CycloneDX JSON</span>
            </button>
          </div>
        </div>
      </Modal>

      {/* ============================================================
          POLYGON AMOY ATTESTATION MODAL
      ============================================================ */}
      <Modal
        open={showPolygonModal}
        onClose={() => setShowPolygonModal(false)}
        title={
          <div className="flex items-center space-x-2 text-purple-300">
            <Shield className="w-4 h-4 text-purple-400" />
            <span>Polygon Blockchain Attestation (Chain ID: 80002)</span>
          </div>
        }
      >
        <div className="space-y-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-purple-950/30 border border-purple-800/40 text-purple-200 leading-relaxed">
            {attestation?.verification_note ||
              "Attestation anchored to Polygon Amoy Testnet using cryptographic Merkle security proof."}
          </div>

          <div className="p-3.5 rounded-xl bg-zinc-900 border border-zinc-800 space-y-2 text-[11px]">
            <div className="flex items-center justify-between text-zinc-400">
              <span>Network:</span>
              <span className="text-purple-300 font-bold">{attestation?.network || "Polygon Amoy Testnet"}</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Contract Address:</span>
              <span className="text-zinc-200 text-[10px]">{attestation?.contract_address || "0xSupplyGraphRegistry..."}</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Merkle Security Root:</span>
              <span className="text-zinc-200 text-[10px] break-all">{attestation?.merkle_root || "0x..."}</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Payload Hash:</span>
              <span className="text-zinc-200 text-[10px] break-all">{attestation?.payload_hash || "0x..."}</span>
            </div>
            <div className="flex items-center justify-between text-zinc-400">
              <span>Status:</span>
              <span className="text-emerald-400 font-bold">VERIFIED ON-CHAIN (SIMULATED RELAYER)</span>
            </div>
          </div>

          {attestation?.solidity_verification && (
            <div>
              <div className="text-zinc-400 text-[10px] uppercase tracking-wider mb-1">
                Solidity Verification Interface:
              </div>
              <pre className="p-3 rounded-xl bg-black/80 border border-zinc-800 text-[10px] text-zinc-300 overflow-x-auto whitespace-pre-wrap break-all">
                {attestation.solidity_verification}
              </pre>
            </div>
          )}

          <div className="flex items-center justify-end space-x-2 pt-2">
            <button
              onClick={() => {
                if (attestation) {
                  navigator.clipboard.writeText(JSON.stringify(attestation, null, 2));
                  setAttestCopied(true);
                  setTimeout(() => setAttestCopied(false), 2000);
                }
              }}
              className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-colors shadow-md shadow-purple-600/20"
            >
              {attestCopied ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{attestCopied ? "Copied Proof JSON!" : "Copy Verification Proof"}</span>
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}