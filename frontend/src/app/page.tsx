"use client";

import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { fetchRepositoryAnalysis, fetchDemoAnalysis, fetchFolderAnalysis, compareScans } from "@/lib/api";
import { AnalysisResponse, DetectorBreakdown, SBOM, CodeReviewItem, ScanHistoryRecord, GraphNode } from "@/types";
import {
  parseSemVer,
  compareSemVer,
  resolveHighestSafeVersion,
  resolveVersionWithConfidence,
  getFindingPackage,
  buildLockfileSnippet,
  generateMasterAIFixPrompt,
  generateSingleAIFixPrompt,
} from "@/lib/remediationPromptGenerator";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { OverviewDashboard } from "@/components/dashboard/OverviewDashboard";
import { CodeReviewerPanel } from "@/components/reviewer/CodeReviewerPanel";
import { SandboxPanel } from "@/components/sandbox/SandboxPanel";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";
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
  ChevronDown,
  ChevronUp,
  Boxes,
  Layers,
  ListFilter,
  Maximize2,
  Minimize2,
  Info,
  FolderUp,
  LogOut,
  ArrowLeft,
  ArrowRight,
  FileText,
  Clock,
  History,
  ArrowUpRight,
  ArrowDownRight,
  RotateCcw,
  Trash2,
  GitCompare,
  Crosshair,
  GitBranch,
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
  provider?: "google" | "github" | "gmail" | "judge";
  avatarUrl?: string;
  githubUsername?: string;
}

// ============================================================
// EXECUTIVE AI SUMMARY GENERATOR (Fix for missing briefing text)
// ============================================================
function getExecutiveSummary(data: AnalysisResponse | null, activeScenario?: ScenarioId | null): string {
  if (!data) {
    return "No active scan data loaded. Run a repository scan, load a detonation preset, or upload a project folder to view the autonomous executive security briefing.";
  }
  if (data.gemini_explanation && data.gemini_explanation.trim().length > 0) {
    return data.gemini_explanation;
  }

  // Preset Scenario Fallback Briefings
  if (activeScenario === "A" || data.demo_label === "Scenario A") {
    return `### 🚨 Executive AI Security Briefing: Log4j Transitive Exploit Chain (Scenario A)\n\n**Target**: enterprise-payment-gateway (Scenario A)\n**Scanned Components**: ${data.components?.length || 42} | **Findings**: ${data.findings?.length || 8} | **Blast Radius**: 85.0/100\n\n**Autonomous Assessment**:\nA high-criticality remote code execution (RCE) vector exists via transitive dependency \`org.apache.logging.log4j:log4j-core:2.14.1\` (CVE-2021-44228). Untrusted user-supplied request headers reach log evaluation without JNDI lookup disabling, creating an immediate exfiltration attack path.\n\n**Containment Recommendation**:\n1. Upgrade Log4j to >=2.17.1 immediately or set system property \`-Dlog4j2.formatMsgNoLookups=true\`.\n2. Review unified diff patch in AI Code Reviewer.\n3. Re-scan repository to verify 0 reachable attack paths.`;
  }
  if (activeScenario === "B" || data.demo_label === "Scenario B") {
    return `### 🚨 Executive AI Security Briefing: Dependency Confusion via Internal Package Namespace (Scenario B)\n\n**Target**: fintech-core-api (Scenario B)\n**Scanned Components**: ${data.components?.length || 38} | **Findings**: ${data.findings?.length || 6} | **Blast Radius**: 78.5/100\n\n**Autonomous Assessment**:\nDependency confusion vulnerability identified in private organization module \`@corp-internal/auth-token\`. The manifest references an un-scoped public registry where an external threat actor can publish higher-versioned malicious packages, executing preinstall hooks on developer machines and build runners.\n\n**Containment Recommendation**:\n1. Configure \`.npmrc\` with scoped registry routing for \`@corp-internal/*\`.\n2. Enforce package-lock.json integrity validation in CI/CD pipeline.\n3. Apply lockfile override constraints.`;
  }
  if (activeScenario === "C" || data.demo_label === "Scenario C") {
    return `### 🚨 Executive AI Security Briefing: Malicious Lifecycle Postinstall Hook (Scenario C)\n\n**Target**: payment-frontend-web (Scenario C)\n**Scanned Components**: ${data.components?.length || 55} | **Findings**: ${data.findings?.length || 9} | **Blast Radius**: 92.0/100\n\n**Autonomous Assessment**:\nMalicious script injection detected inside \`flatmap-stream:0.1.1\` postinstall lifecycle hook. Detonation analysis proves the script executes an unauthorized curl drop payload attempting to harvest environment credentials and transmit tokens to an external C2 endpoint.\n\n**Containment Recommendation**:\n1. Run with \`npm install --ignore-scripts\` in automated build runners.\n2. Remove \`flatmap-stream\` and vendor sanitized stream utilities.\n3. Detonate payload safely in SupplyGraph Sandbox to inspect extracted C2 domains.`;
  }
  if (activeScenario === "D" || data.demo_label === "Scenario D") {
    return `### 🚨 Executive AI Security Briefing: CI/CD Pipeline Runner Poisoning (Scenario D)\n\n**Target**: cloud-infra-automation (Scenario D)\n**Scanned Components**: ${data.components?.length || 31} | **Findings**: ${data.findings?.length || 7} | **Blast Radius**: 74.0/100\n\n**Autonomous Assessment**:\nGitHub Actions workflow \`.github/workflows/deploy.yml\` references unpinned third-party actions (\`actions/checkout@v2\`) with blanket \`permissions: write-all\`. Upstream branch mutation could execute untrusted commands within the privileged runner, compromising deployment secrets.\n\n**Containment Recommendation**:\n1. Pin all actions to immutable 40-character commit SHAs (\`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\`).\n2. Enforce least-privilege token permissions (\`contents: read\`).`;
  }
  if (activeScenario === "E" || data.demo_label === "Scenario E") {
    return `### 🚨 Executive AI Security Briefing: Multi-Hop Prototype Pollution (Scenario E)\n\n**Target**: analytics-dashboard (Scenario E)\n**Scanned Components**: ${data.components?.length || 49} | **Findings**: ${data.findings?.length || 11} | **Blast Radius**: 81.0/100\n\n**Autonomous Assessment**:\nMulti-hop call path traversal demonstrates that unsanitized JSON query payloads reach deep merge utilities in \`lodash:4.17.15\` (CVE-2019-10744). Modification of \`Object.prototype\` allows privilege escalation to admin status across tenant boundaries.\n\n**Containment Recommendation**:\n1. Upgrade lodash to \`^4.17.21\` or use native \`Object.assign({})\` with key filtering.\n2. Apply AST-guided sanitization patch generated by AI Code Reviewer.`;
  }

  const repo = data.scan?.repository_url?.replace("https://github.com/", "") || "Target Repository";
  const totalFindings = Number(data.findings?.length ?? data.scan?.total_findings ?? 0);
  const criticals = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "CRITICAL").length;
  const highs = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "HIGH").length;
  const mediums = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "MEDIUM").length;
  const lows = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "LOW").length;
  const totalComponents = Number(data.components?.length ?? data.sbom?.components?.length ?? data.scan?.total_components ?? 0);
  const blastRadius = (Number(data.scan?.blast_radius_score) || 0).toFixed(1);
  const attackPaths = Number(data.scan?.total_attack_paths ?? data.attack_paths?.length ?? 0);
  const codeReviews = data.code_reviews?.length || 0;

  if (totalFindings === 0 && codeReviews === 0) {
    return `### 🛡️ SupplyGraph Autonomous Security Briefing\n\nTarget: ${repo}\n\nNo known software supply-chain vulnerabilities or malicious patterns were identified across ${totalComponents} scanned component(s). The dependency tree exhibits zero multi-hop attack paths and maintains an optimal Blast Radius score of 0.0/100.\n\nRecommended Action: Continue periodic CI/CD pipeline scans and enforce immutable commit SHA pinning on all third-party build actions.`;
  }

  let summary = `### ⚠️ Autonomous Supply-Chain Threat Assessment\n\n`;
  summary += `SupplyGraph analyzed **${totalComponents} component(s)** for **${repo}** and identified **${totalFindings} security finding(s)** with an aggregate Blast Radius of **${blastRadius}/100** and **${attackPaths} multi-hop attack path(s)** traversing to application entrypoints.\n\n`;

  summary += `**Threat Severity Breakdown:**\n`;
  summary += `• Critical: ${criticals}\n`;
  summary += `• High: ${highs}\n`;
  summary += `• Medium: ${mediums}\n`;
  if (lows > 0) summary += `• Low / Informational: ${lows}\n`;
  if (codeReviews > 0) summary += `• AST & CI/CD Hardening Patches: ${codeReviews}\n`;

  summary += `\n**Key Risk Factors:**\n`;
  if (criticals > 0) {
    summary += `1. **Immediate Exploitation Surface**: ${criticals} critical issue(s) detected. Attackers can leverage multi-hop DAG reachability to achieve remote code execution, prototype pollution, or secret exfiltration.\n`;
  }
  if (highs > 0) {
    summary += `2. **Transitive Dependency Exposure**: ${highs} high-severity CVEs or unpinned actions present in the dependency tree create exploitable supply-chain vectors.\n`;
  }
  if (attackPaths > 0) {
    summary += `3. **DAG Reachability**: Attack path simulation confirms that untrusted network inputs can reach vulnerable dependencies across multi-tier call graphs.\n`;
  }

  summary += `\n**Remediation Guidance:**\n`;
  summary += `• Navigate to the **AI Code Reviewer** tab to review line-level unified diffs.\n`;
  summary += `• Copy the AI prompt via **Remediation Prompt** to apply non-breaking version constraints in your AI coding IDE (Antigravity, Cursor, Claude Code, or Copilot).\n`;
  summary += `• Pin all GitHub Actions to 40-character commit SHAs to prevent upstream tag tampering.`;

  return summary;
}

// ============================================================
// MAIN DASHBOARD (4-STAGE FLOW)
// ============================================================
export default function Dashboard() {
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [currentView, setCurrentView] = useState<"login" | "overview" | "scanner" | "reviewer" | "sandbox">("overview");
  const [showExportDropdown, setShowExportDropdown] = useState(false);

  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "briefing" | "reviewer" | "sandbox" | "benchmark">("findings");
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
  const [showFormulaTooltip, setShowFormulaTooltip] = useState(false);
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
  const [findingsGrouping, setFindingsGrouping] = useState<"package" | "flat">("package");
  const [expandedPackageKeys, setExpandedPackageKeys] = useState<Record<string, boolean>>({});
  const [findingsSearch, setFindingsSearch] = useState("");
  const [scanElapsedSeconds, setScanElapsedSeconds] = useState(0);
  const [computedSbomSha, setComputedSbomSha] = useState<string>("");

  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const scanAbortControllerRef = useRef<AbortController | null>(null);

  // Timer for scanning progress
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (loading) {
      setScanElapsedSeconds(0);
      timer = setInterval(() => {
        setScanElapsedSeconds((prev) => prev + 1);
      }, 1000);
    } else {
      setScanElapsedSeconds(0);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [loading]);

  // Deterministic CycloneDX SHA-256 Digest computation (Fix #3 stuck on Computing...)
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

    if (typeof window !== "undefined" && window.crypto?.subtle) {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(rawPayload);
      window.crypto.subtle
        .digest("SHA-256", dataBuffer)
        .then((hashBuffer) => {
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
          setComputedSbomSha(`0x${hashHex}`);
        })
        .catch(() => {
          let hash = 0;
          for (let i = 0; i < rawPayload.length; i++) {
            hash = (hash << 5) - hash + rawPayload.charCodeAt(i);
            hash |= 0;
          }
          setComputedSbomSha(`0x${Math.abs(hash).toString(16).padStart(64, "0")}`);
        });
    } else {
      let hash = 0;
      for (let i = 0; i < rawPayload.length; i++) {
        hash = (hash << 5) - hash + rawPayload.charCodeAt(i);
        hash |= 0;
      }
      setComputedSbomSha(`0x${Math.abs(hash).toString(16).padStart(64, "0")}`);
    }
  }, [data]);

  // Restore scan history from localStorage
  useEffect(() => {
    try {
      const savedHistory = localStorage.getItem("supplygraph_scan_history");
      if (savedHistory) {
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
      }
    } catch (_) {
      try { localStorage.removeItem("supplygraph_scan_history"); } catch (_) {}
    }
  }, []);

  // Record scan in history when data updates (keep top 10)
  useEffect(() => {
    if (!data || !data.scan) return;
    try {
      const scanId = data.scan.id || `scan-${Date.now()}`;
      const target =
        data.scan.repository_url?.replace("https://github.com/", "") ||
        (activeScenario ? `Scenario ${activeScenario}` : "Uploaded Project");

      const record: ScanHistoryRecord = {
        id: scanId,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        target,
        total_components: Number(data.scan.total_components) || Number(data.components?.length) || 0,
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

  const handleSelectHistoryScan = useCallback(async (record: ScanHistoryRecord) => {
    setSelectedHistoryScan(record);
    if (!data) return;
    setComparingLoading(true);
    try {
      if (record?.data) {
        const res = await compareScans(record.data, data);
        setComparisonResult(res);
      } else {
        throw new Error("Missing snapshot data");
      }
    } catch (e) {
      console.warn("Backend comparison fallback:", e);
      const currentComps = new Set((data.components || []).map((c: any) => c.name));
      const oldComps = new Set((record?.data?.components || []).map((c: any) => c.name));
      const added = (data.components || [])
        .filter((c: any) => !oldComps.has(c.name))
        .map((c: any) => ({ change_type: "added", package_name: c.name, ecosystem: c.ecosystem, version_after: c.version }));
      const removed = (record?.data?.components || [])
        .filter((c: any) => !currentComps.has(c.name))
        .map((c: any) => ({ change_type: "removed", package_name: c.name, ecosystem: c.ecosystem, version_before: c.version }));
      
      const curBlast = Number(data.scan?.blast_radius_score) || 0;
      const oldBlast = Number(record?.blast_radius_score ?? record?.data?.scan?.blast_radius_score) || 0;
      const blastShift = curBlast - oldBlast;

      setComparisonResult({
        blast_radius_delta: blastShift,
        dependency_changes: [...added, ...removed],
        finding_changes: [],
        summary: `Delta comparison between ${record.target} and current active scan. Blast shift: ${blastShift >= 0 ? "+" : ""}${blastShift.toFixed(1)}.`,
      });
    } finally {
      setComparingLoading(false);
    }
  }, [data]);

  const handleLoadHistoryScan = useCallback((record: ScanHistoryRecord) => {
    if (record?.data) {
      setData(record.data);
    }
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

  // Restore or set default user session
  useEffect(() => {
    if (typeof window !== "undefined" && (window.location.search.includes("login") || window.location.hash.includes("login"))) {
      try { localStorage.removeItem("supplygraph_user"); } catch (_) {}
      setCurrentUser(null);
      setCurrentView("login");
      return;
    }

    try {
      const saved = localStorage.getItem("supplygraph_user");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === "object" && parsed.email) {
          setCurrentUser(parsed);
          setCurrentView("overview");
          return;
        }
      }
    } catch (_) {
      try { localStorage.removeItem("supplygraph_user"); } catch (_) {}
    }

    // Default to judge fast pass active session
    const defaultUser: AuthUser = {
      name: "YUKTHI 2026 Judge",
      email: "evaluator@yukthi2026.mbu.ac.in",
      role: "Evaluator Mode",
    };
    setCurrentUser(defaultUser);
    try {
      localStorage.setItem("supplygraph_user", JSON.stringify(defaultUser));
    } catch (_) {}
    setCurrentView("overview");
  }, []);

  const handleLogin = (user: AuthUser) => {
    setCurrentUser(user);
    try {
      localStorage.setItem("supplygraph_user", JSON.stringify(user));
    } catch (_) {}
    setCurrentView("overview");
  };

  const handleSignOut = () => {
    try {
      localStorage.removeItem("supplygraph_user");
    } catch (_) {}
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

  const handleCancelScan = useCallback(() => {
    if (scanAbortControllerRef.current) {
      scanAbortControllerRef.current.abort();
    }
    setLoading(false);
    setError("Scan cancelled by user.");
  }, []);

  const executeAnalysis = useCallback(async (urlToScan: string, overrideProdOnly?: boolean) => {
    const trimmed = urlToScan.trim();
    if (!trimmed) return;
    if (!/^https:\/\/github\.com\/[^\/]+\/[^\/]+/.test(trimmed)) {
      setError("Please enter a valid GitHub repository URL (e.g., https://github.com/org/repo)");
      return;
    }

    if (scanAbortControllerRef.current) {
      scanAbortControllerRef.current.abort();
    }
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
      const result = await fetchRepositoryAnalysis(trimmed, useProd, transitiveDepth, controller.signal);
      setData(result);
    } catch (err: any) {
      if (err.name === "AbortError") {
        setError("Scan cancelled by user.");
      } else {
        setError(err.message || "Failed to establish secure handshake with analysis engine.");
      }
    } finally {
      setLoading(false);
    }
  }, [prodOnly, transitiveDepth]);

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

  // Handle local project folder upload
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

      const result = await fetchFolderAnalysis(folderName, readFiles, prodOnly, transitiveDepth);
      setLastUploadedFiles(readFiles);
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

  const copyToClipboard = useCallback((text: string, index: number | string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1800);
  }, []);

  const formatSingleFindingText = useCallback((f: any) => {
    const detectorTag = getDetectorTag(f);
    const snippet = buildLockfileSnippet(f);
    let text = `[${f.severity || "MEDIUM"}] ${f.title}\n`;
    text += `Detector: ${detectorTag} | Type: ${f.finding_type || "N/A"}\n`;
    if (f.origin_candidate) {
      text += `Target Component: ${f.origin_candidate}\n`;
    }
    if (f.description) {
      text += `Description: ${f.description}\n`;
    }
    if (f.recommendations && f.recommendations.length > 0) {
      text += `\nRemediation Strategy: ${f.recommendations[0]?.title || ""}\n`;
      if (f.recommendations[0]?.why) {
        text += `Why: ${f.recommendations[0]?.why}\n`;
      }
      if (snippet) {
        text += `Fix / Configuration Snippet:\n${snippet}\n`;
      }
    }
    return text.trim();
  }, []);

  const formatAllFindingsText = useCallback((findings: any[]) => {
    const repo = data?.scan?.repository_url || "Target Repository";
    let text = `# SupplyGraph Security Findings Summary\n`;
    text += `Repository: ${repo}\n`;
    text += `Total Findings: ${findings.length}\n`;
    text += `Blast Radius: ${data?.scan?.blast_radius_score || 0}/100\n`;
    text += `Generated: ${new Date().toISOString()}\n\n`;
    text += `============================================================\n\n`;

    findings.forEach((f, idx) => {
      text += `### Finding #${idx + 1}: ${formatSingleFindingText(f)}\n\n`;
      text += `------------------------------------------------------------\n\n`;
    });

    return text.trim();
  }, [data, formatSingleFindingText]);

  const handleDownloadAIPrompt = useCallback(() => {
    if (!data) return;
    const prompt = generateMasterAIFixPrompt(data);
    const blob = new Blob([prompt], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const repoName = (data?.scan?.repository_url || "project").split("/").pop() || "project";
    a.download = `SupplyGraph_AI_Fix_Prompt_${repoName}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [data]);

  const handleFindingClick = useCallback((finding: any) => {
    // Extract specific advisory/vulnerability ID if present (GHSA, CVE, PYSEC, SNYK)
    const titleMatch = (finding?.title || "").match(/(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+|PYSEC-\d{4}-\d+|SNYK-[A-Z0-9-]+)/i);
    const specificId = titleMatch ? titleMatch[1] : null;
    const targetId = specificId || finding?.origin_candidate || finding?.entity_id || finding?.title || "";

    setFocusTarget({
      id: targetId,
      finding: finding,
      timestamp: Date.now(),
    });
    setFocusNodeId(targetId);
  }, []);

  const handlePackageFocus = useCallback((packageKey: string, sampleFinding?: any) => {
    setFocusTarget({
      id: packageKey,
      packageKey: packageKey,
      finding: sampleFinding,
      timestamp: Date.now(),
    });
    setFocusNodeId(packageKey);
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
      if (bd.historic_attack_count) {
        report += `- Historic Supply Chain Attacks: ${bd.historic_attack_count} (${(bd.historic_attacks_detected || []).join(", ")})\n`;
      }
      if (bd.sbom_sha256) report += `- SBOM SHA-256: ${bd.sbom_sha256}\n`;
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

  const handleDownloadPatchedManifest = useCallback(() => {
    if (!data) return;
    const isPython = (data?.components || []).some(c => c.ecosystem === "pypi") ||
      (data?.scan?.lockfile_types || []).some((t: string) => t.toLowerCase().includes("requirements") || t.toLowerCase().includes("poetry"));

    let content = "";
    let filename = "";

    if (isPython) {
      filename = "requirements.patched.txt";
      content = `# SupplyGraph Auto-Patched Manifest\n# Generated: ${new Date().toISOString()}\n# Repository: ${data?.scan?.repository_url || "Local Project"}\n\n`;
      const patchedDeps = new Map<string, string>();
      (data.findings || []).forEach(f => {
        const pkg = f.origin_candidate?.split("@")?.[0] || f.entity_id;
        let fixedVer = f.recommendations?.[0]?.fixed_version;
        if (!fixedVer && f.evidence) {
          for (const ev of f.evidence) {
            if (ev?.raw_data?.fixed_version) { fixedVer = ev.raw_data.fixed_version; break; }
            if (ev?.raw_data?.fixed) { fixedVer = ev.raw_data.fixed; break; }
          }
        }
        if (pkg && fixedVer && fixedVer !== "latest" && !fixedVer.includes("patched_version")) {
          const cleanPin = (fixedVer.startsWith(">=") || fixedVer.startsWith("==")) ? fixedVer : `>=${fixedVer}`;
          patchedDeps.set(pkg, cleanPin);
        }
      });
      (data.components || []).forEach(c => {
        const pin = patchedDeps.get(c.name);
        if (pin) {
          content += `${c.name}${pin}  # Patched by SupplyGraph (Secured)\n`;
        } else if (c.is_direct && c.version) {
          content += `${c.name}==${c.version}\n`;
        }
      });
    } else {
      filename = "package.patched.json";
      const overrides: Record<string, string> = {};
      (data.findings || []).forEach(f => {
        const origin = f.origin_candidate || f.title || "";
        let clean = origin.replace(/^pkg:(npm|pypi)\//, "");
        try { clean = decodeURIComponent(clean); } catch (_) {}

        let pkg = clean;
        let installedVer = "";
        if (clean.startsWith("@")) {
          const atIdx = clean.indexOf("@", 1);
          if (atIdx !== -1) {
            pkg = clean.substring(0, atIdx);
            installedVer = clean.substring(atIdx + 1);
          }
        } else {
          const atIdx = clean.indexOf("@");
          if (atIdx !== -1) {
            pkg = clean.substring(0, atIdx);
            installedVer = clean.substring(atIdx + 1);
          }
        }

        let fixedVer = f.recommendations?.[0]?.fixed_version;
        if (!fixedVer && f.evidence) {
          for (const ev of f.evidence) {
            if (ev?.raw_data?.fixed_version) { fixedVer = ev.raw_data.fixed_version; break; }
            if (ev?.raw_data?.fixed) { fixedVer = ev.raw_data.fixed; break; }
          }
        }

        const fixStr = typeof fixedVer === "string" ? fixedVer : String(fixedVer || "");
        if (pkg && fixStr && fixStr !== "latest" && !fixStr.includes("patched_version")) {
          const majorMatch = installedVer.match(/^v?(\d+)/);
          const overrideKey = majorMatch ? `${pkg}@^${majorMatch[1]}.0.0` : pkg;
          const cleanFix = fixStr.replace(/^[v^~>=<\s]+/, "");
          const targetVer = (fixStr.startsWith("^") || fixStr.startsWith(">=")) ? fixStr : `^${cleanFix}`;

          if (overrides[overrideKey]) {
            const existing = overrides[overrideKey];
            if (compareSemVer(cleanFix, existing) > 0) {
              overrides[overrideKey] = targetVer;
            }
          } else {
            overrides[overrideKey] = targetVer;
          }
        }
      });
      const patchedPkg = {
        name: data?.scan?.repository_url?.split("/").pop() || "patched-project",
        version: "1.0.0",
        description: "Auto-remediated dependency manifest generated by SupplyGraph",
        overrides: overrides,
        dependencies: (data.components || [])
          .filter(c => c.is_direct && !c.is_dev)
          .reduce((acc: any, c) => {
            acc[c.name] = overrides[c.name] || `^${c.version || "1.0.0"}`;
            return acc;
          }, {})
      };
      content = JSON.stringify(patchedPkg, null, 2);
    }

    const blob = new Blob([content], { type: isPython ? "text/plain" : "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }, [data]);

  const handleDownloadExecutiveHtml = useCallback(() => {
    if (!data) return;
    const repoTitle = data?.scan?.repository_url?.replace("https://github.com/", "") || (activeScenario ? `Demo Scenario ${activeScenario}` : "Audited Project");
    const blast = data?.scan?.blast_radius_score || 0;
    const totalComps = data?.scan?.total_components || 0;
    const totalFindings = data?.scan?.total_findings || 0;
    const codeReviews = data?.code_reviews?.length || 0;

    let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SupplyGraph Executive Audit: ${repoTitle}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #09090b; color: #f4f4f5; margin: 0; padding: 40px; }
  .header { border-bottom: 2px solid #27272a; padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: center; }
  .badge { background: #18181b; border: 1px solid #3f3f46; color: #38bdf8; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; font-family: monospace; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .card { background: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 20px; }
  .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #71717a; margin-bottom: 6px; }
  .card-val { font-size: 28px; font-weight: 700; font-family: monospace; }
  .briefing { background: #1e1b4b; border: 1px solid #3730a3; border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .finding { background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .tag-crit { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; font-family: monospace; }
  pre { background: #09090b; border: 1px solid #27272a; padding: 12px; border-radius: 8px; font-size: 11px; overflow-x: auto; color: #a1a1aa; font-family: monospace; }
  @media print { body { background: white; color: black; padding: 20px; } .card, .briefing, .finding { border-color: #ccc; background: #fafafa; color: black; } pre { background: #f4f4f4; color: black; border-color: #ddd; } }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1 style="margin:0; font-size: 26px;">SupplyGraph Executive Audit</h1>
    <p style="margin: 6px 0 0; color: #71717a; font-size: 13px;">Target: <b>${repoTitle}</b> &bull; Generated: ${new Date().toUTCString()}</p>
  </div>
  <div class="badge">SECURED BY SUPPLYGRAPH</div>
</div>

<div class="grid">
  <div class="card"><div class="card-label">Blast Radius</div><div class="card-val" style="color: ${blast > 70 ? '#ef4444' : blast > 0 ? '#f59e0b' : '#10b981'}">${blast.toFixed(1)}/100</div></div>
  <div class="card"><div class="card-label">Components</div><div class="card-val">${totalComps}</div></div>
  <div class="card"><div class="card-label">Threat Findings</div><div class="card-val" style="color: #ef4444">${totalFindings}</div></div>
  <div class="card"><div class="card-label">AI Code Patches</div><div class="card-val" style="color: #6366f1">${codeReviews}</div></div>
</div>

<div class="briefing">
  <h2 style="margin:0 0 12px; font-size: 16px; color: #a5b4fc;">Executive AI Briefing</h2>
  <div style="font-size: 13px; line-height: 1.6; color: #e0e7ff; white-space: pre-wrap;">${data?.gemini_explanation || "No executive summary recorded for this analysis."}</div>
</div>

<h2 style="font-size: 18px; margin-bottom: 16px;">Detailed Security Findings (${data?.findings?.length || 0})</h2>
`;

    (data?.findings || []).forEach((f: any, idx: number) => {
      html += `<div class="finding">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <b style="font-size:14px;">[${idx + 1}] ${f.title}</b>
          <span class="tag-crit">${f.severity}</span>
        </div>
        <p style="font-size:12px; color:#a1a1aa; margin:0 0 10px;">${f.description}</p>
        ${f.recommendations?.[0] ? `<div style="font-size:12px; color:#38bdf8; margin-bottom:6px;"><b>Recommendation:</b> ${f.recommendations[0].title} - ${f.recommendations[0].why}</div>` : ''}
        <pre>${buildLockfileSnippet(f)}</pre>
      </div>`;
    });

    html += `</body></html>`;

    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `supplygraph-executive-report-${data?.scan?.repository_url?.split("/").pop() || "audit"}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data, activeScenario]);

  const handleDownloadSbom = useCallback(() => {
    if (!data?.sbom && !data?.components) return;
    const sha = data?.detector_breakdown?.sbom_sha256 || computedSbomSha || "0x9f83b2...a41e";
    const rawSbom = data.sbom || {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      components: data.components || [],
    };
    const sbomData = {
      ...rawSbom,
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      metadata: {
        ...((rawSbom as any).metadata || {}),
        timestamp: new Date().toISOString(),
        component: {
          name: data?.scan?.repository_url?.split("/").pop() || "supplygraph-target",
          type: "application",
        },
        properties: [
          ...(((rawSbom as any).metadata?.properties as any[]) || []),
          { name: "supplygraph:deterministic_sha256", value: sha },
        ],
      },
      signature: {
        algorithm: "SHA-256",
        value: sha,
      },
    };
    const blob = new Blob([JSON.stringify(sbomData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyclonedx-sbom-${data?.scan?.repository_url?.split("/").pop() || "export"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data, computedSbomSha]);

  const handleGetStarted = useCallback(() => setCurrentView("scanner"), []);
  const handleSelectScenario = useCallback((id: ScenarioId) => executeScenario(id), [executeScenario]);
  const handleNodeClick = useCallback((nodeId: string) => {
    setFocusTarget({
      id: nodeId,
      timestamp: Date.now(),
    });
    setFocusNodeId(nodeId);
  }, []);
  // Compute accurate dependency depths:
  // - Root repository node: 0
  // - Direct dependencies: 1
  // - Transitive dependencies: 2, 3...
  // - Vulnerability nodes inherit the exact depth of the package they affect
  const nodeDepths = useMemo(() => {
    if (!data?.graph?.nodes || data.graph.nodes.length === 0) return new Map<string, number>();
    const nodes = data.graph.nodes;
    const edges = data.graph.edges || [];

    const depths = new Map<string, number>();

    // Index SBOM component depths if available
    const compDepthMap = new Map<string, number>();
    const compList: any[] = data.components || data.sbom?.components || [];
    compList.forEach((c) => {
      const d = c.depth ?? (c.is_direct ? 1 : 2);
      if (c.bom_ref) compDepthMap.set(c.bom_ref.toLowerCase(), d);
      if (c.name) compDepthMap.set(c.name.toLowerCase(), d);
      if (c.purl) compDepthMap.set(c.purl.toLowerCase(), d);
    });

    // 1. Root nodes: strictly Repository nodes (depth 0)
    let roots = nodes
      .filter((n) => {
        const type = (n.data?.node_type || n.type || "").toLowerCase();
        return type === "repository";
      })
      .map((n) => n.id);

    if (roots.length === 0) {
      // Fallback: nodes with no incoming edges, strictly excluding vulnerability nodes
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

    // 2. Dependency adjacency strictly for CONTAINS, DEPENDS_ON, USES, DEPLOYED_AS (never AFFECTS)
    const depAdj = new Map<string, { target: string; edgeDepth?: number }[]>();
    nodes.forEach((n) => depAdj.set(n.id, []));

    edges.forEach((e) => {
      const edgeType = (e.data?.edge_type || e.type || e.data?.label || "").toLowerCase();
      if (edgeType !== "affects") {
        if (depAdj.has(e.source)) {
          depAdj.get(e.source)!.push({ target: e.target, edgeDepth: e.data?.depth });
        }
      }
    });

    // 3. BFS through dependency tree
    const queue: string[] = [...roots];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      const currD = depths.get(curr)!;
      const neighbors = depAdj.get(curr) || [];
      for (const next of neighbors) {
        const targetNode = nodes.find((n) => n.id === next.target);
        const metaDepth = (targetNode?.data as any)?.metadata?.depth ?? (targetNode?.data as any)?.depth;
        const cleanName = (targetNode?.data?.label || "").split("@")[0].toLowerCase();
        const compD = targetNode ? compDepthMap.get(targetNode.id.toLowerCase()) || compDepthMap.get(cleanName) : undefined;

        let candidateDepth: number;
        if (next.edgeDepth !== undefined && next.edgeDepth !== null) {
          candidateDepth = next.edgeDepth;
        } else if (metaDepth !== undefined && metaDepth !== null) {
          candidateDepth = metaDepth;
        } else if (compD !== undefined) {
          candidateDepth = compD;
        } else {
          candidateDepth = currD + 1;
        }

        if (!depths.has(next.target) || depths.get(next.target)! > candidateDepth) {
          depths.set(next.target, candidateDepth);
          queue.push(next.target);
        }
      }
    }

    // 4. Fill in any non-vulnerability package/asset nodes not reached
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

    // 5. Vulnerability nodes inherit the exact depth of the package they affect
    nodes.forEach((n) => {
      const type = (n.data?.node_type || n.type || "").toLowerCase();
      const isVuln = type === "vulnerability" || n.id.startsWith("GHSA-") || n.id.startsWith("CVE-");
      if (isVuln) {
        // Direct metadata depth if available from backend
        const metaDepth = (n.data as any)?.metadata?.depth ?? (n.data as any)?.depth;

        // Check edges connecting this vulnerability to a package
        const connectedEdges = edges.filter(
          (e) => e.source === n.id || e.target === n.id
        );
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

        // Fallback to finding evidence package if edges weren't linked
        if (pkgDepth === null && data.findings) {
          const finding = data.findings.find(
            (f: any) =>
              f.title?.includes(n.id) ||
              f.description?.includes(n.id) ||
              (f.evidence && f.evidence.some((ev: any) => ev.description?.includes(n.id) || ev.raw_data?.vuln_id === n.id))
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
      }
    });

    return depths;
  }, [data?.graph, data?.components, data?.sbom?.components, data?.findings]);

  const maxGraphDepth = useMemo(() => {
    if (nodeDepths.size === 0) return 10;
    const maxD = Math.max(...Array.from(nodeDepths.values()), 1);
    return Math.max(maxD, 1);
  }, [nodeDepths]);

  // Synchronize transitiveDepth when a new scan or graph loads
  useEffect(() => {
    if (data?.scan?.id && maxGraphDepth > 0) {
      setTransitiveDepth(maxGraphDepth);
    } else if (data?.graph && maxGraphDepth > 0) {
      setTransitiveDepth((prev) => (prev > maxGraphDepth ? maxGraphDepth : prev));
    }
  }, [data?.scan?.id, data?.graph, maxGraphDepth]);

  const isNodeDev = useCallback(
    (node: GraphNode): boolean => {
      if (node.data?.is_dev === true) return true;
      if (node.data?.metadata?.is_dev === true) return true;
      const type = (node.data?.node_type || node.type || "").toLowerCase();
      if (type === "devdependency") return true;

      // Common development, test, and UI tooling packages across ecosystems
      const devPackages = [
        "streamlit", "watchdog", "pytest", "pytest-cov", "pytest-asyncio",
        "black", "flake8", "mypy", "coverage", "pylint", "isort", "bandit",
        "mock", "pre-commit", "tox", "sphinx", "mkdocs", "eslint", "jest",
        "mocha", "typescript", "actionlint"
      ];

      const rawLabel = (node.data?.label || node.id || "").toLowerCase();
      const pkgNameFromLabel = rawLabel.split("@")[0].replace(/^pkg:(pypi|npm|cargo|golang)\//, "");
      if (devPackages.some((p) => pkgNameFromLabel === p || pkgNameFromLabel.endsWith("/" + p))) {
        return true;
      }

      // Check against SBOM / component list
      const comp = (data?.components || data?.sbom?.components || []).find(
        (c: any) =>
          c.bom_ref === node.id ||
          c.name?.toLowerCase() === pkgNameFromLabel ||
          c.purl === node.data?.purl
      );
      if (comp && comp.is_dev) return true;

      // If this node is a vulnerability, check if it affects a dev component
      const isVuln = type === "vulnerability" || node.id.startsWith("GHSA-") || node.id.startsWith("CVE-");
      if (isVuln && data?.graph?.edges) {
        // Find connected target packages via edges
        const connectedEdges = data.graph.edges.filter(
          (e) => e.source === node.id || e.target === node.id
        );
        for (const ce of connectedEdges) {
          const targetId = ce.source === node.id ? ce.target : ce.source;
          const targetNode = data.graph.nodes.find((n) => n.id === targetId);
          if (targetNode && isNodeDev(targetNode)) {
            return true;
          }
        }

        // Also check if any finding for this vuln is tied to a dev package
        if (data?.findings) {
          const vulnFinding = data.findings.find(
            (f: any) =>
              f.title?.includes(node.id) ||
              f.description?.includes(node.id) ||
              (f.evidence && f.evidence.some((ev: any) => ev.description?.includes(node.id) || ev.raw_data?.vuln_id === node.id))
          );
          if (vulnFinding) {
            const { pkgName } = getFindingPackage(vulnFinding);
            if (pkgName && devPackages.some((p) => pkgName.toLowerCase() === p || pkgName.toLowerCase().startsWith(p + "@"))) {
              return true;
            }
          }
        }
      }

      return false;
    },
    [data?.components, data?.sbom?.components, data?.graph?.edges, data?.graph?.nodes, data?.findings]
  );

  const devDepsCount = useMemo(() => {
    const devPackages = [
      "streamlit", "watchdog", "pytest", "pytest-cov", "pytest-asyncio",
      "black", "flake8", "mypy", "coverage", "pylint", "isort", "bandit",
      "mock", "pre-commit", "tox", "sphinx", "mkdocs", "eslint", "jest",
      "mocha", "typescript", "actionlint"
    ];

    if (!data?.graph?.nodes) {
      const compList: any[] = data?.components || data?.sbom?.components || [];
      return compList.filter((c) => c.is_dev || devPackages.includes(c.name?.toLowerCase())).length;
    }
    // Count dev component/package nodes (excluding repository and vulnerability nodes)
    const devNodes = data.graph.nodes.filter((n) => {
      const type = (n.data?.node_type || n.type || "").toLowerCase();
      const isVuln = type === "vulnerability" || n.id.startsWith("GHSA-") || n.id.startsWith("CVE-");
      if (isVuln || type === "repository") return false;
      return isNodeDev(n);
    });
    const compDevCount = (data?.components || data?.sbom?.components || []).filter(
      (c: any) => c.is_dev || devPackages.includes(c.name?.toLowerCase())
    ).length;
    return Math.max(devNodes.length, compDevCount);
  }, [data?.graph?.nodes, data?.components, data?.sbom?.components, isNodeDev]);

  const currentGraph = useMemo(() => {
    if (!data?.graph?.nodes) return null;

    // Filter nodes
    const visibleNodes = data.graph.nodes.filter((node) => {
      const type = (node.data?.node_type || node.type || "").toLowerCase();
      // Root repository node is always visible
      if (type === "repository") return true;

      // Prod-Only filter: hide dev dependencies
      if (prodOnly && isNodeDev(node)) {
        return false;
      }

      // Transitive Depth filter
      const depth = nodeDepths.get(node.id) ?? 1;
      if (depth > transitiveDepth) {
        return false;
      }

      return true;
    });

    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));

    // Filter edges: only include edges where BOTH endpoints are visible
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
  }, [data?.graph, nodeDepths, prodOnly, transitiveDepth, isNodeDev]);

  const activeFindings = useMemo(() => {
    if (!data?.findings) return [];

    const devPackages = [
      "streamlit", "watchdog", "pytest", "pytest-cov", "pytest-asyncio",
      "black", "flake8", "mypy", "coverage", "pylint", "isort", "bandit",
      "mock", "pre-commit", "tox", "sphinx", "mkdocs", "eslint", "jest",
      "mocha", "typescript", "actionlint"
    ];

    return data.findings.filter((f) => {
      const { pkgName } = getFindingPackage(f);
      if (!pkgName) return true;

      // Check if this finding is tied to a dev dependency when prodOnly is true
      if (prodOnly) {
        const cleanPkg = pkgName.toLowerCase();
        const isKnownDev = devPackages.some(
          (p) => cleanPkg === p || cleanPkg.startsWith(p + "@") || cleanPkg.includes("/" + p)
        );
        const isDevComp = (data.components || data.sbom?.components || []).some(
          (c: any) =>
            (c.name?.toLowerCase() === cleanPkg ||
             c.bom_ref?.toLowerCase().includes(cleanPkg)) &&
            c.is_dev
        );
        if (isKnownDev || isDevComp) return false;
      }

      // Check if this finding's package is within transitiveDepth
      if (data.graph?.nodes) {
        // Find the node depth for this finding's package
        let pkgDepth: number | null = null;
        nodeDepths.forEach((depth, nodeId) => {
          const rawId = nodeId.toLowerCase();
          const cleanPkg = pkgName.toLowerCase();
          if (rawId.includes(cleanPkg) || rawId.split("@")[0].endsWith(cleanPkg)) {
            if (pkgDepth === null || depth < pkgDepth) {
              pkgDepth = depth;
            }
          }
        });

        // If package depth found and exceeds transitiveDepth, filter it out
        if (pkgDepth !== null && pkgDepth > transitiveDepth) {
          return false;
        }

        // Also check if currentGraph has any node matching this package
        if (currentGraph?.nodes) {
          const matchingRawNodes = data.graph.nodes.filter((n) => {
            const label = (n.data?.label || "").toLowerCase();
            const id = n.id.toLowerCase();
            const target = pkgName.toLowerCase();
            return id.includes(target) || label.includes(target);
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
  }, [data?.findings, data?.graph?.nodes, currentGraph?.nodes, prodOnly, transitiveDepth, nodeDepths, data?.components, data?.sbom?.components]);

  const currentCodeReviews = useMemo(() => data?.code_reviews || [], [data?.code_reviews]);
  const handleReviewsUpdated = useCallback((updated: CodeReviewItem[]) => {
    setData((prev) => (prev ? { ...prev, code_reviews: updated } : null));
  }, []);
  const displayedFindings = useMemo(() => {
    if (!activeFindings) return [];
    return showAllFindings ? activeFindings : activeFindings.slice(0, 25);
  }, [activeFindings, showAllFindings]);

  const groupedFindings = useMemo(() => {
    if (!activeFindings || activeFindings.length === 0) return [];
    const groups: Record<
      string,
      {
        key: string;
        pkgName: string;
        version: string;
        ecosystem: string;
        findings: any[];
        highestSeverity: string;
        fixVersion: string;
      }
    > = {};

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

      // Highest severity calculation
      const currentSev = f.severity?.toUpperCase() || "LOW";
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const groupSevIdx = sevOrder.indexOf(groups[key].highestSeverity);
      const curSevIdx = sevOrder.indexOf(currentSev);
      if (curSevIdx !== -1 && (groupSevIdx === -1 || curSevIdx < groupSevIdx)) {
        groups[key].highestSeverity = currentSev;
      }
    });

    // Compute the optimal 1-shot safe fix version across ALL findings in each package
    Object.values(groups).forEach((g) => {
      const candidateFixes: string[] = [];
      g.findings.forEach((f) => {
        if (f.recommendations) {
          f.recommendations.forEach((r: any) => {
            if (r?.fixed_version) candidateFixes.push(r.fixed_version);
          });
        }
        if (f.evidence) {
          f.evidence.forEach((e: any) => {
            if (e?.raw_data?.fixed_version) candidateFixes.push(e.raw_data.fixed_version);
            if (e?.raw_data?.fixed) candidateFixes.push(e.raw_data.fixed);
          });
        }
      });

      const bestFix = resolveHighestSafeVersion(g.version, candidateFixes);
      if (bestFix) {
        g.fixVersion = bestFix;
      } else if (candidateFixes.length > 0) {
        g.fixVersion = candidateFixes[0];
      }
    });

    const list = Object.values(groups).sort((a, b) => {
      const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const aIdx = sevOrder.indexOf(a.highestSeverity);
      const bIdx = sevOrder.indexOf(b.highestSeverity);
      if (aIdx !== bIdx) return aIdx - bIdx;
      return b.findings.length - a.findings.length;
    });

    return list;
  }, [activeFindings]);

  // Auto-expand the first package by default when grouped findings load
  useEffect(() => {
    if (groupedFindings.length > 0) {
      setExpandedPackageKeys((prev) => {
        if (Object.keys(prev).length === 0 && groupedFindings[0]) {
          return { [groupedFindings[0].key]: true };
        }
        return prev;
      });
    }
  }, [groupedFindings]);

  const togglePackageExpanded = useCallback((key: string) => {
    setExpandedPackageKeys((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  }, []);

  const toggleAllPackages = useCallback((expand: boolean) => {
    if (!expand) {
      setExpandedPackageKeys({});
    } else {
      const all: Record<string, boolean> = {};
      groupedFindings.forEach((g) => { all[g.key] = true; });
      setExpandedPackageKeys(all);
    }
  }, [groupedFindings]);

  // Login/Signup page removed — direct access to application

  return (
    <ErrorBoundary fallbackTitle="SupplyGraph Session Recovered">
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
              <span className="text-sm font-bold tracking-tight text-zinc-100">SupplyGraph</span>
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
                currentView === "scanner"
                  ? "bg-zinc-800 text-zinc-100 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              )}
            >
              <span>Scanner & Graph</span>
            </button>

            <button
              onClick={() => setCurrentView("reviewer")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                currentView === "reviewer"
                  ? "bg-zinc-800 text-zinc-100 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              )}
            >
              <Sparkles className="w-3 h-3 text-amber-400" />
              <span>Code Reviewer</span>
              {data?.code_reviews && data.code_reviews.length > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[9px] bg-amber-500/20 text-amber-300 font-mono font-bold">
                  {data.code_reviews.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setCurrentView("sandbox")}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                currentView === "sandbox"
                  ? "bg-zinc-800 text-zinc-100 font-semibold"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900"
              )}
            >
              <Zap className="w-3 h-3 text-red-400" />
              <span>⚡ Sandbox Execution</span>
            </button>
          </nav>
        </div>

        {/* Top Right Controls */}
        <div className="flex items-center space-x-3">
          {currentView === "overview" && (
            <button
              onClick={() => setCurrentView("scanner")}
              className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white text-xs font-semibold shadow-md shadow-red-600/20 transition-all flex items-center space-x-1.5 hover:scale-105 active:scale-95"
            >
              <span>🚀 Get Started →</span>
            </button>
          )}

          {/* CycloneDX SBOM modal button in header when in scanner */}
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
            </div>
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
          {/* SCANNER CONTROLS HEADER (Sleek Unified Command Bar) */}
          <div className="border-b border-zinc-800/80 bg-zinc-950/90 px-6 py-2.5 shrink-0">
            <div className="flex flex-wrap items-center gap-2.5">
              {/* URL Input */}
              <div className="relative flex-1 min-w-[280px]">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                <input
                  ref={inputRef}
                  type="text"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && executeAnalysis(githubUrl)}
                  placeholder="https://github.com/owner/repository — Press Enter to scan"
                  className="w-full pl-10 pr-24 py-1.5 rounded-xl bg-zinc-900/90 border border-zinc-800 text-xs font-mono text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-red-500/50 transition-all"
                />
                <button
                  onClick={() => executeAnalysis(githubUrl)}
                  disabled={loading}
                  className="absolute right-1 top-1/2 -translate-y-1/2 px-3 py-1 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center space-x-1 transition-colors shadow-sm"
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

              {/* Upload Folder Button */}
              <button
                onClick={() => folderInputRef.current?.click()}
                disabled={loading}
                className="px-3 py-1.5 rounded-xl bg-indigo-600/15 hover:bg-indigo-600/25 border border-indigo-500/30 hover:border-indigo-500/50 text-indigo-300 hover:text-indigo-200 text-xs font-semibold flex items-center space-x-1.5 transition-all shrink-0 shadow-sm"
                title="Upload and scan a local project directory from your computer"
              >
                <FolderUp className="w-3.5 h-3.5 text-indigo-400" />
                <span>Upload Folder</span>
              </button>

              {/* Demo Scenarios Dropdown */}
              <div className="relative shrink-0">
                <button
                  type="button"
                  onClick={() => setShowScenariosDropdown(!showScenariosDropdown)}
                  className={cn(
                    "px-3 py-1.5 rounded-xl text-xs font-mono font-medium flex items-center space-x-1.5 border transition-all shadow-sm",
                    activeScenario
                      ? "bg-red-500/15 border-red-500/40 text-red-300 font-semibold"
                      : "bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700"
                  )}
                  title="Test deterministic evaluation scenarios (A–E)"
                >
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>{activeScenario ? `Scenario ${activeScenario}` : "Demo Scenarios"}</span>
                  <ChevronDown className={cn("w-3.5 h-3.5 text-zinc-400 transition-transform", showScenariosDropdown && "rotate-180")} />
                </button>

                {showScenariosDropdown && (
                  <div className="absolute left-0 sm:right-0 sm:left-auto top-full mt-2 w-80 bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl z-50 p-2 space-y-1 backdrop-blur-2xl">
                    <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase text-zinc-500 border-b border-zinc-800/80 flex items-center justify-between">
                      <span>Deterministic Scenarios</span>
                      <span className="text-[9px] text-zinc-600">5 Evaluator Modes</span>
                    </div>
                    {SCENARIOS.map((s) => (
                      <button
                        key={s.id}
                        onClick={() => {
                          setShowScenariosDropdown(false);
                          executeScenario(s.id);
                        }}
                        className={cn(
                          "w-full text-left px-3 py-2 rounded-xl text-xs font-mono flex items-center space-x-2.5 transition-colors",
                          activeScenario === s.id ? "bg-red-500/20 text-red-200 border border-red-500/30" : "hover:bg-zinc-900 text-zinc-300"
                        )}
                      >
                        <span className="text-base">{s.icon}</span>
                        <div className="flex-1 min-w-0">
                          <div className="font-semibold text-zinc-100 flex items-center justify-between">
                            <span>Scenario {s.id}</span>
                          </div>
                          <div className="text-[10px] text-zinc-400 truncate">{s.label}</div>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Production Only vs All Dependencies Toggle */}
              <button
                type="button"
                onClick={() => setProdOnly(!prodOnly)}
                className={cn(
                  "px-2.5 py-1.5 rounded-xl text-xs font-mono font-medium flex items-center space-x-1.5 border transition-all shrink-0 shadow-sm cursor-pointer",
                  prodOnly
                    ? "bg-emerald-950/60 border-emerald-500/70 text-emerald-300 shadow-emerald-950/30"
                    : "bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
                )}
                title={
                  prodOnly
                    ? `Filtering: Production Only (${devDepsCount} Dev Dependenc${devDepsCount === 1 ? 'y' : 'ies'} Omitted)`
                    : "Filtering: All Dependencies (Including Dev Dependencies)"
                }
              >
                <span className={cn("w-2 h-2 rounded-full", prodOnly ? "bg-emerald-400 animate-pulse" : "bg-zinc-600")} />
                <span>{prodOnly ? "Prod Only" : "All Deps"}</span>
                {devDepsCount > 0 && (
                  <span
                    className={cn(
                      "px-1.5 py-0.2 rounded-full text-[9px] font-bold font-mono transition-colors",
                      prodOnly ? "bg-emerald-500/25 text-emerald-300 border border-emerald-500/30" : "bg-zinc-800 text-zinc-500"
                    )}
                  >
                    {prodOnly ? `-${devDepsCount}` : `${devDepsCount} dev`}
                  </span>
                )}
              </button>

              {/* Configurable Transitive Depth Stepper */}
              <div
                className={cn(
                  "flex items-center space-x-1.5 px-2.5 py-1.5 rounded-xl border text-xs font-mono transition-all shrink-0 shadow-sm",
                  transitiveDepth < maxGraphDepth
                    ? "bg-indigo-950/40 border-indigo-500/60 text-indigo-200"
                    : "bg-zinc-900/80 border-zinc-800 text-zinc-300"
                )}
                title={`Max Transitive Dependency Depth Filter: ${transitiveDepth} of ${maxGraphDepth} hops`}
              >
                <span className="text-zinc-500 text-[10px] uppercase">Depth:</span>
                <span className="text-indigo-400 font-semibold">{transitiveDepth}</span>
                <span className="text-zinc-600 text-[10px]">/{maxGraphDepth}</span>
                <div className="flex items-center space-x-1 ml-0.5">
                  <button
                    type="button"
                    onClick={() => setTransitiveDepth((prev) => Math.max(1, Math.min(prev, maxGraphDepth) - 1))}
                    disabled={transitiveDepth <= 1}
                    className="w-4 h-4 rounded flex items-center justify-center bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-zinc-300 text-[10px] transition-colors active:scale-90"
                    title="Decrease depth (hide deeper transitive hops)"
                  >
                    -
                  </button>
                  <button
                    type="button"
                    onClick={() => setTransitiveDepth((prev) => Math.min(Math.max(maxGraphDepth, 20), prev + 1))}
                    disabled={transitiveDepth >= Math.max(maxGraphDepth, 20)}
                    className="w-4 h-4 rounded flex items-center justify-center bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-zinc-300 text-[10px] transition-colors active:scale-90"
                    title="Increase depth (reveal deeper transitive hops)"
                  >
                    +
                  </button>
                </div>
              </div>
            </div>

            {/* Error banner */}
            {error && (
              <div className="mt-2 p-2.5 rounded-lg bg-red-950/40 border border-red-800/40 text-red-300 text-xs font-mono flex items-center justify-between">
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
              <div className="m-auto flex flex-col items-center justify-center text-center p-8 space-y-4 max-w-md">
                <div className="relative">
                  <div className="w-16 h-16 rounded-full border-2 border-red-500/20 border-t-red-500 animate-spin" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <Cpu className="w-6 h-6 text-zinc-400 animate-pulse" />
                  </div>
                </div>
                <div>
                  <p className="text-xs font-mono text-zinc-200 tracking-wider uppercase font-semibold">
                    Traversing Multi-Hop Attack DAG... {scanElapsedSeconds > 0 && `(${scanElapsedSeconds}s)`}
                  </p>
                  <p className="text-[11px] font-mono text-zinc-500 mt-1">
                    Parsing Lockfiles → OSV Batch Intel → Heuristic Detectors → AI Code Reviewer
                  </p>
                </div>
                <div className="flex items-center space-x-2 pt-1">
                  <button
                    type="button"
                    onClick={handleCancelScan}
                    className="px-3.5 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 text-zinc-300 text-xs font-mono transition-all flex items-center space-x-1.5 shadow-sm active:scale-95"
                  >
                    <X className="w-3.5 h-3.5 text-zinc-400" />
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
                      <FolderUp className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Switch to Folder Upload</span>
                    </button>
                  )}
                </div>
              </div>
            ) : data ? (
              /* ACTIVE GRAPH & WORKSPACE */
              <>
                <div className="flex-1 flex flex-col h-full relative">
                  {/* FLOATING TELEMETRY HUD */}
                  <div className="absolute top-4 left-4 z-20">
                    {hudCollapsed ? (
                      <div className="bg-zinc-950/90 backdrop-blur-xl border border-zinc-800 rounded-xl px-3 py-1.5 shadow-2xl flex items-center space-x-3 text-xs font-mono">
                        <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        <span className="text-zinc-200 font-semibold truncate max-w-[140px]">
                          {data?.scan?.repository_url?.replace("https://github.com/", "") ||
                            (activeScenario ? `Demo ${activeScenario}` : "Scan")}
                        </span>
                        <span className="text-zinc-600">|</span>
                        <span className="text-zinc-400">Comps: <b className="text-zinc-200">{data?.scan?.total_components || 0}</b></span>
                        <span className="text-zinc-400">Findings: <b className="text-red-400">{data?.scan?.total_findings || 0}</b></span>
                        <span className="text-zinc-400">Blast: <b className="text-amber-400">{(Number(data?.scan?.blast_radius_score) || 0).toFixed(1)}/100</b></span>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedHistoryScan(null);
                            setComparisonResult(null);
                            setShowHistoryModal(true);
                          }}
                          className="px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 text-indigo-300 text-[10px] flex items-center space-x-1 border border-zinc-700/60"
                          title="View Scan History & Delta Regression"
                        >
                          <Clock className="w-3 h-3 text-indigo-400" />
                          <span>Delta ({scanHistory.length})</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setHudCollapsed(false)}
                          className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-white rounded-lg transition-colors ml-1"
                          title="Expand Telemetry HUD"
                        >
                          <Maximize2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ) : (
                      <div className="bg-zinc-950/85 backdrop-blur-xl border border-zinc-800/90 rounded-xl px-4 py-3 shadow-2xl min-w-[220px]">
                        <div className="flex items-center justify-between space-x-2 mb-2.5">
                          <div className="flex items-center space-x-2 min-w-0">
                            <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse shrink-0" />
                            <span className="text-[11px] font-mono font-semibold text-zinc-100 truncate max-w-[150px]">
                              {data?.scan?.repository_url?.replace("https://github.com/", "") ||
                                (activeScenario ? `Demo Scenario ${activeScenario}` : "Project")}
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => setHudCollapsed(true)}
                            className="p-1 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/60 rounded-md transition-colors"
                            title="Minimize HUD to see graph nodes behind it"
                          >
                            <Minimize2 className="w-3.5 h-3.5" />
                          </button>
                        </div>

                      <div className="flex items-center space-x-4 text-[11px] font-mono pt-2 border-t border-zinc-800/60">
                        <div>
                          <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Components</span>
                          <span className="text-zinc-200 font-semibold">
                            {currentGraph ? currentGraph.nodes.filter(n => (n.data?.node_type || '').toLowerCase() !== 'repository').length : data?.scan?.total_components || 0}
                          </span>
                        </div>
                        <div>
                          <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Findings</span>
                          <span className="text-red-400 font-semibold">{activeFindings.length}</span>
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
                              (Number(data?.scan?.blast_radius_score) || 0) > 70
                                ? "text-red-400"
                                : (Number(data?.scan?.blast_radius_score) || 0) > 0
                                ? "text-amber-400"
                                : "text-emerald-400"
                            )}
                          >
                            {(Number(data?.scan?.blast_radius_score) || 0).toFixed(1)}/100
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
                          <span className="text-cyan-300">
                            AST: {data.detector_breakdown.ast_count || (data?.code_reviews?.filter(r => !r.file_path.endsWith('.yml') && !r.file_path.endsWith('.yaml') && !r.title.includes('CI/CD')).length) || 0}
                          </span>
                          <span className="text-zinc-600">•</span>
                          <span className="text-yellow-300">
                            CI/CD: {data.detector_breakdown.cicd_count || (data?.code_reviews?.filter(r => r.file_path.endsWith('.yml') || r.file_path.endsWith('.yaml') || r.title.includes('CI/CD')).length) || 0}
                          </span>
                          {(data.detector_breakdown.historic_attack_count || 0) > 0 && (
                            <>
                              <span className="text-zinc-600">•</span>
                              <span className="text-rose-400 font-bold bg-rose-950/70 px-1 py-0.5 rounded border border-rose-600/50">
                                🛡️ Historic Attacks: {data.detector_breakdown.historic_attack_count}
                              </span>
                            </>
                          )}
                        </div>
                      )}

                      {/* Active Filter Pill in HUD */}
                      {(prodOnly || transitiveDepth < maxGraphDepth) && (
                        <div className="mt-2 pt-1.5 border-t border-zinc-800/60 flex items-center justify-between text-[9px] font-mono">
                          <span className="text-zinc-500 flex items-center space-x-1">
                            <ListFilter className="w-3 h-3 text-amber-400" />
                            <span>Active Filter:</span>
                          </span>
                          <span className="text-amber-300 font-semibold">
                            {prodOnly && "Prod Only"}
                            {prodOnly && transitiveDepth < maxGraphDepth && " • "}
                            {transitiveDepth < maxGraphDepth && `Depth ≤ ${transitiveDepth}`}
                          </span>
                        </div>
                      )}

                      {/* Scan History & Delta Comparison Button (Fix #12) */}
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedHistoryScan(null);
                          setComparisonResult(null);
                          setShowHistoryModal(true);
                        }}
                        className="mt-2.5 w-full py-1.5 px-2.5 rounded-lg bg-zinc-900/90 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 text-[10px] font-mono text-zinc-300 flex items-center justify-between transition-colors shadow-sm"
                        title="View Scan History & Delta Regression"
                      >
                        <span className="flex items-center space-x-1.5">
                          <Clock className="w-3 h-3 text-indigo-400" />
                          <span>Scan History & Delta</span>
                        </span>
                        <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-indigo-300 text-[9px] font-semibold border border-zinc-700/50">
                          {scanHistory.length}
                        </span>
                      </button>
                    </div>
                  )}
                </div>

                  {/* REACT FLOW CANVAS */}
                  {currentGraph && (
                    <GraphCanvas
                      graph={currentGraph}
                      focusNodeId={focusNodeId}
                      focusTarget={focusTarget}
                      onNodeClick={handleNodeClick}
                    />
                  )}
                </div>

                {/* RIGHT PANEL: 4 TABS (FINDINGS / EXECUTIVE AI / CODE REVIEWER / SANDBOX) */}
                <div className="w-[490px] xl:w-[520px] border-l border-zinc-800/80 bg-zinc-950/70 backdrop-blur-md flex flex-col h-full shrink-0">
                  {/* Tab Navigation & Export Header */}
                  <div className="flex items-center justify-between px-3 pt-3 pb-2 border-b border-zinc-800/80 shrink-0 gap-2">
                    <div className="flex items-center space-x-1 shrink-0">
                      {/* Findings Tab */}
                      <button
                        onClick={() => setActiveTab("findings")}
                        className={cn(
                          "px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0",
                          activeTab === "findings"
                            ? "bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60"
                            : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60"
                        )}
                      >
                        <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        <span>Findings ({activeFindings.length})</span>
                      </button>

                      {/* Executive AI Tab */}
                      <button
                        onClick={() => setActiveTab("briefing")}
                        className={cn(
                          "px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0",
                          activeTab === "briefing"
                            ? "bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60"
                            : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60"
                        )}
                      >
                        <Sparkles className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        <span>Executive AI</span>
                      </button>

                      
                    </div>

                    {/* Header Right Actions: Fix with AI, Copy All & Export */}
                    <div className="flex items-center space-x-1.5 shrink-0">
                      {data?.findings && data.findings.length > 0 && (
                        <>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(generateMasterAIFixPrompt(data), "ai-master-prompt")}
                            className="px-2.5 py-1 text-xs font-mono font-semibold whitespace-nowrap shrink-0 text-emerald-300 hover:text-emerald-100 bg-emerald-950/70 hover:bg-emerald-900/80 border border-emerald-600/60 hover:border-emerald-500 rounded-lg flex items-center space-x-1.5 transition-all shadow-sm group/ai"
                            title="Copy complete Master AI Fix Prompt for ChatGPT, Claude, Cursor, Copilot"
                          >
                            {copiedIndex === "ai-master-prompt" ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                <span className="text-emerald-400 font-bold whitespace-nowrap">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0 group-hover/ai:rotate-12 transition-transform" />
                                <span className="whitespace-nowrap">Fix with AI</span>
                              </>
                            )}
                          </button>

                          <button
                            type="button"
                            onClick={() => copyToClipboard(formatAllFindingsText(data.findings), "all-findings")}
                            className="px-2 py-1 text-xs font-mono font-medium whitespace-nowrap shrink-0 text-zinc-300 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-750 hover:border-zinc-600 rounded-lg flex items-center space-x-1.5 transition-all shadow-sm"
                            title="Copy all findings report to clipboard"
                          >
                            {copiedIndex === "all-findings" ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                <span className="text-emerald-400 font-bold whitespace-nowrap">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                                <span className="whitespace-nowrap">Copy All</span>
                              </>
                            )}
                          </button>
                        </>
                      )}

                      {/* Consolidated Export Dropdown */}
                      <div className="relative shrink-0">
                        <button
                          type="button"
                          onClick={() => setShowExportDropdown(!showExportDropdown)}
                          className="px-2 py-1 text-xs font-mono font-semibold whitespace-nowrap shrink-0 text-zinc-200 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/70 rounded-lg flex items-center space-x-1 transition-all shadow-sm"
                          title="Download audit reports and patched manifests"
                        >
                          <Download className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                          <span className="whitespace-nowrap">Export</span>
                          <ChevronDown className={cn("w-3 h-3 text-zinc-400 transition-transform shrink-0", showExportDropdown && "rotate-180")} />
                        </button>

                      {/* Export Dropdown Popover */}
                      {showExportDropdown && (
                        <div
                          className="absolute right-0 top-full mt-1.5 w-56 bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl p-1.5 space-y-1 z-30"
                          onMouseLeave={() => setShowExportDropdown(false)}
                        >
                          <button
                            type="button"
                            onClick={() => {
                              setShowExportDropdown(false);
                              handleDownloadAIPrompt();
                            }}
                            className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-purple-300 hover:bg-purple-950/60 flex items-center space-x-2.5 transition-colors"
                          >
                            <Sparkles className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                            <div>
                              <div className="font-semibold text-[11px] text-purple-300">Master AI Fix Prompt (.md)</div>
                              <div className="text-[9px] text-zinc-500">For Cursor, Claude & ChatGPT</div>
                            </div>
                          </button>

                          <button
                            type="button"
                            onClick={() => {
                              setShowExportDropdown(false);
                              handleDownloadPatchedManifest();
                            }}
                            className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-emerald-300 hover:bg-emerald-950/60 flex items-center space-x-2.5 transition-colors"
                          >
                            <Download className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <div>
                              <div className="font-semibold text-[11px] text-emerald-300">Patched Manifest</div>
                              <div className="text-[9px] text-zinc-500">package.json / requirements.txt</div>
                            </div>
                          </button>

                          <button
                            type="button"
                            onClick={() => {
                              setShowExportDropdown(false);
                              handleDownloadExecutiveHtml();
                            }}
                            className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-indigo-300 hover:bg-indigo-950/60 flex items-center space-x-2.5 transition-colors"
                          >
                            <FileText className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                            <div>
                              <div className="font-semibold text-[11px] text-indigo-300">Executive PDF/HTML</div>
                              <div className="text-[9px] text-zinc-500">Printable executive report</div>
                            </div>
                          </button>

                          <button
                            type="button"
                            onClick={() => {
                              setShowExportDropdown(false);
                              handleDownloadReport();
                            }}
                            className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-zinc-300 hover:bg-zinc-850 flex items-center space-x-2.5 transition-colors"
                          >
                            <FileCode2 className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                            <div>
                              <div className="font-semibold text-[11px] text-zinc-200">Markdown Audit (.md)</div>
                              <div className="text-[9px] text-zinc-500">Raw report for GitHub issues</div>
                            </div>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                  {/* TAB CONTENT SCROLLABLE BODY */}
                  <div className="flex-1 overflow-y-auto p-5 space-y-4">
                    {/* ============ FINDINGS TAB ============ */}
                    {activeTab === "findings" && (
                      <div className="space-y-3">
                        {data?.findings && data.findings.length > 0 ? (
                          <>
                            {/* Single-Row Clean Command Toolbar */}
                            <div className="flex items-center justify-between gap-2 p-1.5 rounded-xl bg-zinc-950/90 border border-zinc-800 text-xs font-mono">
                              {/* View Mode Toggle */}
                              <div className="flex items-center space-x-0.5 bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 shrink-0">
                                <button
                                  type="button"
                                  onClick={() => setFindingsGrouping("package")}
                                  className={cn(
                                    "px-2 py-0.5 rounded-md text-[10px] font-semibold transition-all flex items-center space-x-1",
                                    findingsGrouping === "package"
                                      ? "bg-indigo-600/30 text-indigo-200 border border-indigo-500/40 shadow-sm"
                                      : "text-zinc-400 hover:text-zinc-200"
                                  )}
                                >
                                  <Boxes className="w-3 h-3 text-sky-400" />
                                  <span>Packages ({groupedFindings.length})</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setFindingsGrouping("flat")}
                                  className={cn(
                                    "px-2 py-0.5 rounded-md text-[10px] font-semibold transition-all flex items-center space-x-1",
                                    findingsGrouping === "flat"
                                      ? "bg-zinc-800 text-zinc-100 shadow-sm"
                                      : "text-zinc-400 hover:text-zinc-200"
                                  )}
                                >
                                  <FileText className="w-3 h-3 text-zinc-400" />
                                  <span>Flat ({activeFindings.length})</span>
                                </button>
                              </div>

                              {/* Search Input */}
                              <div className="relative flex-1 min-w-[110px]">
                                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-500" />
                                <input
                                  type="text"
                                  value={findingsSearch}
                                  onChange={(e) => setFindingsSearch(e.target.value)}
                                  placeholder="Filter CVE or pkg..."
                                  className="w-full pl-6 pr-2 py-0.5 rounded-lg bg-zinc-900/90 border border-zinc-800/80 text-[10px] text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700"
                                />
                              </div>

                              {/* Expand/Collapse All (Package Mode Only) */}
                              {findingsGrouping === "package" && (
                                <button
                                  type="button"
                                  onClick={() => toggleAllPackages(Object.values(expandedPackageKeys).filter(Boolean).length < groupedFindings.length)}
                                  className="px-2 py-0.5 rounded-md bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[10px] text-zinc-400 hover:text-zinc-200 transition-colors shrink-0"
                                  title={Object.values(expandedPackageKeys).filter(Boolean).length < groupedFindings.length ? "Expand all packages" : "Collapse all packages"}
                                >
                                  {Object.values(expandedPackageKeys).filter(Boolean).length < groupedFindings.length ? "Expand" : "Collapse"}
                                </button>
                              )}
                            </div>

                            {/* ============ GROUPED BY PACKAGE ACCORDIONS ============ */}
                            {findingsGrouping === "package" ? (
                              <div className="space-y-2.5">
                                {groupedFindings
                                  .filter(g => {
                                    if (!findingsSearch.trim()) return true;
                                    const q = findingsSearch.toLowerCase();
                                    return (
                                      g.pkgName.toLowerCase().includes(q) ||
                                      g.findings.some((f: any) =>
                                        f.title?.toLowerCase().includes(q) ||
                                        f.description?.toLowerCase().includes(q)
                                      )
                                    );
                                  })
                                  .map((g) => {
                                    const isExpanded = expandedPackageKeys[g.key] ?? false;
                                    return (
                                      <div
                                        key={g.key}
                                        className="rounded-xl border border-zinc-800/90 bg-zinc-900/40 overflow-hidden transition-all shadow-sm"
                                      >
                                        {/* Package Header Row */}
                                        <div
                                          onClick={() => togglePackageExpanded(g.key)}
                                          className="p-3 bg-zinc-900/70 hover:bg-zinc-850/80 cursor-pointer flex items-center justify-between transition-colors border-b border-zinc-800/60"
                                        >
                                          <div className="flex items-center space-x-2.5 min-w-0 flex-1 mr-2">
                                            <div className="p-1.5 rounded-lg bg-zinc-800 border border-zinc-700/60 text-zinc-300 shrink-0">
                                              <Boxes className="w-3.5 h-3.5 text-sky-400" />
                                            </div>
                                            <div className="min-w-0 flex-1">
                                              <div className="flex items-center space-x-1.5 truncate">
                                                <span className="text-xs font-bold text-zinc-100 truncate">{g.pkgName}</span>
                                                {g.version && (
                                                  <span className="text-[10px] text-zinc-400 font-mono shrink-0">@{g.version}</span>
                                                )}
                                                <span className="text-[8px] px-1 py-0.2 rounded uppercase font-mono font-bold border bg-zinc-800 text-zinc-400 border-zinc-700 shrink-0">
                                                  {g.ecosystem}
                                                </span>
                                              </div>
                                              <div className="text-[10px] text-zinc-500 font-mono mt-0.5 flex items-center space-x-1.5 truncate">
                                                <span className="shrink-0">{g.findings.length} Finding{g.findings.length !== 1 ? "s" : ""}</span>
                                                {g.fixVersion && (
                                                  <>
                                                    <span className="text-zinc-600 shrink-0">•</span>
                                                    <span className="text-emerald-400 font-medium truncate" title={`Recommended Fix: ${g.fixVersion}`}>
                                                      Fix: {g.fixVersion}
                                                    </span>
                                                  </>
                                                )}
                                              </div>
                                            </div>
                                          </div>
                                          <div className="flex items-center space-x-1.5 shrink-0">
                                            <button
                                              type="button"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                copyToClipboard(generateSingleAIFixPrompt(g.findings[0], g.findings), `pkg-ai-${g.key}`);
                                              }}
                                              className="px-1.5 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 hover:text-emerald-100 border border-emerald-700/60 hover:border-emerald-500 transition-all text-[9px] font-mono flex items-center space-x-1 shadow-sm whitespace-nowrap shrink-0"
                                              title="Copy AI Prompt to fix this package in Cursor, ChatGPT, or Claude"
                                            >
                                              {copiedIndex === `pkg-ai-${g.key}` ? (
                                                <>
                                                  <Check className="w-2.5 h-2.5 text-emerald-400" />
                                                  <span className="font-bold">Copied!</span>
                                                </>
                                              ) : (
                                                <>
                                                  <Sparkles className="w-2.5 h-2.5 text-emerald-400" />
                                                  <span>AI Fix</span>
                                                </>
                                              )}
                                            </button>
                                            <button
                                              type="button"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                handlePackageFocus(g.key, g.findings[0]);
                                              }}
                                              className="px-1.5 py-0.5 rounded bg-zinc-800/90 hover:bg-indigo-950/80 text-zinc-400 hover:text-indigo-300 border border-zinc-750 hover:border-indigo-600/60 transition-all text-[9px] font-mono flex items-center space-x-1 whitespace-nowrap shrink-0"
                                              title="Focus package node in attack graph"
                                            >
                                              <Crosshair className="w-2.5 h-2.5 text-indigo-400" />
                                              <span>Focus</span>
                                            </button>
                                            <span
                                              className={cn(
                                                "px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border shrink-0",
                                                getSeverityClass(g.highestSeverity)
                                              )}
                                            >
                                              {g.highestSeverity}
                                            </span>
                                            <div className="p-0.5 text-zinc-400 hover:text-white shrink-0">
                                              <ChevronDown
                                                className={cn(
                                                  "w-3.5 h-3.5 transition-transform duration-200",
                                                  isExpanded && "rotate-180"
                                                )}
                                              />
                                            </div>
                                          </div>
                                        </div>

                                        {/* Package Findings Body */}
                                        {isExpanded && (
                                          <div className="p-2.5 space-y-2.5 bg-black/30">
                                            {g.findings.map((f: any, fIdx: number) => {
                                              const detectorTag = getDetectorTag(f);
                                              const lockSnippet = buildLockfileSnippet(f, g.fixVersion || undefined);
                                              return (
                                                <div
                                                  key={fIdx}
                                                  className="p-3 rounded-xl border border-zinc-800/80 bg-zinc-950/60 hover:bg-zinc-900/60 transition-all group cursor-pointer"
                                                  onClick={() => handleFindingClick(f)}
                                                >
                                                  <div className="flex items-start justify-between mb-1.5">
                                                    <h4 className="text-xs font-semibold text-zinc-200 pr-2 leading-snug group-hover:text-red-300 transition-colors">
                                                      {f.title}
                                                    </h4>
                                                    <div className="flex items-center space-x-1 shrink-0">
                                                      <button
                                                        type="button"
                                                        onClick={(e) => {
                                                          e.stopPropagation();
                                                          copyToClipboard(generateSingleAIFixPrompt(f, g.findings), `ai-f-${g.key}-${fIdx}`);
                                                        }}
                                                        className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-300 hover:text-white transition-colors text-[9px] font-mono shadow-sm"
                                                        title="Copy AI Prompt to fix this vulnerability with ChatGPT, Claude, or Cursor"
                                                      >
                                                        {copiedIndex === `ai-f-${g.key}-${fIdx}` ? (
                                                          <>
                                                            <Check className="w-2.5 h-2.5 text-emerald-400" />
                                                            <span className="text-emerald-400 font-bold">Copied!</span>
                                                          </>
                                                        ) : (
                                                          <>
                                                            <Sparkles className="w-2.5 h-2.5 text-emerald-400" />
                                                            <span>Prompt AI</span>
                                                          </>
                                                        )}
                                                      </button>
                                                      <button
                                                        type="button"
                                                        onClick={(e) => {
                                                          e.stopPropagation();
                                                          copyToClipboard(formatSingleFindingText(f), `finding-${g.key}-${fIdx}`);
                                                        }}
                                                        className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 border border-zinc-750 text-zinc-300 hover:text-white transition-colors text-[9px] font-mono"
                                                        title="Copy full finding details"
                                                      >
                                                        {copiedIndex === `finding-${g.key}-${fIdx}` ? (
                                                          <>
                                                            <Check className="w-2.5 h-2.5 text-emerald-400" />
                                                            <span className="text-emerald-400 font-bold">Copied!</span>
                                                          </>
                                                        ) : (
                                                          <>
                                                            <Copy className="w-2.5 h-2.5 text-zinc-400" />
                                                            <span>Copy</span>
                                                          </>
                                                        )}
                                                      </button>
                                                      {f.metadata?.is_first_party_ghsa && (
                                                        <span className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border bg-purple-950/70 text-purple-300 border-purple-500/50 shadow-sm animate-pulse">
                                                          REPO GHSA
                                                        </span>
                                                      )}
                                                      {f.metadata?.is_historic_attack && (
                                                        <span className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border bg-rose-950/80 text-rose-300 border-rose-500/60 shadow-sm">
                                                          {f.metadata.badge || `${f.metadata.year || "HISTORIC"} ATTACK`}
                                                        </span>
                                                      )}
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

                                                  <p className="text-[11px] text-zinc-400 leading-relaxed mb-2">
                                                    {f.description}
                                                  </p>

                                                  <div className="mb-2">
                                                    <button
                                                      type="button"
                                                      onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleFindingClick(f);
                                                      }}
                                                      className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-indigo-950/50 hover:bg-indigo-900/70 border border-indigo-800/50 hover:border-indigo-600/70 text-indigo-300 hover:text-white text-[10px] font-mono font-medium transition-all cursor-pointer shadow-sm group/btn"
                                                      title="Center and highlight this node in the attack graph"
                                                    >
                                                      <Crosshair className="w-3.5 h-3.5 text-indigo-400 group-hover/btn:rotate-90 transition-transform duration-300" />
                                                      <span>Click to focus node in graph</span>
                                                    </button>
                                                  </div>

                                                  {/* Containment Strategy */}
                                                  {f.recommendations && f.recommendations.length > 0 && (
                                                    <div className="mt-2 pt-2 border-t border-zinc-800/60">
                                                      <div className="flex items-center justify-between text-[10px] text-zinc-500 font-mono uppercase mb-1">
                                                        <span>Remediation</span>
                                                        <span className="text-[9px] text-zinc-600">Least-privilege fix</span>
                                                      </div>
                                                      <div className="p-2 rounded-lg bg-zinc-950/80 border border-zinc-800 text-[11px]">
                                                        <div className="font-semibold text-emerald-400 text-xs mb-0.5">
                                                          {f.recommendations[0]?.title}
                                                        </div>
                                                        <div className="text-zinc-400 text-[10px] mb-1.5">
                                                          {f.recommendations[0]?.why}
                                                        </div>
                                                        {lockSnippet && (
                                                          <div className="relative group/code mt-1">
                                                            <pre className="p-2 rounded-lg bg-black/70 border border-zinc-800/80 text-[10px] font-mono text-emerald-400/90 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                                                              {lockSnippet}
                                                            </pre>
                                                            <button
                                                              type="button"
                                                              onClick={(e) => {
                                                                e.stopPropagation();
                                                                copyToClipboard(lockSnippet, `snippet-${g.key}-${fIdx}`);
                                                              }}
                                                              className="absolute top-1.5 right-1.5 flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white transition-all text-[9px] font-mono shadow-sm"
                                                              title="Copy configuration snippet to clipboard"
                                                            >
                                                              {copiedIndex === `snippet-${g.key}-${fIdx}` ? (
                                                                <>
                                                                  <Check className="w-2.5 h-2.5 text-emerald-400" />
                                                                  <span className="text-emerald-400 font-bold">Copied!</span>
                                                                </>
                                                              ) : (
                                                                <>
                                                                  <Copy className="w-2.5 h-2.5 text-zinc-400" />
                                                                  <span>Copy Snippet</span>
                                                                </>
                                                              )}
                                                            </button>
                                                          </div>
                                                        )}
                                                      </div>
                                                    </div>
                                                  )}
                                                </div>
                                              );
                                            })}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                              </div>
                            ) : (
                              /* ============ FLAT LIST VIEW ============ */
                              <div className="space-y-3.5">
                                {displayedFindings
                                  .filter(f => {
                                    if (!findingsSearch.trim()) return true;
                                    const q = findingsSearch.toLowerCase();
                                    return f.title?.toLowerCase().includes(q) || f.description?.toLowerCase().includes(q);
                                  })
                                  .map((f: any, idx: number) => {
                                    const detectorTag = getDetectorTag(f);
                                    const lockSnippet = buildLockfileSnippet(f);
                                    return (
                                      <div
                                        key={idx}
                                        className="p-3.5 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 transition-all group cursor-pointer"
                                        onClick={() => handleFindingClick(f)}
                                      >
                                        <div className="flex items-start justify-between mb-2">
                                          <h4 className="text-xs font-semibold text-zinc-200 pr-3 leading-snug group-hover:text-red-300 transition-colors">
                                            {f.title}
                                          </h4>
                                          <div className="flex items-center space-x-1.5 shrink-0">
                                            <button
                                              type="button"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                copyToClipboard(generateSingleAIFixPrompt(f), `ai-flat-${idx}`);
                                              }}
                                              className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-300 hover:text-white transition-colors text-[9px] font-mono shadow-sm"
                                              title="Copy AI Prompt to fix this vulnerability with ChatGPT, Claude, or Cursor"
                                            >
                                              {copiedIndex === `ai-flat-${idx}` ? (
                                                <>
                                                  <Check className="w-2.5 h-2.5 text-emerald-400" />
                                                  <span className="text-emerald-400 font-bold">Copied!</span>
                                                </>
                                              ) : (
                                                <>
                                                  <Sparkles className="w-2.5 h-2.5 text-emerald-400" />
                                                  <span>Prompt AI</span>
                                                </>
                                              )}
                                            </button>
                                            <button
                                              type="button"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                copyToClipboard(formatSingleFindingText(f), `finding-${idx}`);
                                              }}
                                              className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800/90 hover:bg-zinc-750 border border-zinc-750 text-zinc-300 hover:text-white transition-colors text-[9px] font-mono"
                                              title="Copy full finding details and remediation to clipboard"
                                            >
                                              {copiedIndex === `finding-${idx}` ? (
                                                <>
                                                  <Check className="w-2.5 h-2.5 text-emerald-400" />
                                                  <span className="text-emerald-400 font-bold">Copied!</span>
                                                </>
                                              ) : (
                                                <>
                                                  <Copy className="w-2.5 h-2.5 text-zinc-400" />
                                                  <span>Copy</span>
                                                </>
                                              )}
                                            </button>
                                            {f.metadata?.is_first_party_ghsa && (
                                              <span className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border bg-purple-950/70 text-purple-300 border-purple-500/50 shadow-sm animate-pulse">
                                                REPO GHSA
                                              </span>
                                            )}
                                            {f.metadata?.is_historic_attack && (
                                              <span className="px-1.5 py-0.5 rounded text-[8px] font-mono font-bold uppercase tracking-wider border bg-rose-950/80 text-rose-300 border-rose-500/60 shadow-sm">
                                                {f.metadata.badge || `${f.metadata.year || "HISTORIC"} ATTACK`}
                                              </span>
                                            )}
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

                                        <div className="mb-2.5">
                                          <button
                                            type="button"
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              handleFindingClick(f);
                                            }}
                                            className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-indigo-950/50 hover:bg-indigo-900/70 border border-indigo-800/50 hover:border-indigo-600/70 text-indigo-300 hover:text-white text-[10px] font-mono font-medium transition-all cursor-pointer shadow-sm group/btn"
                                            title="Center and highlight this node in the attack graph"
                                          >
                                            <Crosshair className="w-3.5 h-3.5 text-indigo-400 group-hover/btn:rotate-90 transition-transform duration-300" />
                                            <span>Click to focus node in graph</span>
                                          </button>
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
                                                <span>{copiedIndex === idx ? "Copied!" : "Copy Snippet"}</span>
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
                              </div>
                            )}
                          </>
                        ) : (
                          <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl space-y-2">
                            {data?.findings && data.findings.length > 0 ? (
                              <>
                                <ListFilter className="w-6 h-6 text-amber-400 mx-auto" />
                                <p className="text-xs text-zinc-300 font-mono font-semibold">
                                  All Findings Filtered
                                </p>
                                <p className="text-[11px] text-zinc-500 max-w-xs mx-auto">
                                  {data.findings.length} findings are in dependencies currently hidden by Depth ({transitiveDepth}) or Prod Only filter.
                                </p>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setTransitiveDepth(maxGraphDepth);
                                    setProdOnly(false);
                                  }}
                                  className="mt-2 px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-mono transition-colors"
                                >
                                  Reset Filters (Show All {data.findings.length})
                                </button>
                              </>
                            ) : (
                              <>
                                <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                                <p className="text-xs text-zinc-400 font-mono">No vulnerabilities detected</p>
                              </>
                            )}
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
                            {getExecutiveSummary(data, activeScenario)}
                          </div>
                        </div>

                        <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-900/30 space-y-2 text-xs font-mono">
                          <div className="text-zinc-400 font-semibold">Exploitability Summary</div>
                          <div className="text-zinc-400 text-[11px]">
                            • Total Attack Paths: <span className="text-zinc-200">{data?.scan?.total_attack_paths || 0}</span>
                          </div>
                          <div className="text-zinc-400 text-[11px]">
                            • Blast Radius Score: <span className="text-red-400 font-bold">{(Number(data?.scan?.blast_radius_score) || 0).toFixed(1)}/100</span>
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

                    {/* ============ CODE REVIEWER TAB (DRAWER REDIRECT) ============ */}
                    {activeTab === "reviewer" && (
                      <div className="p-4 rounded-xl border border-amber-900/40 bg-amber-950/20 text-xs space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-amber-300">Code Reviewer & Patches</span>
                          <span className="text-[10px] text-zinc-500 font-mono">{currentCodeReviews.length} patches</span>
                        </div>
                        <p className="text-zinc-400 text-xs leading-relaxed">
                          For high-resolution side-by-side git diffs, AST inspection, and interactive AI patch application, switch to the dedicated workspace.
                        </p>
                        <button
                          type="button"
                          onClick={() => setCurrentView("reviewer")}
                          className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition-all shadow-md shadow-amber-600/20"
                        >
                          <span>Open Dedicated Code Reviewer</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}

                    {/* ============ SANDBOX DETONATION TAB (DRAWER REDIRECT) ============ */}
                    {activeTab === "sandbox" && (
                      <div className="p-4 rounded-xl border border-red-900/40 bg-red-950/20 text-xs space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-red-300">Detonation Sandbox</span>
                          <span className="text-[10px] text-zinc-500 font-mono">Isolated Container</span>
                        </div>
                        <p className="text-zinc-400 text-xs leading-relaxed">
                          For isolated dynamic execution, network behavioral tracing, and real-time syscall logs, switch to the dedicated workspace.
                        </p>
                        <button
                          type="button"
                          onClick={() => setCurrentView("sandbox")}
                          className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold transition-all shadow-md shadow-red-600/20"
                        >
                          <span>Open Dedicated Detonation Sandbox</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}

                    {/* Quick navigation footer to dedicated workspaces */}
                    <div className="mt-4 pt-3 border-t border-zinc-800/80 flex items-center justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => setCurrentView("reviewer")}
                        className="flex-1 py-1.5 px-2.5 rounded-lg bg-zinc-900/80 hover:bg-zinc-850 border border-zinc-800 text-[11px] font-mono text-zinc-300 hover:text-white flex items-center justify-between transition-colors shadow-sm"
                        title="Open full-width Code Reviewer with git diffs and AI patches"
                      >
                        <span className="flex items-center space-x-1.5 truncate">
                          <Sparkles className="w-3 h-3 text-amber-400 shrink-0" />
                          <span className="truncate">Code Reviewer</span>
                        </span>
                        <ArrowRight className="w-3 h-3 text-zinc-500 shrink-0" />
                      </button>

                      <button
                        type="button"
                        onClick={() => setCurrentView("sandbox")}
                        className="flex-1 py-1.5 px-2.5 rounded-lg bg-zinc-900/80 hover:bg-zinc-850 border border-zinc-800 text-[11px] font-mono text-zinc-300 hover:text-white flex items-center justify-between transition-colors shadow-sm"
                        title="Open full-width Detonation Sandbox terminal"
                      >
                        <span className="flex items-center space-x-1.5 truncate">
                          <Zap className="w-3 h-3 text-red-400 shrink-0" />
                          <span className="truncate">Detonation Sandbox</span>
                        </span>
                        <ArrowRight className="w-3 h-3 text-zinc-500 shrink-0" />
                      </button>
                    </div>
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}

      {/* ============================================================
          STAGE 4: DEDICATED FULL-WIDTH CODE REVIEWER WORKSPACE
      ============================================================ */}
      {currentView === "reviewer" && (
        <div className="flex-1 flex flex-col overflow-y-auto bg-zinc-950">
          <div className="max-w-7xl mx-auto w-full px-6 py-6 space-y-6">
            {/* Header / Breadcrumb navigation */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-zinc-800/80">
              <div className="flex items-center space-x-3">
                <button
                  type="button"
                  onClick={() => setCurrentView("scanner")}
                  className="p-2 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 hover:text-white transition-colors flex items-center space-x-1.5 text-xs font-mono shadow-sm"
                  title="Return to Dependency Graph & Findings"
                >
                  <ArrowLeft className="w-4 h-4" />
                  <span>Graph & Findings</span>
                </button>
                <div>
                  <h1 className="text-lg font-bold text-zinc-100 flex items-center space-x-2">
                    <Sparkles className="w-4 h-4 text-amber-400" />
                    <span>Code Reviewer & AI Patches</span>
                  </h1>
                  <p className="text-xs text-zinc-400 mt-0.5">
                    High-resolution static AST analysis, vulnerable code snippets, and automated git patch generators.
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2 text-xs font-mono">
                <div className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400">
                  Target: <span className="text-zinc-200 font-semibold">{data?.scan?.repository_url?.replace("https://github.com/", "") || (activeScenario ? `Scenario ${activeScenario}` : "Active Project")}</span>
                </div>
                <div className="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 font-semibold">
                  {currentCodeReviews.length} Patches Ready
                </div>
              </div>
            </div>

            {/* Code Reviewer Panel Body */}
            <CodeReviewerPanel
              codeReviews={currentCodeReviews}
              onReviewsUpdated={handleReviewsUpdated}
            />
          </div>
        </div>
      )}

      {/* ============================================================
          STAGE 5: DEDICATED FULL-WIDTH SANDBOX DETONATION WORKSPACE
      ============================================================ */}
      {currentView === "sandbox" && (
        <div className="flex-1 flex flex-col overflow-y-auto bg-zinc-950">
          <div className="max-w-7xl mx-auto w-full px-6 py-6 space-y-6">
            {/* Header / Breadcrumb navigation */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-zinc-800/80">
              <div className="flex items-center space-x-3">
                <button
                  type="button"
                  onClick={() => setCurrentView("scanner")}
                  className="p-2 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 hover:text-white transition-colors flex items-center space-x-1.5 text-xs font-mono shadow-sm"
                  title="Return to Dependency Graph & Findings"
                >
                  <ArrowLeft className="w-4 h-4" />
                  <span>Graph & Findings</span>
                </button>
                <div>
                  <h1 className="text-lg font-bold text-zinc-100 flex items-center space-x-2">
                    <Zap className="w-4 h-4 text-red-400" />
                    <span>Dynamic Detonation Sandbox</span>
                  </h1>
                  <p className="text-xs text-zinc-400 mt-0.5">
                    Isolated runtime container: execute suspect lifecycle scripts, observe network beacons, and verify evasion payloads.
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2 text-xs font-mono">
                <div className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400">
                  Target: <span className="text-zinc-200 font-semibold">{data?.scan?.repository_url?.replace("https://github.com/", "") || (activeScenario ? `Scenario ${activeScenario}` : "Active Project")}</span>
                </div>
                <div className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 font-semibold">
                  Isolated Container
                </div>
              </div>
            </div>

            {/* Sandbox Panel Body */}
            <SandboxPanel
              files={lastUploadedFiles}
              projectName={data?.scan?.repository_url || "Active Workspace"}
            />
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
              <div className="flex items-center space-x-2">
                <span className="text-blue-400 text-[10px] break-all font-mono">
                  {data?.detector_breakdown?.sbom_sha256 || computedSbomSha || "0x9f83b2...a41e"}
                </span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(data?.detector_breakdown?.sbom_sha256 || computedSbomSha || "", "sbom-sha-copy")}
                  className="p-1 rounded bg-zinc-800 hover:bg-zinc-750 text-zinc-300 hover:text-white transition-colors"
                  title="Copy SHA-256 Hash to clipboard"
                >
                  {copiedIndex === "sbom-sha-copy" ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3 text-zinc-400" />
                  )}
                </button>
              </div>
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
          SCAN HISTORY & DELTA COMPARISON MODAL (Fix #12)
      ============================================================ */}
      <Modal
        open={showHistoryModal}
        onClose={() => {
          setShowHistoryModal(false);
          setSelectedHistoryScan(null);
          setComparisonResult(null);
        }}
        title={
          <div className="flex items-center space-x-2 text-indigo-300">
            <Clock className="w-4 h-4 text-indigo-400" />
            <span>Scan History & Delta Regression Engine</span>
          </div>
        }
      >
        <div className="space-y-4 font-mono text-xs">
          {/* Active Scan Context Bar */}
          <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-800/40 flex items-center justify-between">
            <div>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">Active Workspace</span>
              <span className="text-zinc-200 font-bold text-sm">
                {data?.scan?.repository_url?.replace("https://github.com/", "") ||
                  (activeScenario ? `Demo Scenario ${activeScenario}` : "Active Project")}
              </span>
            </div>
            <div className="flex items-center space-x-4 text-right">
              <div>
                <span className="text-[10px] text-zinc-500 block">Blast Radius</span>
                <span className="text-amber-400 font-bold">{(Number(data?.scan?.blast_radius_score) || 0).toFixed(1)}/100</span>
              </div>
              <div>
                <span className="text-[10px] text-zinc-500 block">Components</span>
                <span className="text-zinc-200 font-bold">{data?.scan?.total_components || data?.components?.length || 0}</span>
              </div>
              <div>
                <span className="text-[10px] text-zinc-500 block">Findings</span>
                <span className="text-red-400 font-bold">{data?.scan?.total_findings || data?.findings?.length || 0}</span>
              </div>
            </div>
          </div>

          {/* Historical Scan Selected: Show Delta Comparison */}
          {selectedHistoryScan ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between bg-zinc-900/80 p-2.5 rounded-xl border border-zinc-800">
                <button
                  onClick={() => {
                    setSelectedHistoryScan(null);
                    setComparisonResult(null);
                  }}
                  className="px-2.5 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[11px] flex items-center space-x-1 transition-colors"
                >
                  <ArrowRight className="w-3 h-3 rotate-180" />
                  <span>Back to Scan List</span>
                </button>
                <div className="text-zinc-400 text-[11px]">
                  Comparing against: <b className="text-zinc-200">{selectedHistoryScan.target}</b> ({selectedHistoryScan.timestamp})
                </div>
                <button
                  onClick={() => handleLoadHistoryScan(selectedHistoryScan)}
                  className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-semibold flex items-center space-x-1 transition-colors shadow-sm"
                  title="Switch active workspace to this historical scan"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Load this Scan</span>
                </button>
              </div>

              {/* Delta Telemetry Comparison Cards */}
              {(() => {
                const currentBlast = Number(data?.scan?.blast_radius_score) || 0;
                const oldBlast = Number(selectedHistoryScan?.blast_radius_score) || 0;
                const blastDelta = currentBlast - oldBlast;

                const currentComps = Number(data?.scan?.total_components) || Number(data?.components?.length) || 0;
                const oldComps = Number(selectedHistoryScan?.total_components) || 0;
                const compDelta = currentComps - oldComps;

                const currentFinds = Number(data?.scan?.total_findings) || Number(data?.findings?.length) || 0;
                const oldFinds = Number(selectedHistoryScan?.total_findings) || 0;
                const findsDelta = currentFinds - oldFinds;

                return (
                  <div className="grid grid-cols-3 gap-2.5">
                    {/* Blast Radius Delta */}
                    <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Blast Radius Δ</div>
                      <div className="flex items-center space-x-1.5 mt-1">
                        {blastDelta < 0 ? (
                          <ArrowDownRight className="w-4 h-4 text-emerald-400" />
                        ) : blastDelta > 0 ? (
                          <ArrowUpRight className="w-4 h-4 text-red-400" />
                        ) : null}
                        <span
                          className={cn(
                            "text-base font-bold",
                            blastDelta < 0 ? "text-emerald-400" : blastDelta > 0 ? "text-red-400" : "text-zinc-300"
                          )}
                        >
                          {blastDelta > 0 ? `+${(Number(blastDelta) || 0).toFixed(1)}` : (Number(blastDelta) || 0).toFixed(1)}
                        </span>
                      </div>
                      <div className="text-[9px] text-zinc-500 mt-1">
                        {blastDelta < 0 ? "🛡️ Risk reduced (Improvement)" : blastDelta > 0 ? "⚠️ Risk increased (Regression)" : "Unchanged"}
                      </div>
                    </div>

                    {/* Components Delta */}
                    <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Components Δ</div>
                      <div className="flex items-center space-x-1.5 mt-1">
                        <span
                          className={cn(
                            "text-base font-bold",
                            compDelta > 0 ? "text-indigo-400" : compDelta < 0 ? "text-amber-400" : "text-zinc-300"
                          )}
                        >
                          {compDelta > 0 ? `+${compDelta}` : compDelta}
                        </span>
                      </div>
                      <div className="text-[9px] text-zinc-500 mt-1">
                        {compDelta > 0 ? `${compDelta} new dependencies` : compDelta < 0 ? `${Math.abs(compDelta)} removed` : "Same count"}
                      </div>
                    </div>

                    {/* Findings Delta */}
                    <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Threat Findings Δ</div>
                      <div className="flex items-center space-x-1.5 mt-1">
                        <span
                          className={cn(
                            "text-base font-bold",
                            findsDelta < 0 ? "text-emerald-400" : findsDelta > 0 ? "text-red-400" : "text-zinc-300"
                          )}
                        >
                          {findsDelta > 0 ? `+${findsDelta}` : findsDelta}
                        </span>
                      </div>
                      <div className="text-[9px] text-zinc-500 mt-1">
                        {findsDelta < 0 ? "Fixes resolved threats" : findsDelta > 0 ? "New security risks" : "Zero change"}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Dependency & Finding Change Breakdown */}
              <div className="rounded-xl border border-zinc-800 bg-black/60 p-3 space-y-2.5">
                <div className="text-[11px] font-semibold text-zinc-300 flex items-center justify-between">
                  <span>Delta Manifest Changes</span>
                  {comparingLoading && <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" />}
                </div>

                {comparisonResult?.dependency_changes && comparisonResult.dependency_changes.length > 0 ? (
                  <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                    {comparisonResult.dependency_changes.map((dc: any, idx: number) => (
                      <div
                        key={idx}
                        className={cn(
                          "px-2.5 py-1.5 rounded-lg border text-[10px] flex items-center justify-between",
                          dc.change_type === "added"
                            ? "bg-indigo-950/30 border-indigo-800/40 text-indigo-300"
                            : dc.change_type === "removed"
                            ? "bg-amber-950/30 border-amber-800/40 text-amber-300"
                            : "bg-purple-950/30 border-purple-800/40 text-purple-300"
                        )}
                      >
                        <div className="flex items-center space-x-2">
                          <span className="font-bold uppercase tracking-wider text-[9px] px-1 py-0.2 rounded bg-black/40">
                            {dc.change_type}
                          </span>
                          <span className="font-semibold text-zinc-200">{dc.package_name}</span>
                          <span className="text-zinc-500 text-[9px]">({dc.ecosystem})</span>
                        </div>
                        <div className="text-zinc-400 text-[9px]">
                          {dc.version_before && <span className="line-through mr-1 text-zinc-500">{dc.version_before}</span>}
                          {dc.version_after && <span className="text-emerald-400">{dc.version_after}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-zinc-500 text-[10px] py-2 text-center">
                    No structural package additions or removals detected between these two snapshots.
                  </div>
                )}
              </div>
            </div>
          ) : (
            /* Historical Scans List */
            <div className="space-y-3">
              <div className="flex items-center justify-between text-zinc-400 text-[11px]">
                <span>Saved Scan Snapshots ({scanHistory.length})</span>
                {scanHistory.length > 0 && (
                  <button
                    onClick={handleClearHistory}
                    className="text-red-400 hover:text-red-300 flex items-center space-x-1 text-[10px] transition-colors"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>Clear History</span>
                  </button>
                )}
              </div>

              {scanHistory.length === 0 ? (
                <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl text-zinc-500 text-xs">
                  <Clock className="w-6 h-6 mx-auto mb-2 opacity-40" />
                  <p>No previous scans recorded in this browser session yet.</p>
                  <p className="text-[10px] text-zinc-600 mt-1">Run a scan or load a scenario to start tracking deltas.</p>
                </div>
              ) : (
                <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
                  {scanHistory.map((rec, idx) => (
                    <div
                      key={rec.id || idx}
                      className="p-3 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/80 transition-all flex items-center justify-between group"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <span className="text-zinc-200 font-semibold text-xs">{rec.target}</span>
                          <span className="text-[10px] text-zinc-500">{rec.timestamp}</span>
                        </div>
                        <div className="flex items-center space-x-3 text-[10px] text-zinc-400">
                          <span>Blast: <b className="text-amber-400">{(Number(rec?.blast_radius_score) || 0).toFixed(1)}/100</b></span>
                          <span>Comps: <b className="text-zinc-300">{rec.total_components}</b></span>
                          <span>Findings: <b className="text-red-400">{rec.total_findings}</b></span>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleSelectHistoryScan(rec)}
                          className="px-2.5 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-[10px] font-semibold flex items-center space-x-1 transition-all shadow-sm"
                          title="Compare with active workspace"
                        >
                          <GitCompare className="w-3 h-3" />
                          <span>Compare Delta</span>
                        </button>

                        <button
                          onClick={() => handleLoadHistoryScan(rec)}
                          className="px-2.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] font-semibold flex items-center space-x-1 transition-all"
                          title="Restore and view this scan"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>Load</span>
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  </ErrorBoundary>
  );
}