"use client";

import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { fetchRepositoryAnalysis, fetchDemoAnalysis, fetchFolderAnalysis, compareScans } from "@/lib/api";
import { AnalysisResponse, DetectorBreakdown, PolygonAttestation, SBOM, CodeReviewItem, ScanHistoryRecord } from "@/types";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { LoginPage } from "@/components/auth/LoginPage";
import { OverviewDashboard } from "@/components/dashboard/OverviewDashboard";
import { CodeReviewerPanel } from "@/components/reviewer/CodeReviewerPanel";
import { SandboxPanel } from "@/components/sandbox/SandboxPanel";
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
  FileText,
  Clock,
  History,
  ArrowUpRight,
  ArrowDownRight,
  RotateCcw,
  Trash2,
  GitCompare,
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
  const findingType: string = finding?.finding_type || "";
  const title: string = finding?.title || "";
  const origin: string = finding?.origin_candidate || "";
  const rawRef = origin || title.replace(/^Vulnerability in\s*/i, "") || "package";

  // Decode URI component (handles %40 in purl)
  let cleanRef = rawRef;
  try {
    cleanRef = decodeURIComponent(rawRef);
  } catch (_) {}

  const isPypi = cleanRef.startsWith("pkg:pypi/") || (!cleanRef.startsWith("pkg:npm/") && (findingType === "AST" || finding?.evidence?.some((e: any) => e.source === "ast")));
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

  // 1. Dependency Confusion -> Return .npmrc or pip.conf registry block
  if (findingType === "DEPENDENCY_CONFUSION") {
    for (const ev of finding?.evidence || []) {
      if (ev?.raw_data?.remediation) {
        return ev.raw_data.remediation;
      }
    }
    const scope = pkgName.startsWith("@") ? pkgName.split("/")[0] : `@${pkgName.split("-")[0]}`;
    if (!isPypi) {
      return `// .npmrc registry scope configuration\n${scope}:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=\${NODE_AUTH_TOKEN}`;
    } else {
      return `# pip.conf registry scope configuration\n[global]\nextra-index-url = https://pypi.org/simple\nindex-url = https://private-pypi.company.internal/simple`;
    }
  }

  // 2. Typosquatting -> Recommend removing rogue package and installing legitimate package
  if (findingType === "TYPOSQUATTING") {
    let similarTo = "";
    for (const ev of finding?.evidence || []) {
      if (ev?.raw_data?.similar_to) {
        similarTo = ev.raw_data.similar_to;
        break;
      }
    }
    if (!isPypi) {
      return `// Remediation: Remove malicious typosquat\nnpm uninstall ${pkgName}${similarTo ? `\nnpm install ${similarTo}` : ""}`;
    } else {
      return `# Remediation: Remove malicious typosquat\npip uninstall -y ${pkgName}${similarTo ? `\npip install ${similarTo}` : ""}`;
    }
  }

  // 3. CI/CD Risk -> Workflow permissions & commit SHA pin
  if (findingType === "CICD_RISK") {
    return `# .github/workflows/*.yml - Enforce least-privilege\npermissions:\n  contents: read\n  pull-requests: write\n# Pin actions to full 40-character commit SHA:\n# uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`;
  }

  // 4. AST / Suspicious Code Patterns
  if (findingType === "SUSPICIOUS" || findingType === "OBFUSCATION" || findingType === "DORMANT_LOGIC") {
    return `# Source Code Remediation (AST)\n# 1. Replace eval() / exec() with json.loads() or ast.literal_eval\n# 2. Avoid subprocess(..., shell=True) - pass arguments as a list\n# 3. Store API credentials in environment variables (os.environ)`;
  }

  // 5. Known Vulnerabilities (VULNERABLE) -> SemVer Override or Pin
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

  if (!fixedVer || fixedVer === "latest" || fixedVer.includes("patched_version")) {
    if (!isPypi) {
      return `// package.json mitigation for ${pkgName}\n// No upstream fixed release available yet (Disputed / Unpatched advisory)\n// Monitor vendor disclosures or evaluate alternative packages`;
    } else {
      return `# requirements.txt mitigation for ${pkgName}\n# No upstream fixed release available yet (Disputed / Unpatched advisory)\n# Audit vendor disclosures or consider alternative library`;
    }
  }

  if (!isPypi) {
    const npmVer = (fixedVer.startsWith(">=") || fixedVer.startsWith("^"))
      ? fixedVer
      : `^${fixedVer}`;
    return `// package.json override\n"overrides": {\n  "${pkgName}": "${npmVer}"\n}`;
  } else {
    const pipVer = (fixedVer.startsWith(">=") || fixedVer.startsWith("=="))
      ? fixedVer
      : `>=${fixedVer}`;
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
  const [activeTab, setActiveTab] = useState<"findings" | "briefing" | "reviewer" | "sandbox">("findings");
  const [lastUploadedFiles, setLastUploadedFiles] = useState<{ path: string; content: string }[]>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | string | null>(null);
  const [activeScenario, setActiveScenario] = useState<ScenarioId | null>(null);
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [showSbomModal, setShowSbomModal] = useState(false);
  const [showPolygonModal, setShowPolygonModal] = useState(false);
  const [polygonAttested, setPolygonAttested] = useState(false);
  const [attestCopied, setAttestCopied] = useState(false);
  const [showFormulaTooltip, setShowFormulaTooltip] = useState(false);
  const [showAllFindings, setShowAllFindings] = useState(false);
  const [prodOnly, setProdOnly] = useState(false);
  const [transitiveDepth, setTransitiveDepth] = useState<number>(10);
  const [scanHistory, setScanHistory] = useState<ScanHistoryRecord[]>([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [selectedHistoryScan, setSelectedHistoryScan] = useState<ScanHistoryRecord | null>(null);
  const [comparisonResult, setComparisonResult] = useState<any | null>(null);
  const [comparingLoading, setComparingLoading] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  // Restore scan history from localStorage
  useEffect(() => {
    try {
      const savedHistory = localStorage.getItem("supplygraph_scan_history");
      if (savedHistory) {
        setScanHistory(JSON.parse(savedHistory));
      }
    } catch (_) {}
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
        total_components: data.scan.total_components || data.components?.length || 0,
        total_findings: data.scan.total_findings || data.findings?.length || 0,
        blast_radius_score: data.scan.blast_radius_score || 0,
        data,
      };

      setScanHistory((prev) => {
        if (prev.length > 0 && prev[0].id === scanId) return prev;
        const filtered = prev.filter((item) => item.id !== scanId);
        const updated = [record, ...filtered].slice(0, 10);
        localStorage.setItem("supplygraph_scan_history", JSON.stringify(updated));
        return updated;
      });
    } catch (_) {}
  }, [data, activeScenario]);

  const handleSelectHistoryScan = useCallback(async (record: ScanHistoryRecord) => {
    setSelectedHistoryScan(record);
    if (!data) return;
    setComparingLoading(true);
    try {
      const res = await compareScans(record.data, data);
      setComparisonResult(res);
    } catch (e) {
      console.warn("Backend comparison fallback:", e);
      const currentComps = new Set((data.components || []).map((c: any) => c.name));
      const oldComps = new Set((record.data.components || []).map((c: any) => c.name));
      const added = (data.components || [])
        .filter((c: any) => !oldComps.has(c.name))
        .map((c: any) => ({ change_type: "added", package_name: c.name, ecosystem: c.ecosystem, version_after: c.version }));
      const removed = (record.data.components || [])
        .filter((c: any) => !currentComps.has(c.name))
        .map((c: any) => ({ change_type: "removed", package_name: c.name, ecosystem: c.ecosystem, version_before: c.version }));
      setComparisonResult({
        blast_radius_delta: (data.scan?.blast_radius_score || 0) - (record.data.scan?.blast_radius_score || 0),
        dependency_changes: [...added, ...removed],
        finding_changes: [],
        summary: `Delta comparison between ${record.target} and current active scan.`,
      });
    } finally {
      setComparingLoading(false);
    }
  }, [data]);

  const handleLoadHistoryScan = useCallback((record: ScanHistoryRecord) => {
    setData(record.data);
    setSelectedHistoryScan(null);
    setComparisonResult(null);
    setShowHistoryModal(false);
  }, []);

  const handleClearHistory = useCallback(() => {
    localStorage.removeItem("supplygraph_scan_history");
    setScanHistory([]);
    setSelectedHistoryScan(null);
    setComparisonResult(null);
  }, []);

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

  const executeAnalysis = useCallback(async (urlToScan: string, overrideProdOnly?: boolean) => {
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
    const useProd = overrideProdOnly !== undefined ? overrideProdOnly : prodOnly;
    try {
      const result = await fetchRepositoryAnalysis(trimmed, useProd, transitiveDepth);
      setData(result);
    } catch (err: any) {
      setError(err.message || "Failed to establish secure handshake with analysis engine.");
    } finally {
      setLoading(false);
    }
  }, [prodOnly, transitiveDepth]);

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
        const pkg = f.origin_candidate?.split("@")?.[0] || f.entity_id;
        let fixedVer = f.recommendations?.[0]?.fixed_version;
        if (!fixedVer && f.evidence) {
          for (const ev of f.evidence) {
            if (ev?.raw_data?.fixed_version) { fixedVer = ev.raw_data.fixed_version; break; }
            if (ev?.raw_data?.fixed) { fixedVer = ev.raw_data.fixed; break; }
          }
        }
        if (pkg && fixedVer && fixedVer !== "latest" && !fixedVer.includes("patched_version")) {
          overrides[pkg] = (fixedVer.startsWith("^") || fixedVer.startsWith(">=")) ? fixedVer : `^${fixedVer}`;
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
                currentView === "scanner" && activeTab !== "reviewer" && activeTab !== "sandbox"
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

            <button
              onClick={() => {
                setCurrentView("scanner");
                setActiveTab("sandbox");
              }}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center space-x-1.5",
                currentView === "scanner" && activeTab === "sandbox"
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

              {/* Production Only vs All Dependencies Toggle (Fix #1) */}
              <button
                type="button"
                onClick={() => setProdOnly(!prodOnly)}
                className={cn(
                  "px-3 py-2 rounded-xl text-xs font-mono font-medium flex items-center space-x-2 border transition-all shrink-0 shadow-sm",
                  prodOnly
                    ? "bg-emerald-950/50 border-emerald-500/60 text-emerald-300 shadow-emerald-950/20"
                    : "bg-zinc-900/80 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700"
                )}
                title={prodOnly ? "Filtering: Production Only (Dev Dependencies Omitted)" : "Filtering: All Dependencies (Including Dev Dependencies)"}
              >
                <span className={cn("w-2 h-2 rounded-full", prodOnly ? "bg-emerald-400 animate-pulse" : "bg-zinc-600")} />
                <span>{prodOnly ? "Prod Only" : "All Deps (Inc. Dev)"}</span>
              </button>

              {/* Configurable Transitive Depth Stepper (Fix #8) */}
              <div
                className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-xs font-mono text-zinc-300 shrink-0 shadow-sm"
                title="Max Transitive Dependency Depth (1–20 hops)"
              >
                <span className="text-zinc-500 text-[10px] uppercase">Depth:</span>
                <span className="text-indigo-400 font-semibold">{transitiveDepth} hops</span>
                <div className="flex items-center space-x-1 ml-1">
                  <button
                    type="button"
                    onClick={() => setTransitiveDepth(prev => Math.max(1, prev - 1))}
                    disabled={transitiveDepth <= 1}
                    className="w-5 h-5 rounded flex items-center justify-center bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-zinc-300 text-xs transition-colors"
                  >
                    -
                  </button>
                  <button
                    type="button"
                    onClick={() => setTransitiveDepth(prev => Math.min(20, prev + 1))}
                    disabled={transitiveDepth >= 20}
                    className="w-5 h-5 rounded flex items-center justify-center bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-zinc-300 text-xs transition-colors"
                  >
                    +
                  </button>
                </div>
              </div>
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
                          <span className="text-cyan-300">
                            AST: {data.detector_breakdown.ast_count || (data?.code_reviews?.filter(r => !r.file_path.endsWith('.yml') && !r.file_path.endsWith('.yaml') && !r.title.includes('CI/CD')).length) || 0}
                          </span>
                          <span className="text-zinc-600">•</span>
                          <span className="text-yellow-300">
                            CI/CD: {data.detector_breakdown.cicd_count || (data?.code_reviews?.filter(r => r.file_path.endsWith('.yml') || r.file_path.endsWith('.yaml') || r.title.includes('CI/CD')).length) || 0}
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

                {/* RIGHT PANEL: 4 TABS (FINDINGS / EXECUTIVE AI / CODE REVIEWER / SANDBOX) */}
                <div className="w-[490px] border-l border-zinc-800/80 bg-zinc-950/70 backdrop-blur-md flex flex-col h-full shrink-0">
                  {/* Tab Navigation */}
                  <div className="flex items-center justify-between px-5 pt-3.5 border-b border-zinc-800/80 shrink-0">
                    <div className="flex items-center space-x-3 overflow-x-auto no-scrollbar">
                      {/* Findings Tab */}
                      <button
                        onClick={() => setActiveTab("findings")}
                        className={cn(
                          "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5 shrink-0",
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
                          "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5 shrink-0",
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
                          "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5 shrink-0",
                          activeTab === "reviewer"
                            ? "border-amber-500 text-zinc-100"
                            : "border-transparent text-zinc-400 hover:text-zinc-200"
                        )}
                      >
                        <FileCode2 className="w-3.5 h-3.5 text-amber-400" />
                        <span>Reviewer ({data?.code_reviews?.length || 0})</span>
                      </button>

                      {/* Sandbox Detonation Tab */}
                      <button
                        onClick={() => setActiveTab("sandbox")}
                        className={cn(
                          "pb-2.5 text-xs font-medium border-b-2 transition-all flex items-center space-x-1.5 shrink-0",
                          activeTab === "sandbox"
                            ? "border-red-500 text-zinc-100 font-semibold"
                            : "border-transparent text-zinc-400 hover:text-zinc-200"
                        )}
                      >
                        <Zap className="w-3.5 h-3.5 text-red-400" />
                        <span>⚡ Sandbox</span>
                      </button>
                    </div>

                    <div className="flex items-center space-x-1 mb-2">
                      {/* 1-Click Download Patched Manifest (Fix #9) */}
                      <button
                        onClick={handleDownloadPatchedManifest}
                        className="px-2 py-1 text-[10px] font-mono font-semibold text-emerald-300 bg-emerald-950/50 hover:bg-emerald-900/60 border border-emerald-800/60 rounded-lg flex items-center space-x-1 transition-all shadow-sm"
                        title="1-Click Download Patched Manifest (package.patched.json / requirements.patched.txt)"
                      >
                        <Download className="w-3 h-3 text-emerald-400" />
                        <span>Patched Manifest</span>
                      </button>

                      {/* 1-Click Executive HTML/PDF Report (Fix #11) */}
                      <button
                        onClick={handleDownloadExecutiveHtml}
                        className="px-2 py-1 text-[10px] font-mono font-semibold text-indigo-300 bg-indigo-950/50 hover:bg-indigo-900/60 border border-indigo-800/60 rounded-lg flex items-center space-x-1 transition-all shadow-sm"
                        title="Download Executive HTML Report (Printable to PDF)"
                      >
                        <FileText className="w-3 h-3 text-indigo-400" />
                        <span>PDF/HTML</span>
                      </button>

                      <button
                        onClick={handleDownloadReport}
                        className="p-1.5 text-zinc-400 hover:text-zinc-200 rounded-lg hover:bg-zinc-800/60 transition-colors"
                        title="Export Markdown Report (.md)"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* TAB CONTENT SCROLLABLE BODY */}
                  <div className="flex-1 overflow-y-auto p-5 space-y-4">
                    {/* ============ FINDINGS TAB ============ */}
                    {activeTab === "findings" && (
                      <div className="space-y-3.5">
                        {data?.findings && data.findings.length > 0 ? (
                          <>
                            {/* Findings Top Toolbar: Count + Copy All Findings */}
                            <div className="flex items-center justify-between p-2.5 rounded-lg bg-zinc-950/70 border border-zinc-800 text-xs font-mono">
                              <span className="text-zinc-400">
                                Total Findings: <b className="text-zinc-100">{data.findings.length}</b>
                              </span>
                              <button
                                type="button"
                                onClick={() => copyToClipboard(formatAllFindingsText(data.findings), "all-findings")}
                                className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/60 text-zinc-300 hover:text-zinc-100 transition-colors shadow-sm text-[11px]"
                                title="Copy all findings to clipboard as a complete Markdown report"
                              >
                                {copiedIndex === "all-findings" ? (
                                  <>
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                    <span className="text-emerald-400 font-semibold">Copied All Findings!</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3.5 h-3.5 text-zinc-400" />
                                    <span>Copy All Findings</span>
                                  </>
                                )}
                              </button>
                            </div>

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
                                    <h4 className="text-xs font-semibold text-zinc-200 pr-3 leading-snug group-hover:text-red-300 transition-colors">
                                      {f.title}
                                    </h4>
                                    <div className="flex items-center space-x-1.5 shrink-0">
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

                    {/* ============ SANDBOX DETONATION TAB ============ */}
                    {activeTab === "sandbox" && (
                      <SandboxPanel
                        files={lastUploadedFiles}
                        projectName={data?.scan?.repository_url || "Active Workspace"}
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
                <span className="text-amber-400 font-bold">{data?.scan?.blast_radius_score?.toFixed(1) || 0}/100</span>
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
                const currentBlast = data?.scan?.blast_radius_score || 0;
                const oldBlast = selectedHistoryScan.blast_radius_score;
                const blastDelta = currentBlast - oldBlast;

                const currentComps = data?.scan?.total_components || data?.components?.length || 0;
                const oldComps = selectedHistoryScan.total_components;
                const compDelta = currentComps - oldComps;

                const currentFinds = data?.scan?.total_findings || data?.findings?.length || 0;
                const oldFinds = selectedHistoryScan.total_findings;
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
                          {blastDelta > 0 ? `+${blastDelta.toFixed(1)}` : blastDelta.toFixed(1)}
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
                          <span>Blast: <b className="text-amber-400">{rec.blast_radius_score.toFixed(1)}/100</b></span>
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
  );
}