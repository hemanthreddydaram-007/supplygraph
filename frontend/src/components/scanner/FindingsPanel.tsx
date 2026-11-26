"use client";

import React, { useState } from "react";
import {
  ArrowRight,
  Boxes,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  Crosshair,
  Download,
  FileCode2,
  FileText,
  ListFilter,
  Search,
  ShieldAlert,
  Sparkles,
  Zap,
} from "lucide-react";
import { AnalysisResponse, CodeReviewItem } from "@/types";
import { cn } from "@/lib/utils";
import {
  buildLockfileSnippet,
  generateMasterAIFixPrompt,
  generateSingleAIFixPrompt,
} from "@/lib/remediationPromptGenerator";
import {
  formatAllFindingsText,
  formatSingleFindingText,
  getDetectorTag,
  getDetectorTagClass,
  getExecutiveSummary,
  getSeverityClass,
  ScenarioId,
} from "@/lib/executiveSummary";

export interface GroupedPackageFindings {
  key: string;
  pkgName: string;
  version: string;
  ecosystem: string;
  findings: any[];
  highestSeverity: string;
  fixVersion: string;
}

interface FindingsPanelProps {
  data: AnalysisResponse;
  activeScenario: ScenarioId | null;
  activeFindings: any[];
  displayedFindings: any[];
  groupedFindings: GroupedPackageFindings[];
  currentCodeReviews: CodeReviewItem[];
  copiedIndex: number | string | null;
  prodOnly: boolean;
  transitiveDepth: number;
  maxGraphDepth: number;
  showAllFindings: boolean;
  expandedPackageKeys: Record<string, boolean>;
  onCopy: (text: string, key: number | string) => void;
  onFindingClick: (finding: any) => void;
  onPackageFocus: (pkgKey: string, sampleFinding?: any) => void;
  onTogglePackageExpanded: (pkgKey: string) => void;
  onToggleAllPackages: (expand: boolean) => void;
  onToggleShowAllFindings: () => void;
  onResetFilters: () => void;
  onDownloadAIPrompt: () => void;
  onDownloadPatchedManifest: () => void;
  onDownloadExecutiveHtml: () => void;
  onDownloadReport: () => void;
  onNavigateView: (view: "reviewer" | "sandbox") => void;
}

function handleCardKeyDown(e: React.KeyboardEvent, callback: () => void) {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    callback();
  }
}

export function FindingsPanel({
  data,
  activeScenario,
  activeFindings,
  displayedFindings,
  groupedFindings,
  currentCodeReviews,
  copiedIndex,
  transitiveDepth,
  maxGraphDepth,
  showAllFindings,
  expandedPackageKeys,
  onCopy,
  onFindingClick,
  onPackageFocus,
  onTogglePackageExpanded,
  onToggleAllPackages,
  onToggleShowAllFindings,
  onResetFilters,
  onDownloadAIPrompt,
  onDownloadPatchedManifest,
  onDownloadExecutiveHtml,
  onDownloadReport,
  onNavigateView,
}: FindingsPanelProps) {
  const [activeTab, setActiveTab] = useState<"findings" | "briefing" | "reviewer" | "sandbox">("findings");
  const [showExportDropdown, setShowExportDropdown] = useState(false);
  const [findingsGrouping, setFindingsGrouping] = useState<"package" | "flat">("package");
  const [findingsSearch, setFindingsSearch] = useState("");

  const allExpanded =
    Object.values(expandedPackageKeys).filter(Boolean).length >= groupedFindings.length;

  return (
    <aside
      aria-label="Security findings and remediation workspace"
      className="w-[490px] xl:w-[520px] border-l border-zinc-800/80 bg-zinc-950/70 backdrop-blur-md flex flex-col h-full shrink-0"
    >
      <div className="flex items-center justify-between px-3 pt-3 pb-2 border-b border-zinc-800/80 shrink-0 gap-2">
        <div className="flex items-center space-x-1 shrink-0" role="tablist" aria-label="Analysis panel views">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "findings"}
            onClick={() => setActiveTab("findings")}
            className={cn(
              "px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0",
              activeTab === "findings"
                ? "bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60"
            )}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" aria-hidden="true" />
            <span>Findings ({activeFindings.length})</span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "briefing"}
            onClick={() => setActiveTab("briefing")}
            className={cn(
              "px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5 whitespace-nowrap shrink-0",
              activeTab === "briefing"
                ? "bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60"
            )}
          >
            <Sparkles className="w-3.5 h-3.5 text-indigo-400 shrink-0" aria-hidden="true" />
            <span>Executive AI</span>
          </button>
        </div>

        <div className="flex items-center space-x-1.5 shrink-0">
          {data?.findings && data.findings.length > 0 && (
            <>
              <button
                type="button"
                onClick={() => onCopy(generateMasterAIFixPrompt(data), "ai-master-prompt")}
                className="px-2.5 py-1 text-xs font-mono font-semibold whitespace-nowrap shrink-0 text-emerald-300 hover:text-emerald-100 bg-emerald-950/70 hover:bg-emerald-900/80 border border-emerald-600/60 hover:border-emerald-500 rounded-lg flex items-center space-x-1.5 transition-all shadow-sm group/ai"
                title="Copy complete Master AI Fix Prompt for ChatGPT, Claude, Cursor, Copilot"
              >
                {copiedIndex === "ai-master-prompt" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
                    <span className="text-emerald-400 font-bold whitespace-nowrap">Copied!</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0 group-hover/ai:rotate-12 transition-transform" aria-hidden="true" />
                    <span className="whitespace-nowrap">Fix with AI</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() =>
                  onCopy(
                    formatAllFindingsText(
                      data.findings,
                      data?.scan?.repository_url,
                      data?.scan?.blast_radius_score
                    ),
                    "all-findings"
                  )
                }
                className="px-2 py-1 text-xs font-mono font-medium whitespace-nowrap shrink-0 text-zinc-300 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-750 hover:border-zinc-600 rounded-lg flex items-center space-x-1.5 transition-all shadow-sm"
                title="Copy all findings report to clipboard"
              >
                {copiedIndex === "all-findings" ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
                    <span className="text-emerald-400 font-bold whitespace-nowrap">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-zinc-400 shrink-0" aria-hidden="true" />
                    <span className="whitespace-nowrap">Copy All</span>
                  </>
                )}
              </button>
            </>
          )}

          <div className="relative shrink-0">
            <button
              type="button"
              onClick={() => setShowExportDropdown((prev) => !prev)}
              aria-expanded={showExportDropdown}
              aria-haspopup="menu"
              className="px-2 py-1 text-xs font-mono font-semibold whitespace-nowrap shrink-0 text-zinc-200 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700/70 rounded-lg flex items-center space-x-1 transition-all shadow-sm"
              title="Download audit reports and patched manifests"
            >
              <Download className="w-3.5 h-3.5 text-indigo-400 shrink-0" aria-hidden="true" />
              <span className="whitespace-nowrap">Export</span>
              <ChevronDown
                className={cn("w-3 h-3 text-zinc-400 transition-transform shrink-0", showExportDropdown && "rotate-180")}
                aria-hidden="true"
              />
            </button>

            {showExportDropdown && (
              <div
                role="menu"
                className="absolute right-0 top-full mt-1.5 w-56 bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl p-1.5 space-y-1 z-30"
                onMouseLeave={() => setShowExportDropdown(false)}
              >
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setShowExportDropdown(false);
                    onDownloadAIPrompt();
                  }}
                  className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-purple-300 hover:bg-purple-950/60 flex items-center space-x-2.5 transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5 text-purple-400 shrink-0" aria-hidden="true" />
                  <div>
                    <div className="font-semibold text-[11px] text-purple-300">Master AI Fix Prompt (.md)</div>
                    <div className="text-[9px] text-zinc-400">For Cursor, Claude & ChatGPT</div>
                  </div>
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setShowExportDropdown(false);
                    onDownloadPatchedManifest();
                  }}
                  className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-emerald-300 hover:bg-emerald-950/60 flex items-center space-x-2.5 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
                  <div>
                    <div className="font-semibold text-[11px] text-emerald-300">Patched Manifest</div>
                    <div className="text-[9px] text-zinc-400">package.json / requirements.txt</div>
                  </div>
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setShowExportDropdown(false);
                    onDownloadExecutiveHtml();
                  }}
                  className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-indigo-300 hover:bg-indigo-950/60 flex items-center space-x-2.5 transition-colors"
                >
                  <FileText className="w-3.5 h-3.5 text-indigo-400 shrink-0" aria-hidden="true" />
                  <div>
                    <div className="font-semibold text-[11px] text-indigo-300">Executive PDF/HTML</div>
                    <div className="text-[9px] text-zinc-400">Printable executive report</div>
                  </div>
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setShowExportDropdown(false);
                    onDownloadReport();
                  }}
                  className="w-full text-left px-2.5 py-2 rounded-lg text-xs font-mono text-zinc-300 hover:bg-zinc-850 flex items-center space-x-2.5 transition-colors"
                >
                  <FileCode2 className="w-3.5 h-3.5 text-zinc-400 shrink-0" aria-hidden="true" />
                  <div>
                    <div className="font-semibold text-[11px] text-zinc-200">Markdown Audit (.md)</div>
                    <div className="text-[9px] text-zinc-400">Raw report for GitHub issues</div>
                  </div>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {activeTab === "findings" && (
          <div className="space-y-3">
            {data?.findings && data.findings.length > 0 ? (
              <>
                <div className="flex items-center justify-between gap-2 p-1.5 rounded-xl bg-zinc-950/90 border border-zinc-800 text-xs font-mono">
                  <div className="flex items-center space-x-0.5 bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => setFindingsGrouping("package")}
                      aria-pressed={findingsGrouping === "package"}
                      className={cn(
                        "px-2 py-0.5 rounded-md text-[10px] font-semibold transition-all flex items-center space-x-1",
                        findingsGrouping === "package"
                          ? "bg-indigo-600/30 text-indigo-200 border border-indigo-500/40 shadow-sm"
                          : "text-zinc-400 hover:text-zinc-200"
                      )}
                    >
                      <Boxes className="w-3 h-3 text-sky-400" aria-hidden="true" />
                      <span>Packages ({groupedFindings.length})</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setFindingsGrouping("flat")}
                      aria-pressed={findingsGrouping === "flat"}
                      className={cn(
                        "px-2 py-0.5 rounded-md text-[10px] font-semibold transition-all flex items-center space-x-1",
                        findingsGrouping === "flat"
                          ? "bg-zinc-800 text-zinc-100 shadow-sm"
                          : "text-zinc-400 hover:text-zinc-200"
                      )}
                    >
                      <FileText className="w-3 h-3 text-zinc-400" aria-hidden="true" />
                      <span>Flat ({activeFindings.length})</span>
                    </button>
                  </div>

                  <div className="relative flex-1 min-w-[110px]">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-400" aria-hidden="true" />
                    <input
                      type="text"
                      aria-label="Filter findings by CVE ID or package name"
                      value={findingsSearch}
                      onChange={(e) => setFindingsSearch(e.target.value)}
                      placeholder="Filter CVE or pkg..."
                      className="w-full pl-6 pr-2 py-0.5 rounded-lg bg-zinc-900/90 border border-zinc-800/80 text-[10px] text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-zinc-700"
                    />
                  </div>

                  {findingsGrouping === "package" && (
                    <button
                      type="button"
                      onClick={() => onToggleAllPackages(!allExpanded)}
                      className="px-2 py-0.5 rounded-md bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[10px] text-zinc-300 hover:text-zinc-100 transition-colors shrink-0"
                      title={!allExpanded ? "Expand all packages" : "Collapse all packages"}
                    >
                      {!allExpanded ? "Expand" : "Collapse"}
                    </button>
                  )}
                </div>

                {findingsGrouping === "package" ? (
                  <div className="space-y-2.5">
                    {groupedFindings
                      .filter((g) => {
                        if (!findingsSearch.trim()) return true;
                        const q = findingsSearch.toLowerCase();
                        return (
                          g.pkgName.toLowerCase().includes(q) ||
                          g.findings.some(
                            (f: any) =>
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
                            <div
                              role="button"
                              tabIndex={0}
                              aria-expanded={isExpanded}
                              aria-label={`Toggle findings for package ${g.pkgName}`}
                              onClick={() => onTogglePackageExpanded(g.key)}
                              onKeyDown={(e) =>
                                handleCardKeyDown(e, () => onTogglePackageExpanded(g.key))
                              }
                              className="p-3 bg-zinc-900/70 hover:bg-zinc-850/80 cursor-pointer flex items-center justify-between transition-colors border-b border-zinc-800/60 focus:outline-none focus:ring-1 focus:ring-indigo-500/60"
                            >
                              <div className="flex items-center space-x-2.5 min-w-0 flex-1 mr-2">
                                <div className="p-1.5 rounded-lg bg-zinc-800 border border-zinc-700/60 text-zinc-300 shrink-0">
                                  <Boxes className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center space-x-1.5 truncate">
                                    <span className="text-xs font-bold text-zinc-100 truncate">
                                      {g.pkgName}
                                    </span>
                                    {g.version && (
                                      <span className="text-[10px] text-zinc-400 font-mono shrink-0">
                                        @{g.version}
                                      </span>
                                    )}
                                    <span className="text-[8px] px-1 py-0.2 rounded uppercase font-mono font-bold border bg-zinc-800 text-zinc-300 border-zinc-700 shrink-0">
                                      {g.ecosystem}
                                    </span>
                                  </div>
                                  <div className="text-[10px] text-zinc-400 font-mono mt-0.5 flex items-center space-x-1.5 truncate">
                                    <span className="shrink-0">
                                      {g.findings.length} Finding{g.findings.length !== 1 ? "s" : ""}
                                    </span>
                                    {g.fixVersion && (
                                      <>
                                        <span className="text-zinc-600 shrink-0" aria-hidden="true">•</span>
                                        <span
                                          className="text-emerald-400 font-medium truncate"
                                          title={`Recommended Fix: ${g.fixVersion}`}
                                        >
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
                                    onCopy(
                                      generateSingleAIFixPrompt(g.findings[0], g.findings),
                                      `pkg-ai-${g.key}`
                                    );
                                  }}
                                  className="px-1.5 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 hover:text-emerald-100 border border-emerald-700/60 hover:border-emerald-500 transition-all text-[9px] font-mono flex items-center space-x-1 shadow-sm whitespace-nowrap shrink-0"
                                  title="Copy AI Prompt to fix this package in Cursor, ChatGPT, or Claude"
                                >
                                  {copiedIndex === `pkg-ai-${g.key}` ? (
                                    <>
                                      <Check className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                      <span className="font-bold">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Sparkles className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                      <span>AI Fix</span>
                                    </>
                                  )}
                                </button>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onPackageFocus(g.key, g.findings[0]);
                                  }}
                                  className="px-1.5 py-0.5 rounded bg-zinc-800/90 hover:bg-indigo-950/80 text-zinc-300 hover:text-indigo-200 border border-zinc-750 hover:border-indigo-600/60 transition-all text-[9px] font-mono flex items-center space-x-1 whitespace-nowrap shrink-0"
                                  title="Focus package node in attack graph"
                                >
                                  <Crosshair className="w-2.5 h-2.5 text-indigo-400" aria-hidden="true" />
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
                                <div className="p-0.5 text-zinc-400 shrink-0" aria-hidden="true">
                                  <ChevronDown
                                    className={cn(
                                      "w-3.5 h-3.5 transition-transform duration-200",
                                      isExpanded && "rotate-180"
                                    )}
                                  />
                                </div>
                              </div>
                            </div>

                            {isExpanded && (
                              <div className="p-2.5 space-y-2.5 bg-black/30">
                                {g.findings.map((f: any, fIdx: number) => {
                                  const detectorTag = getDetectorTag(f);
                                  const lockSnippet = buildLockfileSnippet(
                                    f,
                                    g.fixVersion || undefined
                                  );
                                  return (
                                    <div
                                      key={fIdx}
                                      role="button"
                                      tabIndex={0}
                                      aria-label={`Focus finding ${f.title} in attack graph`}
                                      className="p-3 rounded-xl border border-zinc-800/80 bg-zinc-950/60 hover:bg-zinc-900/60 transition-all group cursor-pointer focus:outline-none focus:ring-1 focus:ring-indigo-500/60"
                                      onClick={() => onFindingClick(f)}
                                      onKeyDown={(e) =>
                                        handleCardKeyDown(e, () => onFindingClick(f))
                                      }
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
                                              onCopy(
                                                generateSingleAIFixPrompt(f, g.findings),
                                                `ai-f-${g.key}-${fIdx}`
                                              );
                                            }}
                                            className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-300 hover:text-white transition-colors text-[9px] font-mono shadow-sm"
                                            title="Copy AI Prompt to fix this vulnerability with ChatGPT, Claude, or Cursor"
                                          >
                                            {copiedIndex === `ai-f-${g.key}-${fIdx}` ? (
                                              <>
                                                <Check className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                                <span className="text-emerald-400 font-bold">Copied!</span>
                                              </>
                                            ) : (
                                              <>
                                                <Sparkles className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                                <span>Prompt AI</span>
                                              </>
                                            )}
                                          </button>
                                          <button
                                            type="button"
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              onCopy(
                                                formatSingleFindingText(f),
                                                `finding-${g.key}-${fIdx}`
                                              );
                                            }}
                                            className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 border border-zinc-750 text-zinc-300 hover:text-white transition-colors text-[9px] font-mono"
                                            title="Copy full finding details"
                                          >
                                            {copiedIndex === `finding-${g.key}-${fIdx}` ? (
                                              <>
                                                <Check className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                                <span className="text-emerald-400 font-bold">Copied!</span>
                                              </>
                                            ) : (
                                              <>
                                                <Copy className="w-2.5 h-2.5 text-zinc-400" aria-hidden="true" />
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
                                            onFindingClick(f);
                                          }}
                                          className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-indigo-950/50 hover:bg-indigo-900/70 border border-indigo-800/50 hover:border-indigo-600/70 text-indigo-300 hover:text-white text-[10px] font-mono font-medium transition-all cursor-pointer shadow-sm group/btn"
                                          title="Center and highlight this node in the attack graph"
                                        >
                                          <Crosshair className="w-3.5 h-3.5 text-indigo-400 group-hover/btn:rotate-90 transition-transform duration-300" aria-hidden="true" />
                                          <span>Click to focus node in graph</span>
                                        </button>
                                      </div>

                                      {f.recommendations && f.recommendations.length > 0 && (
                                        <div className="mt-2 pt-2 border-t border-zinc-800/60">
                                          <div className="flex items-center justify-between text-[10px] text-zinc-400 font-mono uppercase mb-1">
                                            <span>Remediation</span>
                                            <span className="text-[9px] text-zinc-500">Least-privilege fix</span>
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
                                                    onCopy(lockSnippet, `snippet-${g.key}-${fIdx}`);
                                                  }}
                                                  className="absolute top-1.5 right-1.5 flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white transition-all text-[9px] font-mono shadow-sm"
                                                  title="Copy configuration snippet to clipboard"
                                                >
                                                  {copiedIndex === `snippet-${g.key}-${fIdx}` ? (
                                                    <>
                                                      <Check className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                                      <span className="text-emerald-400 font-bold">Copied!</span>
                                                    </>
                                                  ) : (
                                                    <>
                                                      <Copy className="w-2.5 h-2.5 text-zinc-400" aria-hidden="true" />
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
                  <div className="space-y-3.5">
                    {displayedFindings
                      .filter((f) => {
                        if (!findingsSearch.trim()) return true;
                        const q = findingsSearch.toLowerCase();
                        return (
                          f.title?.toLowerCase().includes(q) ||
                          f.description?.toLowerCase().includes(q)
                        );
                      })
                      .map((f: any, idx: number) => {
                        const detectorTag = getDetectorTag(f);
                        const lockSnippet = buildLockfileSnippet(f);
                        return (
                          <div
                            key={idx}
                            role="button"
                            tabIndex={0}
                            aria-label={`Focus finding ${f.title} in attack graph`}
                            className="p-3.5 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 transition-all group cursor-pointer focus:outline-none focus:ring-1 focus:ring-indigo-500/60"
                            onClick={() => onFindingClick(f)}
                            onKeyDown={(e) => handleCardKeyDown(e, () => onFindingClick(f))}
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
                                    onCopy(generateSingleAIFixPrompt(f), `ai-flat-${idx}`);
                                  }}
                                  className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700/60 text-emerald-300 hover:text-white transition-colors text-[9px] font-mono shadow-sm"
                                  title="Copy AI Prompt to fix this vulnerability with ChatGPT, Claude, or Cursor"
                                >
                                  {copiedIndex === `ai-flat-${idx}` ? (
                                    <>
                                      <Check className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                      <span className="text-emerald-400 font-bold">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Sparkles className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                      <span>Prompt AI</span>
                                    </>
                                  )}
                                </button>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onCopy(formatSingleFindingText(f), `finding-${idx}`);
                                  }}
                                  className="flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800/90 hover:bg-zinc-750 border border-zinc-750 text-zinc-300 hover:text-white transition-colors text-[9px] font-mono"
                                  title="Copy full finding details and remediation to clipboard"
                                >
                                  {copiedIndex === `finding-${idx}` ? (
                                    <>
                                      <Check className="w-2.5 h-2.5 text-emerald-400" aria-hidden="true" />
                                      <span className="text-emerald-400 font-bold">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-2.5 h-2.5 text-zinc-400" aria-hidden="true" />
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
                                  onFindingClick(f);
                                }}
                                className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-indigo-950/50 hover:bg-indigo-900/70 border border-indigo-800/50 hover:border-indigo-600/70 text-indigo-300 hover:text-white text-[10px] font-mono font-medium transition-all cursor-pointer shadow-sm group/btn"
                                title="Center and highlight this node in the attack graph"
                              >
                                <Crosshair className="w-3.5 h-3.5 text-indigo-400 group-hover/btn:rotate-90 transition-transform duration-300" aria-hidden="true" />
                                <span>Click to focus node in graph</span>
                              </button>
                            </div>

                            {f.recommendations && f.recommendations.length > 0 && (
                              <div className="mt-2.5 pt-2.5 border-t border-zinc-800/60">
                                <div className="flex items-center justify-between text-[10px] text-zinc-400 font-mono uppercase mb-1.5">
                                  <span>Containment Strategy</span>
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      onCopy(lockSnippet, idx);
                                    }}
                                    className="flex items-center space-x-1 hover:text-zinc-200 transition-colors"
                                  >
                                    {copiedIndex === idx ? (
                                      <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" />
                                    ) : (
                                      <Copy className="w-3 h-3" aria-hidden="true" />
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
                          type="button"
                          onClick={onToggleShowAllFindings}
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
                    <ListFilter className="w-6 h-6 text-amber-400 mx-auto" aria-hidden="true" />
                    <p className="text-xs text-zinc-300 font-mono font-semibold">
                      All Findings Filtered
                    </p>
                    <p className="text-[11px] text-zinc-400 max-w-xs mx-auto">
                      {data.findings.length} findings are in dependencies currently hidden by Depth (
                      {transitiveDepth}) or Prod Only filter.
                    </p>
                    <button
                      type="button"
                      onClick={onResetFilters}
                      className="mt-2 px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-mono transition-colors"
                    >
                      Reset Filters (Show All {data.findings.length})
                    </button>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" aria-hidden="true" />
                    <p className="text-xs text-zinc-400 font-mono">No vulnerabilities detected</p>
                  </>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === "briefing" && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-indigo-900/40 bg-indigo-950/20 text-xs leading-relaxed space-y-3">
              <div className="flex items-center justify-between text-indigo-300 font-mono text-[11px] pb-2 border-b border-indigo-900/40">
                <span className="flex items-center space-x-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-indigo-400" aria-hidden="true" />
                  <span>Autonomous Security Audit</span>
                </span>
                <span className="text-zinc-400 text-[10px]">
                  {data?.detector_breakdown?.model_provider || "Gemini 2.5 Flash / Bedrock Fallback"}
                </span>
              </div>

              <div className="text-zinc-300 whitespace-pre-wrap font-sans text-xs leading-relaxed">
                {getExecutiveSummary(data, activeScenario)}
              </div>
            </div>

            <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-900/30 space-y-2 text-xs font-mono">
              <div className="text-zinc-300 font-semibold">Exploitability Summary</div>
              <div className="text-zinc-400 text-[11px]">
                • Total Attack Paths:{" "}
                <span className="text-zinc-200">{data?.scan?.total_attack_paths || 0}</span>
              </div>
              <div className="text-zinc-400 text-[11px]">
                • Blast Radius Score:{" "}
                <span className="text-red-400 font-bold">
                  {(Number(data?.scan?.blast_radius_score) || 0).toFixed(1)}/100
                </span>
              </div>
              <div className="text-zinc-400 text-[11px]">
                • Transitive Vulnerabilities:{" "}
                <span className="text-amber-400 font-bold">{data?.vulnerabilities?.length || 0}</span>
              </div>
              <div className="text-zinc-400 text-[11px]">
                • AI Code Patches:{" "}
                <span className="text-indigo-400 font-bold">{data?.code_reviews?.length || 0}</span>
              </div>
            </div>
          </div>
        )}

        {activeTab === "reviewer" && (
          <div className="p-4 rounded-xl border border-amber-900/40 bg-amber-950/20 text-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-amber-300">Code Reviewer & Patches</span>
              <span className="text-[10px] text-zinc-400 font-mono">
                {currentCodeReviews.length} patches
              </span>
            </div>
            <p className="text-zinc-400 text-xs leading-relaxed">
              For high-resolution side-by-side git diffs, AST inspection, and interactive AI patch
              application, switch to the dedicated workspace.
            </p>
            <button
              type="button"
              onClick={() => onNavigateView("reviewer")}
              className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition-all shadow-md shadow-amber-600/20"
            >
              <span>Open Dedicated Code Reviewer</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        )}

        {activeTab === "sandbox" && (
          <div className="p-4 rounded-xl border border-red-900/40 bg-red-950/20 text-xs space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-red-300">Detonation Sandbox</span>
              <span className="text-[10px] text-zinc-400 font-mono">Isolated Container</span>
            </div>
            <p className="text-zinc-400 text-xs leading-relaxed">
              For isolated dynamic execution, network behavioral tracing, and real-time syscall logs,
              switch to the dedicated workspace.
            </p>
            <button
              type="button"
              onClick={() => onNavigateView("sandbox")}
              className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold transition-all shadow-md shadow-red-600/20"
            >
              <span>Open Dedicated Detonation Sandbox</span>
              <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        )}

        <div className="mt-4 pt-3 border-t border-zinc-800/80 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => onNavigateView("reviewer")}
            className="flex-1 py-1.5 px-2.5 rounded-lg bg-zinc-900/80 hover:bg-zinc-850 border border-zinc-800 text-[11px] font-mono text-zinc-300 hover:text-white flex items-center justify-between transition-colors shadow-sm"
            title="Open full-width Code Reviewer with git diffs and AI patches"
          >
            <span className="flex items-center space-x-1.5 truncate">
              <Sparkles className="w-3 h-3 text-amber-400 shrink-0" aria-hidden="true" />
              <span className="truncate">Code Reviewer</span>
            </span>
            <ArrowRight className="w-3 h-3 text-zinc-400 shrink-0" aria-hidden="true" />
          </button>

          <button
            type="button"
            onClick={() => onNavigateView("sandbox")}
            className="flex-1 py-1.5 px-2.5 rounded-lg bg-zinc-900/80 hover:bg-zinc-850 border border-zinc-800 text-[11px] font-mono text-zinc-300 hover:text-white flex items-center justify-between transition-colors shadow-sm"
            title="Open full-width Detonation Sandbox terminal"
          >
            <span className="flex items-center space-x-1.5 truncate">
              <Zap className="w-3 h-3 text-red-400 shrink-0" aria-hidden="true" />
              <span className="truncate">Detonation Sandbox</span>
            </span>
            <ArrowRight className="w-3 h-3 text-zinc-400 shrink-0" aria-hidden="true" />
          </button>
        </div>
      </div>
    </aside>
  );
}
