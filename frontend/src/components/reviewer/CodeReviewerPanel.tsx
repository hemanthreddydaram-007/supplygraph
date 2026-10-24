"use client";

import React, { useState } from "react";
import { CodeReviewItem } from "@/types";
import { fetchCodeReviewSnippet } from "@/lib/api";
import {
  FileCode2,
  Copy,
  Check,
  Download,
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Play,
  Loader2,
  FileText,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface CodeReviewerPanelProps {
  codeReviews: CodeReviewItem[];
  onReviewsUpdated?: (newReviews: CodeReviewItem[]) => void;
}

export const CodeReviewerPanel = React.memo(function CodeReviewerPanel({
  codeReviews,
  onReviewsUpdated,
}: CodeReviewerPanelProps) {
  const [copiedState, setCopiedState] = useState<string | null>(null);
  const [showTester, setShowTester] = useState(false);
  const [customCode, setCustomCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [filePath, setFilePath] = useState("src/sample.py");
  const [isReviewing, setIsReviewing] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [adHocReviews, setAdHocReviews] = useState<CodeReviewItem[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [viewMode, setViewMode] = useState<"stacked" | "diff">("diff");

  const handleCopy = (code: string, key: string) => {
    navigator.clipboard.writeText(code);
    setCopiedState(key);
    setTimeout(() => setCopiedState(null), 2000);
  };

  const handleDownloadPatch = (item: CodeReviewItem) => {
    let patchContent = item.unified_diff;
    if (!patchContent) {
      patchContent = `--- a/${item.file_path}\n+++ b/${item.file_path}\n@@ -${item.line_number},1 +${item.line_number},1 @@\n-${item.buggy_code}\n+${item.corrected_code}\n`;
    }
    if (!patchContent.endsWith("\n")) {
      patchContent += "\n";
    }
    const blob = new Blob([patchContent], { type: "text/x-diff;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const baseName = item.file_path.split("/").pop() || "patch";
    a.download = `${baseName}.patch`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyAllReviews = () => {
    let text = `# SupplyGraph Code Review & Remediation Patches\n`;
    text += `Total Issues Detected: ${allDisplayReviews.length}\n`;
    text += `Timestamp: ${new Date().toISOString()}\n\n`;
    text += `============================================================\n\n`;

    allDisplayReviews.forEach((item, idx) => {
      text += `### Review #${idx + 1}: ${item.title} [${item.severity}] (${item.category})\n`;
      text += `File: ${item.file_path} : Line ${item.line_number}\n`;
      text += `Explanation: ${item.error_explanation}\n\n`;
      if (item.unified_diff) {
        text += `\`\`\`diff\n${item.unified_diff}\n\`\`\`\n\n`;
      } else {
        text += `Vulnerable Code:\n\`\`\`\n${item.buggy_code}\n\`\`\`\n\nCorrected Replacement Code:\n\`\`\`\n${item.corrected_code}\n\`\`\`\n\n`;
      }
      text += `------------------------------------------------------------\n\n`;
    });

    handleCopy(text.trim(), "all-reviews");
  };

  const handleCopyAIPrompt = () => {
    let prompt = `# AI REMEDIATION TASK: Apply Code Review & CI/CD Security Patches\n\n`;
    prompt += `You are an expert software engineer and CI/CD security architect.\n`;
    prompt += `SupplyGraph detected ${allDisplayReviews.length} security hardening and code quality issue(s) in this repository.\n`;
    prompt += `Please apply the following verified unified diff patches directly to the target files with zero regression:\n\n`;

    allDisplayReviews.forEach((item, idx) => {
      prompt += `### Patch #${idx + 1}: ${item.title} [${item.severity}]\n`;
      prompt += `- Target File: \`${item.file_path}\` (Line ${item.line_number})\n`;
      prompt += `- Category: ${item.category}\n`;
      prompt += `- Issue Explanation: ${item.error_explanation}\n\n`;
      if (item.unified_diff) {
        prompt += `\`\`\`diff\n${item.unified_diff}\n\`\`\`\n\n`;
      } else {
        prompt += `Replace:\n\`\`\`\n${item.buggy_code}\n\`\`\`\nWith:\n\`\`\`\n${item.corrected_code}\n\`\`\`\n\n`;
      }
    });

    prompt += `### INSTRUCTIONS FOR AI:\n`;
    prompt += `1. Locate each file in the repository.\n`;
    prompt += `2. Apply the exact replacement or unified diff shown above.\n`;
    prompt += `3. Preserve valid YAML/source syntax and do not break workflow triggers or build steps.\n\n`;
    prompt += `Please apply these patches now and output the updated file contents.\n`;

    handleCopy(prompt.trim(), "ai-reviews-prompt");
  };

  const handleCopySingleReview = (item: CodeReviewItem) => {
    let text = `[${item.severity}] ${item.title} (${item.category})\n`;
    text += `Target: ${item.file_path} : Line ${item.line_number}\n`;
    text += `Explanation: ${item.error_explanation}\n\n`;
    if (item.unified_diff) {
      text += `Unified Diff:\n${item.unified_diff}\n`;
    } else {
      text += `Original Code:\n${item.buggy_code}\n\nCorrected Code:\n${item.corrected_code}\n`;
    }
    handleCopy(text.trim(), `${item.id}-review`);
  };

  const handleRunAdHocReview = async () => {
    if (!customCode.trim()) return;
    setIsReviewing(true);
    setTestError(null);
    try {
      const res = await fetchCodeReviewSnippet(customCode, language, filePath);
      if (res && res.reviews) {
        setAdHocReviews(res.reviews);
        if (onReviewsUpdated) {
          onReviewsUpdated([...res.reviews, ...codeReviews]);
        }
      }
    } catch (e: any) {
      setTestError(e.message || "Failed to analyze code snippet");
    } finally {
      setIsReviewing(false);
    }
  };

  const allDisplayReviews = [...adHocReviews, ...codeReviews];

  const getSeverityBadge = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-500/10 text-red-400 border-red-500/20";
      case "HIGH":
        return "bg-orange-500/10 text-orange-400 border-orange-500/20";
      case "MEDIUM":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      default:
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    }
  };

  const getCategoryBadge = (category: string) => {
    if (category?.includes("Hardening")) return "bg-sky-950/60 text-sky-300 border-sky-800/40";
    if (category?.includes("Security")) return "bg-rose-950/60 text-rose-300 border-rose-800/40";
    if (category?.includes("Bug")) return "bg-amber-950/60 text-amber-300 border-amber-800/40";
    return "bg-indigo-950/60 text-indigo-300 border-indigo-800/40";
  };

  return (
    <div className="space-y-4">
      {/* COLLAPSIBLE AD-HOC TESTER BOX */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 overflow-hidden">
        <button
          onClick={() => setShowTester(!showTester)}
          className="w-full flex items-center justify-between p-3.5 text-left hover:bg-zinc-900/50 transition-colors"
        >
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span className="text-xs font-semibold text-zinc-200">
              {showTester ? "Collapse Ad-Hoc Code Tester" : "+ Paste Custom File / Code to Review"}
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-mono">
              Live Analyzer
            </span>
          </div>
          {showTester ? <ChevronUp className="w-4 h-4 text-zinc-400" /> : <ChevronDown className="w-4 h-4 text-zinc-400" />}
        </button>

        {showTester && (
          <div className="p-4 border-t border-zinc-800/80 space-y-3 bg-zinc-900/30">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">Language</label>
                <select
                  value={language}
                  onChange={(e) => {
                    setLanguage(e.target.value);
                    if (e.target.value === "python") setFilePath("src/app.py");
                    else if (e.target.value === "javascript") setFilePath("src/utils.js");
                    else if (e.target.value === "typescript") setFilePath("src/component.tsx");
                    else setFilePath(".github/workflows/ci.yml");
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-200 text-xs font-mono focus:outline-none focus:border-red-500/50"
                >
                  <option value="python">Python (.py)</option>
                  <option value="javascript">JavaScript (.js)</option>
                  <option value="typescript">TypeScript / React (.tsx)</option>
                  <option value="yaml">YAML / GitHub Action (.yml)</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">File Path Mock</label>
                <input
                  type="text"
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-200 text-xs font-mono focus:outline-none focus:border-red-500/50"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">Code Snippet to Inspect</label>
              <textarea
                rows={4}
                value={customCode}
                onChange={(e) => setCustomCode(e.target.value)}
                placeholder={
                  language === "python"
                    ? "def run(cmd, items=[]):\n    subprocess.run(cmd, shell=True)"
                    : "const apiKey = 'secret_key_12345';\neval(userInput);"
                }
                className="w-full p-2.5 rounded-lg bg-black/80 border border-zinc-800 text-zinc-200 text-xs font-mono focus:outline-none focus:border-red-500/50 resize-y"
              />
            </div>

            {testError && (
              <div className="text-[11px] text-red-400 font-mono bg-red-950/40 p-2 rounded border border-red-800/40">
                {testError}
              </div>
            )}

            <button
              onClick={handleRunAdHocReview}
              disabled={isReviewing || !customCode.trim()}
              className="w-full py-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center justify-center space-x-2 transition-all shadow-md shadow-red-600/20"
            >
              {isReviewing ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Inspecting AST & Generating Fix...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Review Code & Output Patches</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* TOOLBAR: REVIEW COUNT & VIEW TOGGLE (Fix #10) */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-1">
        <span className="text-[11px] font-mono text-zinc-400">
          Issues Detected: <b className="text-zinc-100">{allDisplayReviews.length}</b>
        </span>

        <div className="flex items-center space-x-2">
          {allDisplayReviews.length > 0 && (
            <>
              <button
                onClick={handleCopyAIPrompt}
                className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-emerald-950/70 hover:bg-emerald-900 border border-emerald-700/60 hover:border-emerald-500 text-emerald-300 hover:text-white transition-colors text-[10px] font-mono shadow-sm"
                title="Copy an AI Prompt for Cursor, Claude, or ChatGPT to apply all unified diffs"
              >
                {copiedState === "ai-reviews-prompt" ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400 font-semibold">AI Prompt Copied!</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3 h-3 text-emerald-400 animate-pulse" />
                    <span>Fix with AI</span>
                  </>
                )}
              </button>

              <button
                onClick={handleCopyAllReviews}
                className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white transition-colors text-[10px] font-mono shadow-sm"
                title="Copy all code reviews and git diffs to clipboard"
              >
                {copiedState === "all-reviews" ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400 font-semibold">Copied All ({allDisplayReviews.length}) Reviews!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-zinc-400" />
                    <span>Copy All Reviews</span>
                  </>
                )}
              </button>
            </>
          )}

          <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-[10px] font-mono">
            <button
              onClick={() => setViewMode("diff")}
              className={cn(
                "px-2.5 py-1 rounded-md transition-all font-medium",
                viewMode === "diff"
                  ? "bg-zinc-800 text-zinc-100 shadow-sm"
                  : "text-zinc-500 hover:text-zinc-300"
              )}
            >
              Unified Git Diff
            </button>
            <button
              onClick={() => setViewMode("stacked")}
              className={cn(
                "px-2.5 py-1 rounded-md transition-all font-medium",
                viewMode === "stacked"
                  ? "bg-zinc-800 text-zinc-100 shadow-sm"
                  : "text-zinc-500 hover:text-zinc-300"
              )}
            >
              Stacked View
            </button>
          </div>
        </div>
      </div>

      {/* REVIEWS LIST */}
      <div className="space-y-4">
        {allDisplayReviews && allDisplayReviews.length > 0 ? (
          <>
            {(showAll ? allDisplayReviews : allDisplayReviews.slice(0, 25)).map((item, idx) => {
              return (
                <div
                  key={item.id || idx}
                  className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/60 transition-all space-y-3"
                >
                  {/* Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-zinc-800 text-zinc-300 border border-zinc-700">
                        📄 {item.file_path} : L{item.line_number}
                      </span>
                      <span
                        className={cn(
                          "px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider border",
                          getSeverityBadge(item.severity)
                        )}
                      >
                        {item.severity}
                      </span>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleCopySingleReview(item)}
                        className="flex items-center space-x-1 px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 border border-zinc-700/60 text-zinc-300 hover:text-white transition-colors text-[9px] font-mono shadow-sm"
                        title="Copy complete review details and fix to clipboard"
                      >
                        {copiedState === `${item.id}-review` ? (
                          <>
                            <Check className="w-2.5 h-2.5 text-emerald-400" />
                            <span className="text-emerald-400 font-bold">Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-2.5 h-2.5 text-zinc-400" />
                            <span>Copy Review</span>
                          </>
                        )}
                      </button>

                      <span
                        className={cn(
                          "px-2 py-0.5 rounded-full text-[9px] font-mono border",
                          getCategoryBadge(item.category)
                        )}
                      >
                        {item.category}
                      </span>
                    </div>
                  </div>

                  {/* Title & Explanation */}
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-100 flex items-center space-x-1.5">
                      <span>{item.title}</span>
                    </h4>
                    <p className="text-[11px] text-zinc-400 mt-1 leading-relaxed">
                      {item.error_explanation}
                    </p>
                  </div>

                  {/* UNIFIED GIT DIFF OR STACKED COMPARISON (Fix #10) */}
                  {viewMode === "diff" ? (
                    <div className="rounded-lg overflow-hidden border border-zinc-800 bg-zinc-950/80 font-mono text-[11px]">
                      <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/90 border-b border-zinc-800 text-zinc-400">
                        <span className="text-[10px] text-zinc-400 font-mono">git diff: {item.file_path}</span>
                        <div className="flex items-center space-x-2 text-[10px]">
                          <button
                            onClick={() => handleCopy(item.unified_diff || item.corrected_code, `${item.id}-diff`)}
                            className="flex items-center space-x-1 text-zinc-400 hover:text-zinc-200 transition-colors"
                            title="Copy full git diff"
                          >
                            {copiedState === `${item.id}-diff` ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            <span>{copiedState === `${item.id}-diff` ? "Copied Diff!" : "Copy Diff"}</span>
                          </button>
                          <button
                            onClick={() => handleCopy(item.corrected_code, `${item.id}-fix`)}
                            className="flex items-center space-x-1 text-emerald-400 hover:text-emerald-300 transition-colors font-semibold"
                            title="Copy corrected code replacement"
                          >
                            {copiedState === `${item.id}-fix` ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            <span>{copiedState === `${item.id}-fix` ? "Copied Fix!" : "Copy Fix"}</span>
                          </button>
                        </div>
                      </div>
                      <div className="p-3 space-y-0.5 overflow-x-auto whitespace-pre select-text bg-black/60 font-mono text-[11px] leading-relaxed">
                        {(() => {
                          const diffText = item.unified_diff || [
                            `--- a/${item.file_path}`,
                            `+++ b/${item.file_path}`,
                            `@@ -${item.line_number},1 +${item.line_number},1 @@`,
                            `-${item.buggy_code}`,
                            `+${item.corrected_code}`,
                          ].join("\n");
                          const lines = diffText.split("\n");
                          return lines.map((line, lIdx) => {
                            if (line.startsWith("---") || line.startsWith("+++")) {
                              return (
                                <div key={lIdx} className="text-cyan-400 font-semibold select-none whitespace-pre">
                                  {line}
                                </div>
                              );
                            }
                            if (line.startsWith("@@")) {
                              return (
                                <div key={lIdx} className="text-indigo-400 font-semibold select-none py-1 whitespace-pre">
                                  {line}
                                </div>
                              );
                            }
                            if (line.startsWith("-")) {
                              return (
                                <div
                                  key={lIdx}
                                  className="bg-red-950/40 text-red-300 px-1.5 py-0.5 rounded-sm whitespace-pre flex items-start"
                                >
                                  <span className="text-red-500 font-bold select-none mr-2 flex-shrink-0">-</span>
                                  <span className="whitespace-pre">{line.slice(1)}</span>
                                </div>
                              );
                            }
                            if (line.startsWith("+")) {
                              return (
                                <div
                                  key={lIdx}
                                  className="bg-emerald-950/40 text-emerald-300 px-1.5 py-0.5 rounded-sm whitespace-pre flex items-start"
                                >
                                  <span className="text-emerald-500 font-bold select-none mr-2 flex-shrink-0">+</span>
                                  <span className="whitespace-pre">{line.slice(1)}</span>
                                </div>
                              );
                            }
                            // Context lines (prefixed with space ' ' in unified diff)
                            const content = line.startsWith(" ") ? line.slice(1) : line;
                            return (
                              <div
                                key={lIdx}
                                className="text-zinc-400 px-1.5 py-0.5 rounded-sm whitespace-pre flex items-start hover:text-zinc-300"
                              >
                                <span className="text-zinc-600 select-none mr-2 flex-shrink-0 opacity-40"> </span>
                                <span className="whitespace-pre">{content}</span>
                              </div>
                            );
                          });
                        })()}
                      </div>
                    </div>
                  ) : (
                    /* STACKED CODE COMPARISON */
                    <div className="space-y-2 pt-1">
                      {/* Problematic Code */}
                      <div className="rounded-lg overflow-hidden border border-red-900/40 bg-red-950/20">
                        <div className="flex items-center justify-between px-2.5 py-1 bg-red-950/40 border-b border-red-900/30 text-[10px] font-mono text-red-300">
                          <span>❌ Original Error / Vulnerable Code (Line {item.line_number})</span>
                        </div>
                        <pre className="p-2.5 text-[11px] font-mono text-red-200 overflow-x-auto whitespace-pre leading-relaxed">
                          {item.buggy_code}
                        </pre>
                      </div>

                      {/* Corrected Replacement Code */}
                      <div className="rounded-lg overflow-hidden border border-emerald-900/40 bg-emerald-950/20">
                        <div className="flex items-center justify-between px-2.5 py-1 bg-emerald-950/40 border-b border-emerald-900/30 text-[10px] font-mono text-emerald-300">
                          <span>✅ Corrected Code by SupplyGraph</span>
                          <button
                            onClick={() => handleCopy(item.corrected_code, `${item.id}-fix`)}
                            className="flex items-center space-x-1 hover:text-emerald-100 transition-colors"
                          >
                            {copiedState === `${item.id}-fix` ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            <span>{copiedState === `${item.id}-fix` ? "Copied!" : "Copy Fix"}</span>
                          </button>
                        </div>
                        <pre className="p-2.5 text-[11px] font-mono text-emerald-200 overflow-x-auto whitespace-pre leading-relaxed">
                          {item.corrected_code}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Card Action Footer */}
                  <div className="flex items-center justify-end space-x-2 pt-1 text-[10px] font-mono">
                    <button
                      onClick={() => handleCopy(item.corrected_code, `${item.id}-code`)}
                      className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 flex items-center space-x-1 transition-colors"
                    >
                      {copiedState === `${item.id}-code` ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>
                        {copiedState === `${item.id}-code` ? "✓ Copied Corrected Code!" : "Copy Corrected Code"}
                      </span>
                    </button>

                    <button
                      onClick={() => handleDownloadPatch(item)}
                      className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 flex items-center space-x-1 transition-colors"
                    >
                      <Download className="w-3 h-3 text-blue-400" />
                      <span>Download Patch</span>
                    </button>
                  </div>
                </div>
              );
            })}

            {allDisplayReviews.length > 25 && (
              <div className="pt-2 text-center">
                <button
                  onClick={() => setShowAll(!showAll)}
                  className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-xs font-mono text-zinc-200 transition-colors shadow-sm"
                >
                  {showAll
                    ? "Show First 25 Issues"
                    : `Show All (${allDisplayReviews.length}) Issues`}
                </button>
              </div>
            )}
          </>
        ) : (
          <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl space-y-2">
            <FileCode2 className="w-8 h-8 text-zinc-600 mx-auto" />
            <div className="text-xs font-semibold text-zinc-300">No Code Review Issues Detected</div>
            <p className="text-[11px] text-zinc-500 max-w-xs mx-auto">
              Scan a GitHub repository, upload a local project folder, or paste custom code above to trigger the AI Code Reviewer.
            </p>
          </div>
        )}
      </div>
    </div>
  );
});

CodeReviewerPanel.displayName = "CodeReviewerPanel";
