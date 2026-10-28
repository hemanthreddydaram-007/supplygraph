"use client";

import React from "react";
import {
  Shield,
  ShieldAlert,
  ArrowRight,
  GitBranch,
  Layers,
  Sparkles,
  ShieldCheck,
  Check,
  X,
  FileCode2,
  FolderUp,
  Cpu,
  Lock,
  Boxes,
  Zap,
  ExternalLink,
} from "lucide-react";

interface OverviewDashboardProps {
  onGetStarted: () => void;
  onSelectScenario?: (id: "A" | "B" | "C" | "D" | "E") => void;
}

export const OverviewDashboard = React.memo(function OverviewDashboard({ onGetStarted, onSelectScenario }: OverviewDashboardProps) {
  return (
    <div className="space-y-16 pb-20 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8">
      {/* HERO BANNER */}
      <div className="relative rounded-3xl p-8 sm:p-12 overflow-hidden border border-zinc-800/80 bg-gradient-to-b from-zinc-900/90 via-zinc-950/80 to-[#070b13] shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-80 h-80 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 max-w-3xl space-y-5">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
            <span>Next-Generation Application Security Posture Management (ASPM)</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-zinc-100 leading-tight">
            Zero-Trust Software Supply-Chain Attack Graph &{" "}
            <span className="bg-gradient-to-r from-red-400 via-rose-300 to-indigo-400 bg-clip-text text-transparent">
              AI Code Reviewer
            </span>
          </h1>

          <p className="text-base text-zinc-400 leading-relaxed max-w-2xl">
            Protect modern applications from deep transitive CVEs, behavioral backdoors, and source code vulnerabilities.
            Combines multi-ecosystem lockfile ingestion with deterministic Reverse DAG reachability,
            cryptographic CycloneDX SBOM verification, and line-level AI code auto-patching.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2">
            <button
              onClick={onGetStarted}
              className="px-6 py-3 rounded-xl bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white font-semibold text-sm shadow-xl shadow-red-600/25 hover:shadow-red-600/40 transition-all flex items-center space-x-2 hover:scale-[1.02] active:scale-[0.98]"
            >
              <span>Get Started — Scan Project</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400 bg-zinc-900/60 border border-zinc-800 rounded-xl px-4 py-3">
              <span className="text-emerald-400 font-bold">100% Deterministic:</span>
              <span>NetworkX DAG • OSV.dev • AST Static Engine</span>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION A: HOW SUPPLYGRAPH WORKS (4-STEP VISUAL ARCHITECTURE PIPELINE) */}
      <div className="space-y-6">
        <div className="text-center sm:text-left space-y-1">
          <div className="text-xs font-mono uppercase tracking-wider text-red-400 font-semibold">
            Architectural Pipeline
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-100">
            How SupplyGraph Works
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400">
            From raw repository ingestion to surgical line-level remediation in four automated stages.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Step 1 */}
          <div className="p-5 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700/80 transition-all space-y-3 relative group">
            <div className="flex items-center justify-between">
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 font-mono font-bold text-xs">
                01
              </div>
              <span className="text-[10px] font-mono text-zinc-500">Ingestion</span>
            </div>
            <h3 className="text-sm font-semibold text-zinc-200 group-hover:text-blue-300 transition-colors">
              Dual Ingestion (GitHub or Folder)
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Ingests lockfiles (<code className="text-zinc-300">npm</code>, <code className="text-zinc-300">PyPI</code>, <code className="text-zinc-300">Poetry</code>), monorepo subdirectories, GitHub Actions workflows, and raw source code files.
            </p>
          </div>

          {/* Step 2 */}
          <div className="p-5 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700/80 transition-all space-y-3 relative group">
            <div className="flex items-center justify-between">
              <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 font-mono font-bold text-xs">
                02
              </div>
              <span className="text-[10px] font-mono text-zinc-500">Threat Engine</span>
            </div>
            <h3 className="text-sm font-semibold text-zinc-200 group-hover:text-red-300 transition-colors">
              5-Layer Threat & AST Detection
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Executes OSV.dev batch CVE intelligence, Levenshtein typosquatting, private scope confusion, CI/CD action pinning audits, and AST static analysis.
            </p>
          </div>

          {/* Step 3 */}
          <div className="p-5 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700/80 transition-all space-y-3 relative group">
            <div className="flex items-center justify-between">
              <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400 font-mono font-bold text-xs">
                03
              </div>
              <span className="text-[10px] font-mono text-zinc-500">Graph Theory</span>
            </div>
            <h3 className="text-sm font-semibold text-zinc-200 group-hover:text-purple-300 transition-colors">
              Reverse DAG & Blast Radius Math
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Traces multi-hop attack propagation to production assets using NetworkX and calculates blast radius (<span className="text-purple-300 font-mono">B = 2P + 15S + 25A + 50D</span>).
            </p>
          </div>

          {/* Step 4 */}
          <div className="p-5 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700/80 transition-all space-y-3 relative group">
            <div className="flex items-center justify-between">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-mono font-bold text-xs">
                04
              </div>
              <span className="text-[10px] font-mono text-zinc-500">Remediation</span>
            </div>
            <h3 className="text-sm font-semibold text-zinc-200 group-hover:text-emerald-300 transition-colors">
              Auto-Fixer & Surgical Code Reviewer
            </h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Generates copyable lockfile overrides, outputs line-level code diffs, and exports standardized CycloneDX SBOMs with deterministic SHA-256 integrity digests.
            </p>
          </div>
        </div>
      </div>

      {/* SECTION B: ALL PROJECT FEATURES GRID (6 FEATURE CARDS) */}
      <div className="space-y-6">
        <div className="text-center sm:text-left space-y-1">
          <div className="text-xs font-mono uppercase tracking-wider text-indigo-400 font-semibold">
            Capability Matrix
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-100">
            Enterprise ASPM Features
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400">
            Comprehensive security observability across dependencies, CI/CD pipelines, and application source code.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {/* Feature 1 */}
          <div className="p-6 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 transition-all space-y-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <GitBranch className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-zinc-100">Interactive Attack Graph Canvas</h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              React Flow canvas powered by topological and BFS layering. Highlights animated red attack paths and filters high-risk sub-DAGs for large repositories.
            </p>
          </div>

          {/* Feature 2 */}
          <div className="p-6 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 transition-all space-y-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-zinc-100">5-Layer Threat Detection Fabric</h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Covers OSV.dev CVEs, namespace typosquatting, internal dependency confusion, CI/CD workflow security leaks, and AST subprocess/credential checks.
            </p>
          </div>

          {/* Feature 3 */}
          <div className="p-6 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 transition-all space-y-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-zinc-100">AI Code Reviewer & Auto-Patcher</h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Scans Python, JS, TS, React, and YAML files. Pinpoints problematic line numbers and generates production-ready, copyable replacement code snippets.
            </p>
          </div>

          {/* Feature 4 */}
          <div className="p-6 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 transition-all space-y-3">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Boxes className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-zinc-100">CycloneDX v1.5 Cryptographic SBOM</h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Exports standardized JSON Software Bills of Materials with canonical PURLs, license classifications, and deterministic SHA-256 integrity digests.
            </p>
          </div>

          {/* Feature 5 */}
          <div className="p-6 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 transition-all space-y-3">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-zinc-100">CI/CD Pipeline & Runner Hardening</h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Audits GitHub Actions workflows to enforce immutable 40-character commit hashes, detects unpinned third-party actions, and enforces least-privilege runner permissions.
            </p>
          </div>

          {/* Feature 6 */}
          <div className="p-6 rounded-2xl bg-zinc-900/40 border border-zinc-800/80 hover:border-zinc-700 transition-all space-y-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-zinc-100">AWS Bedrock & Gemini Triage</h3>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Executive AI summarization powered by AWS Bedrock (Claude 3.5 Sonnet) and Gemini 1.5 Flash with one-click Markdown audit report export.
            </p>
          </div>
        </div>
      </div>

      {/* SECTION C: COMPETITOR COMPARISON MATRIX TABLE */}
      <div className="space-y-6">
        <div className="text-center sm:text-left space-y-1">
          <div className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold">
            Competitive Advantage
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-zinc-100">
            How SupplyGraph Differs From Other Tools
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400">
            Why flat CVE scanners and standard SAST tools miss multi-hop software supply-chain attacks.
          </p>
        </div>

        <div className="overflow-x-auto rounded-2xl border border-zinc-800 bg-zinc-900/40">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-950/80 text-zinc-400 font-mono">
                <th className="py-3.5 px-4 font-semibold">Capability / Metric</th>
                <th className="py-3.5 px-4 font-semibold text-red-400 bg-red-500/5">
                  SupplyGraph v3.0 (ASPM)
                </th>
                <th className="py-3.5 px-4 font-semibold">Standard Dependency Scanners (e.g. basic npm audit / PR alerts)</th>
                <th className="py-3.5 px-4 font-semibold">General SAST Tools (Source Code Analysis)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-sans">
              <tr>
                <td className="py-3.5 px-4 font-medium text-zinc-200">
                  Reverse DAG Transitive Reachability Graph
                </td>
                <td className="py-3.5 px-4 text-emerald-400 font-semibold bg-red-500/5">
                  ✅ Yes (Interactive React Flow)
                </td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Dependency tree list without visual blast radius paths</td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Code-level taint tracking without lockfile dependency DAG</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-medium text-zinc-200">
                  Local Project Folder + Monorepo Upload
                </td>
                <td className="py-3.5 px-4 text-emerald-400 font-semibold bg-red-500/5">
                  ✅ Yes (Zero-config folder upload: npm, poetry, pip, cargo, go)
                </td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ CLI command line only</td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Requires CI agent or project build configuration</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-medium text-zinc-200">
                  AI Code Reviewer with Corrected Code Diffs
                </td>
                <td className="py-3.5 px-4 text-emerald-400 font-semibold bg-red-500/5">
                  ✅ Yes (Exact line fix + copyable patch)
                </td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Automated version bump PRs without code rewrites</td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Explanations without unified dependency code patches</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-medium text-zinc-200">
                  5-Layer Threat Detection (OSV + Typosquat + AST + CI/CD + Confusion)
                </td>
                <td className="py-3.5 px-4 text-emerald-400 font-semibold bg-red-500/5">
                  ✅ Unified Hybrid Engine
                </td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Advisory database matching + known malware feeds</td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Static code analysis rules (separate from registry data)</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-medium text-zinc-200">
                  CycloneDX v1.5 Standard SBOM (Deterministic SHA-256)
                </td>
                <td className="py-3.5 px-4 text-emerald-400 font-semibold bg-red-500/5">
                  ✅ Cryptographic SHA-256 Digest (Staged Contract Anchoring)
                </td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Manifest export without linked posture checksum</td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Varies by enterprise tier configuration</td>
              </tr>
              <tr>
                <td className="py-3.5 px-4 font-medium text-zinc-200">
                  Mathematical Blast Radius & Confidence Formulas
                </td>
                <td className="py-3.5 px-4 text-emerald-400 font-semibold bg-red-500/5">
                  ✅ Quantified 0–100 Topological Scoring Formula
                </td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Standard CVSS v3.1 / EPSS severity scores</td>
                <td className="py-3.5 px-4 text-zinc-400">⚠️ Qualitative severity / CWE ratings</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* QUICK LAUNCH SCENARIO BAR (FOR JUDGES) */}
      <div className="p-6 rounded-2xl bg-zinc-950 border border-zinc-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <div className="text-xs font-mono text-zinc-400">YUKTHI 2026 Evaluator Fast-Track</div>
            <div className="text-sm font-semibold text-zinc-200">Simulate Real-World Attack Scenarios in 1 Click</div>
          </div>
          <button
            onClick={onGetStarted}
            className="text-xs font-mono text-red-400 hover:text-red-300 flex items-center space-x-1"
          >
            <span>Open Custom Scanner</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          <button
            onClick={() => { onSelectScenario?.("A"); onGetStarted(); }}
            className="p-3 rounded-xl bg-zinc-900/60 hover:bg-zinc-850 border border-zinc-800 hover:border-red-500/40 text-left transition-all group"
          >
            <div className="text-base mb-1">🔗</div>
            <div className="text-xs font-semibold text-zinc-200 group-hover:text-red-300">Scenario A</div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">Transitive CVE</div>
          </button>

          <button
            onClick={() => { onSelectScenario?.("B"); onGetStarted(); }}
            className="p-3 rounded-xl bg-zinc-900/60 hover:bg-zinc-850 border border-zinc-800 hover:border-orange-500/40 text-left transition-all group"
          >
            <div className="text-base mb-1">🎭</div>
            <div className="text-xs font-semibold text-zinc-200 group-hover:text-orange-300">Scenario B</div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">Dependency Confusion</div>
          </button>

          <button
            onClick={() => { onSelectScenario?.("C"); onGetStarted(); }}
            className="p-3 rounded-xl bg-zinc-900/60 hover:bg-zinc-850 border border-zinc-800 hover:border-rose-500/40 text-left transition-all group"
          >
            <div className="text-base mb-1">💀</div>
            <div className="text-xs font-semibold text-zinc-200 group-hover:text-rose-300">Scenario C</div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">Malicious Post-Install</div>
          </button>

          <button
            onClick={() => { onSelectScenario?.("D"); onGetStarted(); }}
            className="p-3 rounded-xl bg-zinc-900/60 hover:bg-zinc-850 border border-zinc-800 hover:border-amber-500/40 text-left transition-all group"
          >
            <div className="text-base mb-1">🕸️</div>
            <div className="text-xs font-semibold text-zinc-200 group-hover:text-amber-300">Scenario D</div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">Deep Chain (Depth 4)</div>
          </button>

          <button
            onClick={() => { onSelectScenario?.("E"); onGetStarted(); }}
            className="p-3 rounded-xl bg-zinc-900/60 hover:bg-zinc-850 border border-zinc-800 hover:border-yellow-500/40 text-left transition-all group"
          >
            <div className="text-base mb-1">⚙️</div>
            <div className="text-xs font-semibold text-zinc-200 group-hover:text-yellow-300">Scenario E</div>
            <div className="text-[10px] text-zinc-500 font-mono mt-0.5">CI/CD Workflow Leak</div>
          </button>
        </div>
      </div>
    </div>
  );
});

OverviewDashboard.displayName = "OverviewDashboard";
