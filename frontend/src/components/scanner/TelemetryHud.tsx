"use client";

import React, { useState } from "react";
import { Clock, Info, ListFilter, Maximize2, Minimize2 } from "lucide-react";
import { AnalysisResponse, SecurityGraph } from "@/types";
import { cn } from "@/lib/utils";
import { ScenarioId } from "@/lib/executiveSummary";

interface TelemetryHudProps {
  data: AnalysisResponse;
  activeScenario: ScenarioId | null;
  currentGraph: SecurityGraph | null;
  activeFindingsCount: number;
  scanHistoryCount: number;
  prodOnly: boolean;
  transitiveDepth: number;
  maxGraphDepth: number;
  hudCollapsed: boolean;
  onToggleCollapse: (collapsed: boolean) => void;
  onOpenHistory: () => void;
}

export function TelemetryHud({
  data,
  activeScenario,
  currentGraph,
  activeFindingsCount,
  scanHistoryCount,
  prodOnly,
  transitiveDepth,
  maxGraphDepth,
  hudCollapsed,
  onToggleCollapse,
  onOpenHistory,
}: TelemetryHudProps) {
  const [showFormulaTooltip, setShowFormulaTooltip] = useState(false);

  const repoDisplay =
    data?.scan?.repository_url?.replace("https://github.com/", "") ||
    (activeScenario ? `Demo Scenario ${activeScenario}` : "Project");
  const blastScore = Number(data?.scan?.blast_radius_score) || 0;
  const componentCount = currentGraph
    ? currentGraph.nodes.filter((n) => (n.data?.node_type || "").toLowerCase() !== "repository").length
    : data?.scan?.total_components || 0;

  if (hudCollapsed) {
    return (
      <div className="bg-zinc-950/90 backdrop-blur-xl border border-zinc-800 rounded-xl px-3 py-1.5 shadow-2xl flex items-center space-x-3 text-xs font-mono">
        <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" aria-hidden="true" />
        <span className="text-zinc-200 font-semibold truncate max-w-[140px]">
          {data?.scan?.repository_url?.replace("https://github.com/", "") ||
            (activeScenario ? `Demo ${activeScenario}` : "Scan")}
        </span>
        <span className="text-zinc-600" aria-hidden="true">|</span>
        <span className="text-zinc-400">
          Comps: <b className="text-zinc-200">{data?.scan?.total_components || 0}</b>
        </span>
        <span className="text-zinc-400">
          Findings: <b className="text-red-400">{data?.scan?.total_findings || 0}</b>
        </span>
        <span className="text-zinc-400">
          Blast: <b className="text-amber-400">{blastScore.toFixed(1)}/100</b>
        </span>
        <button
          type="button"
          onClick={onOpenHistory}
          className="px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 text-indigo-300 text-[10px] flex items-center space-x-1 border border-zinc-700/60"
          title="View Scan History & Delta Regression"
        >
          <Clock className="w-3 h-3 text-indigo-400" aria-hidden="true" />
          <span>Delta ({scanHistoryCount})</span>
        </button>
        <button
          type="button"
          onClick={() => onToggleCollapse(false)}
          aria-label="Expand Telemetry HUD"
          className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-white rounded-lg transition-colors ml-1"
          title="Expand Telemetry HUD"
        >
          <Maximize2 className="w-3.5 h-3.5" aria-hidden="true" />
        </button>
      </div>
    );
  }

  return (
    <div className="bg-zinc-950/85 backdrop-blur-xl border border-zinc-800/90 rounded-xl px-4 py-3 shadow-2xl min-w-[220px]">
      <div className="flex items-center justify-between space-x-2 mb-2.5">
        <div className="flex items-center space-x-2 min-w-0">
          <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse shrink-0" aria-hidden="true" />
          <span className="text-[11px] font-mono font-semibold text-zinc-100 truncate max-w-[150px]">
            {repoDisplay}
          </span>
        </div>
        <button
          type="button"
          onClick={() => onToggleCollapse(true)}
          aria-label="Minimize Telemetry HUD"
          className="p-1 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 rounded-md transition-colors"
          title="Minimize HUD to see graph nodes behind it"
        >
          <Minimize2 className="w-3.5 h-3.5" aria-hidden="true" />
        </button>
      </div>

      <div className="flex items-center space-x-4 text-[11px] font-mono pt-2 border-t border-zinc-800/60">
        <div>
          <span className="text-zinc-400 block text-[9px] uppercase tracking-wider">Components</span>
          <span className="text-zinc-200 font-semibold">{componentCount}</span>
        </div>
        <div>
          <span className="text-zinc-400 block text-[9px] uppercase tracking-wider">Findings</span>
          <span className="text-red-400 font-semibold">{activeFindingsCount}</span>
        </div>
        <div className="relative">
          <span className="text-zinc-400 text-[9px] uppercase tracking-wider flex items-center space-x-1">
            <span>Blast Radius</span>
            <button
              type="button"
              onClick={() => setShowFormulaTooltip((prev) => !prev)}
              onMouseEnter={() => setShowFormulaTooltip(true)}
              onMouseLeave={() => setShowFormulaTooltip(false)}
              onFocus={() => setShowFormulaTooltip(true)}
              onBlur={() => setShowFormulaTooltip(false)}
              aria-label="Explain Blast Radius and Confidence formulas"
              aria-expanded={showFormulaTooltip}
              className="text-zinc-400 hover:text-zinc-200 focus:outline-none focus:ring-1 focus:ring-indigo-400 rounded"
            >
              <Info className="w-2.5 h-2.5" aria-hidden="true" />
            </button>
          </span>
          <span
            className={cn(
              "font-semibold",
              blastScore > 70 ? "text-red-400" : blastScore > 0 ? "text-amber-400" : "text-emerald-400"
            )}
          >
            {blastScore.toFixed(1)}/100
          </span>

          {showFormulaTooltip && (
            <div
              role="tooltip"
              className="absolute left-0 bottom-8 z-30 w-64 bg-zinc-900 border border-zinc-700 rounded-lg p-3 shadow-2xl text-[10px] font-mono"
            >
              <div className="text-zinc-300 font-semibold mb-1.5">Scoring Formulas</div>
              <div className="text-zinc-400 space-y-1">
                <div>
                  <span className="text-amber-400">Blast Radius:</span>
                </div>
                <div className="text-zinc-300 pl-2">B = 2P + 15S + 25A + 50D</div>
                <div className="text-zinc-400 pl-2 text-[9px]">
                  P=Packages, S=Services, A=APIs, D=Deployments
                </div>
                <div className="pt-1">
                  <span className="text-indigo-400">Heuristic Confidence:</span>
                </div>
                <div className="text-zinc-300 pl-2">C = 1 - ∏(1 - w_i × r_i)</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {data?.detector_breakdown && (
        <div className="mt-2.5 pt-2 border-t border-zinc-800/60 flex flex-wrap gap-1 text-[9px] font-mono">
          <span className="text-zinc-400">Detectors:</span>
          <span className="text-indigo-300">OSV: {data.detector_breakdown.osv_count || 0}</span>
          <span className="text-zinc-600" aria-hidden="true">•</span>
          <span className="text-rose-300">Typosquat: {data.detector_breakdown.typosquat_count || 0}</span>
          <span className="text-zinc-600" aria-hidden="true">•</span>
          <span className="text-cyan-300">
            AST:{" "}
            {data.detector_breakdown.ast_count ||
              data?.code_reviews?.filter(
                (r) => !r.file_path.endsWith(".yml") && !r.file_path.endsWith(".yaml") && !r.title.includes("CI/CD")
              ).length ||
              0}
          </span>
          <span className="text-zinc-600" aria-hidden="true">•</span>
          <span className="text-yellow-300">
            CI/CD:{" "}
            {data.detector_breakdown.cicd_count ||
              data?.code_reviews?.filter(
                (r) => r.file_path.endsWith(".yml") || r.file_path.endsWith(".yaml") || r.title.includes("CI/CD")
              ).length ||
              0}
          </span>
          {(data.detector_breakdown.historic_attack_count || 0) > 0 && (
            <>
              <span className="text-zinc-600" aria-hidden="true">•</span>
              <span className="text-rose-400 font-bold bg-rose-950/70 px-1 py-0.5 rounded border border-rose-600/50">
                Historic Attacks: {data.detector_breakdown.historic_attack_count}
              </span>
            </>
          )}
        </div>
      )}

      {(prodOnly || transitiveDepth < maxGraphDepth) && (
        <div className="mt-2 pt-1.5 border-t border-zinc-800/60 flex items-center justify-between text-[9px] font-mono">
          <span className="text-zinc-400 flex items-center space-x-1">
            <ListFilter className="w-3 h-3 text-amber-400" aria-hidden="true" />
            <span>Active Filter:</span>
          </span>
          <span className="text-amber-300 font-semibold">
            {prodOnly && "Prod Only"}
            {prodOnly && transitiveDepth < maxGraphDepth && " • "}
            {transitiveDepth < maxGraphDepth && `Depth ≤ ${transitiveDepth}`}
          </span>
        </div>
      )}

      <button
        type="button"
        onClick={onOpenHistory}
        className="mt-2.5 w-full py-1.5 px-2.5 rounded-lg bg-zinc-900/90 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 text-[10px] font-mono text-zinc-300 flex items-center justify-between transition-colors shadow-sm"
        title="View Scan History & Delta Regression"
      >
        <span className="flex items-center space-x-1.5">
          <Clock className="w-3 h-3 text-indigo-400" aria-hidden="true" />
          <span>Scan History & Delta</span>
        </span>
        <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-indigo-300 text-[9px] font-semibold border border-zinc-700/50">
          {scanHistoryCount}
        </span>
      </button>
    </div>
  );
}
