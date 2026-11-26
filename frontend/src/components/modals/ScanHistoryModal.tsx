"use client";

import React from "react";
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Clock,
  GitCompare,
  Loader2,
  RotateCcw,
  Trash2,
} from "lucide-react";
import { AnalysisResponse, ScanHistoryRecord } from "@/types";
import { Modal } from "@/components/common/Modal";
import { cn } from "@/lib/utils";
import { ScenarioId } from "@/lib/executiveSummary";

interface ScanHistoryModalProps {
  open: boolean;
  onClose: () => void;
  data: AnalysisResponse | null;
  activeScenario: ScenarioId | null;
  scanHistory: ScanHistoryRecord[];
  selectedHistoryScan: ScanHistoryRecord | null;
  comparisonResult: any | null;
  comparingLoading: boolean;
  onResetSelected: () => void;
  onSelectHistoryScan: (record: ScanHistoryRecord) => void;
  onLoadHistoryScan: (record: ScanHistoryRecord) => void;
  onClearHistory: () => void;
}

export function ScanHistoryModal({
  open,
  onClose,
  data,
  activeScenario,
  scanHistory,
  selectedHistoryScan,
  comparisonResult,
  comparingLoading,
  onResetSelected,
  onSelectHistoryScan,
  onLoadHistoryScan,
  onClearHistory,
}: ScanHistoryModalProps) {
  const currentBlast = Number(data?.scan?.blast_radius_score) || 0;
  const currentComps =
    Number(data?.scan?.total_components) || Number(data?.components?.length) || 0;
  const currentFinds =
    Number(data?.scan?.total_findings) || Number(data?.findings?.length) || 0;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={
        <div className="flex items-center space-x-2 text-indigo-300">
          <Clock className="w-4 h-4 text-indigo-400" aria-hidden="true" />
          <span>Scan History & Delta Regression Engine</span>
        </div>
      }
    >
      <div className="space-y-4 font-mono text-xs">
        <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-800/40 flex items-center justify-between">
          <div>
            <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">
              Active Workspace
            </span>
            <span className="text-zinc-200 font-bold text-sm">
              {data?.scan?.repository_url?.replace("https://github.com/", "") ||
                (activeScenario ? `Demo Scenario ${activeScenario}` : "Active Project")}
            </span>
          </div>
          <div className="flex items-center space-x-4 text-right">
            <div>
              <span className="text-[10px] text-zinc-400 block">Blast Radius</span>
              <span className="text-amber-400 font-bold">{currentBlast.toFixed(1)}/100</span>
            </div>
            <div>
              <span className="text-[10px] text-zinc-400 block">Components</span>
              <span className="text-zinc-200 font-bold">{currentComps}</span>
            </div>
            <div>
              <span className="text-[10px] text-zinc-400 block">Findings</span>
              <span className="text-red-400 font-bold">{currentFinds}</span>
            </div>
          </div>
        </div>

        {selectedHistoryScan ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between bg-zinc-900/80 p-2.5 rounded-xl border border-zinc-800">
              <button
                type="button"
                onClick={onResetSelected}
                className="px-2.5 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[11px] flex items-center space-x-1 transition-colors"
              >
                <ArrowRight className="w-3 h-3 rotate-180" aria-hidden="true" />
                <span>Back to Scan List</span>
              </button>
              <div className="text-zinc-400 text-[11px]">
                Comparing against: <b className="text-zinc-200">{selectedHistoryScan.target}</b> (
                {selectedHistoryScan.timestamp})
              </div>
              <button
                type="button"
                onClick={() => onLoadHistoryScan(selectedHistoryScan)}
                className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[11px] font-semibold flex items-center space-x-1 transition-colors shadow-sm"
                title="Switch active workspace to this historical scan"
              >
                <RotateCcw className="w-3 h-3" aria-hidden="true" />
                <span>Load this Scan</span>
              </button>
            </div>

            {(() => {
              const oldBlast = Number(selectedHistoryScan?.blast_radius_score) || 0;
              const blastDelta = currentBlast - oldBlast;
              const oldComps = Number(selectedHistoryScan?.total_components) || 0;
              const compDelta = currentComps - oldComps;
              const oldFinds = Number(selectedHistoryScan?.total_findings) || 0;
              const findsDelta = currentFinds - oldFinds;

              return (
                <div className="grid grid-cols-3 gap-2.5">
                  <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800">
                    <div className="text-[10px] text-zinc-400 uppercase tracking-wider">
                      Blast Radius Δ
                    </div>
                    <div className="flex items-center space-x-1.5 mt-1">
                      {blastDelta < 0 ? (
                        <ArrowDownRight className="w-4 h-4 text-emerald-400" aria-hidden="true" />
                      ) : blastDelta > 0 ? (
                        <ArrowUpRight className="w-4 h-4 text-red-400" aria-hidden="true" />
                      ) : null}
                      <span
                        className={cn(
                          "text-base font-bold",
                          blastDelta < 0
                            ? "text-emerald-400"
                            : blastDelta > 0
                            ? "text-red-400"
                            : "text-zinc-300"
                        )}
                      >
                        {blastDelta > 0 ? `+${blastDelta.toFixed(1)}` : blastDelta.toFixed(1)}
                      </span>
                    </div>
                    <div className="text-[9px] text-zinc-400 mt-1">
                      {blastDelta < 0
                        ? "Risk reduced (Improvement)"
                        : blastDelta > 0
                        ? "Risk increased (Regression)"
                        : "Unchanged"}
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800">
                    <div className="text-[10px] text-zinc-400 uppercase tracking-wider">
                      Components Δ
                    </div>
                    <div className="flex items-center space-x-1.5 mt-1">
                      <span
                        className={cn(
                          "text-base font-bold",
                          compDelta > 0
                            ? "text-indigo-400"
                            : compDelta < 0
                            ? "text-amber-400"
                            : "text-zinc-300"
                        )}
                      >
                        {compDelta > 0 ? `+${compDelta}` : compDelta}
                      </span>
                    </div>
                    <div className="text-[9px] text-zinc-400 mt-1">
                      {compDelta > 0
                        ? `${compDelta} new dependencies`
                        : compDelta < 0
                        ? `${Math.abs(compDelta)} removed`
                        : "Same count"}
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-zinc-900 border border-zinc-800">
                    <div className="text-[10px] text-zinc-400 uppercase tracking-wider">
                      Threat Findings Δ
                    </div>
                    <div className="flex items-center space-x-1.5 mt-1">
                      <span
                        className={cn(
                          "text-base font-bold",
                          findsDelta < 0
                            ? "text-emerald-400"
                            : findsDelta > 0
                            ? "text-red-400"
                            : "text-zinc-300"
                        )}
                      >
                        {findsDelta > 0 ? `+${findsDelta}` : findsDelta}
                      </span>
                    </div>
                    <div className="text-[9px] text-zinc-400 mt-1">
                      {findsDelta < 0
                        ? "Fixes resolved threats"
                        : findsDelta > 0
                        ? "New security risks"
                        : "Zero change"}
                    </div>
                  </div>
                </div>
              );
            })()}

            <div className="rounded-xl border border-zinc-800 bg-black/60 p-3 space-y-2.5">
              <div className="text-[11px] font-semibold text-zinc-300 flex items-center justify-between">
                <span>Delta Manifest Changes</span>
                {comparingLoading && (
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" aria-hidden="true" />
                )}
              </div>

              {comparisonResult?.dependency_changes &&
              comparisonResult.dependency_changes.length > 0 ? (
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
                        <span className="text-zinc-400 text-[9px]">({dc.ecosystem})</span>
                      </div>
                      <div className="text-zinc-400 text-[9px]">
                        {dc.version_before && (
                          <span className="line-through mr-1 text-zinc-500">{dc.version_before}</span>
                        )}
                        {dc.version_after && (
                          <span className="text-emerald-400">{dc.version_after}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-zinc-400 text-[10px] py-2 text-center">
                  No structural package additions or removals detected between these two snapshots.
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-zinc-400 text-[11px]">
              <span>Saved Scan Snapshots ({scanHistory.length})</span>
              {scanHistory.length > 0 && (
                <button
                  type="button"
                  onClick={onClearHistory}
                  className="text-red-400 hover:text-red-300 flex items-center space-x-1 text-[10px] transition-colors"
                >
                  <Trash2 className="w-3 h-3" aria-hidden="true" />
                  <span>Clear History</span>
                </button>
              )}
            </div>

            {scanHistory.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl text-zinc-400 text-xs">
                <Clock className="w-6 h-6 mx-auto mb-2 opacity-40" aria-hidden="true" />
                <p>No previous scans recorded in this browser session yet.</p>
                <p className="text-[10px] text-zinc-500 mt-1">
                  Run a scan or load a scenario to start tracking deltas.
                </p>
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
                        <span className="text-[10px] text-zinc-400">{rec.timestamp}</span>
                      </div>
                      <div className="flex items-center space-x-3 text-[10px] text-zinc-400">
                        <span>
                          Blast:{" "}
                          <b className="text-amber-400">
                            {(Number(rec?.blast_radius_score) || 0).toFixed(1)}/100
                          </b>
                        </span>
                        <span>
                          Comps: <b className="text-zinc-300">{rec.total_components}</b>
                        </span>
                        <span>
                          Findings: <b className="text-red-400">{rec.total_findings}</b>
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        type="button"
                        onClick={() => onSelectHistoryScan(rec)}
                        className="px-2.5 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-[10px] font-semibold flex items-center space-x-1 transition-all shadow-sm"
                        title="Compare with active workspace"
                      >
                        <GitCompare className="w-3 h-3" aria-hidden="true" />
                        <span>Compare Delta</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => onLoadHistoryScan(rec)}
                        className="px-2.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] font-semibold flex items-center space-x-1 transition-all"
                        title="Restore and view this scan"
                      >
                        <RotateCcw className="w-3 h-3" aria-hidden="true" />
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
  );
}
