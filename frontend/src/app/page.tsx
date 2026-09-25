"use client";

import React, { useState } from "react";
import { fetchDemoAnalysis } from "@/lib/api";
import { AnalysisResponse } from "@/types";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { AlertCircle, ShieldAlert, PackageSearch, Loader2, Play, Sparkles } from "lucide-react";

export default function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scenario, setScenario] = useState("D");

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchDemoAnalysis(scenario);
      setData(result);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen w-full flex-col bg-white">
      {/* HEADER */}
      <header className="flex h-16 items-center justify-between border-b border-slate-200 px-6 bg-slate-50 shrink-0">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-600 rounded-lg">
            <PackageSearch className="text-white w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-900 leading-tight">SupplyGraph</h1>
            <p className="text-xs font-medium text-slate-500">HackFusion 2026 - Theme 6</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <select 
            value={scenario}
            onChange={(e) => setScenario(e.target.value)}
            className="h-9 px-3 py-1 bg-white border border-slate-300 rounded-md text-sm font-medium shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="A">Scenario A: Transitive Vulnerability</option>
            <option value="B">Scenario B: Typosquatting</option>
            <option value="C">Scenario C: Compromised Update</option>
            <option value="D">Scenario D: Multi-Level Propagation</option>
            <option value="E">Scenario E: CI/CD Risk</option>
          </select>
          <button
            onClick={handleAnalyze}
            disabled={loading}
            className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md font-semibold text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            <span>Run Analysis</span>
          </button>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <main className="flex-1 flex overflow-hidden">
        {error ? (
          <div className="m-auto flex flex-col items-center justify-center p-8 text-center max-w-md">
            <div className="w-16 h-16 bg-red-100 text-red-600 rounded-full flex items-center justify-center mb-4">
              <AlertCircle size={32} />
            </div>
            <h2 className="text-xl font-bold text-slate-900 mb-2">Analysis Failed</h2>
            <p className="text-slate-600">{error}</p>
          </div>
        ) : !data && !loading ? (
          <div className="m-auto flex flex-col items-center justify-center p-8 text-center max-w-md">
            <div className="w-16 h-16 bg-slate-100 text-slate-400 rounded-full flex items-center justify-center mb-4">
              <ShieldAlert size={32} />
            </div>
            <h2 className="text-xl font-bold text-slate-900 mb-2">No Analysis Loaded</h2>
            <p className="text-slate-500 text-sm">Select a demo scenario and click Run Analysis to view the supply-chain security graph.</p>
          </div>
        ) : loading ? (
          <div className="m-auto flex flex-col items-center justify-center">
            <Loader2 className="w-12 h-12 text-indigo-600 animate-spin mb-4" />
            <p className="text-slate-600 font-medium">Running security analysis pipeline...</p>
          </div>
        ) : (
          <div className="flex-1 flex h-full overflow-hidden">
            
            {/* LEFT: GRAPH CANVAS AREA */}
            <div className="flex-1 flex flex-col h-full p-6 pr-3">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-slate-900">{data?.scan?.repository_url || "Unknown Repository"}</h2>
                  <div className="flex space-x-4 text-sm text-slate-500 mt-1">
                    <span>{data?.scan?.total_components || 0} Components</span>
                    <span>{data?.scan?.total_findings || 0} Findings</span>
                    <span className="text-red-600 font-medium">Blast Radius: {data?.scan?.blast_radius_score || 0}</span>
                  </div>
                </div>
                {data?.is_demo && (
                  <span className="px-3 py-1 bg-amber-100 text-amber-800 text-xs font-bold rounded-full uppercase tracking-wide">
                    Demo Mode
                  </span>
                )}
              </div>
              
              <div className="flex-1 w-full min-h-0 relative shadow-sm">
                {data && data.graph && (
                  <GraphCanvas graph={data.graph} />
                )}
              </div>
            </div>

            {/* RIGHT: SIDE PANEL */}
            <div className="w-[450px] flex flex-col border-l border-slate-200 bg-white h-full overflow-y-auto p-6">
              
              {/* GEMINI AI EXPLANATION */}
              <div className="mb-8">
                <div className="flex items-center space-x-2 mb-3">
                  <Sparkles className="w-5 h-5 text-purple-600" />
                  <h3 className="text-lg font-bold text-slate-900">AI Explanation</h3>
                </div>
                <div className="bg-purple-50 rounded-xl p-4 border border-purple-100 text-sm text-purple-900 leading-relaxed shadow-sm">
                  {data?.gemini_explanation ? (
                    <div dangerouslySetInnerHTML={{ __html: data.gemini_explanation.replace(/\n/g, '<br />') }} />
                  ) : (
                    <span className="text-slate-500 italic">No AI explanation provided by the backend for this scan.</span>
                  )}
                </div>
              </div>

              {/* FINDINGS LIST */}
              <div>
                <h3 className="text-lg font-bold text-slate-900 mb-3 border-b border-slate-100 pb-2">Identified Findings</h3>
                {data?.findings && data.findings.length > 0 ? (
                  <div className="space-y-4">
                    {data.findings.map((finding: any) => (
                      <div key={finding.id} className="border border-red-200 bg-red-50/30 rounded-lg p-4">
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-bold text-slate-900 text-sm">{finding.title}</h4>
                          <span className="text-[10px] font-bold px-2 py-1 bg-red-100 text-red-700 rounded-full uppercase">
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-600 mb-3 leading-relaxed">{finding.description}</p>
                        
                        {/* RECOMMENDATIONS */}
                        {finding.recommendations && finding.recommendations.length > 0 && (
                          <div className="mt-4">
                            <h5 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2">Containment</h5>
                            <div className="space-y-2">
                              {finding.recommendations.map((rec: any, idx: number) => (
                                <div key={idx} className="bg-white border border-slate-200 rounded p-2 text-xs shadow-sm">
                                  <span className="font-bold text-indigo-700 mr-2">{rec.action_type}:</span>
                                  <span className="text-slate-700">{rec.title}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500 italic">No security findings detected.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
