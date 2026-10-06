"use client";

import React, { useState, useEffect, useRef } from "react";
import { fetchRepositoryAnalysis } from "@/lib/api";
import { AnalysisResponse } from "@/types";
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
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function Dashboard() {
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "briefing">("findings");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
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

  const executeAnalysis = async (urlToScan: string) => {
    const trimmed = urlToScan.trim();
    if (!trimmed) return;
    
    if (!/^https:\/\/github\.com\/[^\/]+\/[^\/]+/.test(trimmed)) {
      setError("Please enter a valid GitHub repository URL (e.g., https://github.com/org/repo)");
      return;
    }

    setLoading(true);
    setError(null);
    setData(null);
    try {
      const result = await fetchRepositoryAnalysis(trimmed);
      setData(result);
    } catch (err: any) {
      setError(err.message || "Failed to establish secure handshake with analysis engine.");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1800);
  };

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
            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono uppercase tracking-wider bg-red-950/40 border border-red-500/30 text-red-300">
              ASPM
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
        
        {/* ENGINE TELEMETRY */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-zinc-900/90 border border-zinc-800 text-[11px] font-mono shadow-inner">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-zinc-400 text-[10px]">ANALYSIS DAEMON READY</span>
          </div>
        </div>
      </header>

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
            
            /* ADVANCED ASPM HERO CENTERPIECE */
            <div className="m-auto flex flex-col items-center justify-center text-center p-8 max-w-2xl">
              
              {/* 3D FLOATING HOLOGRAPHIC SHIELD CORE */}
              <div className="relative group cursor-pointer mb-7">
                <div className="absolute -inset-5 rounded-full border border-red-500/20 animate-[spin_14s_linear_infinite] [border-dasharray:4_4] pointer-events-none" />
                <div className="absolute -inset-9 rounded-full border border-indigo-500/15 animate-[spin_22s_linear_infinite_reverse] pointer-events-none" />
                <div className="absolute -inset-1 bg-gradient-to-r from-red-600 via-rose-500 to-amber-500 rounded-3xl blur-2xl opacity-40 group-hover:opacity-70 transition duration-500" />
                
                <div className="relative w-24 h-24 rounded-3xl bg-gradient-to-b from-zinc-900 via-zinc-950 to-black border border-zinc-700/80 shadow-[0_25px_60px_rgba(0,0,0,0.9),inset_0_1px_0_rgba(255,255,255,0.15)] flex items-center justify-center transform group-hover:scale-105 group-hover:-translate-y-1 transition-all duration-300">
                  <Shield className="w-11 h-11 text-red-400 drop-shadow-[0_0_14px_rgba(239,68,68,0.6)]" />
                </div>
              </div>

              {/* PILL BADGE */}
              <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-red-950/40 border border-red-500/30 text-red-300 text-[10px] font-mono uppercase tracking-widest mb-3.5 shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping"></span>
                <span>Next-Gen Reachability & ASPM Intelligence</span>
              </div>

              {/* PROMINENT TITLE */}
              <h2 className="text-2xl font-bold tracking-tight text-zinc-100 sm:text-3xl mb-3">
                Contextual Attack Path Analysis
              </h2>

              {/* HIGH-VALUE VALUE PROPOSITION */}
              <p className="text-xs text-zinc-400 leading-relaxed font-mono max-w-lg mb-6">
                Standard scanners generate static vulnerability lists. SupplyGraph traverses transitive dependency trees to calculate upward runtime reachability, real blast radius, and surgical patch containment.
              </p>

              {/* ACTION PROMPT */}
              <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-zinc-900/60 border border-zinc-800 text-[11px] font-mono text-zinc-400">
                <span className="text-zinc-600">INPUT TARGET:</span>
                <span className="text-zinc-200">Paste any public repository URL in the search dock above</span>
              </div>
            </div>

          ) : loading ? (
            
            /* SCANNING TELEMETRY ANIMATION */
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
                <div className="absolute top-5 left-5 z-20 flex items-center space-x-3">
                  <div className="bg-zinc-950/85 backdrop-blur-xl border border-zinc-800/90 rounded-xl px-4 py-3 shadow-2xl">
                    <div className="flex items-center space-x-2.5">
                      <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
                      <span className="text-xs font-mono font-semibold text-zinc-100">
                        {data?.scan?.repository_url?.replace("https://github.com/", "")}
                      </span>
                    </div>

                    <div className="flex items-center space-x-5 text-[11px] font-mono mt-2.5 pt-2 border-t border-zinc-800/60">
                      <div>
                        <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Components</span>
                        <span className="text-zinc-200 font-semibold">{data?.scan?.total_components || 0}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Findings</span>
                        <span className="text-red-400 font-semibold">{data?.scan?.total_findings || 0}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block text-[9px] uppercase tracking-wider">Blast Radius</span>
                        <span className={cn(
                          "font-semibold",
                          (data?.scan?.blast_radius_score || 0) > 70 ? "text-red-400" :
                          (data?.scan?.blast_radius_score || 0) > 0 ? "text-amber-400" : "text-emerald-400"
                        )}>
                          {data?.scan?.blast_radius_score || 0}/100
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* GRAPH CANVAS */}
                <div className="flex-1 w-full h-full">
                  {data && data.graph && <GraphCanvas graph={data.graph} />}
                </div>
              </div>

              {/* INSPECTOR & AUDIT DRAWER */}
              <div className="w-[440px] flex flex-col border-l border-zinc-800/80 bg-zinc-950/80 backdrop-blur-2xl h-full shadow-2xl shrink-0 z-30">
                
                {/* DRAWER TAB HEADER */}
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
                    onClick={() => {
                      let report = `SUPPLYGRAPH SECURITY AUDIT\nTarget: ${data?.scan?.repository_url}\nBlast Radius: ${data?.scan?.blast_radius_score}\n\n`;
                      report += `EXECUTIVE SUMMARY:\n${data?.gemini_explanation}\n\nFINDINGS:\n`;
                      data?.findings?.forEach((f, i) => {
                        report += `\n[${i+1}] ${f.title} (${f.severity})\n${f.description}\n`;
                      });
                      const blob = new Blob([report], { type: "text/plain" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `supplygraph-${data?.scan?.repository_url?.split("/").pop()}.txt`;
                      a.click();
                    }}
                    className="p-1.5 text-zinc-400 hover:text-zinc-200 rounded-md hover:bg-zinc-800/60 transition-colors mb-2"
                    title="Export Audit Report"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* TAB CONTENT */}
                <div className="flex-1 overflow-y-auto p-5 space-y-4">
                  {activeTab === "findings" && (
                    <div className="space-y-3.5">
                      {data?.findings && data.findings.length > 0 ? (
                        data.findings.map((f: any, idx: number) => (
                          <div key={idx} className="p-3.5 rounded-xl border border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 transition-all group">
                            <div className="flex items-start justify-between mb-2">
                              <h4 className="text-xs font-semibold text-zinc-200 pr-4 leading-snug group-hover:text-red-300 transition-colors">
                                {f.title}
                              </h4>
                              <span className={cn(
                                "px-1.5 py-0.2 rounded text-[8px] font-mono font-bold uppercase tracking-wider shrink-0 border",
                                f.severity === "CRITICAL" ? "bg-red-500/10 text-red-400 border-red-500/20" :
                                f.severity === "HIGH" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                                "bg-amber-500/10 text-amber-400 border-amber-500/20"
                              )}>
                                {f.severity}
                              </span>
                            </div>

                            <p className="text-[11px] text-zinc-400 leading-relaxed mb-3">
                              {f.description}
                            </p>

                            {f.recommendations && f.recommendations.length > 0 && (
                              <div className="mt-2.5 pt-2.5 border-t border-zinc-800/60">
                                <div className="flex items-center justify-between text-[10px] text-zinc-500 font-mono uppercase mb-1.5">
                                  <span>Containment Strategy</span>
                                  <button
                                    onClick={() => copyToClipboard(`"overrides": { "${f.title.split('@')[0]}": "latest" }`, idx)}
                                    className="flex items-center space-x-1 hover:text-zinc-300 transition-colors"
                                  >
                                    {copiedIndex === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                    <span>{copiedIndex === idx ? "Copied" : "Copy Lock"}</span>
                                  </button>
                                </div>
                                <div className="p-2 rounded bg-black/60 border border-zinc-800/70 font-mono text-[10px] text-zinc-300">
                                  <div className="text-emerald-400 font-semibold">{f.recommendations[0]?.title}</div>
                                  <div className="text-zinc-400 text-[9px] mt-0.5">{f.recommendations[0]?.why}</div>
                                </div>
                              </div>
                            )}
                          </div>
                        ))
                      ) : (
                        <div className="p-8 text-center border border-dashed border-zinc-800 rounded-xl">
                          <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                          <div className="text-xs font-semibold text-zinc-200">Zero Attack Paths Found</div>
                          <div className="text-[11px] text-zinc-500 mt-1">All nested transitive dependencies resolve cleanly.</div>
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab === "briefing" && (
                    <div className="space-y-4">
                      <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/20 text-xs text-zinc-300 leading-relaxed">
                        <div className="flex items-center space-x-2 text-indigo-400 font-medium mb-3">
                          <Sparkles className="w-4 h-4" />
                          <span className="uppercase text-[10px] font-mono tracking-wider">Automated Triaging</span>
                        </div>
                        <div dangerouslySetInnerHTML={{ __html: data?.gemini_explanation?.replace(/\n/g, '<br />') || "No summary available." }} />
                      </div>
                    </div>
                  )}

                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}