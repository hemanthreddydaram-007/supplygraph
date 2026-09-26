"use client";

import React, { useState } from "react";
import { fetchDemoAnalysis, fetchRepositoryAnalysis } from "@/lib/api";
import { AnalysisResponse } from "@/types";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { 
  PackageSearch, Play, AlertCircle, ShieldAlert, 
  Loader2, Sparkles, Activity, ShieldCheck, Cpu, Database, Download
} from "lucide-react";
import { cn } from "@/lib/utils";

const SCENARIOS = [
  { id: "A", name: "Scenario A", desc: "Transitive Dependency Compromise" },
  { id: "B", name: "Scenario B", desc: "Typosquatting" },
  { id: "C", name: "Scenario C", desc: "Suspicious Package Update" },
  { id: "D", name: "Scenario D", desc: "Supply-Chain Attack Path" },
  { id: "E", name: "Scenario E", desc: "Build / CI-CD Compromise" },
];

export default function Dashboard() {
  const [scenario, setScenario] = useState("A");
  const [githubUrl, setGithubUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyzeDemo = async () => {
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const result = await fetchDemoAnalysis(scenario);
      setData(result);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeRepo = async () => {
    const trimmedUrl = githubUrl.trim();
    if (!trimmedUrl) return;
    
    if (!/^https:\/\/github\.com\/[^\/]+\/[^\/]+/.test(trimmedUrl)) {
      setError("Please enter a valid GitHub repository URL (e.g., https://github.com/user/repo)");
      return;
    }

    setLoading(true);
    setError(null);
    setData(null);
    try {
      const result = await fetchRepositoryAnalysis(trimmedUrl);
      setData(result);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen w-full flex-col bg-background text-foreground selection:bg-primary/20 font-sans">
      
      {/* HEADER */}
      <header className="flex h-14 items-center justify-between border-b border-border px-6 bg-card shrink-0">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className="flex items-center justify-center w-6 h-6 rounded bg-primary text-primary-foreground">
              <PackageSearch className="w-3.5 h-3.5" />
            </div>
            <h1 className="text-sm font-semibold tracking-tight">SupplyGraph</h1>
          </div>
          <div className="h-4 w-px bg-border"></div>
          <span className="text-xs text-muted-foreground font-medium">Software Supply-Chain Security</span>
        </div>
        
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 mr-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
            <span className="text-xs text-muted-foreground font-medium tracking-wide uppercase">Connected</span>
          </div>
        </div>
      </header>

      {/* MAIN LAYOUT */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* LEFT SIDEBAR: SCENARIO SELECTOR */}
        <aside className="w-64 border-r border-border bg-card/50 flex flex-col shrink-0 overflow-y-auto">
          <div className="p-4 border-b border-border">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-4">Scenarios</h2>
            <div className="space-y-1">
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setScenario(s.id)}
                  className={cn(
                    "w-full text-left px-3 py-2 rounded-md text-sm transition-all duration-200 border",
                    scenario === s.id 
                      ? "bg-primary/10 border-primary/20 text-foreground" 
                      : "bg-transparent border-transparent text-muted-foreground hover:bg-white/5 hover:text-foreground"
                  )}
                >
                  <div className="font-medium">{s.name}</div>
                  <div className={cn(
                    "text-[10px] mt-0.5",
                    scenario === s.id ? "text-primary/80" : "text-muted-foreground/70"
                  )}>
                    {s.desc}
                  </div>
                </button>
              ))}
            </div>
          </div>
          <div className="p-4 border-b border-border">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-4 flex items-center"><PackageSearch className="w-3.5 h-3.5 mr-2" /> Analyze Repository</h2>
            <div className="space-y-3">
              <input 
                type="text" 
                placeholder="https://github.com/user/repo" 
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                className="w-full bg-background border border-border text-xs px-3 py-2 rounded-md focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground/50"
              />
              <button
                onClick={handleAnalyzeRepo}
                disabled={loading || !githubUrl.trim()}
                className="w-full flex items-center justify-center space-x-2 bg-secondary text-secondary-foreground hover:bg-secondary/80 border border-border px-4 py-2 rounded-md font-medium text-xs transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading && githubUrl ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-current" />}
                <span>{loading && githubUrl ? "Analyzing..." : "Analyze Repository"}</span>
              </button>
            </div>
          </div>

          <div className="p-4 mt-auto">
            <button
              onClick={handleAnalyzeDemo}
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 bg-foreground text-background hover:bg-foreground/90 px-4 py-2 rounded-md font-medium text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(255,255,255,0.1)]"
            >
              {loading && !githubUrl ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
              <span>{loading && !githubUrl ? "Analyzing..." : "Run Demo"}</span>
            </button>
          </div>
        </aside>

        {/* CENTER + RIGHT PANEL AREA */}
        <main className="flex-1 flex overflow-hidden relative bg-[#0a0a0a]">
          
          {error ? (
            <div className="m-auto flex flex-col items-center justify-center p-8 max-w-md border border-destructive/20 bg-destructive/5 rounded-lg">
              <AlertCircle className="w-8 h-8 text-destructive mb-3" />
              <h2 className="text-sm font-semibold text-foreground mb-1">Analysis failed</h2>
              <p className="text-xs text-muted-foreground text-center mb-4">{error}</p>
              <button onClick={githubUrl ? handleAnalyzeRepo : handleAnalyzeDemo} className="text-xs font-medium bg-background border border-border px-3 py-1.5 rounded-md hover:bg-accent transition-colors">
                Retry
              </button>
            </div>
          ) : !data && !loading ? (
            <div className="m-auto flex flex-col items-center justify-center p-8 max-w-md text-center">
              <div className="w-12 h-12 bg-white/5 border border-border rounded-xl flex items-center justify-center mb-4 shadow-xl">
                <ShieldAlert className="w-5 h-5 text-muted-foreground" />
              </div>
              <h2 className="text-sm font-medium text-foreground mb-2">No Analysis Loaded</h2>
              <p className="text-xs text-muted-foreground leading-relaxed">Select a scenario from the sidebar and run an analysis to visualize the software supply-chain attack surface.</p>
            </div>
          ) : loading ? (
            <div className="m-auto flex flex-col items-center justify-center">
              <Loader2 className="w-8 h-8 text-muted-foreground animate-spin mb-4" />
              <p className="text-xs text-muted-foreground font-medium tracking-widest uppercase">Analyzing supply chain...</p>
            </div>
          ) : (
            <>
              {/* GRAPH CANVAS AREA */}
              <div className="flex-1 flex flex-col h-full relative">
                
                {/* GRAPH HEADER OVERLAY */}
                <div className="absolute top-4 left-4 z-10 bg-card/80 backdrop-blur-md border border-border rounded-lg px-4 py-3 shadow-2xl">
                  <h2 className="text-sm font-semibold text-foreground flex items-center space-x-2">
                    <Database className="w-4 h-4 text-muted-foreground" />
                    <span>{data?.scan?.repository_url || "Unknown Repository"}</span>
                  </h2>
                  <div className="flex items-center space-x-4 text-[11px] font-medium text-muted-foreground mt-2">
                    <span className="flex items-center"><Cpu className="w-3 h-3 mr-1" /> {data?.scan?.total_components || 0} Components</span>
                    <span className="flex items-center text-destructive"><AlertCircle className="w-3 h-3 mr-1" /> {data?.scan?.total_findings || 0} Findings</span>
                    <span className="flex items-center text-orange-500"><Activity className="w-3 h-3 mr-1" /> Blast Radius: {data?.scan?.blast_radius_score || 0}</span>
                  </div>
                </div>

                <div className="flex-1 w-full h-full">
                  {data && data.graph && (
                    <GraphCanvas graph={data.graph} />
                  )}
                </div>
              </div>

              {/* RIGHT SIDEBAR: ANALYSIS PANEL */}
              <div className="w-[400px] flex flex-col border-l border-border bg-card/80 backdrop-blur-xl h-full overflow-y-auto shadow-2xl shrink-0 z-20">
                
                <div className="p-5 border-b border-border">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Analysis Overview</h3>
                </div>
                
                <div className="p-5 space-y-6">
                  
                  {/* AI EXPLANATION */}
                  {data?.gemini_explanation && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Sparkles className="w-3.5 h-3.5 text-primary" />
                          <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider">AI Explanation</h4>
                        </div>
                        <button 
                          onClick={() => {
                            let downloadText = `--- SUPPLYGRAPH ANALYSIS REPORT ---

`;
                            downloadText += `AI EXPLANATION:
${data.gemini_explanation || 'No explanation generated.'}

`;
                            downloadText += `--- DETERMINISTIC FINDINGS (${data.findings?.length || 0}) ---

`;
                            
                            if (data.findings && data.findings.length > 0) {
                              data.findings.forEach((f: any, idx: number) => {
                                downloadText += `[FINDING ${idx + 1}] ${f.title}
`;
                                downloadText += `Severity: ${f.severity}
`;
                                downloadText += `Description: ${f.description}
`;
                                
                                if (f.evidence && f.evidence.length > 0) {
                                  downloadText += `
Evidence:
`;
                                  f.evidence.forEach((ev: any) => {
                                    downloadText += `  - [${ev.classification}] (${ev.source}) ${ev.description}
`;
                                  });
                                }
                                
                                if (f.recommendations && f.recommendations.length > 0) {
                                  downloadText += `
Containment:
`;
                                  f.recommendations.forEach((rec: any) => {
                                    downloadText += `  - [${rec.action_type}] ${rec.title}: ${rec.description}
`;
                                  });
                                }
                                downloadText += `
----------------------------------------

`;
                              });
                            } else {
                              downloadText += `No security findings detected.
`;
                            }

                            const blob = new Blob([downloadText], { type: 'text/plain' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = 'supplygraph-analysis-report.txt';
                            a.click();
                            URL.revokeObjectURL(url);
                          }}
                          className="flex items-center space-x-1 text-xs text-muted-foreground hover:text-primary transition-colors cursor-pointer bg-transparent border-none p-0"
                          title="Download Explanation"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Download</span>
                        </button>
                      </div>
                      <div className="bg-primary/5 border border-primary/10 rounded-lg p-3 text-xs text-foreground/90 leading-relaxed shadow-inner">
                        <div dangerouslySetInnerHTML={{ __html: data.gemini_explanation.replace(/\n/g, '<br />') }} />
                      </div>
                    </div>
                  )}

                  {/* DETERMINISTIC FINDINGS */}
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-destructive" />
                      <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider">Deterministic Findings</h4>
                    </div>
                    
                    {data?.findings && data.findings.length > 0 ? (
                      <div className="space-y-3">
                        {data.findings.map((finding: any) => (
                          <div key={finding.id} className="border border-destructive/20 bg-destructive/5 rounded-lg p-3 relative overflow-hidden group">
                            
                            <div className="flex justify-between items-start mb-2">
                              <h5 className="font-semibold text-foreground text-xs pr-12">{finding.title}</h5>
                              <span className="absolute top-3 right-3 text-[9px] font-bold px-1.5 py-0.5 bg-destructive/10 text-destructive rounded uppercase tracking-widest border border-destructive/20">
                                {finding.severity}
                              </span>
                            </div>
                            
                            <p className="text-[11px] text-muted-foreground mb-3 leading-relaxed">{finding.description}</p>
                            
                            {/* EVIDENCE (FACT, HEURISTIC, SIMULATED) */}
                            {finding.evidence && finding.evidence.length > 0 && (
                              <div className="mb-3 space-y-1.5">
                                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Evidence</span>
                                {finding.evidence.map((ev: any, idx: number) => (
                                  <div key={idx} className="flex flex-col bg-background/50 border border-border/50 rounded p-2 text-[10px]">
                                    <div className="flex items-center justify-between mb-1">
                                      <span className="text-muted-foreground font-mono">{ev.source}</span>
                                      <span className={cn(
                                        "font-bold uppercase text-[9px] px-1 py-0.5 rounded",
                                        ev.classification === 'FACT' ? 'text-emerald-500 bg-emerald-500/10' :
                                        ev.classification === 'HEURISTIC' ? 'text-orange-500 bg-orange-500/10' :
                                        'text-purple-500 bg-purple-500/10'
                                      )}>
                                        {ev.classification}
                                      </span>
                                    </div>
                                    <span className="text-foreground/80">{ev.description}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                            
                            {/* CONTAINMENT */}
                            {finding.recommendations && finding.recommendations.length > 0 && (
                              <div className="mt-3 pt-3 border-t border-destructive/10">
                                <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Containment</span>
                                <div className="space-y-1.5">
                                  {finding.recommendations.map((rec: any, idx: number) => (
                                    <div key={idx} className="bg-background border border-border rounded p-2 text-[10px] shadow-sm">
                                      <div className="font-semibold text-foreground mb-0.5">{rec.action_type}: {rec.title}</div>
                                      <div className="text-muted-foreground">{rec.why}</div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="border border-border border-dashed rounded-lg p-4 text-center">
                        <ShieldCheck className="w-5 h-5 text-muted-foreground mx-auto mb-2" />
                        <span className="text-[11px] text-muted-foreground">No security findings detected.</span>
                      </div>
                    )}
                  </div>

                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}

