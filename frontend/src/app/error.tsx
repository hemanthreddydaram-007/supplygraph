"use client";

import React, { useEffect } from "react";
import { ShieldAlert, RefreshCw, Trash2, Home } from "lucide-react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("SupplyGraph Application Error Intercepted:", error);
  }, [error]);

  const handleClearAndReload = () => {
    try {
      if (typeof window !== "undefined") {
        localStorage.removeItem("supplygraph_scan_history");
        localStorage.removeItem("supplygraph_user");
        window.location.href = "/";
      }
    } catch (_) {
      reset();
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 bg-[#070b13] text-zinc-100 font-sans selection:bg-red-500/30 selection:text-red-200">
      <div className="max-w-lg w-full p-8 rounded-3xl bg-zinc-950/90 border border-red-500/30 shadow-2xl backdrop-blur-xl space-y-6 text-center relative overflow-hidden">
        {/* Glow Effects */}
        <div className="absolute top-0 right-0 w-48 h-48 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-48 h-48 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 w-14 h-14 rounded-2xl bg-gradient-to-tr from-red-600 to-indigo-600 flex items-center justify-center mx-auto text-white shadow-xl shadow-red-500/20 border border-red-400/30">
          <ShieldAlert className="w-7 h-7" />
        </div>

        <div className="relative z-10 space-y-2">
          <div className="inline-flex items-center space-x-1.5 px-3 py-0.5 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono font-semibold">
            <span>Client State Exception Intercepted</span>
          </div>
          <h2 className="text-xl font-extrabold text-white tracking-tight">
            SupplyGraph Session Recovery
          </h2>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-sm mx-auto">
            A client-side exception occurred during render or workspace hydration.
            You can restore your workspace, clear legacy cached data, or reload clean.
          </p>
        </div>

        {error?.message && (
          <div className="relative z-10 p-3.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-[11px] font-mono text-red-400 text-left overflow-x-auto max-h-28">
            <span className="text-zinc-500 block mb-1">Details:</span>
            {error.message}
          </div>
        )}

        <div className="relative z-10 flex flex-wrap items-center justify-center gap-3 pt-2">
          <button
            onClick={() => reset()}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white text-xs font-semibold flex items-center space-x-2 transition-all shadow-lg shadow-red-600/25"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Try Again</span>
          </button>

          <button
            onClick={handleClearAndReload}
            className="px-4 py-2.5 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 text-xs font-semibold flex items-center space-x-2 transition-colors"
            title="Purge localStorage scan history and reload"
          >
            <Trash2 className="w-3.5 h-3.5 text-zinc-400" />
            <span>Clear Cache & Reload</span>
          </button>

          <button
            onClick={() => { window.location.href = "/"; }}
            className="px-4 py-2.5 rounded-xl bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 text-xs font-semibold flex items-center space-x-2 transition-colors"
          >
            <Home className="w-3.5 h-3.5 text-zinc-400" />
            <span>Dashboard Home</span>
          </button>
        </div>
      </div>
    </div>
  );
}
