"use client";

import React, { useState } from "react";
import { Shield, Zap, Sparkles, Lock, ArrowRight, CheckCircle2, ShieldAlert, Cpu } from "lucide-react";

interface LoginPageProps {
  onLogin: (user: { name: string; email: string; role: string }) => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setInfoMessage(null);

    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();

    if (!trimmedEmail) {
      setErrorMessage("Please enter your work email address.");
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      setErrorMessage("Please enter a valid work email address (e.g., developer@company.com).");
      return;
    }

    if (!trimmedPassword) {
      setErrorMessage("Please enter your password.");
      return;
    }

    if (trimmedPassword.length < 6) {
      setErrorMessage("Password must be at least 6 characters long.");
      return;
    }

    setIsSubmitting(true);
    setTimeout(() => {
      const rawName = trimmedEmail.split("@")[0];
      const capitalized = rawName.charAt(0).toUpperCase() + rawName.slice(1);
      onLogin({
        name: capitalized || "Security Lead",
        email: trimmedEmail,
        role: "DevSecOps Engineer",
      });
      setIsSubmitting(false);
    }, 350);
  };

  const handleOAuthLogin = (provider: "google" | "github") => {
    setIsSubmitting(true);
    setTimeout(() => {
      onLogin({
        name: provider === "github" ? "GitHub Developer" : "Google Cloud Engineer",
        email: provider === "github" ? "dev@github.com" : "cloud.sec@gmail.com",
        role: "Security Architect",
      });
      setIsSubmitting(false);
    }, 300);
  };

  const handleJudgeFastPass = () => {
    setIsSubmitting(true);
    setTimeout(() => {
      onLogin({
        name: "YUKTHI 2026 Evaluator",
        email: "judge@yukthi2026.mbu.ac.in",
        role: "Hackathon Judge (Full Access)",
      });
      setIsSubmitting(false);
    }, 200);
  };

  return (
    <div className="min-h-screen w-full flex bg-[#070b13] text-zinc-100 selection:bg-red-500/30 selection:text-red-200">
      {/* LEFT PANEL: CYBER BRANDING & LIVE TELEMETRY */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 relative overflow-hidden border-r border-zinc-800/80 bg-gradient-to-br from-zinc-950 via-[#090e1a] to-[#0d1527]">
        {/* Ambient background glow */}
        <div className="absolute top-0 left-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293708_1px,transparent_1px),linear-gradient(to_bottom,#1f293708_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />

        {/* Brand Header */}
        <div className="relative z-10 flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-red-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-red-500/20 border border-red-400/30">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
              <span>SupplyGraph</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/30 text-red-400 font-mono font-semibold">
                v3.0 ASPM
              </span>
            </div>
            <p className="text-xs text-zinc-400 font-mono">Software Supply-Chain Attack Graph & AI Code Reviewer</p>
          </div>
        </div>

        {/* Center Graphic & Mission Statement */}
        <div className="relative z-10 my-auto py-8 space-y-6 max-w-lg">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Target Event: YUKTHI 2026 (Mohan Babu University)</span>
          </div>

          <h1 className="text-3xl font-extrabold tracking-tight text-zinc-100 sm:text-4xl leading-tight">
            Stop supply-chain threats before production deployment.
          </h1>

          <p className="text-sm text-zinc-400 leading-relaxed">
            Multi-layer threat detection fusing OSV.dev CVE intelligence, typosquatting heuristics,
            AST static analysis, CI/CD pipeline auditing, and an autonomous AI Code Reviewer with line-level corrected patches.
          </p>

          {/* Platform Telemetry Pills */}
          <div className="grid grid-cols-2 gap-3 pt-2">
            <div className="p-3 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm">
              <div className="text-[11px] font-mono text-zinc-400 flex items-center space-x-1.5">
                <Cpu className="w-3.5 h-3.5 text-red-400" />
                <span>Deterministic DAG</span>
              </div>
              <div className="text-sm font-semibold text-zinc-200 mt-1">Multi-Hop Reachability</div>
              <div className="text-[10px] text-zinc-500 font-mono mt-0.5">NetworkX reverse BFS layout</div>
            </div>

            <div className="p-3 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm">
              <div className="text-[11px] font-mono text-zinc-400 flex items-center space-x-1.5">
                <Shield className="w-3.5 h-3.5 text-indigo-400" />
                <span>On-Chain SBOM</span>
              </div>
              <div className="text-sm font-semibold text-zinc-200 mt-1">Polygon Amoy Testnet</div>
              <div className="text-[10px] text-zinc-500 font-mono mt-0.5">Immutable Merkle proofs</div>
            </div>

            <div className="p-3 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm">
              <div className="text-[11px] font-mono text-zinc-400 flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span>AI Code Reviewer</span>
              </div>
              <div className="text-sm font-semibold text-zinc-200 mt-1">Auto-Patcher Engine</div>
              <div className="text-[10px] text-zinc-500 font-mono mt-0.5">Line-level corrected diffs</div>
            </div>

            <div className="p-3 rounded-xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-sm">
              <div className="text-[11px] font-mono text-zinc-400 flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Quantified Math HUD</span>
              </div>
              <div className="text-sm font-semibold text-zinc-200 mt-1">Blast Radius & Confidence</div>
              <div className="text-[10px] text-zinc-500 font-mono mt-0.5">0–100 Exploitability Telemetry</div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="relative z-10 text-[11px] text-zinc-500 font-mono flex items-center justify-between">
          <span>Theme: Blockchain & Cybersecurity</span>
          <span>Sponsors: AWS • Chai aur Code • Masterji • RTIH</span>
        </div>
      </div>

      {/* RIGHT PANEL: AUTH CARD */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12 relative">
        <div className="w-full max-w-md space-y-7">
          {/* Header */}
          <div className="text-center sm:text-left space-y-2">
            <div className="lg:hidden flex items-center justify-center sm:justify-start space-x-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-red-600 flex items-center justify-center shadow-lg shadow-red-500/20">
                <ShieldAlert className="w-4 h-4 text-white" />
              </div>
              <span className="text-lg font-bold text-white">SupplyGraph</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-zinc-100">Sign in to SupplyGraph</h2>
            <p className="text-xs text-zinc-400">
              Access the ASPM dashboard, Attack Graph visualizer, and AI Code Reviewer.
            </p>
          </div>

          {/* JUDGE FAST PASS BUTTON (High-Impact for Evaluators) */}
          <div className="p-4 rounded-2xl bg-gradient-to-r from-amber-500/15 via-red-500/15 to-indigo-500/15 border border-amber-500/40 relative group overflow-hidden">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-xs font-bold text-amber-300 flex items-center space-x-1.5">
                  <Zap className="w-4 h-4 text-amber-400 fill-amber-400" />
                  <span>YUKTHI 2026 Judge Fast-Pass</span>
                </div>
                <p className="text-[11px] text-zinc-300 mt-1">
                  1-click instant evaluator login with full platform permissions.
                </p>
              </div>
              <button
                type="button"
                onClick={handleJudgeFastPass}
                disabled={isSubmitting}
                className="px-3.5 py-1.5 rounded-xl bg-amber-400 hover:bg-amber-300 text-black text-xs font-bold transition-all shadow-md shadow-amber-400/20 hover:scale-105 active:scale-95 shrink-0"
              >
                ⚡ Instant Login
              </button>
            </div>
          </div>

          {/* Standard Email / Password Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {errorMessage && (
              <div className="p-3 rounded-xl bg-red-950/70 border border-red-500/50 text-red-300 text-xs flex items-center space-x-2 animate-in fade-in">
                <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            {infoMessage && (
              <div className="p-3 rounded-xl bg-indigo-950/70 border border-indigo-500/50 text-indigo-300 text-xs flex items-center space-x-2 animate-in fade-in">
                <Sparkles className="w-4 h-4 text-indigo-400 shrink-0" />
                <span>{infoMessage}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-mono font-medium text-zinc-300 mb-1.5">
                Work Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                placeholder="developer@company.com"
                className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:border-red-500/50 transition-all font-mono"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-mono font-medium text-zinc-300">
                  Password
                </label>
                <button
                  type="button"
                  onClick={() => setInfoMessage("Single Sign-On (SSO) active. Use Judge Fast-Pass or OAuth for immediate evaluation access.")}
                  className="text-[11px] text-zinc-500 font-mono hover:text-zinc-400"
                >
                  Forgot?
                </button>
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:border-red-500/50 transition-all font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white font-semibold text-sm shadow-lg shadow-red-600/20 hover:shadow-red-600/30 transition-all active:scale-[0.98] flex items-center justify-center space-x-2 disabled:opacity-60"
            >
              {isSubmitting ? (
                <span className="flex items-center space-x-2">
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Authenticating...</span>
                </span>
              ) : (
                <>
                  <span>Sign In to SupplyGraph</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="relative flex items-center justify-center">
            <div className="border-t border-zinc-800/80 w-full" />
            <span className="bg-[#070b13] px-3 text-[11px] text-zinc-500 font-mono uppercase tracking-wider">
              Or continue with
            </span>
          </div>

          {/* OAuth Buttons */}
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => handleOAuthLogin("google")}
              disabled={isSubmitting}
              className="flex items-center justify-center space-x-2 px-3 py-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 text-xs font-medium text-zinc-300 hover:text-white transition-all shadow-sm"
            >
              {/* Google SVG */}
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path
                  fill="#EA4335"
                  d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.3 9 5 12 5z"
                />
                <path
                  fill="#4285F4"
                  d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.5h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.8z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.8s.2-2.1.4-2.8L1.9 6.3C.7 8.7 0 10.8 0 12s.7 3.3 1.9 5.7l3.7-2.9z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2.3-6.4-5.2L1.9 16c1.8 3.7 5.6 7 10.1 7z"
                />
              </svg>
              <span>Google</span>
            </button>

            <button
              type="button"
              onClick={() => handleOAuthLogin("github")}
              disabled={isSubmitting}
              className="flex items-center justify-center space-x-2 px-3 py-2.5 rounded-xl bg-zinc-900/80 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 text-xs font-medium text-zinc-300 hover:text-white transition-all shadow-sm"
            >
              {/* GitHub SVG */}
              <svg className="w-4 h-4 fill-current text-white" viewBox="0 0 24 24">
                <path
                  fillRule="evenodd"
                  clipRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                />
              </svg>
              <span>GitHub</span>
            </button>
          </div>

          {/* Privacy Note */}
          <p className="text-[11px] text-zinc-500 text-center font-mono">
            Protected by SupplyGraph Zero-Trust Architecture. No raw code stored.
          </p>
        </div>
      </div>
    </div>
  );
}
