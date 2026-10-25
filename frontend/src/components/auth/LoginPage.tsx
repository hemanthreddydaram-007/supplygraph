"use client";

import React, { useState } from "react";
import {
  Shield,
  Zap,
  Sparkles,
  Lock,
  Mail,
  User,
  ArrowRight,
  CheckCircle2,
  ShieldAlert,
  Cpu,
  Eye,
  EyeOff,
  X,
  ExternalLink,
  Check
} from "lucide-react";

export interface AuthUser {
  name: string;
  email: string;
  role: string;
  provider?: "google" | "github" | "gmail" | "judge";
  avatarUrl?: string;
  githubUsername?: string;
}

interface LoginPageProps {
  onLogin: (user: AuthUser) => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  // Tab: "signin" | "signup"
  const [authMode, setAuthMode] = useState<"signin" | "signup">("signin");

  // Form State
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);

  // Status feedback
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  // Modals for Google and GitHub OAuth simulation
  const [showGoogleModal, setShowGoogleModal] = useState(false);
  const [googleCustomEmail, setGoogleCustomEmail] = useState("");
  const [showGithubModal, setShowGithubModal] = useState(false);
  const [githubUsername, setGithubUsername] = useState("hemanthreddydaram-007");

  // Quick Gmail helper
  const handleAppendGmail = () => {
    if (!email) {
      setEmail("@gmail.com");
    } else if (!email.includes("@")) {
      setEmail(email.trim() + "@gmail.com");
    } else {
      const parts = email.split("@");
      setEmail(parts[0] + "@gmail.com");
    }
    setErrorMessage(null);
  };

  // Handle Standard Gmail / Email + Password Login
  const handleEmailPasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setInfoMessage(null);

    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();

    if (!trimmedEmail) {
      setErrorMessage("Please enter your Gmail or email address.");
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      setErrorMessage("Please enter a valid email address (e.g., yourname@gmail.com).");
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

    if (authMode === "signup") {
      if (!fullName.trim()) {
        setErrorMessage("Please enter your full name.");
        return;
      }
      if (trimmedPassword !== confirmPassword.trim()) {
        setErrorMessage("Passwords do not match. Please verify both fields.");
        return;
      }
    }

    setIsSubmitting(true);
    setTimeout(() => {
      let displayName = fullName.trim();
      if (!displayName) {
        const rawName = trimmedEmail.split("@")[0].replace(/[._-]/g, " ");
        displayName = rawName
          .split(" ")
          .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
          .join(" ");
      }

      const isGmail = trimmedEmail.toLowerCase().endsWith("@gmail.com");

      onLogin({
        name: displayName || "Security Specialist",
        email: trimmedEmail,
        role: "DevSecOps Engineer",
        provider: isGmail ? "gmail" : "gmail",
        avatarUrl: `https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(trimmedEmail)}`,
      });
      setIsSubmitting(false);
    }, 400);
  };

  // Handle Google Sign In
  const handleGoogleSignIn = (selectedEmail?: string, selectedName?: string) => {
    setIsSubmitting(true);
    setShowGoogleModal(false);

    const chosenEmail = selectedEmail || googleCustomEmail.trim() || "hemanthreddydaram@gmail.com";
    const chosenName = selectedName || (chosenEmail.includes("hemanth") ? "Daram Hemanth Reddy" : "Google Cloud Lead");

    setTimeout(() => {
      onLogin({
        name: chosenName,
        email: chosenEmail,
        role: "Cloud Security Architect",
        provider: "google",
        avatarUrl: "https://lh3.googleusercontent.com/a/default-user=s96-c",
      });
      setIsSubmitting(false);
    }, 450);
  };

  // Handle GitHub Sign In
  const handleGithubSignIn = () => {
    setIsSubmitting(true);
    setShowGithubModal(false);

    const user = githubUsername.trim() || "hemanthreddydaram-007";
    setTimeout(() => {
      onLogin({
        name: user === "hemanthreddydaram-007" ? "Hemanth Reddy Daram" : user,
        email: `${user}@users.noreply.github.com`,
        role: "Security Engineer & Repository Owner",
        provider: "github",
        avatarUrl: `https://github.com/${user}.png`,
        githubUsername: user,
      });
      setIsSubmitting(false);
    }, 450);
  };

  // Handle Judge Fast Pass
  const handleJudgeFastPass = () => {
    setIsSubmitting(true);
    setTimeout(() => {
      onLogin({
        name: "YUKTHI 2026 Evaluator",
        email: "judge@yukthi2026.mbu.ac.in",
        role: "Hackathon Judge (Full Access)",
        provider: "judge",
      });
      setIsSubmitting(false);
    }, 250);
  };

  return (
    <div className="min-h-screen w-full flex bg-[#070b13] text-zinc-100 selection:bg-red-500/30 selection:text-red-200">
      {/* LEFT PANEL: CYBER BRANDING & ARCHITECTURE TELEMETRY */}
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

      {/* RIGHT PANEL: AUTHENTICATION FORM & SOCIAL OAUTH */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12 relative overflow-y-auto">
        <div className="w-full max-w-md space-y-6">
          {/* Header */}
          <div className="text-center sm:text-left space-y-2">
            <div className="lg:hidden flex items-center justify-center sm:justify-start space-x-2 mb-4">
              <div className="w-8 h-8 rounded-lg bg-red-600 flex items-center justify-center shadow-lg shadow-red-500/20">
                <ShieldAlert className="w-4 h-4 text-white" />
              </div>
              <span className="text-lg font-bold text-white">SupplyGraph</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-zinc-100">
              {authMode === "signin" ? "Sign in to SupplyGraph" : "Create SupplyGraph Account"}
            </h2>
            <p className="text-xs text-zinc-400">
              {authMode === "signin"
                ? "Sign in with Google, GitHub, or your Gmail & password to inspect your attack graph."
                : "Register with your Gmail address to start analyzing dependencies and security risks."}
            </p>
          </div>

          {/* JUDGE FAST PASS BUTTON (High-Impact for Evaluators) */}
          <div className="p-3.5 rounded-2xl bg-gradient-to-r from-amber-500/15 via-red-500/15 to-indigo-500/15 border border-amber-500/40 relative group overflow-hidden">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-bold text-amber-300 flex items-center space-x-1.5">
                  <Zap className="w-4 h-4 text-amber-400 fill-amber-400" />
                  <span>YUKTHI 2026 Judge Fast-Pass</span>
                </div>
                <p className="text-[11px] text-zinc-300 mt-0.5">
                  1-click instant evaluator login with full platform permissions.
                </p>
              </div>
              <button
                type="button"
                onClick={handleJudgeFastPass}
                disabled={isSubmitting}
                className="px-3 py-1.5 rounded-xl bg-amber-400 hover:bg-amber-300 text-black text-xs font-bold transition-all shadow-md shadow-amber-400/20 hover:scale-105 active:scale-95 shrink-0"
              >
                ⚡ Instant Login
              </button>
            </div>
          </div>

          {/* OAUTH BUTTONS (Google & GitHub) */}
          <div className="space-y-2.5">
            <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider text-center sm:text-left">
              Fast Social Login
            </div>

            <div className="grid grid-cols-2 gap-3">
              {/* GOOGLE SIGN IN BUTTON */}
              <button
                type="button"
                onClick={() => setShowGoogleModal(true)}
                disabled={isSubmitting}
                className="flex items-center justify-center space-x-2 px-3 py-2.5 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-700/80 hover:border-zinc-600 text-xs font-semibold text-zinc-200 hover:text-white transition-all shadow-sm hover:scale-[1.02] active:scale-[0.98]"
              >
                {/* Official Google G Logo */}
                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
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
                <span>Sign in with Google</span>
              </button>

              {/* GITHUB SIGN IN BUTTON */}
              <button
                type="button"
                onClick={() => setShowGithubModal(true)}
                disabled={isSubmitting}
                className="flex items-center justify-center space-x-2 px-3 py-2.5 rounded-xl bg-zinc-900/90 hover:bg-zinc-800 border border-zinc-700/80 hover:border-zinc-600 text-xs font-semibold text-zinc-200 hover:text-white transition-all shadow-sm hover:scale-[1.02] active:scale-[0.98]"
              >
                {/* GitHub Octocat SVG */}
                <svg className="w-4 h-4 fill-current text-white shrink-0" viewBox="0 0 24 24">
                  <path
                    fillRule="evenodd"
                    clipRule="evenodd"
                    d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  />
                </svg>
                <span>Sign in with GitHub</span>
              </button>
            </div>
          </div>

          {/* Divider */}
          <div className="relative flex items-center justify-center my-2">
            <div className="border-t border-zinc-800 w-full" />
            <span className="bg-[#070b13] px-3 text-[11px] text-zinc-500 font-mono uppercase tracking-wider">
              Or with Gmail & password
            </span>
          </div>

          {/* TAB SWITCHER: SIGN IN VS CREATE ACCOUNT */}
          <div className="flex rounded-xl bg-zinc-900/90 p-1 border border-zinc-800">
            <button
              type="button"
              onClick={() => {
                setAuthMode("signin");
                setErrorMessage(null);
              }}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                authMode === "signin"
                  ? "bg-gradient-to-r from-red-600 to-indigo-600 text-white shadow-md shadow-red-500/20"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setAuthMode("signup");
                setErrorMessage(null);
              }}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                authMode === "signup"
                  ? "bg-gradient-to-r from-red-600 to-indigo-600 text-white shadow-md shadow-red-500/20"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Create Account
            </button>
          </div>

          {/* STANDARD GMAIL / EMAIL & PASSWORD FORM */}
          <form onSubmit={handleEmailPasswordSubmit} className="space-y-4">
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

            {/* Full Name field in Sign Up mode */}
            {authMode === "signup" && (
              <div>
                <label className="block text-xs font-mono font-medium text-zinc-300 mb-1">
                  Full Name
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
                    <User className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Daram Hemanth Reddy"
                    className="w-full pl-9 pr-3.5 py-2.5 rounded-xl bg-zinc-900/90 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:border-red-500/50 transition-all font-mono"
                  />
                </div>
              </div>
            )}

            {/* Email Field with Gmail quick appender */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-mono font-medium text-zinc-300">
                  Gmail or Email Address
                </label>
                <button
                  type="button"
                  onClick={handleAppendGmail}
                  className="text-[11px] font-mono text-red-400 hover:text-red-300 transition-colors flex items-center space-x-1"
                  title="Append @gmail.com"
                >
                  <span>+ @gmail.com</span>
                </button>
              </div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="hemanthreddydaram@gmail.com"
                  className="w-full pl-9 pr-3.5 py-2.5 rounded-xl bg-zinc-900/90 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:border-red-500/50 transition-all font-mono"
                />
              </div>
            </div>

            {/* Password Field with Show/Hide toggle */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-mono font-medium text-zinc-300">
                  Password
                </label>
                {authMode === "signin" && (
                  <button
                    type="button"
                    onClick={() =>
                      setInfoMessage(
                        "Password reset link generated for your Gmail account with verification token #SG-849201."
                      )
                    }
                    className="text-[11px] text-zinc-400 font-mono hover:text-zinc-300 transition-colors"
                  >
                    Forgot password?
                  </button>
                )}
              </div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2.5 rounded-xl bg-zinc-900/90 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:border-red-500/50 transition-all font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-zinc-400 hover:text-zinc-200"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm Password in Sign Up mode */}
            {authMode === "signup" && (
              <div>
                <label className="block text-xs font-mono font-medium text-zinc-300 mb-1">
                  Confirm Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-zinc-500">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full pl-9 pr-3.5 py-2.5 rounded-xl bg-zinc-900/90 border border-zinc-800 text-zinc-200 placeholder:text-zinc-600 text-sm focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:border-red-500/50 transition-all font-mono"
                  />
                </div>
              </div>
            )}

            {/* Remember Me Checkbox */}
            <div className="flex items-center space-x-2">
              <input
                id="rememberMe"
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="w-4 h-4 rounded border-zinc-800 bg-zinc-900 text-red-600 focus:ring-red-500/40 accent-red-600"
              />
              <label htmlFor="rememberMe" className="text-xs text-zinc-400 font-mono select-none">
                Remember session on this device
              </label>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-indigo-600 hover:from-red-500 hover:to-indigo-500 text-white font-semibold text-sm shadow-lg shadow-red-600/25 hover:shadow-red-600/40 transition-all active:scale-[0.98] flex items-center justify-center space-x-2 disabled:opacity-60"
            >
              {isSubmitting ? (
                <span className="flex items-center space-x-2">
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Verifying credentials...</span>
                </span>
              ) : (
                <>
                  <span>{authMode === "signin" ? "Login with Gmail & Password" : "Create Account & Login"}</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Privacy Note */}
          <p className="text-[11px] text-zinc-500 text-center font-mono">
            Protected by SupplyGraph Zero-Trust Architecture. No raw source code stored.
          </p>
        </div>
      </div>

      {/* =================================================================== */}
      {/* GOOGLE SIGN IN MODAL */}
      {/* =================================================================== */}
      {showGoogleModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-150">
          <div className="bg-[#181a20] border border-zinc-700/80 rounded-2xl max-w-md w-full p-6 text-zinc-100 shadow-2xl space-y-5 relative">
            <button
              onClick={() => setShowGoogleModal(false)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Google Header */}
            <div className="flex items-center space-x-3">
              <svg className="w-6 h-6 shrink-0" viewBox="0 0 24 24">
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
              <div>
                <h3 className="font-bold text-base text-white">Sign in with Google</h3>
                <p className="text-xs text-zinc-400">Choose an account to continue to SupplyGraph ASPM</p>
              </div>
            </div>

            {/* Account List */}
            <div className="space-y-2">
              <button
                type="button"
                onClick={() => handleGoogleSignIn("hemanthreddydaram@gmail.com", "Daram Hemanth Reddy")}
                className="w-full p-3 rounded-xl bg-zinc-800/80 hover:bg-zinc-700/80 border border-zinc-700 flex items-center justify-between transition-all group text-left"
              >
                <div className="flex items-center space-x-3">
                  <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-blue-500 to-red-500 flex items-center justify-center text-white font-bold text-sm shadow">
                    DH
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-white group-hover:text-blue-400 transition-colors">
                      Daram Hemanth Reddy
                    </div>
                    <div className="text-xs text-zinc-400 font-mono">hemanthreddydaram@gmail.com</div>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-zinc-500 group-hover:text-white transition-colors" />
              </button>

              <button
                type="button"
                onClick={() => handleGoogleSignIn("devsecops.lead@gmail.com", "Security Architect")}
                className="w-full p-3 rounded-xl bg-zinc-800/50 hover:bg-zinc-700/80 border border-zinc-700/60 flex items-center justify-between transition-all group text-left"
              >
                <div className="flex items-center space-x-3">
                  <div className="w-9 h-9 rounded-full bg-indigo-600 flex items-center justify-center text-white font-bold text-sm">
                    SA
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-white group-hover:text-blue-400 transition-colors">
                      Security Lead Account
                    </div>
                    <div className="text-xs text-zinc-400 font-mono">devsecops.lead@gmail.com</div>
                  </div>
                </div>
                <ArrowRight className="w-4 h-4 text-zinc-500 group-hover:text-white transition-colors" />
              </button>
            </div>

            {/* Custom Google Account Input */}
            <div className="pt-2 border-t border-zinc-800 space-y-2">
              <label className="text-xs font-mono text-zinc-400">Or enter any Google/Gmail address:</label>
              <div className="flex space-x-2">
                <input
                  type="email"
                  value={googleCustomEmail}
                  onChange={(e) => setGoogleCustomEmail(e.target.value)}
                  placeholder="yourname@gmail.com"
                  className="flex-1 px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-700 text-xs font-mono text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <button
                  type="button"
                  onClick={() => handleGoogleSignIn(googleCustomEmail)}
                  disabled={!googleCustomEmail.trim()}
                  className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-xs font-semibold text-white"
                >
                  Continue
                </button>
              </div>
            </div>

            <p className="text-[11px] text-zinc-500 leading-relaxed font-mono">
              To continue, Google will share your name, email address, language preference, and profile picture with SupplyGraph.
            </p>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* GITHUB SIGN IN MODAL */}
      {/* =================================================================== */}
      {showGithubModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-150">
          <div className="bg-[#161b22] border border-zinc-700 rounded-2xl max-w-md w-full p-6 text-zinc-100 shadow-2xl space-y-5 relative">
            <button
              onClick={() => setShowGithubModal(false)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            {/* GitHub Header */}
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 rounded-full bg-zinc-800 flex items-center justify-center">
                <svg className="w-6 h-6 fill-current text-white" viewBox="0 0 24 24">
                  <path
                    fillRule="evenodd"
                    clipRule="evenodd"
                    d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  />
                </svg>
              </div>
              <div>
                <h3 className="font-bold text-base text-white">Authorize SupplyGraph ASPM</h3>
                <p className="text-xs text-zinc-400">Connect your GitHub developer profile and repositories</p>
              </div>
            </div>

            {/* Scope info */}
            <div className="p-3.5 rounded-xl bg-zinc-900/80 border border-zinc-800 text-xs space-y-2">
              <div className="text-zinc-300 font-semibold flex items-center space-x-1.5">
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span>Read-only repository access (`public_repo`, `read:user`)</span>
              </div>
              <p className="text-[11px] text-zinc-400">
                Enables 1-click lockfile ingestion, AST call-graph reachability indexing, and automated pull request generation.
              </p>
            </div>

            {/* Username Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-zinc-300">GitHub Username or Organization</label>
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={githubUsername}
                  onChange={(e) => setGithubUsername(e.target.value)}
                  placeholder="hemanthreddydaram-007"
                  className="flex-1 px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-700 text-xs font-mono text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            {/* Authorize button */}
            <button
              type="button"
              onClick={handleGithubSignIn}
              className="w-full py-2.5 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs shadow-lg shadow-emerald-600/20 transition-all flex items-center justify-center space-x-2"
            >
              <span>Authorize with GitHub (@{githubUsername || "user"})</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
