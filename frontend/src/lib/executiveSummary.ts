import { AnalysisResponse } from "@/types";
import { buildLockfileSnippet } from "@/lib/remediationPromptGenerator";

export const SCENARIOS = [
  { id: "A", label: "Transitive CVE", icon: "🔗", color: "red" },
  { id: "B", label: "Dependency Confusion", icon: "🎭", color: "orange" },
  { id: "C", label: "Malicious Post-Install", icon: "💀", color: "rose" },
  { id: "D", label: "Deep Chain (Depth 4)", icon: "🕸️", color: "amber" },
  { id: "E", label: "CI/CD Workflow Leak", icon: "⚙️", color: "yellow" },
] as const;

export type ScenarioId = "A" | "B" | "C" | "D" | "E";

export function getSeverityClass(severity: string): string {
  switch (severity?.toUpperCase()) {
    case "CRITICAL":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "HIGH":
      return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "MEDIUM":
      return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

export function getDetectorTag(finding: any): string {
  const type = finding?.finding_type || "";
  if (type === "VULNERABLE") return "OSV";
  if (type === "TYPOSQUATTING") return "TYPOSQUAT";
  if (type === "CICD_RISK") return "CI/CD";
  if (type === "DEPENDENCY_CONFUSION") return "CONFUSION";
  if (type === "SUSPICIOUS") return "AST";
  return "ENGINE";
}

export function getDetectorTagClass(tag: string): string {
  switch (tag) {
    case "OSV":
      return "bg-indigo-950/60 text-indigo-300 border-indigo-700/40";
    case "TYPOSQUAT":
      return "bg-rose-950/60 text-rose-300 border-rose-700/40";
    case "CI/CD":
      return "bg-yellow-950/60 text-yellow-300 border-yellow-700/40";
    case "CONFUSION":
      return "bg-orange-950/60 text-orange-300 border-orange-700/40";
    case "AST":
      return "bg-cyan-950/60 text-cyan-300 border-cyan-700/40";
    default:
      return "bg-zinc-800/80 text-zinc-300 border-zinc-700/60";
  }
}

export function formatSingleFindingText(f: any): string {
  const detectorTag = getDetectorTag(f);
  const snippet = buildLockfileSnippet(f);
  let text = `[${f.severity || "MEDIUM"}] ${f.title}\n`;
  text += `Detector: ${detectorTag} | Type: ${f.finding_type || "N/A"}\n`;
  if (f.origin_candidate) {
    text += `Target Component: ${f.origin_candidate}\n`;
  }
  if (f.description) {
    text += `Description: ${f.description}\n`;
  }
  if (f.recommendations && f.recommendations.length > 0) {
    text += `\nRemediation Strategy: ${f.recommendations[0]?.title || ""}\n`;
    if (f.recommendations[0]?.why) {
      text += `Why: ${f.recommendations[0]?.why}\n`;
    }
    if (snippet) {
      text += `Fix / Configuration Snippet:\n${snippet}\n`;
    }
  }
  return text.trim();
}

export function formatAllFindingsText(
  findings: any[],
  repositoryUrl?: string,
  blastRadiusScore?: number
): string {
  const repo = repositoryUrl || "Target Repository";
  let text = `# SupplyGraph Security Findings Summary\n`;
  text += `Repository: ${repo}\n`;
  text += `Total Findings: ${findings.length}\n`;
  text += `Blast Radius: ${blastRadiusScore || 0}/100\n`;
  text += `Generated: ${new Date().toISOString()}\n\n`;
  text += `============================================================\n\n`;

  findings.forEach((f, idx) => {
    text += `### Finding #${idx + 1}: ${formatSingleFindingText(f)}\n\n`;
    text += `------------------------------------------------------------\n\n`;
  });

  return text.trim();
}

export function getExecutiveSummary(
  data: AnalysisResponse | null,
  activeScenario?: ScenarioId | null
): string {
  if (!data) {
    return "No active scan data loaded. Run a repository scan, load a detonation preset, or upload a project folder to view the autonomous executive security briefing.";
  }
  if (data.gemini_explanation && data.gemini_explanation.trim().length > 0) {
    return data.gemini_explanation;
  }

  if (activeScenario === "A" || data.demo_label === "Scenario A") {
    return `### 🚨 Executive AI Security Briefing: Transitive CVE Chain (Scenario A)\n\n**Target**: ${data.scan?.repository_url || "Scenario A"}\n**Scanned Components**: ${data.components?.length || 0} | **Findings**: ${data.findings?.length || 0}\n\n**Assessment**:\nA high-severity prototype pollution vulnerability exists via a transitive dependency path reaching \`mixin-deep@1.3.1\`. Apply non-breaking dependency overrides and verify in the Dependency Attack Graph.`;
  }
  if (activeScenario === "B" || data.demo_label === "Scenario B") {
    return `### 🚨 Executive AI Security Briefing: Typosquatting & Confusion (Scenario B)\n\n**Target**: ${data.scan?.repository_url || "Scenario B"}\n**Scanned Components**: ${data.components?.length || 0} | **Findings**: ${data.findings?.length || 0}\n\n**Assessment**:\nSuspicious package naming (\`requets\`) detected relative to canonical \`requests\`. Configure scoped registries and remove unverified lookalike dependencies.`;
  }
  if (activeScenario === "C" || data.demo_label === "Scenario C") {
    return `### 🚨 Executive AI Security Briefing: Compromised Update & Hook Risk (Scenario C)\n\n**Target**: ${data.scan?.repository_url || "Scenario C"}\n**Scanned Components**: ${data.components?.length || 0} | **Findings**: ${data.findings?.length || 0}\n\n**Assessment**:\nStatic AST heuristics and clearly labeled simulated behavioral signals highlight obfuscated update logic. Pin to a verified version and inspect hooks in the isolated sandbox.`;
  }
  if (activeScenario === "D" || data.demo_label === "Scenario D") {
    return `### 🚨 Executive AI Security Briefing: Multi-Level Supply-Chain Propagation (Scenario D)\n\n**Target**: ${data.scan?.repository_url || "Scenario D"}\n**Scanned Components**: ${data.components?.length || 0} | **Findings**: ${data.findings?.length || 0}\n\n**Assessment**:\n4-hop transitive dependency propagation connects \`malicious-logger\` to downstream services, APIs, and deployments. Review path traversal and isolate affected components.`;
  }
  if (activeScenario === "E" || data.demo_label === "Scenario E") {
    return `### 🚨 Executive AI Security Briefing: CI/CD Workflow Risk (Scenario E)\n\n**Target**: ${data.scan?.repository_url || "Scenario E"}\n**Scanned Components**: ${data.components?.length || 0} | **Findings**: ${data.findings?.length || 0}\n\n**Assessment**:\nCI/CD workflow configuration contains external script execution (\`curl | bash\`), excessive permissions (\`write-all\`), or unpinned third-party actions. Pin immutable 40-character commit SHAs and enforce least-privilege \`permissions\`.`;
  }

  const repo = data.scan?.repository_url?.replace("https://github.com/", "") || "Target Repository";
  const totalFindings = Number(data.findings?.length ?? data.scan?.total_findings ?? 0);
  const criticals = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "CRITICAL").length;
  const highs = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "HIGH").length;
  const mediums = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "MEDIUM").length;
  const lows = (data.findings || []).filter((f: any) => f.severity?.toUpperCase() === "LOW").length;
  const totalComponents = Number(data.components?.length ?? data.sbom?.components?.length ?? data.scan?.total_components ?? 0);
  const blastRadius = (Number(data.scan?.blast_radius_score) || 0).toFixed(1);
  const attackPaths = Number(data.scan?.total_attack_paths ?? data.attack_paths?.length ?? 0);
  const codeReviews = data.code_reviews?.length || 0;

  if (totalFindings === 0 && codeReviews === 0) {
    return `### 🛡️ SupplyGraph Autonomous Security Briefing\n\nTarget: ${repo}\n\nNo known software supply-chain vulnerabilities or malicious patterns were identified across ${totalComponents} scanned component(s). The dependency tree exhibits zero multi-hop attack paths and maintains a Blast Radius score of 0.0/100.\n\nRecommended Action: Continue periodic CI/CD pipeline scans and enforce immutable commit SHA pinning on all third-party build actions.`;
  }

  let summary = `### ⚠️ Autonomous Supply-Chain Threat Assessment\n\n`;
  summary += `SupplyGraph analyzed **${totalComponents} component(s)** for **${repo}** and identified **${totalFindings} security finding(s)** with an aggregate Blast Radius of **${blastRadius}/100** and **${attackPaths} multi-hop attack path(s)** traversing to application entrypoints.\n\n`;

  summary += `**Threat Severity Breakdown:**\n`;
  summary += `• Critical: ${criticals}\n`;
  summary += `• High: ${highs}\n`;
  summary += `• Medium: ${mediums}\n`;
  if (lows > 0) summary += `• Low / Informational: ${lows}\n`;
  if (codeReviews > 0) summary += `• AST & CI/CD Hardening Patches: ${codeReviews}\n`;

  summary += `\n**Key Risk Factors:**\n`;
  if (criticals > 0) {
    summary += `1. **Immediate Exposure Surface**: ${criticals} critical issue(s) detected requiring prioritized triage.\n`;
  }
  if (highs > 0) {
    summary += `2. **Transitive Dependency Exposure**: ${highs} high-severity advisories or workflow risks identified in the dependency graph.\n`;
  }
  if (attackPaths > 0) {
    summary += `3. **DAG Reachability**: Graph traversal traces affected dependencies across multi-tier dependency paths.\n`;
  }

  summary += `\n**Remediation Guidance:**\n`;
  summary += `• Open the **Code Reviewer** workspace to inspect line-level snippets and diffs.\n`;
  summary += `• Copy the **Remediation Prompt** to apply non-breaking version constraints.\n`;
  summary += `• Pin all GitHub Actions to immutable 40-character commit SHAs.`;

  return summary;
}
