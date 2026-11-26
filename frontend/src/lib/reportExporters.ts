import { AnalysisResponse, CodeReviewItem } from "@/types";
import {
  buildLockfileSnippet,
  compareSemVer,
  generateMasterAIFixPrompt,
} from "@/lib/remediationPromptGenerator";
import { getDetectorTag, ScenarioId } from "@/lib/executiveSummary";

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function downloadAIPrompt(data: AnalysisResponse | null): void {
  if (!data) return;
  const prompt = generateMasterAIFixPrompt(data);
  const repoName = (data?.scan?.repository_url || "project").split("/").pop() || "project";
  triggerDownload(
    new Blob([prompt], { type: "text/markdown;charset=utf-8" }),
    `SupplyGraph_AI_Fix_Prompt_${repoName}.md`
  );
}

export function downloadAuditReport(data: AnalysisResponse | null): void {
  if (!data) return;
  const bd = data.detector_breakdown;
  const timestamp = new Date().toISOString();
  let report = `# SupplyGraph Security Audit Report\n`;
  report += `Generated: ${timestamp}\n`;
  report += `Repository / Project: ${data?.scan?.repository_url || "N/A"}\n`;
  report += `Blast Radius: ${data?.scan?.blast_radius_score || 0}/100\n`;
  report += `Total Components: ${data?.scan?.total_components || 0}\n`;
  report += `Total Findings: ${data?.scan?.total_findings || 0}\n`;
  report += `Code Review Issues: ${data?.code_reviews?.length || 0}\n`;

  if (bd) {
    report += `\n## Detector Breakdown\n`;
    report += `- OSV/CVE: ${bd.osv_count || 0}\n`;
    report += `- Typosquatting: ${bd.typosquat_count || 0}\n`;
    report += `- Static AST: ${bd.ast_count || 0}\n`;
    report += `- CI/CD Workflows: ${bd.cicd_count || 0}\n`;
    report += `- Dependency Confusion: ${bd.confusion_count || 0}\n`;
    if (bd.historic_attack_count) {
      report += `- Historic Supply Chain Attacks: ${bd.historic_attack_count} (${(bd.historic_attacks_detected || []).join(", ")})\n`;
    }
    if (bd.sbom_sha256) report += `- SBOM SHA-256: ${bd.sbom_sha256}\n`;
    if (bd.model_provider) report += `- AI Provider: ${bd.model_provider}\n`;
  }

  report += `\n## AI Executive Briefing\n${data?.gemini_explanation || "N/A"}\n`;
  report += `\n## Findings\n`;
  (data?.findings || []).forEach((f: any, i: number) => {
    report += `\n### [${i + 1}] ${f.title} (${f.severity})\n`;
    report += `Type: ${f.finding_type || "UNKNOWN"} | Detector: ${getDetectorTag(f)}\n`;
    report += `${f.description}\n`;
    if (f.recommendations?.length > 0) {
      report += `\nContainment: ${f.recommendations[0].title}\n`;
      report += `${f.recommendations[0].why}\n`;
    }
    report += `\nLockfile Override:\n\`\`\`\n${buildLockfileSnippet(f)}\n\`\`\`\n`;
  });

  if (data?.code_reviews && data.code_reviews.length > 0) {
    report += `\n## AI Code Reviewer Patches\n`;
    data.code_reviews.forEach((cr: CodeReviewItem, i: number) => {
      report += `\n### Patch [${i + 1}] ${cr.title} (${cr.severity})\n`;
      report += `File: ${cr.file_path} (Line ${cr.line_number}) | Category: ${cr.category}\n`;
      report += `Explanation: ${cr.error_explanation}\n`;
      report += `\nOriginal Code:\n\`\`\`\n${cr.buggy_code}\n\`\`\`\n`;
      report += `\nCorrected Code:\n\`\`\`\n${cr.corrected_code}\n\`\`\`\n`;
    });
  }

  triggerDownload(
    new Blob([report], { type: "text/markdown" }),
    `supplygraph-audit-${data?.scan?.repository_url?.split("/").pop() || "report"}.md`
  );
}

export function downloadPatchedManifest(data: AnalysisResponse | null): void {
  if (!data) return;
  const isPython =
    (data?.components || []).some((c) => c.ecosystem === "pypi") ||
    (data?.scan?.lockfile_types || []).some(
      (t: string) =>
        t.toLowerCase().includes("requirements") ||
        t.toLowerCase().includes("poetry")
    );

  let content = "";
  let filename = "";

  if (isPython) {
    filename = "requirements.patched.txt";
    content = `# SupplyGraph Auto-Patched Manifest\n# Generated: ${new Date().toISOString()}\n# Repository: ${data?.scan?.repository_url || "Local Project"}\n\n`;
    const patchedDeps = new Map<string, string>();
    (data.findings || []).forEach((f) => {
      const pkg = f.origin_candidate?.split("@")?.[0] || f.entity_id;
      let fixedVer = f.recommendations?.[0]?.fixed_version;
      if (!fixedVer && f.evidence) {
        for (const ev of f.evidence) {
          if (ev?.raw_data?.fixed_version) {
            fixedVer = ev.raw_data.fixed_version;
            break;
          }
          if (ev?.raw_data?.fixed) {
            fixedVer = ev.raw_data.fixed;
            break;
          }
        }
      }
      if (pkg && fixedVer && fixedVer !== "latest" && !fixedVer.includes("patched_version")) {
        const cleanPin =
          fixedVer.startsWith(">=") || fixedVer.startsWith("==")
            ? fixedVer
            : `>=${fixedVer}`;
        patchedDeps.set(pkg, cleanPin);
      }
    });
    (data.components || []).forEach((c) => {
      const pin = patchedDeps.get(c.name);
      if (pin) {
        content += `${c.name}${pin}  # Patched by SupplyGraph (Secured)\n`;
      } else if (c.is_direct && c.version) {
        content += `${c.name}==${c.version}\n`;
      }
    });
  } else {
    filename = "package.patched.json";
    const overrides: Record<string, string> = {};
    (data.findings || []).forEach((f) => {
      const origin = f.origin_candidate || f.title || "";
      let clean = origin.replace(/^pkg:(npm|pypi)\//, "");
      try {
        clean = decodeURIComponent(clean);
      } catch (_) {}

      let pkg = clean;
      let installedVer = "";
      if (clean.startsWith("@")) {
        const atIdx = clean.indexOf("@", 1);
        if (atIdx !== -1) {
          pkg = clean.substring(0, atIdx);
          installedVer = clean.substring(atIdx + 1);
        }
      } else {
        const atIdx = clean.indexOf("@");
        if (atIdx !== -1) {
          pkg = clean.substring(0, atIdx);
          installedVer = clean.substring(atIdx + 1);
        }
      }

      let fixedVer = f.recommendations?.[0]?.fixed_version;
      if (!fixedVer && f.evidence) {
        for (const ev of f.evidence) {
          if (ev?.raw_data?.fixed_version) {
            fixedVer = ev.raw_data.fixed_version;
            break;
          }
          if (ev?.raw_data?.fixed) {
            fixedVer = ev.raw_data.fixed;
            break;
          }
        }
      }

      const fixStr = typeof fixedVer === "string" ? fixedVer : String(fixedVer || "");
      if (pkg && fixStr && fixStr !== "latest" && !fixStr.includes("patched_version")) {
        const majorMatch = installedVer.match(/^v?(\d+)/);
        const overrideKey = majorMatch ? `${pkg}@^${majorMatch[1]}.0.0` : pkg;
        const cleanFix = fixStr.replace(/^[v^~>=<\s]+/, "");
        const targetVer =
          fixStr.startsWith("^") || fixStr.startsWith(">=") ? fixStr : `^${cleanFix}`;

        if (overrides[overrideKey]) {
          if (compareSemVer(cleanFix, overrides[overrideKey]) > 0) {
            overrides[overrideKey] = targetVer;
          }
        } else {
          overrides[overrideKey] = targetVer;
        }
      }
    });
    const patchedPkg = {
      name: data?.scan?.repository_url?.split("/").pop() || "patched-project",
      version: "1.0.0",
      description: "Auto-remediated dependency manifest generated by SupplyGraph",
      overrides,
      dependencies: (data.components || [])
        .filter((c) => c.is_direct && !c.is_dev)
        .reduce((acc: Record<string, string>, c) => {
          acc[c.name] = overrides[c.name] || `^${c.version || "1.0.0"}`;
          return acc;
        }, {}),
    };
    content = JSON.stringify(patchedPkg, null, 2);
  }

  triggerDownload(
    new Blob([content], { type: isPython ? "text/plain" : "application/json" }),
    filename
  );
}

export function downloadExecutiveHtml(
  data: AnalysisResponse | null,
  activeScenario?: ScenarioId | null
): void {
  if (!data) return;
  const repoTitle =
    data?.scan?.repository_url?.replace("https://github.com/", "") ||
    (activeScenario ? `Demo Scenario ${activeScenario}` : "Audited Project");
  const blast = data?.scan?.blast_radius_score || 0;
  const totalComps = data?.scan?.total_components || 0;
  const totalFindings = data?.scan?.total_findings || 0;
  const codeReviews = data?.code_reviews?.length || 0;

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SupplyGraph Executive Audit: ${repoTitle}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #09090b; color: #f4f4f5; margin: 0; padding: 40px; }
  .header { border-bottom: 2px solid #27272a; padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: center; }
  .badge { background: #18181b; border: 1px solid #3f3f46; color: #38bdf8; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; font-family: monospace; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .card { background: #18181b; border: 1px solid #27272a; border-radius: 12px; padding: 20px; }
  .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #71717a; margin-bottom: 6px; }
  .card-val { font-size: 28px; font-weight: 700; font-family: monospace; }
  .briefing { background: #1e1b4b; border: 1px solid #3730a3; border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .finding { background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .tag-crit { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); padding: 2px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; font-family: monospace; }
  pre { background: #09090b; border: 1px solid #27272a; padding: 12px; border-radius: 8px; font-size: 11px; overflow-x: auto; color: #a1a1aa; font-family: monospace; }
  @media print { body { background: white; color: black; padding: 20px; } .card, .briefing, .finding { border-color: #ccc; background: #fafafa; color: black; } pre { background: #f4f4f4; color: black; border-color: #ddd; } }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1 style="margin:0; font-size: 26px;">SupplyGraph Executive Audit</h1>
    <p style="margin: 6px 0 0; color: #71717a; font-size: 13px;">Target: <b>${repoTitle}</b> &bull; Generated: ${new Date().toUTCString()}</p>
  </div>
  <div class="badge">SECURED BY SUPPLYGRAPH</div>
</div>
<div class="grid">
  <div class="card"><div class="card-label">Blast Radius</div><div class="card-val" style="color: ${blast > 70 ? "#ef4444" : blast > 0 ? "#f59e0b" : "#10b981"}">${blast.toFixed(1)}/100</div></div>
  <div class="card"><div class="card-label">Components</div><div class="card-val">${totalComps}</div></div>
  <div class="card"><div class="card-label">Threat Findings</div><div class="card-val" style="color: #ef4444">${totalFindings}</div></div>
  <div class="card"><div class="card-label">AI Code Patches</div><div class="card-val" style="color: #6366f1">${codeReviews}</div></div>
</div>
<div class="briefing">
  <h2 style="margin:0 0 12px; font-size: 16px; color: #a5b4fc;">Executive AI Briefing</h2>
  <div style="font-size: 13px; line-height: 1.6; color: #e0e7ff; white-space: pre-wrap;">${data?.gemini_explanation || "No executive summary recorded for this analysis."}</div>
</div>
<h2 style="font-size: 18px; margin-bottom: 16px;">Detailed Security Findings (${data?.findings?.length || 0})</h2>`;

  (data?.findings || []).forEach((f: any, idx: number) => {
    html += `<div class="finding">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <b style="font-size:14px;">[${idx + 1}] ${f.title}</b>
        <span class="tag-crit">${f.severity}</span>
      </div>
      <p style="font-size:12px; color:#a1a1aa; margin:0 0 10px;">${f.description}</p>
      ${f.recommendations?.[0] ? `<div style="font-size:12px; color:#38bdf8; margin-bottom:6px;"><b>Recommendation:</b> ${f.recommendations[0].title} - ${f.recommendations[0].why}</div>` : ""}
      <pre>${buildLockfileSnippet(f)}</pre>
    </div>`;
  });

  html += `</body></html>`;
  triggerDownload(
    new Blob([html], { type: "text/html" }),
    `supplygraph-executive-report-${data?.scan?.repository_url?.split("/").pop() || "audit"}.html`
  );
}

export function downloadSbomJson(
  data: AnalysisResponse | null,
  computedSbomSha: string
): void {
  if (!data?.sbom && !data?.components) return;
  const sha = data?.detector_breakdown?.sbom_sha256 || computedSbomSha || "0x9f83b2...a41e";
  const rawSbom = data.sbom || {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    components: data.components || [],
  };
  const sbomData = {
    ...rawSbom,
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    metadata: {
      ...((rawSbom as any).metadata || {}),
      timestamp: new Date().toISOString(),
      component: {
        name: data?.scan?.repository_url?.split("/").pop() || "supplygraph-target",
        type: "application",
      },
      properties: [
        ...(((rawSbom as any).metadata?.properties as any[]) || []),
        { name: "supplygraph:deterministic_sha256", value: sha },
      ],
    },
    signature: {
      algorithm: "SHA-256",
      value: sha,
    },
  };
  triggerDownload(
    new Blob([JSON.stringify(sbomData, null, 2)], { type: "application/json" }),
    `cyclonedx-sbom-${data?.scan?.repository_url?.split("/").pop() || "export"}.json`
  );
}
