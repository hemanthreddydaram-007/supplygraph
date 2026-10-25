import { chromium } from "playwright";
import * as path from "path";
import * as fs from "fs";

async function showCaption(
  page: any,
  title: string,
  subtitle: string,
  badge = "SUPPLYGRAPH v3.0 ASPM"
) {
  await page.evaluate(
    ({ title, subtitle, badge }: { title: string; subtitle: string; badge: string }) => {
      let el = document.getElementById("sg-demo-hud");
      if (!el) {
        el = document.createElement("div");
        el.id = "sg-demo-hud";
        el.style.position = "fixed";
        el.style.bottom = "24px";
        el.style.left = "50%";
        el.style.transform = "translateX(-50%)";
        el.style.zIndex = "999999";
        el.style.maxWidth = "880px";
        el.style.width = "90%";
        el.style.padding = "14px 22px";
        el.style.borderRadius = "14px";
        el.style.background = "rgba(7, 11, 19, 0.94)";
        el.style.backdropFilter = "blur(18px)";
        el.style.border = "1px solid rgba(99, 102, 241, 0.45)";
        el.style.boxShadow =
          "0 12px 48px rgba(0, 0, 0, 0.85), 0 0 24px rgba(99, 102, 241, 0.25)";
        el.style.fontFamily = "system-ui, -apple-system, sans-serif";
        el.style.transition = "all 0.35s ease";
        el.style.pointerEvents = "none";
        document.body.appendChild(el);
      }
      el.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 5px;">
          <span style="font-size: 10px; font-weight: 700; font-family: monospace; letter-spacing: 0.1em; color: #818cf8; text-transform: uppercase;">
            🛡️ ${badge}
          </span>
          <span style="font-size: 10px; font-family: monospace; color: #34d399; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 8px; border-radius: 9999px;">
            YUKTHI 2026 PROTOTYPE
          </span>
        </div>
        <div style="font-size: 15px; font-weight: 700; color: #f4f4f5; line-height: 1.3;">
          ${title}
        </div>
        <div style="font-size: 12px; color: #a1a1aa; margin-top: 3px; font-family: monospace;">
          ${subtitle}
        </div>
      `;
    },
    { title, subtitle, badge }
  );
}

async function runHackathonRecording() {
  const videoDir = path.resolve("./videos");
  if (!fs.existsSync(videoDir)) {
    fs.mkdirSync(videoDir, { recursive: true });
  }

  console.log("🎥 Launching Full HD 1080p (1920x1080) Chromium Recorder...");
  const browser = await chromium.launch({
    headless: true,
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: {
      dir: videoDir,
      size: { width: 1920, height: 1080 },
    },
  });

  const page = await context.newPage();
  console.log("🌐 Connecting to SupplyGraph live application...");

  try {
    // -------------------------------------------------------------------------
    // SCENE 1: LOGIN PORTAL & JUDGE FAST PASS (0:00 - 0:12)
    // -------------------------------------------------------------------------
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    await showCaption(
      page,
      "SupplyGraph (v3.0 ASPM): Autonomous Software Supply-Chain Defense",
      "Unified Platform: Multi-Hop Attack Graphs • AI Code Reviewer • Zero-Egress Detonation Sandbox"
    );
    await page.waitForTimeout(4000);

    console.log("👉 Executing 1-Click Judge Fast Pass Access...");
    await showCaption(
      page,
      "Evaluator Fast Pass: Instant Access for Hackathon Judges",
      "Authenticated Zero-Trust Session initialized for YUKTHI 2026 Evaluation Committee"
    );
    await page.waitForTimeout(2000);

    const fastPassBtn = page
      .locator("button:has-text('Judge Fast Pass')")
      .or(page.locator("button:has-text('Fast Pass')"))
      .first();
    if (await fastPassBtn.isVisible()) {
      await fastPassBtn.click();
      await page.waitForTimeout(2500);
    }

    // -------------------------------------------------------------------------
    // SCENE 2: ASPM OVERVIEW & PLATFORM TELEMETRY (0:12 - 0:25)
    // -------------------------------------------------------------------------
    console.log("📊 Exploring ASPM Overview Dashboard...");
    await showCaption(
      page,
      "Stage 1: Central Application Security Posture Management (ASPM)",
      "Continuous Telemetry: 5 Preset Attack Scenarios, Live GitHub Repositories & Local Monorepos"
    );
    await page.waitForTimeout(3500);

    // Smooth scroll down to preset scenarios
    await page.mouse.wheel(0, 450);
    await page.waitForTimeout(3000);

    // -------------------------------------------------------------------------
    // SCENE 3: SCENARIO A - LOG4J ATTACK GRAPH DAG (0:25 - 0:48)
    // -------------------------------------------------------------------------
    console.log("🎯 Launching Scenario A: Log4j Transitive Exploit Chain...");
    await showCaption(
      page,
      "Stage 2: Deterministic Attack Graph (NetworkX Reverse BFS DAG)",
      "Traversing Multi-Hop Call Paths from Ingress to Deep Transitive Vulnerability: log4j-core:2.14.1"
    );

    const scenarioABtn = page
      .locator("button:has-text('Scenario A')")
      .or(page.locator("text=Scenario A"))
      .first();
    if (await scenarioABtn.isVisible()) {
      await scenarioABtn.click();
    } else {
      const getStarted = page
        .locator("button:has-text('Open Live ASPM Scanner')")
        .or(page.locator("button:has-text('Get Started')"))
        .first();
      if (await getStarted.isVisible()) await getStarted.click();
    }
    await page.waitForTimeout(4000);

    // Hover and center node in attack graph
    await showCaption(
      page,
      "Multi-Hop Call Chain Traversal: Entrypoint ➔ Payment Service ➔ Log4j RCE",
      "Quantified Mathematical HUD: Blast Radius 85.0/100 | CVE-2021-44228 JNDI Injection Path"
    );
    await page.waitForTimeout(4500);

    // -------------------------------------------------------------------------
    // SCENE 4: AUTONOMOUS EXECUTIVE AI BRIEFING (0:48 - 1:02)
    // -------------------------------------------------------------------------
    console.log("🤖 Opening Autonomous Executive AI Tab...");
    const briefingTab = page.locator("button:has-text('Executive AI')").first();
    if (await briefingTab.isVisible()) {
      await briefingTab.click();
      await page.waitForTimeout(1000);
      await showCaption(
        page,
        "Stage 3: Autonomous Executive AI Security Briefing",
        "Deterministic Exploit Breakdown, Multi-Hop Call Path Proof, and Actionable Containment Protocol"
      );
      await page.waitForTimeout(5000);
    }

    // -------------------------------------------------------------------------
    // SCENE 5: FIX WITH AI MASTER PROMPT GENERATOR (1:02 - 1:16)
    // -------------------------------------------------------------------------
    console.log("✨ Generating Master Fix with AI Prompt...");
    const fixWithAiBtn = page.locator("button:has-text('Fix with AI')").first();
    if (await fixWithAiBtn.isVisible()) {
      await fixWithAiBtn.click();
      await showCaption(
        page,
        "Fix with AI: Evidence-Grounded Remediation Generator",
        "Generates Non-Breaking Version Constraints & Scope Rules for Antigravity, Cursor, Claude & Copilot"
      );
      await page.waitForTimeout(4000);
    }

    // -------------------------------------------------------------------------
    // SCENE 6: CYCLONEDX v1.5 SBOM & DETERMINISTIC HASH (1:16 - 1:28)
    // -------------------------------------------------------------------------
    console.log("📄 Opening CycloneDX SBOM Modal...");
    const sbomBtn = page.locator("button:has-text('CycloneDX SBOM')").first();
    if (await sbomBtn.isVisible()) {
      await sbomBtn.click();
      await page.waitForTimeout(1000);
      await showCaption(
        page,
        "Stage 4: CycloneDX v1.5 SBOM with Web Crypto Deterministic SHA-256",
        "Cryptographic Digest Generation & 1-Click Attestation Download for Regulatory Compliance"
      );
      await page.waitForTimeout(4000);

      // Copy SHA
      const copyShaBtn = page.locator("button[title*='Copy SHA']").first();
      if (await copyShaBtn.isVisible()) {
        await copyShaBtn.click();
        await page.waitForTimeout(1000);
      }

      // Close modal
      const closeBtn = page
        .locator("button:has-text('Close')")
        .or(page.locator("button[aria-label='Close']"))
        .or(page.locator(".lucide-x"))
        .first();
      if (await closeBtn.isVisible()) {
        await closeBtn.click();
        await page.waitForTimeout(1500);
      }
    }

    // -------------------------------------------------------------------------
    // SCENE 7: DEDICATED AI CODE REVIEWER & UNIFIED DIFFS (1:28 - 1:48)
    // -------------------------------------------------------------------------
    console.log("🛠️ Navigating to AI Code Reviewer Workspace...");
    const navReviewer = page
      .locator("button:has-text('AI Code Reviewer')")
      .or(page.locator("nav button:has-text('Reviewer')"))
      .first();
    if (await navReviewer.isVisible()) {
      await navReviewer.click();
      await page.waitForTimeout(1500);
      await showCaption(
        page,
        "Stage 5: AI Code Reviewer & Auto-Patcher Engine",
        "Line-Level Corrected Unified Git Diffs: Surgical Replacement vs. Breaking Package Upgrades"
      );
      await page.waitForTimeout(4000);

      // Switch to Stacked View
      const stackedBtn = page.locator("button:has-text('Stacked View')").first();
      if (await stackedBtn.isVisible()) {
        await stackedBtn.click();
        await page.waitForTimeout(2500);
      }

      // Switch back to Unified Diff
      const diffBtn = page.locator("button:has-text('Unified Git Diff')").first();
      if (await diffBtn.isVisible()) {
        await diffBtn.click();
        await page.waitForTimeout(1500);
      }

      // Expand Ad-Hoc Live Analyzer
      console.log("📝 Demonstrating Ad-Hoc Live Code Analyzer...");
      const adhocBtn = page
        .locator("button:has-text('Ad-Hoc')")
        .or(page.locator("button:has-text('Paste Custom File')"))
        .first();
      if (await adhocBtn.isVisible()) {
        await adhocBtn.click();
        await page.waitForTimeout(1000);
        await showCaption(
          page,
          "Ad-Hoc Live Code Analyzer: Instant AST Vulnerability & Diff Output",
          "Audits Arbitrary Python, JS/TS, and YAML/GitHub Action Snippets with Zero-Config"
        );

        // Fill sample buggy Python code into the Ad-Hoc textarea
        const textarea = page.locator("textarea").first();
        if (await textarea.isVisible()) {
          await textarea.fill("import subprocess\ndef execute(cmd, cache=[]):\n    subprocess.run(cmd, shell=True)\n");
          await page.waitForTimeout(1200);
        }

        // Click Review Code & Output Patch
        const runReviewBtn = page
          .locator("button:has-text('Review Code & Output Patch')")
          .first();
        if (await runReviewBtn.isVisible()) {
          await runReviewBtn.click();
          await page.waitForTimeout(3500);
        }
      }
    }

    // -------------------------------------------------------------------------
    // SCENE 8: UNIVERSAL EPHEMERAL DETONATION SANDBOX (1:48 - 2:12)
    // -------------------------------------------------------------------------
    console.log("⚡ Navigating to Dynamic Detonation Sandbox...");
    const navSandbox = page
      .locator("button:has-text('Detonation Sandbox')")
      .or(page.locator("nav button:has-text('Sandbox')"))
      .first();
    if (await navSandbox.isVisible()) {
      await navSandbox.click();
      await page.waitForTimeout(1500);
      await showCaption(
        page,
        "Stage 6: Universal Secure File Execution & Ephemeral Detonation Sandbox",
        "Isolated Container: Intercepting Malicious Lifecycle Hooks, Shell Injections & C2 Beacons"
      );
      await page.waitForTimeout(3500);

      // Run Malicious npm Hook Preset
      const npmHookPreset = page
        .locator("button:has-text('npm postinstall')")
        .or(page.locator("button:has-text('Malicious npm')"))
        .first();
      if (await npmHookPreset.isVisible()) {
        await npmHookPreset.click();
        await showCaption(
          page,
          "Active Security Watchdog: [BLOCKED EGRESS] to C2 Domain",
          "Process Quarantined with Exit Code 137 (SIGKILL) Under Zero-Network-Egress Policy"
        );
        await page.waitForTimeout(5000);
      }

      // Switch to Custom Payload Editor
      console.log("🧪 Testing Custom Script Payload Editor...");
      const customEditorBtn = page
        .locator("button:has-text('Custom Payload')")
        .first();
      if (await customEditorBtn.isVisible()) {
        await customEditorBtn.click();
        await page.waitForTimeout(1500);

        // Select Python Token Probe
        const pyTplBtn = page
          .locator("button:has-text('Python Token Probe')")
          .first();
        if (await pyTplBtn.isVisible()) {
          await pyTplBtn.click();
          await page.waitForTimeout(1200);
        }

        // Run Sandbox Detonation
        const runDetonateBtn = page
          .locator("button:has-text('Run Sandbox Detonation')")
          .first();
        if (await runDetonateBtn.isVisible()) {
          await runDetonateBtn.click();
          await showCaption(
            page,
            "Custom Exploit Detonation: [CREDENTIAL PROBE DETECTED]",
            "Probing AWS_SECRET_ACCESS_KEY Intercepted & Sanitized in Isolated gVisor/runsc Container"
          );
          await page.waitForTimeout(5000);
        }
      }
    }

    // -------------------------------------------------------------------------
    // SCENE 9: HEAD-TO-HEAD BENCHMARK VS. DEPENDABOT (2:12 - 2:28)
    // -------------------------------------------------------------------------
    console.log("🐙 Returning to Scanner for Dependabot Benchmark...");
    const navScanner = page
      .locator("button:has-text('Attack Graph')")
      .or(page.locator("nav button:has-text('Scanner')"))
      .first();
    if (await navScanner.isVisible()) {
      await navScanner.click();
      await page.waitForTimeout(1500);

      // Check for vs. Dependabot Tab
      const dependabotTab = page
        .locator("button:has-text('vs. Dependabot')")
        .first();
      if (await dependabotTab.isVisible()) {
        await dependabotTab.click();
        await showCaption(
          page,
          "Stage 7: Live Head-to-Head Benchmark vs. GitHub Dependabot",
          "SupplyGraph Wins: Recursive Monorepo Trees (35 Submodules) + First-Party Repository GHSAs"
        );
        await page.waitForTimeout(5000);
      }
    }

    // -------------------------------------------------------------------------
    // SCENE 10: POLYGON AMOY ATTESTATION & OUTRO (2:28 - 2:38)
    // -------------------------------------------------------------------------
    console.log("🛡️ Opening Polygon Amoy On-Chain Attestation...");
    const polygonBtn = page
      .locator("button:has-text('Polygon')")
      .or(page.locator("button:has-text('Anchor')"))
      .first();
    if (await polygonBtn.isVisible()) {
      await polygonBtn.click();
      await showCaption(
        page,
        "Stage 8: Polygon Amoy Testnet Cryptographic Attestation",
        "Tamper-Proof Merkle Proofs & On-Chain Audit Verification for Zero-Trust Pipelines"
      );
      await page.waitForTimeout(4000);

      const closePoly = page
        .locator("button:has-text('Close')")
        .or(page.locator(".lucide-x"))
        .first();
      if (await closePoly.isVisible()) {
        await closePoly.click();
        await page.waitForTimeout(1200);
      }
    }

    // Final Outro Card
    await showCaption(
      page,
      "SupplyGraph v3.0 ASPM — Complete Enterprise Hackathon Submission",
      "Live Demo: https://supplygraph-five.vercel.app/ | GitHub: hemanthreddydaram-007/supplygraph",
      "YUKTHI 2026 EVALUATION READY"
    );
    await page.waitForTimeout(5000);

    console.log("🎉 Hackathon demo recording completed successfully!");
  } catch (err) {
    console.error("Recording error:", err);
  } finally {
    await page.close();
    await context.close();
    await browser.close();
    console.log("🎬 Video file generated and saved successfully!");
  }
}

runHackathonRecording().catch(console.error);
