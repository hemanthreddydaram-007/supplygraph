import { chromium } from "playwright";
import * as path from "path";
import * as fs from "fs";

interface SceneTiming {
  index: number;
  id: string;
  title: string;
  start_time: number;
  audio_duration: number;
  total_scene_duration: number;
  text: string;
}

interface TimingsData {
  total_duration: number;
  scene_count: number;
  scenes: SceneTiming[];
}

async function showCaption(
  page: any,
  title: string,
  subtitle: string,
  badge = "SUPPLYGRAPH v3.0 ASPM",
  stepNumber = ""
) {
  await page.evaluate(
    ({ title, subtitle, badge, stepNumber }: { title: string; subtitle: string; badge: string; stepNumber: string }) => {
      let el = document.getElementById("sg-demo-hud");
      if (!el) {
        el = document.createElement("div");
        el.id = "sg-demo-hud";
        el.style.position = "fixed";
        el.style.bottom = "24px";
        el.style.left = "50%";
        el.style.transform = "translateX(-50%)";
        el.style.zIndex = "999999";
        el.style.maxWidth = "920px";
        el.style.width = "90%";
        el.style.padding = "14px 22px";
        el.style.borderRadius = "14px";
        el.style.background = "rgba(7, 11, 19, 0.94)";
        el.style.backdropFilter = "blur(20px)";
        el.style.border = "1px solid rgba(99, 102, 241, 0.5)";
        el.style.boxShadow =
          "0 16px 48px rgba(0, 0, 0, 0.85), 0 0 24px rgba(99, 102, 241, 0.3)";
        el.style.fontFamily = "system-ui, -apple-system, sans-serif";
        el.style.transition = "all 0.3s ease";
        el.style.pointerEvents = "none";
        document.body.appendChild(el);
      }
      el.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 5px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 10px; font-weight: 700; font-family: monospace; letter-spacing: 0.1em; color: #818cf8; text-transform: uppercase;">
              🛡️ ${badge}
            </span>
            ${stepNumber ? `<span style="font-size: 10px; font-weight: 700; font-family: monospace; color: #a5b4fc; background: rgba(99, 102, 241, 0.2); padding: 1px 6px; border-radius: 4px;">${stepNumber}</span>` : ''}
          </div>
          <span style="font-size: 10px; font-family: monospace; color: #34d399; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 8px; border-radius: 9999px;">
            YUKTHI 2026 OFFICIAL EVALUATION
          </span>
        </div>
        <div style="font-size: 15px; font-weight: 700; color: #f4f4f5; line-height: 1.35;">
          ${title}
        </div>
        <div style="font-size: 12px; color: #94a3b8; margin-top: 3px; font-family: monospace;">
          ${subtitle}
        </div>
      `;
    },
    { title, subtitle, badge, stepNumber }
  );
}

async function runSynchronizedRecording() {
  let timingsPath = path.resolve("./voiceover_timings.json");
  if (!fs.existsSync(timingsPath)) {
    timingsPath = path.resolve("../voiceover_timings.json");
  }
  if (!fs.existsSync(timingsPath)) {
    throw new Error(`voiceover_timings.json not found at ${timingsPath}`);
  }
  const timings: TimingsData = JSON.parse(fs.readFileSync(timingsPath, "utf-8"));
  console.log(`⏱️ Loaded ${timings.scenes.length} scenes. Total duration: ${timings.total_duration}s`);

  const videoDir = path.resolve("./videos");
  if (!fs.existsSync(videoDir)) {
    fs.mkdirSync(videoDir, { recursive: true });
  }

  console.log("🎥 Launching Chromium Full HD 1080p (1920x1080)...");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: {
      dir: videoDir,
      size: { width: 1920, height: 1080 },
    },
  });

  const page = await context.newPage();

  try {
    // =========================================================================
    // SCENE 1: Introduction & Evaluator Fast Pass (~20.45s)
    // =========================================================================
    const s1 = timings.scenes[0];
    console.log(`\n🎬 [Scene 1/11] ${s1.title} (${s1.total_scene_duration}s)`);
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    await showCaption(
      page,
      "SupplyGraph (v3.0 ASPM): Software Supply-Chain Defense",
      "Unified Platform: Multi-Hop Attack Graphs • AI Code Reviewer • Zero-Egress Detonation Sandbox",
      "SUPPLYGRAPH v3.0 ASPM",
      "STAGE 1 OF 11"
    );
    await page.waitForTimeout(4500);

    await showCaption(
      page,
      "Evaluator Fast Pass: Instant Access for Hackathon Judges",
      "Authenticated Zero-Trust Session initialized for YUKTHI 2026 Evaluation Committee",
      "AUTHENTICATION",
      "STAGE 1 OF 11"
    );
    await page.waitForTimeout(3000);

    const fastPassBtn = page
      .locator("button:has-text('Judge Fast Pass')")
      .or(page.locator("button:has-text('Fast Pass')"))
      .first();
    if (await fastPassBtn.isVisible()) {
      await fastPassBtn.hover();
      await page.waitForTimeout(1000);
      await fastPassBtn.click();
    }
    await page.waitForTimeout(10950);

    // =========================================================================
    // SCENE 2: ASPM Dashboard & Telemetry HUD (~21.19s)
    // =========================================================================
    const s2 = timings.scenes[1];
    console.log(`🎬 [Scene 2/11] ${s2.title} (${s2.total_scene_duration}s)`);
    await showCaption(
      page,
      "Central ASPM Telemetry: Continuous Multi-Ecosystem Surveillance",
      "Correlating Direct & Transitive Dependencies across npm, PyPI, Go, and GitHub Actions",
      "ASPM TELEMETRY",
      "STAGE 2 OF 11"
    );
    await page.waitForTimeout(4500);

    // Smooth scroll down to view preset attack scenarios
    await page.mouse.wheel(0, 420);
    await page.waitForTimeout(4500);

    // Hover over scenario cards
    const cardB = page.locator("text=Scenario B").first();
    if (await cardB.isVisible()) {
      await cardB.hover();
      await page.waitForTimeout(2500);
    }
    const cardC = page.locator("text=Scenario C").first();
    if (await cardC.isVisible()) {
      await cardC.hover();
      await page.waitForTimeout(2500);
    }

    // Scroll back to top
    await page.mouse.wheel(0, -420);
    await page.waitForTimeout(7190);

    // =========================================================================
    // SCENE 3: Multi-Hop Attack Graph (Log4j RCE DAG) (~28.32s)
    // =========================================================================
    const s3 = timings.scenes[2];
    console.log(`🎬 [Scene 3/11] ${s3.title} (${s3.total_scene_duration}s)`);
    await showCaption(
      page,
      "Scenario A: Deterministic Reverse-BFS Attack Graph DAG",
      "NetworkX Traversal from Ingress server.js ➔ payment-service ➔ log4j-core:2.14.1",
      "ATTACK REACHABILITY",
      "STAGE 3 OF 11"
    );

    const scenarioABtn = page
      .locator("button:has-text('Scenario A')")
      .or(page.locator("text=Scenario A"))
      .first();
    if (await scenarioABtn.isVisible()) {
      await scenarioABtn.click();
    }
    await page.waitForTimeout(5000);

    // Center on node and highlight blast radius
    await showCaption(
      page,
      "Quantified Mathematical HUD: Blast Radius 85.0 / 100",
      "True Runtime Reachability Proven: CVE-2021-44228 JNDI Exploit Call Chain Confirmed",
      "ATTACK REACHABILITY",
      "STAGE 3 OF 11"
    );
    await page.waitForTimeout(6000);

    // Pan/drag graph canvas slightly to show 60fps interactivity
    await page.mouse.move(700, 400);
    await page.mouse.down();
    await page.mouse.move(650, 380, { steps: 10 });
    await page.mouse.up();
    await page.waitForTimeout(5000);

    await page.mouse.move(650, 380);
    await page.mouse.down();
    await page.mouse.move(700, 400, { steps: 10 });
    await page.mouse.up();
    await page.waitForTimeout(12320);

    // =========================================================================
    // SCENE 4: Autonomous Executive AI Briefing (~18.77s)
    // =========================================================================
    const s4 = timings.scenes[3];
    console.log(`🎬 [Scene 4/11] ${s4.title} (${s4.total_scene_duration}s)`);
    const briefingTab = page.locator("button:has-text('Executive AI')").first();
    if (await briefingTab.isVisible()) {
      await briefingTab.click();
      await page.waitForTimeout(1200);
    }

    await showCaption(
      page,
      "Autonomous Executive AI Security Briefing",
      "Exploit Breakdown, Multi-Hop Call Path Proof & Prioritized Engineering Protocols",
      "EXECUTIVE AI",
      "STAGE 4 OF 11"
    );
    await page.waitForTimeout(6000);

    // Scroll down inside Executive AI briefing
    await page.mouse.wheel(0, 250);
    await page.waitForTimeout(5000);
    await page.mouse.wheel(0, -250);
    await page.waitForTimeout(6570);

    // =========================================================================
    // SCENE 5: Fix with AI Master Remediation Generator (~20.71s)
    // =========================================================================
    const s5 = timings.scenes[4];
    console.log(`🎬 [Scene 5/11] ${s5.title} (${s5.total_scene_duration}s)`);
    const fixWithAiBtn = page.locator("button:has-text('Fix with AI')").first();
    if (await fixWithAiBtn.isVisible()) {
      await fixWithAiBtn.click();
      await page.waitForTimeout(1200);
    }

    await showCaption(
      page,
      "Fix with AI: Evidence-Grounded Remediation Generator",
      "Non-Breaking Version Constraints & 3-Tier Modification Boundaries for Coding Agents",
      "PROMPT GENERATOR",
      "STAGE 5 OF 11"
    );
    await page.waitForTimeout(6000);

    // Scroll through prompt generator modal
    await page.mouse.wheel(0, 300);
    await page.waitForTimeout(4000);

    // Click copy prompt button
    const copyPromptBtn = page.locator("button:has-text('Copy Prompt')").first();
    if (await copyPromptBtn.isVisible()) {
      await copyPromptBtn.click();
      await page.waitForTimeout(2000);
    }

    // Close modal
    const closeFixModal = page
      .locator("button:has-text('Close')")
      .or(page.locator("button[aria-label='Close']"))
      .first();
    if (await closeFixModal.isVisible()) {
      await closeFixModal.click();
    }
    await page.waitForTimeout(7510);

    // =========================================================================
    // SCENE 6: CycloneDX v1.5 SBOM & Deterministic Hash (~22.54s)
    // =========================================================================
    const s6 = timings.scenes[5];
    console.log(`🎬 [Scene 6/11] ${s6.title} (${s6.total_scene_duration}s)`);
    const sbomBtn = page.locator("button:has-text('CycloneDX SBOM')").first();
    if (await sbomBtn.isVisible()) {
      await sbomBtn.click();
      await page.waitForTimeout(1200);
    }

    await showCaption(
      page,
      "CycloneDX v1.5 SBOM with Web Crypto Deterministic SHA-256",
      "Cryptographic Inventory Digest & Tamper-Evident Attestation for Enterprise Compliance",
      "SBOM ATTESTATION",
      "STAGE 6 OF 11"
    );
    await page.waitForTimeout(6000);

    // Copy SHA-256 Digest
    const copyShaBtn = page.locator("button[title*='Copy SHA']").first();
    if (await copyShaBtn.isVisible()) {
      await copyShaBtn.hover();
      await page.waitForTimeout(1000);
      await copyShaBtn.click();
      await page.waitForTimeout(2500);
    }

    // Close SBOM modal
    const closeSbom = page
      .locator("button:has-text('Close')")
      .or(page.locator("button[aria-label='Close']"))
      .or(page.locator(".lucide-x"))
      .first();
    if (await closeSbom.isVisible()) {
      await closeSbom.click();
    }
    await page.waitForTimeout(11840);

    // =========================================================================
    // SCENE 7: AI Code Reviewer & Line-Level Unified Diffs (~22.54s)
    // =========================================================================
    const s7 = timings.scenes[6];
    console.log(`🎬 [Scene 7/11] ${s7.title} (${s7.total_scene_duration}s)`);
    const navReviewer = page
      .locator("button:has-text('AI Code Reviewer')")
      .or(page.locator("nav button:has-text('Reviewer')"))
      .first();
    if (await navReviewer.isVisible()) {
      await navReviewer.click();
      await page.waitForTimeout(1500);
    }

    await showCaption(
      page,
      "AI Code Reviewer: Line-Level Surgical Git Diffs",
      "AST Vulnerability Patches: Prototype Pollution, Insecure Deserialization & XSS",
      "CODE REVIEWER",
      "STAGE 7 OF 11"
    );
    await page.waitForTimeout(5500);

    // Switch to Stacked View
    const stackedBtn = page.locator("button:has-text('Stacked View')").first();
    if (await stackedBtn.isVisible()) {
      await stackedBtn.click();
      await page.waitForTimeout(3500);
    }

    // Switch back to Unified Diff
    const unifiedBtn = page.locator("button:has-text('Unified Git Diff')").first();
    if (await unifiedBtn.isVisible()) {
      await unifiedBtn.click();
      await page.waitForTimeout(2500);
    }
    await page.waitForTimeout(9540);

    // =========================================================================
    // SCENE 8: Ad-Hoc Live Code Analyzer (~20.52s)
    // =========================================================================
    const s8 = timings.scenes[7];
    console.log(`🎬 [Scene 8/11] ${s8.title} (${s8.total_scene_duration}s)`);
    const adhocBtn = page
      .locator("button:has-text('Ad-Hoc')")
      .or(page.locator("button:has-text('Paste Custom File')"))
      .first();
    if (await adhocBtn.isVisible()) {
      await adhocBtn.click();
      await page.waitForTimeout(1200);
    }

    await showCaption(
      page,
      "Ad-Hoc Live Code Analyzer: Instant AST Vulnerability Audit",
      "Audits Arbitrary Python, JS/TS, and YAML/GitHub Actions Snippets with Zero-Config",
      "LIVE ANALYZER",
      "STAGE 8 OF 11"
    );
    await page.waitForTimeout(4000);

    // Fill sample Python code
    const textarea = page.locator("textarea").first();
    if (await textarea.isVisible()) {
      await textarea.fill("import subprocess\ndef execute(cmd, cache=[]):\n    subprocess.run(cmd, shell=True)\n");
      await page.waitForTimeout(1500);
    }

    // Click Review Code & Output Patch
    const runReviewBtn = page.locator("button:has-text('Review Code & Output Patch')").first();
    if (await runReviewBtn.isVisible()) {
      await runReviewBtn.click();
      await page.waitForTimeout(4000);
    }
    await page.waitForTimeout(9820);

    // =========================================================================
    // SCENE 9: Universal Detonation Sandbox (~23.81s)
    // =========================================================================
    const s9 = timings.scenes[8];
    console.log(`🎬 [Scene 9/11] ${s9.title} (${s9.total_scene_duration}s)`);
    const navSandbox = page
      .locator("button:has-text('Detonation Sandbox')")
      .or(page.locator("nav button:has-text('Sandbox')"))
      .first();
    if (await navSandbox.isVisible()) {
      await navSandbox.click();
      await page.waitForTimeout(1500);
    }

    await showCaption(
      page,
      "Universal Secure Execution & Detonation Sandbox",
      "Intercepting Malicious Lifecycle Hooks: Zero-Network-Egress Quarantines C2 Traffic",
      "DETONATION SANDBOX",
      "STAGE 9 OF 11"
    );
    await page.waitForTimeout(4000);

    // Run malicious npm hook preset
    const npmHookPreset = page
      .locator("button:has-text('npm postinstall')")
      .or(page.locator("button:has-text('Malicious npm')"))
      .first();
    if (await npmHookPreset.isVisible()) {
      await npmHookPreset.click();
      await page.waitForTimeout(4000);
    }

    // Test Python Token Probe preset
    const customEditorBtn = page.locator("button:has-text('Custom Payload')").first();
    if (await customEditorBtn.isVisible()) {
      await customEditorBtn.click();
      await page.waitForTimeout(1200);

      const pyTplBtn = page.locator("button:has-text('Python Token Probe')").first();
      if (await pyTplBtn.isVisible()) {
        await pyTplBtn.click();
        await page.waitForTimeout(1200);
      }

      const runDetonateBtn = page.locator("button:has-text('Run Sandbox Detonation')").first();
      if (await runDetonateBtn.isVisible()) {
        await runDetonateBtn.click();
        await page.waitForTimeout(4000);
      }
    }
    await page.waitForTimeout(7910);

    // =========================================================================
    // SCENE 10: Head-to-Head Benchmark vs. GitHub Dependabot (~20.76s)
    // =========================================================================
    const s10 = timings.scenes[9];
    console.log(`🎬 [Scene 10/11] ${s10.title} (${s10.total_scene_duration}s)`);
    const navScanner = page
      .locator("button:has-text('Attack Graph')")
      .or(page.locator("nav button:has-text('Scanner')"))
      .first();
    if (await navScanner.isVisible()) {
      await navScanner.click();
      await page.waitForTimeout(1500);
    }

    const dependabotTab = page.locator("button:has-text('vs. Dependabot')").first();
    if (await dependabotTab.isVisible()) {
      await dependabotTab.click();
      await page.waitForTimeout(1200);
    }

    await showCaption(
      page,
      "Live Head-to-Head Benchmark vs. GitHub Dependabot",
      "SupplyGraph Outperforms: 35 Recursive Submodules + 6 First-Party GHSAs in listmonk",
      "HEAD-TO-HEAD BENCHMARK",
      "STAGE 10 OF 11"
    );
    await page.waitForTimeout(5500);

    // Scroll across benchmark table
    await page.mouse.wheel(0, 220);
    await page.waitForTimeout(3500);
    await page.mouse.wheel(0, -220);
    await page.waitForTimeout(9060);

    // =========================================================================
    // SCENE 11: Polygon Amoy Cryptographic Anchor & Conclusion (~19.34s)
    // =========================================================================
    const s11 = timings.scenes[10];
    console.log(`🎬 [Scene 11/11] ${s11.title} (${s11.total_scene_duration}s)`);
    const polygonBtn = page
      .locator("button:has-text('Polygon')")
      .or(page.locator("button:has-text('Anchor')"))
      .first();
    if (await polygonBtn.isVisible()) {
      await polygonBtn.click();
      await page.waitForTimeout(1200);
    }

    await showCaption(
      page,
      "Polygon Amoy Testnet Cryptographic Attestation",
      "Tamper-Proof Merkle Proofs & Immutable On-Chain Audit Trail for Zero-Trust Pipelines",
      "BLOCKCHAIN ANCHOR",
      "STAGE 11 OF 11"
    );
    await page.waitForTimeout(5500);

    const closePoly = page
      .locator("button:has-text('Close')")
      .or(page.locator(".lucide-x"))
      .first();
    if (await closePoly.isVisible()) {
      await closePoly.click();
      await page.waitForTimeout(1200);
    }

    // Final Outro Card
    await showCaption(
      page,
      "SupplyGraph v3.0 ASPM — Complete Enterprise Hackathon Submission",
      "Live Demo: https://supplygraph-five.vercel.app/ | GitHub: hemanthreddydaram-007/supplygraph",
      "YUKTHI 2026 READY",
      "CONCLUSION"
    );
    await page.waitForTimeout(11440);

    console.log("🎉 Synchronized recording session completed!");
  } catch (err) {
    console.error("Recording error:", err);
  } finally {
    await page.close();
    await context.close();
    await browser.close();
    console.log("🎬 Video file generated and saved successfully!");
  }
}

runSynchronizedRecording().catch(console.error);
