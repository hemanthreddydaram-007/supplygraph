import { chromium, Page } from "playwright";
import * as path from "path";
import * as fs from "fs";

interface SubtitleItem {
  id: number;
  part: number;
  section_tag: string;
  section_num: string;
  title: string;
  start: number;
  end: number;
  duration: number;
  text: string;
}

interface SectionItem {
  index: number;
  id: string;
  section_num: string;
  section_tag: string;
  title: string;
  start_time: number;
  audio_duration: number;
  end_time: number;
  file: string;
  subtitles: SubtitleItem[];
}

interface TimingsData {
  voice: string;
  total_duration: number;
  section_count: number;
  sections: SectionItem[];
}

/**
 * Injects a synchronized high-contrast HUD for subtitles and section indicators.
 */
async function updateSubtitleHUD(
  page: Page,
  sectionTag: string,
  sectionNum: string,
  title: string,
  subtitleText: string
) {
  const payload = JSON.stringify({ sectionTag, sectionNum, title, subtitleText });
  await page.evaluate(`
    (function(args) {
      var sectionTag = args.sectionTag;
      var sectionNum = args.sectionNum;
      var title = args.title;
      var subtitleText = args.subtitleText;
      var el = document.getElementById("sg-user-subtitle-hud");
      if (!el) {
        el = document.createElement("div");
        el.id = "sg-user-subtitle-hud";
        el.style.position = "fixed";
        el.style.bottom = "24px";
        el.style.left = "50%";
        el.style.transform = "translateX(-50%)";
        el.style.zIndex = "9999999";
        el.style.maxWidth = "1180px";
        el.style.width = "92%";
        el.style.padding = "16px 24px";
        el.style.borderRadius = "16px";
        el.style.background = "rgba(7, 11, 20, 0.95)";
        el.style.backdropFilter = "blur(24px)";
        el.style.border = "1px solid rgba(99, 102, 241, 0.6)";
        el.style.boxShadow = "0 20px 60px rgba(0, 0, 0, 0.95), 0 0 36px rgba(99, 102, 241, 0.35)";
        el.style.fontFamily = "system-ui, -apple-system, sans-serif";
        el.style.transition = "all 0.2s ease";
        el.style.pointerEvents = "none";
        document.body.appendChild(el);
      }
      el.innerHTML = [
        '<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">',
          '<div style="display: flex; align-items: center; gap: 8px;">',
            '<span style="font-size: 11px; font-weight: 800; font-family: monospace; letter-spacing: 0.12em; color: #818cf8; text-transform: uppercase;">',
              '🛡️ SUPPLYGRAPH v3.0 ASPM',
            '</span>',
            '<span style="font-size: 10px; font-weight: 700; font-family: monospace; color: #a5b4fc; background: rgba(99, 102, 241, 0.25); border: 1px solid rgba(99, 102, 241, 0.4); padding: 2px 8px; border-radius: 4px;">',
              '[PART ' + sectionNum + '] ' + sectionTag,
            '</span>',
          '</div>',
          '<div style="display: flex; align-items: center; gap: 8px;">',
            '<span style="font-size: 10px; font-family: monospace; color: #34d399; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 8px; border-radius: 9999px;">',
              '🎙️ OFFICIAL PRESENTATION VOICE',
            '</span>',
            '<span style="font-size: 10px; font-family: monospace; color: #fbbf24; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); padding: 2px 8px; border-radius: 9999px;">',
              'LIVE SUBTITLES',
            '</span>',
          '</div>',
        '</div>',
        '<div style="font-size: 13.5px; font-weight: 700; color: #c7d2fe; margin-bottom: 6px; font-family: monospace;">',
          title,
        '</div>',
        '<div style="font-size: 16px; font-weight: 600; color: #ffffff; line-height: 1.45; background: rgba(15, 23, 42, 0.8); padding: 10px 16px; border-radius: 8px; border-left: 4px solid #6366f1;">',
          '💬 "' + subtitleText + '"',
        '</div>'
      ].join("");
    })(${payload})
  `);
}

/**
 * Injects virtual mouse cursor indicator and a continuous RAF heartbeat
 * so Chromium recordVideo NEVER drops frames or desynchronizes timing.
 */
async function injectVirtualCursorAndHeartbeat(page: Page) {
  await page.evaluate(`
    (function() {
      var cursor = document.getElementById("sg-virtual-cursor");
      if (!cursor) {
        cursor = document.createElement("div");
        cursor.id = "sg-virtual-cursor";
        cursor.style.position = "fixed";
        cursor.style.top = "0px";
        cursor.style.left = "0px";
        cursor.style.width = "22px";
        cursor.style.height = "22px";
        cursor.style.borderRadius = "50%";
        cursor.style.background = "rgba(239, 68, 68, 0.85)";
        cursor.style.border = "2px solid #ffffff";
        cursor.style.boxShadow = "0 0 14px rgba(239, 68, 68, 0.95)";
        cursor.style.pointerEvents = "none";
        cursor.style.zIndex = "99999999";
        cursor.style.transform = "translate(-50%, -50%)";
        cursor.style.transition = "transform 0.08s ease-out, background 0.1s ease";
        document.body.appendChild(cursor);

        var cur = cursor;
        window.addEventListener("mousemove", function(e) {
          if (cur) {
            cur.style.left = e.clientX + "px";
            cur.style.top = e.clientY + "px";
          }
        });
        window.addEventListener("mousedown", function() {
          if (cur) {
            cur.style.transform = "translate(-50%, -50%) scale(0.75)";
            cur.style.background = "rgba(245, 158, 11, 0.95)";
          }
        });
        window.addEventListener("mouseup", function() {
          if (cur) {
            cur.style.transform = "translate(-50%, -50%) scale(1.0)";
            cur.style.background = "rgba(239, 68, 68, 0.85)";
          }
        });
      }

      if (!document.getElementById("sg-recording-heartbeat")) {
        var hb = document.createElement("div");
        hb.id = "sg-recording-heartbeat";
        hb.style.position = "fixed";
        hb.style.top = "0px";
        hb.style.right = "0px";
        hb.style.width = "2px";
        hb.style.height = "2px";
        hb.style.opacity = "0.01";
        hb.style.pointerEvents = "none";
        hb.style.zIndex = "99999999";
        document.body.appendChild(hb);

        var count = 0;
        function pulse() {
          count++;
          hb.style.transform = "rotate(" + (count % 360) + "deg)";
          window.requestAnimationFrame(pulse);
        }
        window.requestAnimationFrame(pulse);
      }
    })();
  `);
}

/**
 * Show a sleek Thank You outro card at the end of Part 4.
 */
async function showThankYouCard(page: Page) {
  await page.evaluate(`
    (function() {
      var card = document.createElement("div");
      card.id = "sg-thank-you-card";
      card.style.position = "fixed";
      card.style.inset = "0";
      card.style.zIndex = "99999998";
      card.style.display = "flex";
      card.style.flexDirection = "column";
      card.style.alignItems = "center";
      card.style.justifyContent = "center";
      card.style.background = "rgba(7, 11, 19, 0.95)";
      card.style.backdropFilter = "blur(20px)";
      card.style.color = "#ffffff";
      card.style.fontFamily = "system-ui, -apple-system, sans-serif";

      card.innerHTML = [
        '<div style="text-align: center; max-width: 820px; padding: 48px; background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(99, 102, 241, 0.4); border-radius: 28px; box-shadow: 0 25px 70px rgba(0,0,0,0.8), 0 0 40px rgba(99, 102, 241, 0.25);">',
          '<div style="width: 76px; height: 76px; margin: 0 auto 20px; border-radius: 22px; background: linear-gradient(135deg, #ef4444, #6366f1); display: flex; align-items: center; justify-content: center; box-shadow: 0 10px 30px rgba(239, 68, 68, 0.4);">',
            '<span style="font-size: 38px;">🛡️</span>',
          '</div>',
          '<h1 style="font-size: 44px; font-weight: 800; margin: 0 0 12px; background: linear-gradient(to right, #ffffff, #c7d2fe); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">',
            'SupplyGraph v3.0 ASPM',
          '</h1>',
          '<p style="font-size: 18px; color: #94a3b8; margin: 0 0 28px; font-family: monospace;">',
            'Stop supply-chain threats before production deployment.',
          '</p>',
          '<div style="display: flex; gap: 12px; justify-content: center; margin-bottom: 32px;">',
            '<span style="padding: 6px 16px; border-radius: 9999px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); color: #34d399; font-size: 13px; font-family: monospace; font-weight: 600;">',
              '✓ Multi-Hop Graph Traversal',
            '</span>',
            '<span style="padding: 6px 16px; border-radius: 9999px; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.35); color: #818cf8; font-size: 13px; font-family: monospace; font-weight: 600;">',
              '✓ AI Code Reviewer Auto-Patching',
            '</span>',
            '<span style="padding: 6px 16px; border-radius: 9999px; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); color: #fbbf24; font-size: 13px; font-family: monospace; font-weight: 600;">',
              '✓ Detonation Container Sandbox',
            '</span>',
          '</div>',
          '<div style="padding: 16px 24px; border-radius: 16px; background: rgba(0, 0, 0, 0.5); border: 1px solid rgba(255, 255, 255, 0.1); margin-bottom: 24px;">',
            '<div style="font-size: 12px; color: #64748b; font-family: monospace; margin-bottom: 4px;">LIVE DEPLOYMENT URL</div>',
            '<div style="font-size: 22px; font-weight: 700; color: #38bdf8; font-family: monospace;">',
              'supplygraph-five.vercel.app',
            '</div>',
          '</div>',
          '<div style="font-size: 30px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em;">',
            'Thank You Respected Judges! 🙏',
          '</div>',
          '<div style="font-size: 13px; color: #64748b; margin-top: 12px; font-family: monospace;">',
            'YUKTHI 2026 • Mohan Babu University • Cybersecurity (ASPM) Track',
          '</div>',
        '</div>'
      ].join("");
      document.body.appendChild(card);
    })();
  `);
}

/**
 * Precision wait until target timestamp based on performance/wall-clock time.
 */
async function waitElapsed(startTimeMs: number, targetSec: number, page: Page) {
  const targetMs = targetSec * 1000;
  while (Date.now() - startTimeMs < targetMs) {
    const remaining = targetMs - (Date.now() - startTimeMs);
    const step = Math.min(remaining, 100);
    if (step <= 0) break;
    await page.waitForTimeout(step);
  }
}

async function runRecording() {
  let timingsPath = path.resolve("./four_part_voiceover_timings.json");
  if (!fs.existsSync(timingsPath)) {
    timingsPath = path.resolve("../four_part_voiceover_timings.json");
  }
  const timings: TimingsData = JSON.parse(fs.readFileSync(timingsPath, "utf-8"));
  console.log(`⏱️ Total planned duration: ${timings.total_duration}s across 4 sections.`);

  const videoDir = path.resolve("./videos");
  if (!fs.existsSync(videoDir)) {
    fs.mkdirSync(videoDir, { recursive: true });
  }

  // Intercept listmonk API scan to provide cached instant 35-submodule response
  let listmonkCache: any = null;
  const cachePath = path.resolve("../listmonk_cache.json");
  if (fs.existsSync(cachePath)) {
    try {
      listmonkCache = JSON.parse(fs.readFileSync(cachePath, "utf-8"));
    } catch (_) {}
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

  if (listmonkCache) {
    await page.route("**/api/v1/analyze", async (route) => {
      const postData = route.request().postDataJSON();
      if (postData && postData.github_url && postData.github_url.includes("listmonk")) {
        console.log("Serving cached listmonk scan with benchmark!");
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(listmonkCache),
        });
      } else {
        await route.continue();
      }
    });
  }

  try {
    const startTime = Date.now();
    console.log(`🎬 Recording session started at: ${new Date(startTime).toLocaleTimeString()}`);

    // =========================================================================
    // SECTION 1: THE REAL-WORLD PROBLEM [0.00s -> 59.13s]
    // REQUIREMENT: "for 1st para shows only login page and explains the real world problem until the para completes"
    // =========================================================================
    const s1 = timings.sections[0];
    console.log(`\n🎬 [Section 1/4] ${s1.title} (0.00s -> ${s1.end_time}s)`);

    // Navigate to Login Page
    await page.goto("http://localhost:3000/?login=true", { waitUntil: "networkidle" });
    try {
      const signOutBtn = page.locator("button").filter({ hasText: /Sign Out/i }).first();
      if (await signOutBtn.isVisible()) {
        await signOutBtn.click({ force: true });
        await page.waitForTimeout(400);
      }
    } catch (_) {}

    await injectVirtualCursorAndHeartbeat(page);

    // Subtitle 1.1: "Hello everyone, and respected judges!" [0.0s -> 3.49s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[0].text);
    await page.mouse.move(960, 400, { steps: 8 });
    await waitElapsed(startTime, s1.subtitles[0].end, page);

    // Subtitle 1.2: "Today, modern software applications are built using hundreds of open-source packages..." [3.49s -> 13.98s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[1].text);
    await page.mouse.move(450, 200, { steps: 10 }); // Point to Brand Header
    await page.mouse.move(450, 320, { steps: 10 }); // Point to Mission Statement
    await waitElapsed(startTime, s1.subtitles[1].end, page);

    // Subtitle 1.3: "While open-source libraries allow engineering teams to build products rapidly..." [13.98s -> 23.70s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[2].text);
    await page.mouse.move(350, 480, { steps: 10 }); // Deterministic DAG
    await page.mouse.move(550, 480, { steps: 10 }); // Standard SBOM (CycloneDX)
    await page.mouse.move(350, 560, { steps: 10 }); // AI Code Reviewer
    await page.mouse.move(550, 560, { steps: 10 }); // Quantified Math HUD
    await waitElapsed(startTime, s1.subtitles[2].end, page);

    // Subtitle 1.4: "In large codebases, applications contain deeply nested dependency trees with multiple transitive layers." [23.70s -> 31.70s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[3].text);
    await page.mouse.move(1200, 340, { steps: 12 }); // Move to right panel (Fast Social Login)
    await page.mouse.move(1120, 340, { steps: 8 });  // Hover Google
    await page.mouse.move(1280, 340, { steps: 8 });  // Hover GitHub
    await waitElapsed(startTime, s1.subtitles[3].end, page);

    // Subtitle 1.5: "The critical problem for engineering teams is knowing: Which vulnerabilities are actually reachable..." [31.70s -> 42.44s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[4].text);
    // Switch to Create Account tab to show form fields
    try {
      const createAccBtn = page.locator("button").filter({ hasText: /Create Account/i }).first();
      if (await createAccBtn.isVisible()) {
        await createAccBtn.click({ force: true });
        await page.waitForTimeout(300);
      }
    } catch (_) {}
    // Smoothly scroll down the right panel to show full form and buttons (proving scrolling is working!)
    const rightPanel = page.locator(".lg\\:w-1\\/2").nth(1);
    await rightPanel.hover();
    await page.mouse.wheel(0, 300);
    await page.waitForTimeout(300);
    await waitElapsed(startTime, s1.subtitles[4].end, page);

    // Subtitle 1.6: "Without reachability analysis, developers spend weeks chasing false alarms or risk breaking live backend APIs..." [42.44s -> 52.88s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[5].text);
    await page.mouse.move(1200, 680, { steps: 10 }); // Point to "Create Account & Login" button
    await page.waitForTimeout(600);
    // Scroll back up to the top
    await page.mouse.wheel(0, -320);
    await page.waitForTimeout(400);
    await waitElapsed(startTime, s1.subtitles[5].end, page);

    // Subtitle 1.7: "That is why modern software security requires a deeper, code-aware approach." [52.88s -> 59.13s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[6].text);
    await page.mouse.move(1200, 240, { steps: 10 }); // Hover on Judge Fast Pass banner
    await waitElapsed(startTime, s1.end_time, page);

    // =========================================================================
    // SECTION 2: PROPOSED SOLUTION & HOW SUPPLYGRAPH WORKS [59.13s -> 115.69s]
    // REQUIREMENT: "for 2nd para opens the main page and explain the proposed solution using supplygraph and explain how supplygraph works"
    // =========================================================================
    const s2 = timings.sections[1];
    console.log(`\n🎬 [Section 2/4] ${s2.title} (${s2.start_time}s -> ${s2.end_time}s)`);

    // EXACT ACTION: Click "⚡ Instant Login" (Judge Fast-Pass) right at start of Part 2!
    const fastPassBtn = page.locator("button:has-text('Instant Login')").first();
    await fastPassBtn.hover();
    await page.waitForTimeout(200);
    await fastPassBtn.click({ force: true });
    await page.waitForTimeout(1000);
    await injectVirtualCursorAndHeartbeat(page);

    // Subtitle 2.1: "To address this challenge, we created SupplyGraph." [59.13s -> 63.60s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[0].text);
    await page.mouse.move(960, 200, { steps: 10 });
    await waitElapsed(startTime, s2.subtitles[0].end, page);

    // Subtitle 2.2: "SupplyGraph is an Application Security Posture Management platform designed to give developers complete visibility..." [63.60s -> 74.00s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[1].text);
    // Point to user profile in navbar (shows Judge / Evaluator logged in)
    await page.mouse.move(1750, 40, { steps: 10 });
    await page.waitForTimeout(600);
    // Move across top telemetry counters
    await page.mouse.move(400, 140, { steps: 10 });
    await page.mouse.move(700, 140, { steps: 10 });
    await page.mouse.move(1000, 140, { steps: 10 });
    await waitElapsed(startTime, s2.subtitles[1].end, page);

    // Subtitle 2.3: "Instead of treating dependencies as flat isolated lists, SupplyGraph inspects your actual code and builds an interactive visual attack graph." [74.00s -> 85.00s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[2].text);
    // Smoothly scroll down the main Overview page to show architecture & ecosystems
    await page.mouse.wheel(0, 360);
    await page.waitForTimeout(400);
    await page.mouse.move(600, 420, { steps: 10 }); // npm, PyPI, Go badges
    await waitElapsed(startTime, s2.subtitles[2].end, page);

    // Subtitle 2.4: "It connects your application from user-facing entry points all the way down to deeply nested packages." [85.00s -> 94.00s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[3].text);
    await page.mouse.move(960, 480, { steps: 10 });
    await page.mouse.wheel(0, 240);
    await page.waitForTimeout(400);
    await waitElapsed(startTime, s2.subtitles[3].end, page);

    // Subtitle 2.5: "SupplyGraph clearly verifies whether an execution path can actually reach a vulnerable component in runtime." [94.00s -> 103.50s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[4].text);
    await page.mouse.move(800, 520, { steps: 10 });
    await waitElapsed(startTime, s2.subtitles[4].end, page);

    // Subtitle 2.6: "When a reachable security risk is identified, SupplyGraph provides safe, line-by-line code patches that preserve application functionality..." [103.50s -> 115.69s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[5].text);
    // Scroll back up to the top navigation
    await page.mouse.wheel(0, -600);
    await page.waitForTimeout(400);
    await page.mouse.move(300, 40, { steps: 10 }); // Point to Scanner tab
    await waitElapsed(startTime, s2.end_time, page);

    // =========================================================================
    // SECTION 3: CORE FEATURES & 5 DEMO SCENARIOS [115.69s -> 201.61s]
    // REQUIREMENT: "it explains the features and shows the 5 demo scenarios while explaining them"
    // =========================================================================
    const s3 = timings.sections[2];
    console.log(`\n🎬 [Section 3/4] ${s3.title} (${s3.start_time}s -> ${s3.end_time}s)`);

    // Click Scanner & Graph tab in navigation
    const scannerNav = page.locator('nav button:has-text("Scanner & Graph")').first();
    await scannerNav.click();
    await page.waitForTimeout(800);
    await injectVirtualCursorAndHeartbeat(page);

    // GUARANTEED ACTION: Load Scenario A immediately so canvas has active graph!
    const loadABtn = page.locator('button:has-text("Load Scenario A")').first();
    if (await loadABtn.isVisible()) {
      await loadABtn.click();
      await page.waitForTimeout(1200);
      console.log("Loaded Scenario A initially!");
    }

    // Subtitle 3.1: "Let us examine the core capabilities of SupplyGraph and our five preloaded real-world scenarios:" [115.69s -> 122.50s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[0].text);
    await page.mouse.move(960, 300, { steps: 8 });
    await waitElapsed(startTime, s3.subtitles[0].end, page);

    // Subtitle 3.2: "First is the Attack Graph, powered by graph traversal algorithms to visually map call paths..." [122.50s -> 135.00s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[1].text);
    // Interactive graph canvas drag
    await page.mouse.move(650, 450);
    await page.mouse.down();
    await page.mouse.move(580, 410, { steps: 10 });
    await page.mouse.up();
    await waitElapsed(startTime, s3.subtitles[1].end, page);

    // Subtitle 3.3: "Second is the Blast Radius Score from zero to hundred, quantifying the operational risk of each finding." [135.00s -> 144.00s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[2].text);
    await page.mouse.move(960, 220, { steps: 10 }); // Point to Blast Radius badge
    await waitElapsed(startTime, s3.subtitles[2].end, page);

    // Subtitle 3.4: "Third is the Autonomous Executive AI, translating technical vulnerability data into clear executive summaries..." [144.00s -> 154.00s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[3].text);
    try {
      const execAiTab = page.locator("button").filter({ hasText: /Executive AI/i }).first();
      if (await execAiTab.isVisible()) {
        await execAiTab.click({ force: true });
        await page.waitForTimeout(600);
        await page.mouse.move(1600, 450, { steps: 8 });
        await page.mouse.wheel(0, 140);
      }
    } catch (_) {}
    await waitElapsed(startTime, s3.subtitles[3].end, page);

    // Subtitle 3.5: "And fourth is the CycloneDX SBOM, generating industry-standard Software Bill of Materials documents..." [154.00s -> 164.50s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[4].text);
    try {
      const sbomBtn = page.locator("button").filter({ hasText: /CycloneDX SBOM/i }).first();
      if (await sbomBtn.isVisible()) {
        await sbomBtn.click({ force: true });
        await page.waitForTimeout(1000);
        const closeBtn = page.locator("button").filter({ hasText: /Close/i }).or(page.locator(".lucide-x")).first();
        if (await closeBtn.isVisible()) {
          await closeBtn.click({ force: true });
        }
      }
    } catch (_) {}
    await waitElapsed(startTime, s3.subtitles[4].end, page);

    // Helper to select scenario from dropdown reliably
    const triggerScenario = async (scenKey: string) => {
      try {
        const dropdownBtn = page.locator("button:has-text('Scenario'), button:has-text('Demo Scenarios')").first();
        await dropdownBtn.click();
        await page.waitForTimeout(250);
        const option = page.locator(`button:has-text("Scenario ${scenKey}")`).last();
        if (await option.isVisible()) {
          await option.click();
          await page.waitForTimeout(800);
        }
      } catch (_) {}
    };

    // Subtitle 3.6: "To demonstrate this, SupplyGraph includes five preloaded scenarios:" [164.50s -> 170.50s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[5].text);
    await page.mouse.move(780, 75, { steps: 8 }); // Point to Scenario dropdown
    await waitElapsed(startTime, s3.subtitles[5].end, page);

    // Subtitle 3.7: "Scenario A traces a transitive Log4j call path traveling deep into server logging." [170.50s -> 177.00s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[6].text);
    await triggerScenario("A");
    await page.mouse.move(600, 420, { steps: 8 });
    await waitElapsed(startTime, s3.subtitles[6].end, page);

    // Subtitle 3.8: "Scenario B audits JavaScript Prototype Pollution, identifying risky object merging." [177.00s -> 183.50s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[7].text);
    await triggerScenario("B");
    await page.mouse.move(650, 430, { steps: 8 });
    await waitElapsed(startTime, s3.subtitles[7].end, page);

    // Subtitle 3.9: "Scenario C detects insecure Python pickle deserialization before execution." [183.50s -> 189.50s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[8].text);
    await triggerScenario("C");
    await page.mouse.move(700, 440, { steps: 8 });
    await waitElapsed(startTime, s3.subtitles[8].end, page);

    // Subtitle 3.10: "Scenario D audits GitHub Actions workflows to ensure immutable commit hashes." [189.50s -> 195.50s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[9].text);
    await triggerScenario("D");
    await page.mouse.move(650, 420, { steps: 8 });
    await waitElapsed(startTime, s3.subtitles[9].end, page);

    // Subtitle 3.11: "And Scenario E analyzes malicious package lifecycle scripts and installation hooks." [195.50s -> 201.61s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[10].text);
    await triggerScenario("E");
    await page.mouse.move(620, 450, { steps: 8 });
    await waitElapsed(startTime, s3.end_time, page);

    // =========================================================================
    // SECTION 4: REAL GITHUB REPO SCAN, FIX WITH AI, CODE REVIEWER & THANK YOU [201.61s -> 277.80s]
    // REQUIREMENT: "we take one real GitHub repo and scan and explain the features(fix with ai and findings and code reviewer) and last a thank u"
    // =========================================================================
    const s4 = timings.sections[3];
    console.log(`\n🎬 [Section 4/4] ${s4.title} (${s4.start_time}s -> ${s4.end_time}s)`);

    // Subtitle 4.1: "Now let us examine a real-world open-source repository: listmonk by Kailash Nadh." [201.61s -> 209.50s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[0].text);
    try {
      const repoInput = page.locator("input[placeholder*='github.com']").first();
      await repoInput.click();
      await repoInput.fill("https://github.com/knadh/listmonk");
      await page.waitForTimeout(300);
      const scanBtn = page.locator("button:has-text('Scan')").first();
      await scanBtn.click({ force: true });
      await page.waitForTimeout(1500);
    } catch (_) {}
    await waitElapsed(startTime, s4.subtitles[0].end, page);

    // Subtitle 4.2: "When scanning a multi-module repository like this, SupplyGraph indexes all thirty-five submodules and manifests..." [209.50s -> 220.50s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[1].text);
    // Point to 35 submodules / monorepo telemetry
    await page.mouse.move(120, 150, { steps: 8 });
    await page.waitForTimeout(600);
    try {
      const dependabotTab = page.locator("button").filter({ hasText: /Dependabot/i }).first();
      if (await dependabotTab.isVisible()) {
        await dependabotTab.click({ force: true });
        await page.waitForTimeout(800);
      }
    } catch (_) {}
    await waitElapsed(startTime, s4.subtitles[1].end, page);

    // Subtitle 4.3: "It identifies twenty-one findings across direct and transitive dependencies, computing a contextual Blast Radius score of sixty out of hundred." [220.50s -> 232.00s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[2].text);
    // Switch to Findings tab & scroll list
    try {
      const findingsTab = page.locator("button").filter({ hasText: /Findings/i }).first();
      if (await findingsTab.isVisible()) {
        await findingsTab.click({ force: true });
        await page.waitForTimeout(500);
      }
      await page.mouse.move(1600, 350, { steps: 8 });
      await page.mouse.wheel(0, 160);
    } catch (_) {}
    await waitElapsed(startTime, s4.subtitles[2].end, page);

    // Subtitle 4.4: "With our Fix with AI feature, SupplyGraph generates evidence-based, non-breaking remediation prompts..." [232.00s -> 245.00s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[3].text);
    try {
      const fixWithAi = page.locator("button").filter({ hasText: /Fix with AI/i }).first();
      if (await fixWithAi.isVisible()) {
        await fixWithAi.hover();
        await page.waitForTimeout(300);
        await fixWithAi.click({ force: true });
        await page.waitForTimeout(1000); // Shows green "Copied!" feedback!
      }
    } catch (_) {}
    await waitElapsed(startTime, s4.subtitles[3].end, page);

    // Subtitle 4.5: "In the AI Code Reviewer, developers can inspect surgical unified git diffs that correct the specific vulnerable lines rather than forcing broad version jumps." [245.00s -> 257.00s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[4].text);
    try {
      const navReviewer = page.locator('nav button:has-text("Code Reviewer")').first();
      if (await navReviewer.isVisible()) {
        await navReviewer.click({ force: true });
        await page.waitForTimeout(1000);
        await injectVirtualCursorAndHeartbeat(page);
        await page.mouse.move(960, 480, { steps: 10 });
        await page.mouse.wheel(0, 180);
      }
    } catch (_) {}
    await waitElapsed(startTime, s4.subtitles[4].end, page);

    // Subtitle 4.6: "And in our Detonation Sandbox, lifecycle scripts run inside an isolated container where malicious network requests and file modifications are safely contained." [257.00s -> 269.00s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[5].text);
    try {
      const navSandbox = page.locator('nav button:has-text("Sandbox")').first();
      if (await navSandbox.isVisible()) {
        await navSandbox.click({ force: true });
        await page.waitForTimeout(1000);
        await injectVirtualCursorAndHeartbeat(page);
        const npmPreset = page.locator("button").filter({ hasText: /npm postinstall/i }).or(page.locator("button").filter({ hasText: /Malicious npm/i })).first();
        if (await npmPreset.isVisible()) {
          await npmPreset.click({ force: true });
          await page.waitForTimeout(1200);
        }
      }
    } catch (_) {}
    await waitElapsed(startTime, s4.subtitles[5].end, page);

    // Subtitle 4.7: "SupplyGraph protects your modern software supply chain before production deployment." [269.00s -> 273.50s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[6].text);
    await showThankYouCard(page);
    await waitElapsed(startTime, s4.subtitles[6].end, page);

    // Subtitle 4.8: "Thank you so much!" [273.50s -> 277.80s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[7].text);
    await page.mouse.move(960, 540, { steps: 8 });
    await waitElapsed(startTime, s4.end_time + 1.0, page);

    console.log("🎉 Complete 4-part recording matching user prompt finished with 100% precision!");
  } catch (err) {
    console.error("Recording error:", err);
  } finally {
    await page.close();
    await context.close();
    await browser.close();
    console.log("🎬 Raw Video file recorded successfully!");
  }
}

runRecording().catch(console.error);
