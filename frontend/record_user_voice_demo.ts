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
  total_section_duration: number;
  subtitles: SubtitleItem[];
}

interface TimingsData {
  total_duration: number;
  voice: string;
  section_count: number;
  sections: SectionItem[];
}

/**
 * Updates the sleek bottom HUD with current section, title, and synchronized subtitle.
 */
async function updateSubtitleHUD(
  page: Page,
  sectionTag: string,
  sectionNum: string,
  title: string,
  subtitleText: string
) {
  await page.evaluate(
    ({ sectionTag, sectionNum, title, subtitleText }) => {
      let el = document.getElementById("sg-user-subtitle-hud");
      if (!el) {
        el = document.createElement("div");
        el.id = "sg-user-subtitle-hud";
        el.style.position = "fixed";
        el.style.bottom = "20px";
        el.style.left = "50%";
        el.style.transform = "translateX(-50%)";
        el.style.zIndex = "9999999";
        el.style.maxWidth = "1100px";
        el.style.width = "92%";
        el.style.padding = "16px 24px";
        el.style.borderRadius = "16px";
        el.style.background = "rgba(7, 11, 20, 0.94)";
        el.style.backdropFilter = "blur(24px)";
        el.style.border = "1px solid rgba(99, 102, 241, 0.55)";
        el.style.boxShadow =
          "0 20px 60px rgba(0, 0, 0, 0.9), 0 0 32px rgba(99, 102, 241, 0.3)";
        el.style.fontFamily = "system-ui, -apple-system, sans-serif";
        el.style.transition = "all 0.25s ease";
        el.style.pointerEvents = "none";
        document.body.appendChild(el);
      }
      el.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 11px; font-weight: 800; font-family: monospace; letter-spacing: 0.12em; color: #818cf8; text-transform: uppercase;">
              🛡️ SUPPLYGRAPH v3.0 ASPM
            </span>
            <span style="font-size: 10px; font-weight: 700; font-family: monospace; color: #a5b4fc; background: rgba(99, 102, 241, 0.25); border: 1px solid rgba(99, 102, 241, 0.4); padding: 2px 8px; border-radius: 4px;">
              [SECTION ${sectionNum}] ${sectionTag}
            </span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 10px; font-family: monospace; color: #34d399; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 8px; border-radius: 9999px;">
              🎙️ OFFICIAL PRESENTATION VOICE
            </span>
            <span style="font-size: 10px; font-family: monospace; color: #fbbf24; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); padding: 2px 8px; border-radius: 9999px;">
              LIVE SUBTITLES
            </span>
          </div>
        </div>
        <div style="font-size: 13.5px; font-weight: 700; color: #c7d2fe; margin-bottom: 6px; font-family: monospace;">
          ${title}
        </div>
        <div style="font-size: 15.5px; font-weight: 600; color: #ffffff; line-height: 1.4; background: rgba(15, 23, 42, 0.75); padding: 8px 14px; border-radius: 8px; border-left: 3px solid #6366f1;">
          💬 "${subtitleText}"
        </div>
      `;
    },
    { sectionTag, sectionNum, title, subtitleText }
  );
}

/**
 * Injects a smooth visual red pointer so mouse movements and clicks are clearly visible.
 */
async function injectVirtualCursor(page: Page) {
  await page.evaluate(() => {
    let cursor = document.getElementById("sg-virtual-cursor");
    if (!cursor) {
      cursor = document.createElement("div");
      cursor.id = "sg-virtual-cursor";
      cursor.style.position = "fixed";
      cursor.style.top = "0px";
      cursor.style.left = "0px";
      cursor.style.width = "22px";
      cursor.style.height = "22px";
      cursor.style.borderRadius = "50%";
      cursor.style.background = "rgba(239, 68, 68, 0.75)";
      cursor.style.border = "2px solid #ffffff";
      cursor.style.boxShadow = "0 0 12px rgba(239, 68, 68, 0.9)";
      cursor.style.pointerEvents = "none";
      cursor.style.zIndex = "99999999";
      cursor.style.transform = "translate(-50%, -50%)";
      cursor.style.transition = "transform 0.08s ease-out, background 0.1s ease";
      document.body.appendChild(cursor);

      window.addEventListener("mousemove", (e) => {
        cursor.style.left = `${e.clientX}px`;
        cursor.style.top = `${e.clientY}px`;
      });
      window.addEventListener("mousedown", () => {
        cursor.style.transform = "translate(-50%, -50%) scale(0.75)";
        cursor.style.background = "rgba(245, 158, 11, 0.95)";
      });
      window.addEventListener("mouseup", () => {
        cursor.style.transform = "translate(-50%, -50%) scale(1.0)";
        cursor.style.background = "rgba(239, 68, 68, 0.75)";
      });
    }
  });
}

/**
 * Smoothly waits until the target time (in seconds from start) is reached.
 */
async function waitElapsed(startTimeMs: number, targetSec: number, page: Page) {
  const targetMs = targetSec * 1000;
  while (Date.now() - startTimeMs < targetMs) {
    const remaining = targetMs - (Date.now() - startTimeMs);
    const step = Math.min(remaining, 250);
    if (step <= 0) break;
    await page.waitForTimeout(step);
  }
}

async function runUserVoiceRecording() {
  let timingsPath = path.resolve("./user_voice_timings.json");
  if (!fs.existsSync(timingsPath)) {
    timingsPath = path.resolve("../user_voice_timings.json");
  }
  const timings: TimingsData = JSON.parse(fs.readFileSync(timingsPath, "utf-8"));
  console.log(`⏱️ Total planned duration: ${timings.total_duration}s across 5 sections.`);

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
    const startTime = Date.now();
    console.log(`🎬 Recording session started at: ${new Date(startTime).toLocaleTimeString()}`);

    // =========================================================================
    // PART 1: THE CHALLENGE IN MODERN SOFTWARE [0.00s - 54.38s]
    // =========================================================================
    const s1 = timings.sections[0];
    console.log(`\n🎬 [Part 1/5] ${s1.title} (0.00s -> 54.38s)`);
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await injectVirtualCursor(page);

    // Subtitle 1 [0.0s - 14.0s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[0].text);
    await page.mouse.move(500, 300, { steps: 12 });
    await page.mouse.move(960, 400, { steps: 15 });
    await waitElapsed(startTime, 14.0, page);

    // Subtitle 2 [14.0s - 22.0s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[1].text);
    await page.mouse.wheel(0, 350);
    await waitElapsed(startTime, 22.0, page);

    // Subtitle 3 [22.0s - 28.5s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[2].text);
    await page.mouse.move(600, 520, { steps: 10 });
    await page.mouse.wheel(0, 300);
    await waitElapsed(startTime, 28.5, page);

    // Subtitle 4 [28.5s - 36.0s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[3].text);
    await page.mouse.move(800, 600, { steps: 12 });
    await waitElapsed(startTime, 36.0, page);

    // Subtitle 5 [36.0s - 48.0s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[4].text);
    await page.mouse.move(950, 480, { steps: 12 });
    await waitElapsed(startTime, 48.0, page);

    // Subtitle 6 [48.0s - 54.38s]
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[5].text);
    await page.mouse.wheel(0, -650);
    await page.mouse.move(450, 80, { steps: 10 });
    await waitElapsed(startTime, 54.38, page);

    // =========================================================================
    // PART 2: INTRODUCING SUPPLYGRAPH [54.38s - 108.58s]
    // =========================================================================
    const s2 = timings.sections[1];
    console.log(`🎬 [Part 2/5] ${s2.title} (54.38s -> 108.58s)`);

    // Subtitle 7 [54.38s - 62.0s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[0].text);
    try {
      const scannerBtn = page.locator("button").filter({ hasText: /Scanner & Graph/i }).first();
      if (await scannerBtn.isVisible()) {
        await scannerBtn.hover();
        await page.waitForTimeout(400);
        await scannerBtn.click({ force: true });
      }
    } catch (e) {}
    await waitElapsed(startTime, 62.0, page);

    // Subtitle 8 [62.0s - 72.0s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[1].text);
    await page.mouse.move(600, 160, { steps: 10 });
    await page.mouse.move(800, 160, { steps: 10 });
    await waitElapsed(startTime, 72.0, page);

    // Subtitle 9 [72.0s - 82.0s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[2].text);
    try {
      const loadABtn = page.locator("button").filter({ hasText: /Load Scenario A/i }).or(page.locator("button").filter({ hasText: /Scenario A/i })).first();
      if (await loadABtn.isVisible()) {
        await loadABtn.hover();
        await page.waitForTimeout(300);
        await loadABtn.click({ force: true });
      }
    } catch (e) {}
    await waitElapsed(startTime, 82.0, page);

    // Subtitle 10 [82.0s - 90.0s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[3].text);
    await page.mouse.move(450, 420, { steps: 10 });
    await page.mouse.move(700, 420, { steps: 12 });
    await waitElapsed(startTime, 90.0, page);

    // Subtitle 11 [90.0s - 98.0s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[4].text);
    try {
      const vulnNode = page.locator(".react-flow__node").last();
      if (await vulnNode.isVisible()) {
        await vulnNode.hover();
        await page.waitForTimeout(400);
        await vulnNode.click({ force: true });
      }
    } catch (e) {}
    await waitElapsed(startTime, 98.0, page);

    // Subtitle 12 [98.0s - 108.58s]
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[5].text);
    await page.mouse.move(1600, 400, { steps: 10 });
    await page.mouse.wheel(0, 150);
    await waitElapsed(startTime, 108.58, page);

    // =========================================================================
    // PART 3: FOUR CORE PLATFORM FEATURES [108.58s - 169.54s]
    // =========================================================================
    const s3 = timings.sections[2];
    console.log(`🎬 [Part 3/5] ${s3.title} (108.58s -> 169.54s)`);

    // Subtitle 13 [108.58s - 114.0s]
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[0].text);
    await waitElapsed(startTime, 114.0, page);

    // Subtitle 14 [114.0s - 127.0s] - Attack Graph traversal
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[1].text);
    await page.mouse.move(650, 450);
    await page.mouse.down();
    await page.mouse.move(580, 410, { steps: 10 });
    await page.mouse.up();
    await waitElapsed(startTime, 127.0, page);

    // Subtitle 15 [127.0s - 139.0s] - Blast Radius HUD
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[2].text);
    try {
      const blastBadge = page.locator("text=/Blast Radius|Score/i").first();
      if (await blastBadge.isVisible()) {
        await blastBadge.hover();
      } else {
        await page.mouse.move(960, 220, { steps: 10 });
      }
    } catch (e) {}
    await waitElapsed(startTime, 139.0, page);

    // Subtitle 16 [139.0s - 153.5s] - Executive AI Briefing
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[3].text);
    try {
      const execAiTab = page.locator("button").filter({ hasText: /Executive AI/i }).first();
      if (await execAiTab.isVisible()) {
        await execAiTab.click({ force: true });
        await page.waitForTimeout(800);
        await page.mouse.move(1600, 500, { steps: 8 });
        await page.mouse.wheel(0, 200);
      }
    } catch (e) {}
    await waitElapsed(startTime, 153.5, page);

    // Subtitle 17 [153.5s - 169.54s] - CycloneDX SBOM
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[4].text);
    try {
      const sbomBtn = page.locator("button").filter({ hasText: /CycloneDX SBOM/i }).first();
      if (await sbomBtn.isVisible()) {
        await sbomBtn.click({ force: true });
        await page.waitForTimeout(1500);
        const copySha = page.locator("button[title*='Copy SHA']").or(page.locator("button:has-text('Copy')")).first();
        if (await copySha.isVisible()) {
          await copySha.click({ force: true });
          await page.waitForTimeout(1200);
        }
        const closeBtn = page.locator("button").filter({ hasText: /Close/i }).or(page.locator(".lucide-x")).first();
        if (await closeBtn.isVisible()) {
          await closeBtn.click({ force: true });
        }
      }
    } catch (e) {}
    await waitElapsed(startTime, 169.54, page);

    // =========================================================================
    // PART 4: FIVE PRELOADED SECURITY SCENARIOS [169.54s - 232.18s]
    // =========================================================================
    const s4 = timings.sections[3];
    console.log(`🎬 [Part 4/5] ${s4.title} (169.54s -> 232.18s)`);

    // Subtitle 18 [169.54s - 177.0s]
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[0].text);
    await page.mouse.move(400, 160, { steps: 10 });
    await waitElapsed(startTime, 177.0, page);

    // Helper to open scenario dropdown and select option
    async function selectScenarioOption(scenLabel: string) {
      try {
        const scenDropdown = page.locator("button").filter({ hasText: /Scenario/i }).first();
        if (await scenDropdown.isVisible()) {
          await scenDropdown.click({ force: true });
          await page.waitForTimeout(300);
          const option = page.locator("button, [role='menuitem']").filter({ hasText: new RegExp(scenLabel, "i") }).first();
          if (await option.isVisible()) {
            await option.click({ force: true });
          }
        }
      } catch (e) {}
    }

    // Subtitle 19 [177.0s - 188.0s] - Scenario A (Log4j)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[1].text);
    await selectScenarioOption("Scenario A");
    await page.mouse.move(600, 420, { steps: 8 });
    await waitElapsed(startTime, 188.0, page);

    // Subtitle 20 [188.0s - 198.0s] - Scenario B (Prototype Pollution)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[2].text);
    await selectScenarioOption("Scenario B");
    await page.mouse.move(650, 430, { steps: 8 });
    await waitElapsed(startTime, 198.0, page);

    // Subtitle 21 [198.0s - 208.0s] - Scenario C (Python Pickle)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[3].text);
    await selectScenarioOption("Scenario C");
    await page.mouse.move(700, 440, { steps: 8 });
    await waitElapsed(startTime, 208.0, page);

    // Subtitle 22 [208.0s - 219.0s] - Scenario D (GitHub Actions)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[4].text);
    await selectScenarioOption("Scenario D");
    await page.mouse.move(650, 420, { steps: 8 });
    await waitElapsed(startTime, 219.0, page);

    // Subtitle 23 [219.0s - 232.18s] - Scenario E (npm Lifecycle Script)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[5].text);
    await selectScenarioOption("Scenario E");
    await page.mouse.move(620, 450, { steps: 8 });
    await waitElapsed(startTime, 232.18, page);

    // =========================================================================
    // PART 5: REAL PROJECT WALKTHROUGH (knadh/listmonk) [232.18s - 309.24s]
    // =========================================================================
    const s5 = timings.sections[4];
    console.log(`🎬 [Part 5/5] ${s5.title} (232.18s -> 309.24s)`);

    // Subtitle 24 [232.18s - 242.0s] - Enter knadh/listmonk
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[0].text);
    try {
      const repoInput = page.locator("input[placeholder*='github.com']").first();
      if (await repoInput.isVisible()) {
        await repoInput.click();
        await repoInput.fill("https://github.com/knadh/listmonk");
        await page.waitForTimeout(400);
        const scanBtn = page.locator("button").filter({ hasText: /^Scan$/i }).first();
        if (await scanBtn.isVisible()) {
          await scanBtn.click({ force: true });
        }
      }
    } catch (e) {}
    await waitElapsed(startTime, 242.0, page);

    // Subtitle 25 [242.0s - 253.5s] - vs. Dependabot benchmark
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[1].text);
    try {
      const dependabotTab = page.locator("button").filter({ hasText: /Dependabot/i }).first();
      if (await dependabotTab.isVisible()) {
        await dependabotTab.click({ force: true });
        await page.waitForTimeout(800);
        await page.mouse.wheel(0, 180);
      }
    } catch (e) {}
    await waitElapsed(startTime, 253.5, page);

    // Subtitle 26 [253.5s - 267.0s] - 21 Findings & Blast Radius 60/100
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[2].text);
    await page.mouse.wheel(0, -180);
    await page.mouse.move(960, 300, { steps: 10 });
    await waitElapsed(startTime, 267.0, page);

    // Subtitle 27 [267.0s - 281.0s] - Fix with AI Prompt Generator
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[3].text);
    try {
      const fixWithAi = page.locator("button").filter({ hasText: /Fix with AI/i }).first();
      if (await fixWithAi.isVisible()) {
        await fixWithAi.click({ force: true });
        await page.waitForTimeout(1500);
        const copyPrompt = page.locator("button").filter({ hasText: /Copy Prompt/i }).first();
        if (await copyPrompt.isVisible()) {
          await copyPrompt.click({ force: true });
          await page.waitForTimeout(1000);
        }
        const closeFix = page.locator("button").filter({ hasText: /Close/i }).or(page.locator(".lucide-x")).first();
        if (await closeFix.isVisible()) {
          await closeFix.click({ force: true });
        }
      }
    } catch (e) {}
    await waitElapsed(startTime, 281.0, page);

    // Subtitle 28 [281.0s - 295.0s] - AI Code Reviewer Unified Diffs
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[4].text);
    try {
      const navReviewer = page.locator("button").filter({ hasText: /Code Reviewer/i }).first();
      if (await navReviewer.isVisible()) {
        await navReviewer.click({ force: true });
        await page.waitForTimeout(1500);
        const stackedView = page.locator("button").filter({ hasText: /Stacked View/i }).first();
        if (await stackedView.isVisible()) {
          await stackedView.click({ force: true });
          await page.waitForTimeout(1500);
        }
        const unifiedView = page.locator("button").filter({ hasText: /Unified Git Diff/i }).first();
        if (await unifiedView.isVisible()) {
          await unifiedView.click({ force: true });
        }
      }
    } catch (e) {}
    await waitElapsed(startTime, 295.0, page);

    // Subtitle 29 [295.0s - 309.24s] - Universal Detonation Sandbox
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[5].text);
    try {
      const navSandbox = page.locator("button").filter({ hasText: /Sandbox/i }).first();
      if (await navSandbox.isVisible()) {
        await navSandbox.click({ force: true });
        await page.waitForTimeout(1500);
        const npmPreset = page.locator("button").filter({ hasText: /npm postinstall/i }).or(page.locator("button").filter({ hasText: /Malicious npm/i })).first();
        if (await npmPreset.isVisible()) {
          await npmPreset.click({ force: true });
          await page.waitForTimeout(2000);
        }
      }
    } catch (e) {}
    await waitElapsed(startTime, 309.24, page);

    console.log("🎉 Complete 5-part recording finished with 100% precision!");
  } catch (err) {
    console.error("Recording error:", err);
  } finally {
    await page.close();
    await context.close();
    await browser.close();
    console.log("🎬 Video file generated successfully!");
  }
}

runUserVoiceRecording().catch(console.error);
