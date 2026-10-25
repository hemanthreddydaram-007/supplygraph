import { chromium } from "playwright";
import * as path from "path";
import * as fs from "fs";

interface SubtitleItem {
  sub_index: number;
  text: string;
  start: number;
  end: number;
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
  file: string;
}

interface TimingsData {
  total_duration: number;
  voice: string;
  section_count: number;
  sections: SectionItem[];
}

async function updateSubtitleHUD(
  page: any,
  sectionTag: string,
  sectionNum: string,
  title: string,
  subtitleText: string
) {
  await page.evaluate(
    ({ sectionTag, sectionNum, title, subtitleText }: {
      sectionTag: string;
      sectionNum: string;
      title: string;
      subtitleText: string;
    }) => {
      let el = document.getElementById("sg-user-subtitle-hud");
      if (!el) {
        el = document.createElement("div");
        el.id = "sg-user-subtitle-hud";
        el.style.position = "fixed";
        el.style.bottom = "20px";
        el.style.left = "50%";
        el.style.transform = "translateX(-50%)";
        el.style.zIndex = "9999999";
        el.style.maxWidth = "1060px";
        el.style.width = "92%";
        el.style.padding = "16px 24px";
        el.style.borderRadius = "16px";
        el.style.background = "rgba(5, 8, 16, 0.95)";
        el.style.backdropFilter = "blur(24px)";
        el.style.border = "1px solid rgba(99, 102, 241, 0.6)";
        el.style.boxShadow =
          "0 20px 60px rgba(0, 0, 0, 0.9), 0 0 32px rgba(99, 102, 241, 0.35)";
        el.style.fontFamily = "system-ui, -apple-system, sans-serif";
        el.style.transition = "all 0.25s ease";
        el.style.pointerEvents = "none";
        document.body.appendChild(el);
      }
      el.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 10.5px; font-weight: 800; font-family: monospace; letter-spacing: 0.12em; color: #818cf8; text-transform: uppercase;">
              🛡️ SUPPLYGRAPH v3.0 ASPM
            </span>
            <span style="font-size: 10px; font-weight: 700; font-family: monospace; color: #a5b4fc; background: rgba(99, 102, 241, 0.25); border: 1px solid rgba(99, 102, 241, 0.4); padding: 1px 7px; border-radius: 4px;">
              [SECTION ${sectionNum}] ${sectionTag}
            </span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 10px; font-family: monospace; color: #6ee7b7; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 8px; border-radius: 9999px;">
              🎙️ OFFICIAL PRESENTATION VOICE
            </span>
            <span style="font-size: 10px; font-family: monospace; color: #fcd34d; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); padding: 2px 8px; border-radius: 9999px;">
              LIVE SUBTITLES
            </span>
          </div>
        </div>
        <div style="font-size: 13.5px; font-weight: 700; color: #e0e7ff; margin-bottom: 5px; font-family: monospace;">
          ${title}
        </div>
        <div style="font-size: 15.5px; font-weight: 600; color: #ffffff; line-height: 1.4; background: rgba(15, 23, 42, 0.7); padding: 8px 12px; border-radius: 8px; border-left: 3px solid #6366f1;">
          💬 "${subtitleText}"
        </div>
      `;
    },
    { sectionTag, sectionNum, title, subtitleText }
  );
}

async function runUserVoiceRecording() {
  let timingsPath = path.resolve("./user_voice_timings.json");
  if (!fs.existsSync(timingsPath)) {
    timingsPath = path.resolve("../user_voice_timings.json");
  }
  if (!fs.existsSync(timingsPath)) {
    throw new Error(`user_voice_timings.json not found at ${timingsPath}`);
  }
  const timings: TimingsData = JSON.parse(fs.readFileSync(timingsPath, "utf-8"));
  console.log(`⏱️ Loaded ${timings.sections.length} user sections. Total duration: ${timings.total_duration}s`);

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
    // PART 1: THE CHALLENGE IN MODERN SOFTWARE (~55.0s)
    // =========================================================================
    const s1 = timings.sections[0];
    console.log(`\n🎬 [Part 1/5] ${s1.title} (${s1.total_section_duration}s)`);
    await page.goto("http://localhost:3000", { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    // Subtitle 1.1
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[0].text);
    await page.waitForTimeout(9000);

    // Subtitle 1.2
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[1].text);
    try {
      const fastPassBtn = page.locator("button").filter({ hasText: /Fast Pass/i }).first();
      if (await fastPassBtn.isVisible()) {
        await fastPassBtn.hover();
        await page.waitForTimeout(1500);
        await fastPassBtn.click({ timeout: 2000, force: true });
      }
    } catch (e) {}
    await page.waitForTimeout(7500);

    // Subtitle 1.3
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[2].text);
    await page.mouse.wheel(0, 200);
    await page.waitForTimeout(9000);

    // Subtitle 1.4
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[3].text);
    await page.mouse.wheel(0, 200);
    await page.waitForTimeout(9000);

    // Subtitle 1.5
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[4].text);
    await page.waitForTimeout(9000);

    // Subtitle 1.6
    await updateSubtitleHUD(page, s1.section_tag, s1.section_num, s1.title, s1.subtitles[5].text);
    await page.mouse.wheel(0, -400);
    await page.waitForTimeout(10480);

    // =========================================================================
    // PART 2: INTRODUCING SUPPLYGRAPH (~54.8s)
    // =========================================================================
    const s2 = timings.sections[1];
    console.log(`🎬 [Part 2/5] ${s2.title} (${s2.total_section_duration}s)`);

    // Subtitle 2.1
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[0].text);
    await page.waitForTimeout(9000);

    // Subtitle 2.2
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[1].text);
    await page.mouse.wheel(0, 250);
    await page.waitForTimeout(9000);

    // Subtitle 2.3
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[2].text);
    await page.waitForTimeout(9000);

    // Subtitle 2.4
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[3].text);
    await page.waitForTimeout(9000);

    // Subtitle 2.5
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[4].text);
    await page.waitForTimeout(9000);

    // Subtitle 2.6
    await updateSubtitleHUD(page, s2.section_tag, s2.section_num, s2.title, s2.subtitles[5].text);
    await page.mouse.wheel(0, -250);
    await page.waitForTimeout(9790);

    // =========================================================================
    // PART 3: FOUR CORE PLATFORM FEATURES (~61.6s)
    // =========================================================================
    const s3 = timings.sections[2];
    console.log(`🎬 [Part 3/5] ${s3.title} (${s3.total_section_duration}s)`);

    // Subtitle 3.1
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[0].text);
    await page.waitForTimeout(10000);

    // Subtitle 3.2 - Attack Graph
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[1].text);
    try {
      const scenA = page.locator("button").filter({ hasText: /Scenario A/i }).first();
      if (await scenA.isVisible()) await scenA.click({ timeout: 2000, force: true });
    } catch (e) {}
    // Pan graph
    await page.mouse.move(700, 420);
    await page.mouse.down();
    await page.mouse.move(650, 400, { steps: 8 });
    await page.mouse.up();
    await page.waitForTimeout(12500);

    // Subtitle 3.3 - Blast Radius HUD
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[2].text);
    await page.waitForTimeout(12500);

    // Subtitle 3.4 - Executive AI
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[3].text);
    try {
      const execAiTab = page.locator("button").filter({ hasText: /Executive AI/i }).first();
      if (await execAiTab.isVisible()) await execAiTab.click({ timeout: 2000, force: true });
    } catch (e) {}
    await page.waitForTimeout(12500);

    // Subtitle 3.5 - CycloneDX SBOM
    await updateSubtitleHUD(page, s3.section_tag, s3.section_num, s3.title, s3.subtitles[4].text);
    try {
      const sbomBtn = page.locator("button").filter({ hasText: /CycloneDX SBOM/i }).first();
      if (await sbomBtn.isVisible()) {
        await sbomBtn.click({ timeout: 2000, force: true });
        await page.waitForTimeout(2000);
        const copySha = page.locator("button[title*='Copy SHA']").first();
        if (await copySha.isVisible()) await copySha.click({ timeout: 1500, force: true });
        await page.waitForTimeout(1500);
        const closeSbom = page.locator("button").filter({ hasText: /Close/i }).or(page.locator(".lucide-x")).first();
        if (await closeSbom.isVisible()) await closeSbom.click({ timeout: 1500, force: true });
      }
    } catch (e) {}
    await page.waitForTimeout(14060);

    // =========================================================================
    // PART 4: FIVE PRELOADED SECURITY SCENARIOS (~63.2s)
    // =========================================================================
    const s4 = timings.sections[3];
    console.log(`🎬 [Part 4/5] ${s4.title} (${s4.total_section_duration}s)`);

    // Subtitle 4.1
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[0].text);
    await page.waitForTimeout(10000);

    // Subtitle 4.2 - Scenario A (Log4j)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[1].text);
    try {
      const scenA = page.locator("button").filter({ hasText: /Scenario A/i }).first();
      if (await scenA.isVisible()) await scenA.click({ timeout: 2000, force: true });
    } catch (e) {}
    await page.waitForTimeout(10500);

    // Subtitle 4.3 - Scenario B (Prototype Pollution)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[2].text);
    try {
      const scenB = page.locator("button").filter({ hasText: /Scenario B/i }).first();
      if (await scenB.isVisible()) await scenB.click({ timeout: 2000, force: true });
    } catch (e) {}
    await page.waitForTimeout(10500);

    // Subtitle 4.4 - Scenario C (Python pickle)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[3].text);
    try {
      const scenC = page.locator("button").filter({ hasText: /Scenario C/i }).first();
      if (await scenC.isVisible()) await scenC.click({ timeout: 2000, force: true });
    } catch (e) {}
    await page.waitForTimeout(10500);

    // Subtitle 4.5 - Scenario D (GitHub Actions)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[4].text);
    try {
      const scenD = page.locator("button").filter({ hasText: /Scenario D/i }).first();
      if (await scenD.isVisible()) await scenD.click({ timeout: 2000, force: true });
    } catch (e) {}
    await page.waitForTimeout(10500);

    // Subtitle 4.6 - Scenario E (npm install script)
    await updateSubtitleHUD(page, s4.section_tag, s4.section_num, s4.title, s4.subtitles[5].text);
    try {
      const scenE = page.locator("button").filter({ hasText: /Scenario E/i }).first();
      if (await scenE.isVisible()) await scenE.click({ timeout: 2000, force: true });
    } catch (e) {}
    await page.waitForTimeout(11240);

    // =========================================================================
    // PART 5: REAL PROJECT WALKTHROUGH (knadh/listmonk) (~79.1s)
    // =========================================================================
    const s5 = timings.sections[4];
    console.log(`🎬 [Part 5/5] ${s5.title} (${s5.total_section_duration}s)`);

    // Subtitle 5.1 - Select knadh/listmonk
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[0].text);
    try {
      const repoInput = page.locator("input[placeholder*='github.com']").first();
      if (await repoInput.isVisible()) {
        await repoInput.fill("https://github.com/knadh/listmonk");
      }
    } catch (e) {}
    await page.waitForTimeout(12500);

    // Subtitle 5.2 - vs. Dependabot benchmark
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[1].text);
    try {
      const dependabotTab = page.locator("button").filter({ hasText: /Dependabot/i }).first();
      if (await dependabotTab.isVisible()) {
        await dependabotTab.click({ timeout: 2000, force: true });
        await page.mouse.wheel(0, 150);
      }
    } catch (e) {}
    await page.waitForTimeout(12500);

    // Subtitle 5.3 - 21 findings & Blast Radius 60/100
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[2].text);
    await page.mouse.wheel(0, -150);
    await page.waitForTimeout(12500);

    // Subtitle 5.4 - Fix with AI Prompt Generator
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[3].text);
    try {
      const fixWithAi = page.locator("button").filter({ hasText: /Fix with AI/i }).first();
      if (await fixWithAi.isVisible()) {
        await fixWithAi.click({ timeout: 2000, force: true });
        await page.waitForTimeout(2000);
        const copyPrompt = page.locator("button").filter({ hasText: /Copy Prompt/i }).first();
        if (await copyPrompt.isVisible()) await copyPrompt.click({ timeout: 1500, force: true });
        await page.waitForTimeout(1500);
        const closeFix = page.locator("button").filter({ hasText: /Close/i }).or(page.locator(".lucide-x")).first();
        if (await closeFix.isVisible()) await closeFix.click({ timeout: 1500, force: true });
      }
    } catch (e) {}
    await page.waitForTimeout(12500);

    // Subtitle 5.5 - AI Code Reviewer Unified Diffs
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[4].text);
    try {
      const navReviewer = page.locator("nav button").filter({ hasText: /Reviewer/i }).first();
      if (await navReviewer.isVisible()) {
        await navReviewer.click({ timeout: 2000, force: true });
        await page.waitForTimeout(2000);
        const stackedView = page.locator("button").filter({ hasText: /Stacked View/i }).first();
        if (await stackedView.isVisible()) {
          await stackedView.click({ timeout: 2000, force: true });
          await page.waitForTimeout(2000);
        }
        const unifiedView = page.locator("button").filter({ hasText: /Unified Git Diff/i }).first();
        if (await unifiedView.isVisible()) {
          await unifiedView.click({ timeout: 2000, force: true });
        }
      }
    } catch (e) {}
    await page.waitForTimeout(12500);

    // Subtitle 5.6 - Universal Detonation Sandbox
    await updateSubtitleHUD(page, s5.section_tag, s5.section_num, s5.title, s5.subtitles[5].text);
    try {
      const navSandbox = page.locator("nav button").filter({ hasText: /Sandbox/i }).first();
      if (await navSandbox.isVisible()) {
        await navSandbox.click({ timeout: 2000, force: true });
        await page.waitForTimeout(2000);
        const npmPreset = page.locator("button").filter({ hasText: /npm postinstall/i }).or(page.locator("button").filter({ hasText: /Malicious npm/i })).first();
        if (await npmPreset.isVisible()) {
          await npmPreset.click({ timeout: 2000, force: true });
          await page.waitForTimeout(3000);
        }
      }
    } catch (e) {}
    await page.waitForTimeout(16560);

    console.log("🎉 Complete 5-part user voice recording session finished!");
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
