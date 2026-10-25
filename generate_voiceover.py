import asyncio
import os
import json
import subprocess
import edge_tts
import imageio_ffmpeg

VOICE = "en-US-ChristopherNeural"
RATE = "+4%"

SCENES = [
    {
        "id": "scene_01_fastpass",
        "title": "Introduction & Evaluator Fast Pass",
        "text": "Welcome to SupplyGraph—an advanced Application Security Posture Management, or ASPM platform, engineered to defend modern software supply chains. We are kicking off this walkthrough using our Evaluator Fast Pass, granting hackathon judges immediate, one-click access to an authenticated zero-trust security session."
    },
    {
        "id": "scene_02_dashboard",
        "title": "ASPM Dashboard & Telemetry HUD",
        "text": "Here on the main ASPM dashboard, SupplyGraph continuously monitors security posture across multiple package managers, lockfiles, and CI-CD pipelines. Rather than presenting flat, disconnected vulnerability lists, our engine correlates direct and transitive dependencies into unified posture analytics and live exploit matrices."
    },
    {
        "id": "scene_03_attack_graph",
        "title": "Multi-Hop Attack Graph (Log4j RCE DAG)",
        "text": "Now exploring Scenario A: a critical Log4j remote code execution chain. Powered by our deterministic NetworkX reverse-BFS engine, SupplyGraph builds an interactive attack DAG. Notice how it traces the multi-hop call path from public API entrypoints down to deeply nested log4j-core. It calculates a quantified Blast Radius of 85 out of 100, proving true runtime reachability."
    },
    {
        "id": "scene_04_executive_ai",
        "title": "Autonomous Executive AI Briefing",
        "text": "Switching to the Executive AI tab, SupplyGraph autonomously translates raw graph topology into an actionable security briefing. It delivers a plain-English exploit breakdown, verified call path proofs, and prioritized containment protocols, giving security leads immediate decision clarity."
    },
    {
        "id": "scene_05_fix_prompt",
        "title": "Fix with AI Master Remediation Generator",
        "text": "Our Fix with AI engine eliminates the biggest frustration in automated security: broken builds. Instead of blunt version bumps, it generates evidence-grounded remediation prompts tailored for AI coding agents like Antigravity, Cursor, and Copilot—enforcing non-breaking version constraints and strict modification boundaries."
    },
    {
        "id": "scene_06_cyclonedx_sbom",
        "title": "CycloneDX v1.5 SBOM & Deterministic Hash",
        "text": "SupplyGraph generates enterprise-grade CycloneDX version 1.5 Software Bill of Materials. Using client-side Web Crypto, it computes a deterministic SHA-256 cryptographic digest on the fly. This ensures every exported inventory has tamper-evident attestation, ready for regulatory compliance and audit trails."
    },
    {
        "id": "scene_07_code_reviewer",
        "title": "AI Code Reviewer & Line-Level Unified Diffs",
        "text": "Navigating to the AI Code Reviewer workspace, SupplyGraph provides line-level surgical code patches. Here we inspect real AST vulnerability analyses for prototype pollution, insecure pickle deserialization, and cross-site scripting. Developers can toggle between Unified Git Diffs and Stacked Views to verify fixes before applying them."
    },
    {
        "id": "scene_08_adhoc_analyzer",
        "title": "Ad-Hoc Live Code Analyzer",
        "text": "For uncommitted code or custom scripts, the Ad-Hoc Live Analyzer offers instant AST auditing. Pasting a command-execution snippet in Python, we trigger live review. Within seconds, SupplyGraph flags the insecure subprocess execution and generates a production-ready, sanitized replacement."
    },
    {
        "id": "scene_09_detonation_sandbox",
        "title": "Universal Detonation Sandbox",
        "text": "To neutralize untrusted packages before deployment, SupplyGraph features an ephemeral Detonation Sandbox. When an npm postinstall script attempts outbound command-and-control communication, our zero-egress sandbox intercepts the socket and halts the process with exit code 137. Testing a Python credential probe similarly blocks unauthorized token scraping."
    },
    {
        "id": "scene_10_dependabot_benchmark",
        "title": "Head-to-Head Benchmark vs. GitHub Dependabot",
        "text": "In our live head-to-head benchmark across real-world open-source repositories like listmonk, SupplyGraph dramatically outperforms native tools. While Dependabot only parses top-level manifests, SupplyGraph indexes 35 nested submodules and detects 6 first-party repository security advisories that native scanners miss."
    },
    {
        "id": "scene_11_polygon_outro",
        "title": "Polygon Amoy Cryptographic Anchor & Conclusion",
        "text": "Finally, every audit result can be cryptographically anchored to the Polygon Amoy blockchain, producing verifiable on-chain Merkle proofs. From multi-hop attack graphs to runtime container sandboxing, SupplyGraph delivers true end-to-end supply-chain defense. Thank you for evaluating SupplyGraph!"
    }
]

def get_audio_duration(ffmpeg_exe: str, file_path: str) -> float:
    cmd = [ffmpeg_exe, "-i", file_path]
    res = subprocess.run(cmd, stderr=subprocess.PIPE, text=True, errors="replace")
    for line in res.stderr.splitlines():
        if "Duration:" in line:
            # Duration: 00:00:15.34, start: ...
            parts = line.strip().split(",")[0].replace("Duration:", "").strip().split(":")
            hours = float(parts[0])
            mins = float(parts[1])
            secs = float(parts[2])
            return hours * 3600 + mins * 60 + secs
    return 0.0

async def main():
    audio_dir = os.path.abspath("./voiceover_audio")
    os.makedirs(audio_dir, exist_ok=True)
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()

    print(f"[TTS] Generating English neural voiceover using {VOICE} ({RATE})...")
    timings = []
    file_list_txt = os.path.join(audio_dir, "concat_list.txt")
    
    current_offset = 0.0
    concat_lines = []

    for idx, scene in enumerate(SCENES):
        out_mp3 = os.path.join(audio_dir, f"{scene['id']}.mp3")
        print(f"[{idx+1}/{len(SCENES)}] Synthesizing: {scene['title']}...")
        comm = edge_tts.Communicate(scene["text"], VOICE, rate=RATE)
        await comm.save(out_mp3)

        duration = get_audio_duration(ffmpeg_exe, out_mp3)
        # We will add a small 0.6s pause between scenes
        pause_duration = 0.6 if idx < len(SCENES) - 1 else 0.0
        total_scene_time = duration + pause_duration

        timings.append({
            "index": idx + 1,
            "id": scene["id"],
            "title": scene["title"],
            "start_time": round(current_offset, 2),
            "audio_duration": round(duration, 2),
            "total_scene_duration": round(total_scene_time, 2),
            "text": scene["text"],
            "file": out_mp3
        })
        concat_lines.append(f"file '{out_mp3.replace(chr(92), '/')}'")
        current_offset += total_scene_time

    # Save timings to JSON for Playwright to consume
    timings_json_path = os.path.abspath("./voiceover_timings.json")
    with open(timings_json_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_duration": round(current_offset, 2),
            "scene_count": len(timings),
            "scenes": timings
        }, f, indent=2)

    # Write concat list for ffmpeg
    with open(file_list_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(concat_lines) + "\n")

    master_mp3 = os.path.abspath("./SupplyGraph_Master_Voiceover.mp3")
    print(f"[Audio] Concatenating master voiceover audio to {master_mp3}...")
    # Use ffmpeg to concatenate
    concat_cmd = [
        ffmpeg_exe, "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", file_list_txt,
        "-c", "copy",
        master_mp3
    ]
    subprocess.run(concat_cmd, check=True)

    master_duration = get_audio_duration(ffmpeg_exe, master_mp3)
    print(f"[Done] Voiceover generation complete!")
    print(f"[Summary] Total voiceover length: {master_duration:.2f} seconds ({master_duration/60:.2f} minutes)")
    print(f"[Summary] Timings file: {timings_json_path}")

if __name__ == "__main__":
    asyncio.run(main())
