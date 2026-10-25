import asyncio
import os
import json
import subprocess
import edge_tts
import imageio_ffmpeg

VOICE = "en-IN-PrabhatNeural"
RATE = "+3%"

# 6 Structured Sections as required by the user
SECTIONS = [
    {
        "id": "sec_01_problem_statement",
        "section_num": "1/6",
        "section_tag": "PROBLEM STATEMENT",
        "title": "Software Supply-Chain Vulnerabilities & The Alert Fatigue Crisis",
        "subtitles": [
            "Welcome to SupplyGraph. In modern software engineering, software supply-chain attacks like Log4j, SolarWinds, and malicious npm lifecycle hooks have surged by over 600%.",
            "Traditional security tools like GitHub Dependabot, Snyk, or npm audit only perform flat, direct manifest lookups.",
            "This creates overwhelming alert fatigue—over 90% of reported CVEs are never actually reachable in application runtime code.",
            "Furthermore, when automated tools blindly bump package versions, they break production builds and critical backend APIs, while remaining completely blind to CI/CD runner exploits."
        ],
        "speech_text": "Welcome to SupplyGraph. In modern software engineering, software supply-chain attacks like Log4j, SolarWinds, and malicious npm lifecycle hooks have surged by over 600 percent. Traditional security tools like GitHub Dependabot, Snyk, or npm audit only perform flat, direct manifest lookups. This creates overwhelming alert fatigue—over 90 percent of reported CVEs are never actually reachable in application runtime code. Furthermore, when automated tools blindly bump package versions, they break production builds and critical backend APIs, while remaining completely blind to CI-CD runner exploits."
    },
    {
        "id": "sec_02_proposed_solution",
        "section_num": "2/6",
        "section_tag": "PROPOSED SOLUTION",
        "title": "SupplyGraph: Unified Application Security Posture Management (ASPM)",
        "subtitles": [
            "To solve these fundamental flaws, we engineered SupplyGraph: an enterprise Application Security Posture Management, or ASPM platform.",
            "SupplyGraph unifies static dependency trees, multi-hop reachability graph algorithms, AST-guided surgical code remediation, runtime container sandboxing, and immutable blockchain attestation.",
            "Instead of isolated alerts, SupplyGraph correlates dependencies across npm, PyPI, Go, and GitHub Actions into actionable, verifiable security posture."
        ],
        "speech_text": "To solve these fundamental flaws, we engineered SupplyGraph: an enterprise Application Security Posture Management, or ASPM platform. SupplyGraph unifies static dependency trees, multi-hop reachability graph algorithms, AST-guided surgical code remediation, runtime container sandboxing, and immutable blockchain attestation. Instead of isolated alerts, SupplyGraph correlates dependencies across npm, PyPI, Go, and GitHub Actions into actionable, verifiable security posture."
    },
    {
        "id": "sec_03_features",
        "section_num": "3/6",
        "section_tag": "CORE FEATURES",
        "title": "Deterministic DAG Reachability, Blast Radius & Autonomous AI Briefings",
        "subtitles": [
            "SupplyGraph introduces four breakthrough capabilities:",
            "First, our deterministic NetworkX reverse-BFS engine constructs an interactive Attack DAG, proving actual multi-hop reachability from ingress endpoints to deep transitive packages.",
            "Second, it calculates a mathematical Blast Radius score, quantifying organizational exposure.",
            "Third, our Autonomous Executive AI translates complex graph topology into plain-English threat briefings and containment protocols.",
            "And fourth, it generates enterprise CycloneDX version 1.5 SBOMs with deterministic SHA-256 digests computed via client-side Web Crypto for compliance."
        ],
        "speech_text": "SupplyGraph introduces four breakthrough capabilities: First, our deterministic NetworkX reverse-BFS engine constructs an interactive Attack DAG, proving actual multi-hop reachability from ingress endpoints to deep transitive packages. Second, it calculates a mathematical Blast Radius score, quantifying organizational exposure. Third, our Autonomous Executive AI translates complex graph topology into plain-English threat briefings and containment protocols. And fourth, it generates enterprise CycloneDX version 1.5 SBOMs with deterministic SHA-256 digests computed via client-side Web Crypto for compliance."
    },
    {
        "id": "sec_04_scenarios",
        "section_num": "4/6",
        "section_tag": "DEMO SCENARIOS",
        "title": "Preloaded Real-World Exploit Scenarios (Scenarios A through E)",
        "subtitles": [
            "SupplyGraph comes preloaded with five critical real-world attack scenarios:",
            "Scenario A demonstrates transitive Log4j remote code execution through multi-hop call paths.",
            "Scenario B exposes prototype pollution in core JavaScript utility functions.",
            "Scenario C catches arbitrary code execution from malicious PyTorch pickle deserialization.",
            "Scenario D identifies unpinned GitHub Actions runners vulnerable to CI/CD pipeline poisoning.",
            "And Scenario E simulates an npm postinstall script attempting malicious credential theft and command-and-control beaconing."
        ],
        "speech_text": "SupplyGraph comes preloaded with five critical real-world attack scenarios: Scenario A demonstrates transitive Log4j remote code execution through multi-hop call paths. Scenario B exposes prototype pollution in core JavaScript utility functions. Scenario C catches arbitrary code execution from malicious PyTorch pickle deserialization. Scenario D identifies unpinned GitHub Actions runners vulnerable to CI-CD pipeline poisoning. And Scenario E simulates an npm postinstall script attempting malicious credential theft and command-and-control beaconing."
    },
    {
        "id": "sec_05_repo_deep_dive",
        "section_num": "5/6",
        "section_tag": "REAL REPOSITORY AUDIT",
        "title": "Deep Dive: Auditing knadh/listmonk & Full Platform Feature Tour",
        "subtitles": [
            "Now let's examine a real-world open-source repository: listmonk by Kailash Nadh.",
            "When scanned with native GitHub Dependabot, zero pull requests are opened because Dependabot only examines top-level manifests.",
            "SupplyGraph recursively indexes all 35 nested monorepo submodules and surfaces 21 critical findings—including 16 OSV CVEs and 6 first-party repository GHSAs with a Blast Radius of 60 out of 100.",
            "Clicking 'Fix with AI' generates an evidence-grounded, non-breaking remediation prompt specifically calibrated for AI coding agents like Antigravity, Cursor, and Copilot.",
            "In the AI Code Reviewer workspace, developers inspect surgical line-level unified git diffs rather than disruptive version bumps.",
            "And in our Universal Detonation Sandbox, untrusted lifecycle hooks are detonated inside isolated containers—instantly blocking outbound C2 network egress with exit code 137."
        ],
        "speech_text": "Now let's examine a real-world open-source repository: listmonk by Kailash Nadh. When scanned with native GitHub Dependabot, zero pull requests are opened because Dependabot only examines top-level manifests. But SupplyGraph recursively indexes all thirty-five nested monorepo submodules and surfaces twenty-one critical findings—including sixteen OSV CVEs and six first-party repository security advisories with a Blast Radius of sixty out of one hundred. Clicking 'Fix with AI' generates an evidence-grounded, non-breaking remediation prompt specifically calibrated for AI coding agents like Antigravity, Cursor, and Copilot. In the AI Code Reviewer workspace, developers inspect surgical line-level unified git diffs rather than disruptive version bumps. And in our Universal Detonation Sandbox, untrusted lifecycle hooks are detonated inside isolated containers—instantly blocking outbound C2 network egress with exit code 137."
    },
    {
        "id": "sec_06_attestation_conclusion",
        "section_num": "6/6",
        "section_tag": "BLOCKCHAIN ATTESTATION & CONCLUSION",
        "title": "Polygon Amoy Cryptographic Anchor & Enterprise Readiness",
        "subtitles": [
            "Finally, every audit result is cryptographically anchored to the Polygon Amoy blockchain testnet, producing tamper-evident on-chain Merkle proofs for zero-trust compliance.",
            "With full subtitle accessibility, multi-hop attack reachability, surgical AI auto-patching, and runtime container sandboxing, SupplyGraph delivers complete, verifiable software supply-chain defense.",
            "Thank you for evaluating SupplyGraph!"
        ],
        "speech_text": "Finally, every audit result is cryptographically anchored to the Polygon Amoy blockchain testnet, producing tamper-evident on-chain Merkle proofs for zero-trust compliance. With full subtitle accessibility, multi-hop attack reachability, surgical AI auto-patching, and runtime container sandboxing, SupplyGraph delivers complete, verifiable software supply-chain defense. Thank you for evaluating SupplyGraph!"
    }
]

def get_audio_duration(ffmpeg_exe: str, file_path: str) -> float:
    cmd = [ffmpeg_exe, "-i", file_path]
    res = subprocess.run(cmd, stderr=subprocess.PIPE, text=True, errors="replace")
    for line in res.stderr.splitlines():
        if "Duration:" in line:
            parts = line.strip().split(",")[0].replace("Duration:", "").strip().split(":")
            hours = float(parts[0])
            mins = float(parts[1])
            secs = float(parts[2])
            return hours * 3600 + mins * 60 + secs
    return 0.0

def format_timestamp_vtt(seconds: float) -> str:
    hrs = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    millis = int((seconds - int(seconds)) * 1000)
    return f"{hrs:02d}:{mins:02d}:{secs:02d}.{millis:03d}"

def format_timestamp_srt(seconds: float) -> str:
    hrs = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    millis = int((seconds - int(seconds)) * 1000)
    return f"{hrs:02d}:{mins:02d}:{secs:02d},{millis:03d}"

async def main():
    audio_dir = os.path.abspath("./voiceover_audio_indian")
    os.makedirs(audio_dir, exist_ok=True)
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()

    print(f"[TTS] Synthesizing Indian English neural voiceover using {VOICE} ({RATE})...")
    timings = []
    file_list_txt = os.path.join(audio_dir, "concat_list.txt")
    concat_lines = []

    current_offset = 0.0

    srt_entries = []
    vtt_entries = ["WEBVTT\n"]
    subtitle_counter = 1

    for idx, sec in enumerate(SECTIONS):
        out_mp3 = os.path.join(audio_dir, f"{sec['id']}.mp3")
        print(f"[{idx+1}/{len(SECTIONS)}] Synthesizing: {sec['title']}...")
        comm = edge_tts.Communicate(sec["speech_text"], VOICE, rate=RATE)
        await comm.save(out_mp3)

        duration = get_audio_duration(ffmpeg_exe, out_mp3)
        pause_duration = 0.8 if idx < len(SECTIONS) - 1 else 0.0
        total_section_time = duration + pause_duration

        # Divide section time among its subtitle lines
        sub_count = len(sec["subtitles"])
        sub_time_slice = duration / sub_count if sub_count > 0 else duration

        sub_list = []
        for s_i, sub_text in enumerate(sec["subtitles"]):
            sub_start = current_offset + (s_i * sub_time_slice)
            sub_end = sub_start + sub_time_slice
            sub_list.append({
                "sub_index": s_i + 1,
                "text": sub_text,
                "start": round(sub_start, 2),
                "end": round(sub_end, 2)
            })

            # Append to SRT
            srt_entries.append(
                f"{subtitle_counter}\n"
                f"{format_timestamp_srt(sub_start)} --> {format_timestamp_srt(sub_end)}\n"
                f"[{sec['section_tag']}] {sub_text}\n"
            )
            # Append to VTT
            vtt_entries.append(
                f"{format_timestamp_vtt(sub_start)} --> {format_timestamp_vtt(sub_end)}\n"
                f"[{sec['section_tag']}] {sub_text}\n"
            )
            subtitle_counter += 1

        timings.append({
            "index": idx + 1,
            "id": sec["id"],
            "section_num": sec["section_num"],
            "section_tag": sec["section_tag"],
            "title": sec["title"],
            "start_time": round(current_offset, 2),
            "audio_duration": round(duration, 2),
            "total_section_duration": round(total_section_time, 2),
            "subtitles": sub_list,
            "speech_text": sec["speech_text"],
            "file": out_mp3
        })
        concat_lines.append(f"file '{out_mp3.replace(chr(92), '/')}'")
        current_offset += total_section_time

    # Save timings to JSON for Playwright
    timings_json_path = os.path.abspath("./indian_voiceover_timings.json")
    with open(timings_json_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_duration": round(current_offset, 2),
            "voice": VOICE,
            "accent": "Indian English (en-IN-PrabhatNeural)",
            "section_count": len(timings),
            "sections": timings
        }, f, indent=2)

    # Write concat list for ffmpeg
    with open(file_list_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(concat_lines) + "\n")

    # Write SRT & VTT files
    srt_path = os.path.abspath("./supplygraph_demo_subtitles.srt")
    vtt_path = os.path.abspath("./supplygraph_demo_subtitles.vtt")
    with open(srt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(srt_entries))
    with open(vtt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(vtt_entries))

    master_mp3 = os.path.abspath("./SupplyGraph_Master_Indian_Voiceover.mp3")
    print(f"[Audio] Concatenating master audio to {master_mp3}...")
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
    print(f"[Done] Indian English Voiceover generation complete!")
    print(f"[Summary] Total length: {master_duration:.2f} seconds ({master_duration/60:.2f} minutes)")
    print(f"[Summary] Timings JSON: {timings_json_path}")
    print(f"[Summary] SRT Subtitles: {srt_path}")
    print(f"[Summary] VTT Subtitles: {vtt_path}")

if __name__ == "__main__":
    asyncio.run(main())
