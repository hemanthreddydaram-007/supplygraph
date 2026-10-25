import os
import json
import subprocess
import imageio_ffmpeg

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

def main():
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    root_dir = os.path.abspath(".")
    upload_dir = r"C:\Users\DARAM  HEMANTH REDDY\.gemini\antigravity\brain\8e77a058-88dc-4f96-867e-2a14e12ca8ba\.user_uploaded"

    input_audios = [
        os.path.join(upload_dir, "uploaded_media_0_1792929503934.mp3"),
        os.path.join(upload_dir, "uploaded_media_1_1792929503934.mp3"),
        os.path.join(upload_dir, "uploaded_media_2_1792929503934.mp3"),
        os.path.join(upload_dir, "uploaded_media_3_1792929503934.mp3"),
        os.path.join(upload_dir, "uploaded_media_4_1792929503934.mp3"),
    ]

    parts_meta = [
        {
            "id": "part_01_problem",
            "section_num": "1/5",
            "section_tag": "THE CHALLENGE",
            "title": "Modern Software Supply Chains & Reachability Context",
            "subtitles": [
                "Hello everyone, and respected judges! Today, modern applications are built using hundreds of open-source packages across npm, Python, Go, and GitHub workflows.",
                "While open-source libraries help us build products faster, managing their security has become extremely complex.",
                "In large codebases, applications often contain multiple levels of nested dependencies.",
                "The real challenge for engineering teams is knowing: Which vulnerabilities are actually reachable in production code, and which ones are never called?",
                "Without this reachability context, developers spend weeks investigating alerts or risk breaking live backend APIs during package upgrades.",
                "This is why modern software security requires a deeper, code-aware approach."
            ]
        },
        {
            "id": "part_02_solution",
            "section_num": "2/5",
            "section_tag": "PROPOSED SOLUTION",
            "title": "Introducing SupplyGraph: Unified ASPM Platform",
            "subtitles": [
                "To address this challenge, we created SupplyGraph.",
                "SupplyGraph is an Application Security Posture Management platform designed to give developers complete visibility into their software supply chain.",
                "Instead of treating dependencies as flat isolated lists, SupplyGraph analyzes project call paths and builds an interactive visual attack graph.",
                "It connects your code from user-facing entry points all the way down to deeply nested libraries.",
                "It clearly verifies whether an execution path actually reaches a vulnerable component.",
                "When an issue is identified, SupplyGraph provides safe, line-by-line code patches that preserve application functionality, while testing untrusted packages inside an isolated sandbox."
            ]
        },
        {
            "id": "part_03_features",
            "section_num": "3/5",
            "section_tag": "CORE FEATURES",
            "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
            "subtitles": [
                "Let us look at four core capabilities of SupplyGraph:",
                "First is the Attack Graph. Powered by graph traversal algorithms, it visually maps the relationship between code and libraries, showing exact reachability paths.",
                "Second is the Blast Radius Score. It calculates a clear risk metric from 0 to 100, helping teams understand potential operational impact.",
                "Third is the Autonomous Executive AI. It summarizes technical vulnerability data into actionable briefings and prioritized containment steps.",
                "And fourth is the CycloneDX SBOM. It generates standard Software Bill of Materials documents with deterministic SHA-256 cryptographic verification for compliance."
            ]
        },
        {
            "id": "part_04_scenarios",
            "section_num": "4/5",
            "section_tag": "DEMO SCENARIOS",
            "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
            "subtitles": [
                "To demonstrate these capabilities, SupplyGraph includes five preloaded real-world scenarios:",
                "Scenario A illustrates a transitive Log4j call path, mapping how an incoming request travels through service layers to a vulnerable logging library.",
                "Scenario B examines Prototype Pollution, showing how improper object merging can be safely identified and corrected.",
                "Scenario C analyzes insecure Python pickle deserialization, demonstrating AST-level detection before code execution.",
                "Scenario D audits GitHub Actions workflows, ensuring runners and third-party actions use immutable commit hashes.",
                "And Scenario E tests lifecycle scripts, demonstrating how package installation hooks are monitored and controlled."
            ]
        },
        {
            "id": "part_05_repo_deepdive",
            "section_num": "5/5",
            "section_tag": "REAL PROJECT WALKTHROUGH",
            "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
            "subtitles": [
                "Now let us examine a real-world open-source repository: listmonk by Kailash Nadh.",
                "When scanning a multi-module repository like this, SupplyGraph indexes all 35 submodules and manifests, providing a unified inventory across frontend, backend, and workflows.",
                "It identifies 21 findings across direct and transitive dependencies, computing a contextual Blast Radius score of 60 out of 100.",
                "With the 'Fix with AI' feature, SupplyGraph generates evidence-based, non-breaking remediation prompts specifically structured for AI coding agents like Antigravity, Cursor, and Copilot.",
                "In the AI Code Reviewer, developers inspect surgical unified git diffs that correct specific vulnerable lines rather than forcing broad version jumps.",
                "And in our Detonation Sandbox, lifecycle scripts run within an isolated container where unauthorized network connections and file modifications are safely contained."
            ]
        }
    ]

    print("[Process] Normalizing and measuring user audio files...")
    concat_lines = []
    timings = []
    current_offset = 0.0

    srt_entries = []
    vtt_entries = ["WEBVTT\n"]
    sub_counter = 1

    for idx, (aud_file, meta) in enumerate(zip(input_audios, parts_meta)):
        duration = get_audio_duration(ffmpeg_exe, aud_file)
        print(f"Part {idx+1}: {duration:.2f}s -> {aud_file}")

        pause_dur = 0.6 if idx < len(input_audios) - 1 else 1.5
        total_section_dur = duration + pause_dur

        # Calculate subtitle slices
        sub_count = len(meta["subtitles"])
        slice_dur = duration / sub_count

        sub_list = []
        for s_i, sub_text in enumerate(meta["subtitles"]):
            s_start = current_offset + (s_i * slice_dur)
            s_end = s_start + slice_dur
            sub_list.append({
                "sub_index": s_i + 1,
                "text": sub_text,
                "start": round(s_start, 2),
                "end": round(s_end, 2)
            })

            srt_entries.append(
                f"{sub_counter}\n"
                f"{format_timestamp_srt(s_start)} --> {format_timestamp_srt(s_end)}\n"
                f"[{meta['section_tag']}] {sub_text}\n"
            )
            vtt_entries.append(
                f"{format_timestamp_vtt(s_start)} --> {format_timestamp_vtt(s_end)}\n"
                f"[{meta['section_tag']}] {sub_text}\n"
            )
            sub_counter += 1

        timings.append({
            "index": idx + 1,
            "id": meta["id"],
            "section_num": meta["section_num"],
            "section_tag": meta["section_tag"],
            "title": meta["title"],
            "start_time": round(current_offset, 2),
            "audio_duration": round(duration, 2),
            "total_section_duration": round(total_section_dur, 2),
            "subtitles": sub_list,
            "file": aud_file
        })

        concat_lines.append(f"file '{aud_file.replace(chr(92), '/')}'")
        current_offset += total_section_dur

    # Save timings json
    timings_path = os.path.join(root_dir, "user_voice_timings.json")
    with open(timings_path, "w", encoding="utf-8") as f:
        json.dump({
            "total_duration": round(current_offset, 2),
            "voice": "User Actual Spoken Audio (5 Parts)",
            "section_count": len(timings),
            "sections": timings
        }, f, indent=2)
    print(f"[Done] Saved timings to {timings_path}")

    # Write SRT & VTT
    srt_path = os.path.join(root_dir, "supplygraph_demo_subtitles.srt")
    vtt_path = os.path.join(root_dir, "supplygraph_demo_subtitles.vtt")
    with open(srt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(srt_entries))
    with open(vtt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(vtt_entries))
    print(f"[Done] Generated SRT and VTT subtitles")

    # Concatenate audio files into master user voiceover
    concat_list_file = os.path.join(root_dir, "user_audio_concat.txt")
    with open(concat_list_file, "w", encoding="utf-8") as f:
        f.write("\n".join(concat_lines) + "\n")

    master_user_audio = os.path.join(root_dir, "User_Master_Voiceover.mp3")
    print(f"[Audio] Merging 5 recordings into {master_user_audio}...")
    concat_cmd = [
        ffmpeg_exe, "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", concat_list_file,
        "-c:a", "libmp3lame",
        "-q:a", "2",
        master_user_audio
    ]
    subprocess.run(concat_cmd, check=True)

    master_dur = get_audio_duration(ffmpeg_exe, master_user_audio)
    print(f"[Success] User Master Voiceover Ready!")
    print(f"Total Duration: {master_dur:.2f} seconds ({master_dur/60:.2f} minutes)")

if __name__ == "__main__":
    main()
