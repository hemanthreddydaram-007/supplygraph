import json
import os

# Exact timings based on empirical speech recognition of user audio:
# Total duration: 309.24s
# Part 1: 54.38s (0.00s -> 54.38s)
# Part 2: 54.19s (54.38s -> 108.58s)
# Part 3: 60.96s (108.58s -> 169.54s)
# Part 4: 62.64s (169.54s -> 232.18s)
# Part 5: 77.06s (232.18s -> 309.24s)

subtitles = [
    # --- PART 1 ---
    {
        "id": 1,
        "part": 1,
        "section_tag": "THE CHALLENGE",
        "section_num": "1/5",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start": 0.0,
        "end": 14.0,
        "text": "Hello everyone, and respected judges! Today, modern applications are built using hundreds of open-source packages across npm, Python, Go, and GitHub workflows."
    },
    {
        "id": 2,
        "part": 1,
        "section_tag": "THE CHALLENGE",
        "section_num": "1/5",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start": 14.0,
        "end": 22.0,
        "text": "While open-source libraries help us build products faster, managing their security has become extremely complex."
    },
    {
        "id": 3,
        "part": 1,
        "section_tag": "THE CHALLENGE",
        "section_num": "1/5",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start": 22.0,
        "end": 28.5,
        "text": "In large codebases, applications often contain multiple levels of nested dependencies."
    },
    {
        "id": 4,
        "part": 1,
        "section_tag": "THE CHALLENGE",
        "section_num": "1/5",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start": 28.5,
        "end": 36.0,
        "text": "The real challenge for engineering teams is knowing: Which vulnerabilities are actually reachable in production code, and which ones are never called?"
    },
    {
        "id": 5,
        "part": 1,
        "section_tag": "THE CHALLENGE",
        "section_num": "1/5",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start": 36.0,
        "end": 48.0,
        "text": "Without this reachability context, developers can spend weeks investigating alerts or risk breaking live backend APIs during package upgrades."
    },
    {
        "id": 6,
        "part": 1,
        "section_tag": "THE CHALLENGE",
        "section_num": "1/5",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start": 48.0,
        "end": 54.38,
        "text": "This is why modern software security requires a deeper, code-aware approach."
    },

    # --- PART 2 ---
    {
        "id": 7,
        "part": 2,
        "section_tag": "PROPOSED SOLUTION",
        "section_num": "2/5",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start": 54.38,
        "end": 62.0,
        "text": "To address this challenge, we created SupplyGraph."
    },
    {
        "id": 8,
        "part": 2,
        "section_tag": "PROPOSED SOLUTION",
        "section_num": "2/5",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start": 62.0,
        "end": 72.0,
        "text": "SupplyGraph is an Application Security Posture Management platform designed to give developers complete visibility into their software supply chain."
    },
    {
        "id": 9,
        "part": 2,
        "section_tag": "PROPOSED SOLUTION",
        "section_num": "2/5",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start": 72.0,
        "end": 82.0,
        "text": "Instead of treating dependencies as flat isolated lists, SupplyGraph analyzes project call paths and builds an interactive visual attack graph."
    },
    {
        "id": 10,
        "part": 2,
        "section_tag": "PROPOSED SOLUTION",
        "section_num": "2/5",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start": 82.0,
        "end": 90.0,
        "text": "It connects your code from user-facing entry points all the way down to deeply nested libraries."
    },
    {
        "id": 11,
        "part": 2,
        "section_tag": "PROPOSED SOLUTION",
        "section_num": "2/5",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start": 90.0,
        "end": 98.0,
        "text": "It clearly verifies whether an execution path actually reaches a vulnerable component."
    },
    {
        "id": 12,
        "part": 2,
        "section_tag": "PROPOSED SOLUTION",
        "section_num": "2/5",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start": 98.0,
        "end": 108.58,
        "text": "When an issue is identified, SupplyGraph provides safe, line-by-line code patches that preserve application functionality, while testing untrusted packages inside an isolated sandbox."
    },

    # --- PART 3 ---
    {
        "id": 13,
        "part": 3,
        "section_tag": "CORE FEATURES",
        "section_num": "3/5",
        "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
        "start": 108.58,
        "end": 114.0,
        "text": "Let us look at four core capabilities of SupplyGraph:"
    },
    {
        "id": 14,
        "part": 3,
        "section_tag": "CORE FEATURES",
        "section_num": "3/5",
        "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
        "start": 114.0,
        "end": 127.0,
        "text": "First is the Attack Graph. Powered by graph traversal algorithms, it visually maps the relationship between code and libraries, showing exact reachability paths."
    },
    {
        "id": 15,
        "part": 3,
        "section_tag": "CORE FEATURES",
        "section_num": "3/5",
        "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
        "start": 127.0,
        "end": 139.0,
        "text": "Second is the Blast Radius Score. It calculates a clear risk metric from 0 to 100, helping teams understand potential operational impact."
    },
    {
        "id": 16,
        "part": 3,
        "section_tag": "CORE FEATURES",
        "section_num": "3/5",
        "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
        "start": 139.0,
        "end": 153.5,
        "text": "Third is the Autonomous Executive AI. It summarizes technical vulnerability data into actionable briefings and prioritized containment steps."
    },
    {
        "id": 17,
        "part": 3,
        "section_tag": "CORE FEATURES",
        "section_num": "3/5",
        "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
        "start": 153.5,
        "end": 169.54,
        "text": "And fourth is the CycloneDX SBOM. It generates standard Software Bill of Materials documents with deterministic SHA-256 cryptographic verification for compliance."
    },

    # --- PART 4 ---
    {
        "id": 18,
        "part": 4,
        "section_tag": "DEMO SCENARIOS",
        "section_num": "4/5",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start": 169.54,
        "end": 177.0,
        "text": "To demonstrate these capabilities, SupplyGraph includes five preloaded real-world scenarios:"
    },
    {
        "id": 19,
        "part": 4,
        "section_tag": "DEMO SCENARIOS",
        "section_num": "4/5",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start": 177.0,
        "end": 188.0,
        "text": "Scenario A illustrates a transitive Log4j call path, mapping how an incoming request travels through service layers to a vulnerable logging library."
    },
    {
        "id": 20,
        "part": 4,
        "section_tag": "DEMO SCENARIOS",
        "section_num": "4/5",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start": 188.0,
        "end": 198.0,
        "text": "Scenario B examines Prototype Pollution, showing how improper object merging can be safely identified and corrected."
    },
    {
        "id": 21,
        "part": 4,
        "section_tag": "DEMO SCENARIOS",
        "section_num": "4/5",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start": 198.0,
        "end": 208.0,
        "text": "Scenario C analyzes insecure Python pickle deserialization, demonstrating AST-level detection before code execution."
    },
    {
        "id": 22,
        "part": 4,
        "section_tag": "DEMO SCENARIOS",
        "section_num": "4/5",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start": 208.0,
        "end": 219.0,
        "text": "Scenario D audits GitHub Actions workflows, ensuring runners and third-party actions use immutable commit hashes."
    },
    {
        "id": 23,
        "part": 4,
        "section_tag": "DEMO SCENARIOS",
        "section_num": "4/5",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start": 219.0,
        "end": 232.18,
        "text": "And Scenario E tests lifecycle scripts, demonstrating how package installation hooks are monitored and controlled."
    },

    # --- PART 5 ---
    {
        "id": 24,
        "part": 5,
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "section_num": "5/5",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start": 232.18,
        "end": 242.0,
        "text": "Now let us examine a real-world open-source repository: listmonk by Kailash Nadh."
    },
    {
        "id": 25,
        "part": 5,
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "section_num": "5/5",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start": 242.0,
        "end": 253.5,
        "text": "When scanning a multi-module repository like this, SupplyGraph indexes all 35 submodules and manifests, providing a unified inventory across frontend, backend, and workflows."
    },
    {
        "id": 26,
        "part": 5,
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "section_num": "5/5",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start": 253.5,
        "end": 267.0,
        "text": "It identifies 21 findings across direct and transitive dependencies, computing a contextual Blast Radius score of 60 out of 100."
    },
    {
        "id": 27,
        "part": 5,
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "section_num": "5/5",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start": 267.0,
        "end": 281.0,
        "text": "With the 'Fix with AI' feature, SupplyGraph generates evidence-based, non-breaking remediation prompts specifically structured for AI coding agents like Antigravity, Cursor, and Copilot."
    },
    {
        "id": 28,
        "part": 5,
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "section_num": "5/5",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start": 281.0,
        "end": 295.0,
        "text": "In the AI Code Reviewer, developers inspect surgical unified git diffs that correct specific vulnerable lines rather than forcing broad version jumps."
    },
    {
        "id": 29,
        "part": 5,
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "section_num": "5/5",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start": 295.0,
        "end": 309.24,
        "text": "And in our Detonation Sandbox, lifecycle scripts run within an isolated container where unauthorized network connections and file modifications are safely contained."
    }
]

# 1. Format user_voice_timings.json
part_meta = [
    {
        "index": 1,
        "id": "part_01_problem",
        "section_num": "1/5",
        "section_tag": "THE CHALLENGE",
        "title": "Modern Software Supply Chains & Reachability Context",
        "start_time": 0.0,
        "audio_duration": 54.38,
        "total_section_duration": 54.38,
        "subtitles": [s for s in subtitles if s["part"] == 1]
    },
    {
        "index": 2,
        "id": "part_02_solution",
        "section_num": "2/5",
        "section_tag": "PROPOSED SOLUTION",
        "title": "Introducing SupplyGraph: Unified ASPM Platform",
        "start_time": 54.38,
        "audio_duration": 54.19,
        "total_section_duration": 54.19,
        "subtitles": [s for s in subtitles if s["part"] == 2]
    },
    {
        "index": 3,
        "id": "part_03_features",
        "section_num": "3/5",
        "section_tag": "CORE FEATURES",
        "title": "Four Breakthrough Capabilities: DAG, Blast Radius, AI Briefing & SBOM",
        "start_time": 108.58,
        "audio_duration": 60.96,
        "total_section_duration": 60.96,
        "subtitles": [s for s in subtitles if s["part"] == 3]
    },
    {
        "index": 4,
        "id": "part_04_scenarios",
        "section_num": "4/5",
        "section_tag": "DEMO SCENARIOS",
        "title": "Five Preloaded Exploit Scenarios (Scenarios A through E)",
        "start_time": 169.54,
        "audio_duration": 62.64,
        "total_section_duration": 62.64,
        "subtitles": [s for s in subtitles if s["part"] == 4]
    },
    {
        "index": 5,
        "id": "part_05_repo_deepdive",
        "section_num": "5/5",
        "section_tag": "REAL PROJECT WALKTHROUGH",
        "title": "Real-World Audit of knadh/listmonk & Full Platform Feature Tour",
        "start_time": 232.18,
        "audio_duration": 77.06,
        "total_section_duration": 77.06,
        "subtitles": [s for s in subtitles if s["part"] == 5]
    }
]

timings_data = {
    "total_duration": 309.24,
    "voice": "User Actual Spoken Audio (5 Parts, Accurately Synced)",
    "section_count": 5,
    "sections": part_meta
}

with open("user_voice_timings.json", "w", encoding="utf-8") as f:
    json.dump(timings_data, f, indent=2)
print("Updated user_voice_timings.json")

# 2. Format SRT and VTT
def sec_to_srt(s):
    h = int(s // 3600)
    m = int((s % 3600) // 60)
    sec = int(s % 60)
    ms = int(round((s - int(s)) * 1000))
    return f"{h:02d}:{m:02d}:{sec:02d},{ms:03d}"

def sec_to_vtt(s):
    h = int(s // 3600)
    m = int((s % 3600) // 60)
    sec = int(s % 60)
    ms = int(round((s - int(s)) * 1000))
    return f"{h:02d}:{m:02d}:{sec:02d}.{ms:03d}"

srt_lines = []
vtt_lines = ["WEBVTT", ""]

for idx, sub in enumerate(subtitles, 1):
    # SRT
    srt_lines.append(str(idx))
    srt_lines.append(f"{sec_to_srt(sub['start'])} --> {sec_to_srt(sub['end'])}")
    srt_lines.append(f"[{sub['section_num']} {sub['section_tag']}] {sub['text']}")
    srt_lines.append("")

    # VTT
    vtt_lines.append(str(idx))
    vtt_lines.append(f"{sec_to_vtt(sub['start'])} --> {sec_to_vtt(sub['end'])}")
    vtt_lines.append(f"[{sub['section_num']} {sub['section_tag']}] {sub['text']}")
    vtt_lines.append("")

with open("supplygraph_demo_subtitles.srt", "w", encoding="utf-8") as f:
    f.write("\n".join(srt_lines))
print("Updated supplygraph_demo_subtitles.srt")

with open("supplygraph_demo_subtitles.vtt", "w", encoding="utf-8") as f:
    f.write("\n".join(vtt_lines))
print("Updated supplygraph_demo_subtitles.vtt")
