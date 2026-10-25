import os
import sys
import glob
import shutil
import subprocess
import imageio_ffmpeg

def main():
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    root_dir = os.path.abspath(".")
    frontend_dir = os.path.join(root_dir, "frontend")
    videos_dir = os.path.join(frontend_dir, "videos")
    frontend_public = os.path.join(frontend_dir, "public")
    voiceover_mp3 = os.path.join(root_dir, "SupplyGraph_Master_Indian_Voiceover.mp3")

    if not os.path.exists(voiceover_mp3):
        print(f"[Error] Indian voiceover audio {voiceover_mp3} does not exist.")
        sys.exit(1)

    print("==================================================================")
    print("STEP 1: Executing Playwright Indian Voiceover Recording...")
    print("==================================================================")
    if os.path.exists(videos_dir):
        for f in glob.glob(os.path.join(videos_dir, "*.*")):
            try:
                os.remove(f)
            except Exception:
                pass

    record_cmd = ["npx", "tsx", "record_indian_voiceover_demo.ts"]
    print(f"Running: {' '.join(record_cmd)} in {frontend_dir}...")
    subprocess.run(record_cmd, cwd=frontend_dir, shell=True, check=True)

    recorded_webms = glob.glob(os.path.join(videos_dir, "*.webm"))
    if not recorded_webms:
        print("[Error] No recorded webm found in videos directory!")
        sys.exit(1)

    raw_video = recorded_webms[0]
    print(f"[Record] Found raw recorded video: {raw_video}")

    out_mp4 = os.path.join(root_dir, "SupplyGraph_Hackathon_Demo_IndianVoiceover.mp4")
    out_webm = os.path.join(root_dir, "SupplyGraph_Hackathon_Demo_IndianVoiceover.webm")

    print("==================================================================")
    print("STEP 2: Multiplexing Video and Indian English Voiceover (H.264 + AAC)")
    print("==================================================================")

    cmd_mp4 = [
        ffmpeg_exe, "-y",
        "-i", raw_video,
        "-i", voiceover_mp3,
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-preset", "fast",
        "-crf", "22",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        out_mp4
    ]
    subprocess.run(cmd_mp4, check=True)
    print(f"[Success] MP4 created: {os.path.getsize(out_mp4):,} bytes")

    print("==================================================================")
    print("STEP 3: Generating WebM (VP9 + Opus)")
    print("==================================================================")
    cmd_webm = [
        ffmpeg_exe, "-y",
        "-i", raw_video,
        "-i", voiceover_mp3,
        "-c:v", "copy",
        "-c:a", "libopus",
        "-b:a", "128k",
        "-shortest",
        out_webm
    ]
    subprocess.run(cmd_webm, check=True)
    print(f"[Success] WebM created: {os.path.getsize(out_webm):,} bytes")

    # Copy files to frontend/public
    print(f"[Public] Copying assets to {frontend_public}...")
    os.makedirs(frontend_public, exist_ok=True)
    shutil.copyfile(out_mp4, os.path.join(frontend_public, "SupplyGraph_Hackathon_Demo_IndianVoiceover.mp4"))
    shutil.copyfile(out_webm, os.path.join(frontend_public, "SupplyGraph_Hackathon_Demo_IndianVoiceover.webm"))
    shutil.copyfile(out_mp4, os.path.join(frontend_public, "SupplyGraph_Hackathon_Demo_1080p_Voiceover.mp4"))
    
    # Subtitles
    shutil.copyfile(
        os.path.join(root_dir, "supplygraph_demo_subtitles.vtt"),
        os.path.join(frontend_public, "supplygraph_demo_subtitles.vtt")
    )
    shutil.copyfile(
        os.path.join(root_dir, "supplygraph_demo_subtitles.srt"),
        os.path.join(frontend_public, "supplygraph_demo_subtitles.srt")
    )

    # HTML deck
    shutil.copyfile(
        os.path.join(root_dir, "supplygraph_hackathon_demo.html"),
        os.path.join(frontend_public, "demo.html")
    )

    print("==================================================================")
    print("SUCCESS: 1080p Video with Indian English Voiceover & Subtitles Ready!")
    print("==================================================================")

if __name__ == "__main__":
    main()
