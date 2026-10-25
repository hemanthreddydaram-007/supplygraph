import os
import glob
import shutil
import subprocess
import imageio_ffmpeg

def main():
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    root_dir = os.path.abspath(".")
    frontend_dir = os.path.join(root_dir, "frontend")
    frontend_public = os.path.join(frontend_dir, "public")
    voiceover_mp3 = os.path.join(root_dir, "SupplyGraph_Master_Voiceover.mp3")
    mp4_file = os.path.join(root_dir, "SupplyGraph_Hackathon_Demo_1080p_Voiceover.mp4")
    webm_file = os.path.join(root_dir, "SupplyGraph_Hackathon_Demo_1080p_Voiceover.webm")
    
    # Locate raw webm
    recorded_webms = glob.glob(os.path.join(frontend_dir, "videos", "*.webm"))
    if not recorded_webms:
        print("[Error] No raw webm found in frontend/videos!")
        return
    raw_video = recorded_webms[0]
    print(f"[Fast Mux] Raw video: {raw_video}")

    # Instant mux using stream copy for VP9 video + libopus for audio
    cmd_webm = [
        ffmpeg_exe, "-y",
        "-i", raw_video,
        "-i", voiceover_mp3,
        "-c:v", "copy",
        "-c:a", "libopus",
        "-b:a", "128k",
        "-shortest",
        webm_file
    ]
    print("Running instant stream-copy WebM mux...")
    subprocess.run(cmd_webm, check=True)
    print(f"[Success] WebM created: {os.path.getsize(webm_file):,} bytes")

    # Copy files to frontend/public
    os.makedirs(frontend_public, exist_ok=True)
    shutil.copyfile(mp4_file, os.path.join(frontend_public, "SupplyGraph_Hackathon_Demo_1080p_Voiceover.mp4"))
    shutil.copyfile(webm_file, os.path.join(frontend_public, "SupplyGraph_Hackathon_Demo_1080p_Voiceover.webm"))
    shutil.copyfile(webm_file, os.path.join(frontend_public, "SupplyGraph_Hackathon_Demo_1080p.webm"))
    shutil.copyfile(
        os.path.join(root_dir, "supplygraph_hackathon_demo.html"),
        os.path.join(frontend_public, "demo.html")
    )
    print("[Done] Copied MP4, WebM, and demo.html to frontend/public")

if __name__ == "__main__":
    main()
