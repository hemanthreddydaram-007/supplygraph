import os
import glob
import subprocess
import imageio_ffmpeg

def main():
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()

    # Find the latest video file in frontend/videos
    video_files = glob.glob(os.path.abspath("./frontend/videos/*.webm"))
    if not video_files:
        video_files = glob.glob(os.path.abspath("./videos/*.webm"))
    if not video_files:
        print("[ERROR] No webm video found!")
        return

    latest_video = max(video_files, key=os.path.getmtime)
    print(f"[Video] Found raw recorded video: {latest_video} ({os.path.getsize(latest_video) / 1024 / 1024:.2f} MB)")

    master_audio = os.path.abspath("./SupplyGraph_Master_4Part_Voiceover.mp3")
    if not os.path.exists(master_audio):
        print(f"[ERROR] Master audio not found at: {master_audio}")
        return
    print(f"[Audio] Found master voiceover: {master_audio} ({os.path.getsize(master_audio) / 1024 / 1024:.2f} MB)")

    out_mp4 = os.path.abspath("./SupplyGraph_Hackathon_Demo_4Part.mp4")
    out_webm = os.path.abspath("./SupplyGraph_Hackathon_Demo_4Part.webm")

    print("[Mux] Encoding Full HD 1080p MP4 with normalized voiceover and guaranteed sync...")
    # MP4 encode with exact CFR 25fps sync
    cmd_mp4 = [
        ffmpeg_exe, "-y",
        "-i", latest_video,
        "-i", master_audio,
        "-filter_complex", "[0:v]setpts=PTS-STARTPTS,fps=25[v];[1:a]asetpts=PTS-STARTPTS[a]",
        "-map", "[v]",
        "-map", "[a]",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "20",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        out_mp4
    ]
    subprocess.run(cmd_mp4, check=True)
    print(f"[SUCCESS] MP4 Video generated: {out_mp4} ({os.path.getsize(out_mp4) / 1024 / 1024:.2f} MB)")

    print("[Mux] Encoding WebM 1080p with normalized voiceover...")
    # Fast WebM encode using VP8 realtime
    cmd_webm = [
        ffmpeg_exe, "-y",
        "-i", out_mp4,
        "-c:v", "libvpx",
        "-b:v", "3000k",
        "-deadline", "realtime",
        "-cpu-used", "5",
        "-c:a", "libvorbis",
        "-q:a", "4",
        "-shortest",
        out_webm
    ]
    subprocess.run(cmd_webm, check=True)
    print(f"[SUCCESS] WebM Video generated: {out_webm} ({os.path.getsize(out_webm) / 1024 / 1024:.2f} MB)")

    # Also copy to frontend/public for live web preview
    public_dir = os.path.abspath("./frontend/public")
    if os.path.exists(public_dir):
        import shutil
        shutil.copy2(out_mp4, os.path.join(public_dir, "SupplyGraph_Hackathon_Demo_4Part.mp4"))
        shutil.copy2(out_webm, os.path.join(public_dir, "SupplyGraph_Hackathon_Demo_4Part.webm"))
        print(f"[SUCCESS] Copied to frontend/public for web playback.")

if __name__ == "__main__":
    main()
