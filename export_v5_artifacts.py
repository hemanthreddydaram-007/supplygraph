"""
Export SupplyGraph_Final_v5.pptx to:
- SupplyGraph_Final_v5.pdf & SupplyGraph_Blue_Final.pdf
- slide_previews_v5/slide_1.png .. slide_6.png
- slide_previews_v5/montage_v5.png
"""

import os
import sys
import comtypes.client
from PIL import Image

def export_all():
    base_dir = r"c:\Users\DARAM  HEMANTH REDDY\Desktop\supplygraph"
    pptx_path = os.path.join(base_dir, "SupplyGraph_Final_v5.pptx")
    pdf_path = os.path.join(base_dir, "SupplyGraph_Final_v5.pdf")
    blue_pdf = os.path.join(base_dir, "SupplyGraph_Blue_Final.pdf")
    preview_dir = os.path.join(base_dir, "slide_previews_v5")
    os.makedirs(preview_dir, exist_ok=True)

    print(f"Opening PowerPoint to export: {pptx_path}")
    powerpoint = comtypes.client.CreateObject("PowerPoint.Application")
    # ppFixedFormatTypePDF = 2
    # ppSaveAsPNG = 18

    try:
        deck = powerpoint.Presentations.Open(pptx_path, WithWindow=False)

        # 1. Export PDF
        print(f"Exporting PDF: {pdf_path}")
        deck.SaveAs(pdf_path, 32) # 32 is ppSaveAsPDF
        deck.SaveAs(blue_pdf, 32)
        print("  PDF exported successfully!")

        # 2. Export Slide PNGs
        slide_images = []
        for i, slide in enumerate(deck.Slides, start=1):
            png_path = os.path.join(preview_dir, f"slide_{i}.png")
            print(f"Exporting Slide {i} -> {png_path}")
            slide.Export(png_path, "PNG", 1920, 1080)
            if os.path.exists(png_path):
                slide_images.append(png_path)

        deck.Close()

        # 3. Create 2x3 Grid Montage
        if len(slide_images) == 6:
            montage_path = os.path.join(preview_dir, "montage_v5.png")
            print(f"Creating 2x3 Montage: {montage_path}")
            # Load images
            imgs = [Image.open(p) for p in slide_images]
            w, h = imgs[0].size
            # Scale down each image for montage
            thumb_w = 640
            thumb_h = int(h * (640 / w))
            thumbs = [img.resize((thumb_w, thumb_h), Image.Resampling.LANCZOS) for img in imgs]

            margin = 16
            montage_w = 3 * thumb_w + 4 * margin
            montage_h = 2 * thumb_h + 3 * margin

            montage = Image.new("RGB", (montage_w, montage_h), (8, 47, 73)) # Navy background
            for idx, thumb in enumerate(thumbs):
                col = idx % 3
                row = idx // 3
                x = margin + col * (thumb_w + margin)
                y = margin + row * (thumb_h + margin)
                montage.paste(thumb, (x, y))

            montage.save(montage_path, "PNG", quality=95)
            print(f"  Montage saved: {montage_path}")

    finally:
        powerpoint.Quit()

    print("\nAll v5 artifacts generated successfully!")

if __name__ == "__main__":
    export_all()
