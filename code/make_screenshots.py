"""Renders the real program output into terminal-style PNGs (evidence images)."""
import subprocess, sys, textwrap, pathlib
from PIL import Image, ImageDraw, ImageFont

root = pathlib.Path(__file__).resolve().parent
out = root.parent / "screenshots"; out.mkdir(exist_ok=True)
font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 15)
W = 118
jobs = {
 "01_task2_encrypt_decrypt": ["aes_gcm_demo.py"],
 "02_expA_tampering": ["experiments.py", "A"],
 "03_expB_modes": ["experiments.py", "B"],
 "04_expC_key_management": ["experiments.py", "C"],
}
for name, cmd in jobs.items():
    res = subprocess.run([sys.executable, str(root / cmd[0]), *cmd[1:]], capture_output=True, text=True, cwd=root)
    text = f"$ python {' '.join(cmd)}\n" + res.stdout + res.stderr
    lines = []
    for l in text.splitlines():
        lines += textwrap.wrap(l, W, subsequent_indent="    ", replace_whitespace=False, drop_whitespace=False) or [""]
    h, cw = 22, 9
    img = Image.new("RGB", (W * cw + 40, h * (len(lines) + 2) + 40), "#1e1e2e")
    d = ImageDraw.Draw(img)
    d.ellipse((14, 12, 26, 24), fill="#ff5f56"); d.ellipse((34, 12, 46, 24), fill="#ffbd2e"); d.ellipse((54, 12, 66, 24), fill="#27c93f")
    for i, l in enumerate(lines):
        c = "#a6e3a1" if i == 0 else "#f38ba8" if ("REJECTED" in l or "caught" in l) else "#cdd6f4"
        d.text((20, 40 + i * h), l, font=font, fill=c)
    img.save(out / f"{name}.png"); print("wrote", name, img.size)
