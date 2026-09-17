from pathlib import Path
import re
import zipfile
import os
import time

text = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\DANGER.txt").read_text(encoding="utf-8")
m2 = re.search(r'["\u201c\u201d]([^"\u201c\u201d]{6,})["\u201c\u201d]', text)
pw = m2.group(1) if m2 else "E9$LQ2@Mr7A!"

zpath = r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\danger.zip"
dest = r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted"
os.makedirs(dest, exist_ok=True)
out = Path(dest) / "TrustSettle_1.0.0.exe"

z = zipfile.ZipFile(zpath)
info = z.getinfo("TrustSettle 1.0.0.exe")
print("exe flag", hex(info.flag_bits), "compress", info.compress_type, "file_size", info.file_size, "compress_size", info.compress_size)

t0 = time.time()
with z.open(info, pwd=pw.encode("utf-8")) as src, open(out, "wb") as dst:
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            break
        dst.write(chunk)
        done = dst.tell()
        if done % (10 * 1024 * 1024) < 1024 * 1024:
            print(f"wrote {done/1024/1024:.1f} MB in {time.time()-t0:.1f}s", flush=True)

print("done", out, out.stat().st_size, "bytes in", round(time.time()-t0, 1), "s")
