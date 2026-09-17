from pathlib import Path
import re
import zipfile
import os

text = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\DANGER.txt").read_text(encoding="utf-8")
m2 = re.search(r'["\u201c\u201d]([^"\u201c\u201d]{6,})["\u201c\u201d]', text)
pw = m2.group(1) if m2 else "E9$LQ2@Mr7A!"
print("using password:", repr(pw))

zpath = r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\danger.zip"
dest = r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted"
os.makedirs(dest, exist_ok=True)

z = zipfile.ZipFile(zpath)
print("names:", z.namelist())

# extract only README.md first
info = z.getinfo("README.md")
print("README flag", hex(info.flag_bits), "compress", info.compress_type, "size", info.file_size)

with z.open(info, pwd=pw.encode("utf-8")) as src:
    data = src.read()
out = Path(dest) / "README.md"
out.write_bytes(data)
print("README extracted", len(data), "bytes")
print(data.decode("utf-8", errors="replace"))
