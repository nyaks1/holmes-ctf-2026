"""Carve data after 7z archive end in TrustSettle installer."""
from pathlib import Path

src = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted\TrustSettle_1.0.0.exe")
data = src.read_bytes()
# from 7za: Offset = 50496, Physical Size = 95153536, Tail Size = 287998
offset = 50496
phys = 95153536
tail_size = 287998
tail_off = offset + phys
print("file size", len(data), "computed tail off", tail_off, "tail size", len(data) - tail_off)
tail = data[tail_off:]
print("tail first 64", tail[:64])
print("tail hex head", tail[:128].hex())

# search strings in tail
import re
for m in re.finditer(rb"[ -~]{6,}", tail):
    print("ASCII", m.group()[:200])

# unicode strings
for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", tail):
    try:
        print("UTF16", m.group().decode("utf-16le")[:200])
    except Exception:
        pass

out = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\installer_tail.bin")
out.write_bytes(tail)
print("wrote", out, "len", len(tail))

# also check PE of elevate.exe
elevate = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\resources\elevate.exe")
edata = elevate.read_bytes()
print("\nelevate size", len(edata), "md5", __import__("hashlib").md5(edata).hexdigest())
for m in re.finditer(rb"[ -~]{8,}", edata):
    s = m.group().decode("latin-1")
    if any(k in s.lower() for k in ["http", "elevate", "uac", "fodhelper", "eventvwr", "cmstp", "dll", "runas"]):
        print("elevate str", s[:150])
