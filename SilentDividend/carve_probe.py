from pathlib import Path
import re

data = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted\TrustSettle_1.0.0.exe").read_bytes()

# around NSIS
for off in [37364, 37373, 38408]:
    ctx = data[off-20:off+80]
    print(hex(off), ctx)

print("--- around PYZ ---")
off = 86323665
print(data[off-32:off+128])

print("--- around MEI-like ---")
off = 86408960
print(data[off-16:off+80])

# search PyInstaller-ish
for pat in [b'PYZ\x00', b'pyiboot', b'pyimod', b'struct', b'_MEIPASS', b'base_library', b'python3', b'python310', b'python311', b'python312', b'python39', b'python38', b'python313']:
    idx = data.find(pat)
    print(pat, idx)

# NSIS header typically has nullsoft string and $PLUGINSDIR
for pat in [b'$PLUGINSDIR', b'nsis', b'Nullsoft Inst', b'.onInit', b'RequestExecutionLevel', b'WriteUninstaller']:
    idx = data.find(pat)
    print(pat, idx)

# look for ZIP after NSIS
idx = 0
hits = []
while True:
    i = data.find(b'PK\x03\x04', idx)
    if i < 0:
        break
    hits.append(i)
    idx = i + 1
    if len(hits) > 20:
        break
print("PK hits", hits[:20], "total_at_least", len(hits))

# strings around 86M that look like paths
region = data[86000000:87000000]
paths = re.findall(rb"[A-Za-z]:\\[^\x00-\x1f]{5,120}", region)
print("paths in 86M region:")
for p in paths[:40]:
    print(" ", p.decode("latin-1", errors="replace"))

# also unix-style paths common in pyinstaller
for m in re.finditer(rb"[\w./-]{3,60}\.py[dc]?", region):
    s = m.group().decode("latin-1", errors="replace")
    if any(x in s for x in ["main", "settle", "wallet", "client", "app", "trust", "src"]):
        print("py:", s)
