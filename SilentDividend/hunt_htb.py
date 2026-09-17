"""Deep HTB{ flag hunt across SilentDividend artifacts."""
from pathlib import Path
import re
import zlib

ROOT = Path(r"C:\src\projects\HackTheBox CTF Holme")
FLAG_RE = re.compile(rb"HTB\{[^}\x00]{0,200}\}", re.I)
FLAG_RE2 = re.compile(rb"HTB<[^>\x00]{0,200}>", re.I)

# also looser
LOOSE = re.compile(rb"(?:HTB|flag|FLAG)[\{<][^\x00]{0,180}[\}>]")

def scan_file(p: Path):
    hits = []
    try:
        data = p.read_bytes()
    except Exception as e:
        return hits
    for rx in (FLAG_RE, FLAG_RE2, LOOSE):
        for m in rx.finditer(data):
            hits.append((p, m.start(), m.group()[:200]))
    # zlib decompress streams
    for i in range(len(data) - 2):
        if data[i] == 0x78 and data[i+1] in (0x01, 0x5e, 0x9c, 0xda):
            try:
                dec = zlib.decompress(data[i:i+2_000_000])
                for m in FLAG_RE.finditer(dec):
                    hits.append((p, i, b"zlib:" + m.group()[:200]))
            except Exception:
                pass
    return hits

interesting_suffixes = {
    "", ".js", ".html", ".txt", ".json", ".md", ".env", ".lua", ".xml",
    ".pdb", ".pak", ".asar", ".exe", ".dll", ".pdf", ".png", ".jpg",
    ".svg", ".css", ".map", ".yml", ".ini", ".cfg", ".log",
}

skip_dirs = {"node_modules", "locales", "__pycache__", "7zextra", "tools"}

all_hits = []
scanned = 0
for p in ROOT.rglob("*"):
    if not p.is_file():
        continue
    if any(s in p.parts for s in skip_dirs):
        continue
    # skip huge chromium libs
    if p.suffix.lower() in {".html"} and "LICENSES" in p.name:
        continue
    if p.name in {"icudtl.dat", "snapshot_blob.bin", "v8_context_snapshot.bin"}:
        continue
    if p.stat().st_size > 80_000_000:
        continue
    scanned += 1
    hits = scan_file(p)
    if hits:
        all_hits.extend(hits)

print(f"scanned {scanned} files")
print(f"hits: {len(all_hits)}")
for p, off, g in all_hits:
    print(f"  {p.relative_to(ROOT)} @ {off}: {g!r}")
