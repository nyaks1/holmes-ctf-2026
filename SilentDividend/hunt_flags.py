import hashlib
import re
from pathlib import Path

plain = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\decrypted_payload.txt").read_text()
print("plain:", repr(plain))
print("sha256:", hashlib.sha256(plain.encode("utf-8")).hexdigest())
print("len utf8:", len(plain.encode("utf-8")))

roots = [
    Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis"),
    Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\asar"),
]
skip = {"node_modules", "locales"}
exts = {".js", ".html", ".txt", ".json", ".md", ".env", ".lua"}
pats = [
    rb"HTB\{[^}]+\}",
    rb"flag\{[^}]+\}",
    rb"NAPOLEON",
    rb"SR-4821",
    rb"MILVERTON",
    rb"0x[a-fA-F0-9]{40}",
    rb"https?://[^\s\"'<>]+",
]

found = []
for root in roots:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(s in p.parts for s in skip):
            continue
        if p.stat().st_size > 2_000_000:
            continue
        if p.suffix.lower() not in exts and p.name not in {"api.txt", ".env"}:
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        for pat in pats:
            for m in re.finditer(pat, data):
                found.append((p.name, m.group().decode("latin-1", errors="replace")[:220]))

for name, s in found:
    print(f"{name}: {s}")
print("total findings", len(found))
