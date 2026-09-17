"""Re-scan sample for alternate flag formats we may have ignored."""
from pathlib import Path
import re
import base64
import hashlib

ROOT = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend")

pats = {
    "htb_brace": re.compile(rb"HTB\{[^}\x00]{3,200}\}", re.I),
    "flag_brace": re.compile(rb"flag\{[^}\x00]{3,200}\}", re.I),
    "htb_us": re.compile(rb"HTB_[A-Za-z0-9_]{4,80}"),
    "holmes": re.compile(rb"Holmes|Reichenbach|MILVERTON|DIOGENES|NAPOLEON", re.I),
    "uuid": re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),
}

skip = {"node_modules", "locales", "7zextra", "tools", "__pycache__", "pdf_carved", "asar"}
# scan smaller critical files + api.txt + preload + settlement
focus = [
    ROOT/"nsis"/"extraResources"/"api.txt",
    ROOT/"asar"/"preload.js",
    ROOT/"asar"/"main.js",
    ROOT/"nsis"/"src"/"settlement.html",
    ROOT/"nsis"/"src"/"renderer.js",
    ROOT/"nsis"/"src"/"index.html",
    ROOT/"decrypted_payload.txt",
    ROOT/"installer_tail.bin",
    ROOT/"Holmes CTF 2026 Sherlock 01.pdf",
]
# asar non-nm
asar = ROOT/"asar"
if asar.exists():
    for p in asar.rglob("*"):
        if p.is_file() and "node_modules" not in p.parts and p.stat().st_size < 200000:
            focus.append(p)

seen = set()
for p in focus:
    if not p.exists() or p in seen:
        continue
    seen.add(p)
    try:
        data = p.read_bytes()
    except Exception:
        continue
    for name, rx in pats.items():
        for m in rx.finditer(data):
            print(f"{p.name} [{name}] {m.group()[:120]!r}")

# try decode ENCRYPTED_DATA and cipher as if they are flags with different algos
enc = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
print("enc len", len(enc))
# reverse ROL7+xor0x42 without key? skip
# base64 of known plaintext
for s in [b"NAPOLEON", b"SR-4821", b"51.5049,0.0348"]:
    print(s, "b64", base64.b64encode(s), "md5", hashlib.md5(s).hexdigest(), "sha256", hashlib.sha256(s).hexdigest()[:32])

# WhisperChain PDF title
from pypdf import PdfReader
w = Path(r"C:\src\projects\HackTheBox CTF Holme\WhisperChain")
for pdf in w.rglob("*.pdf"):
    r = PdfReader(str(pdf))
    print("Whisper meta", r.metadata)
