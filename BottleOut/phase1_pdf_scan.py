"""BottleOut Phase 1 — static pass on available artifacts only."""
from pathlib import Path
from pypdf import PdfReader
import re
import hashlib
import zlib

BO = Path(r"C:\src\projects\HackTheBox CTF Holme\BottleOut")
pdf = BO / "Holmes CTF 2026 Sherlock 02.pdf"
raw = pdf.read_bytes()
print("sha256", hashlib.sha256(raw).hexdigest())
print("size", len(raw))

reader = PdfReader(str(pdf))
print("meta", reader.metadata)
print("pages", len(reader.pages))

# planted flag patterns
pats = {
    "HTB": re.compile(rb"HTB\{[^}]{0,200}\}"),
    "flag": re.compile(rb"flag\{[^}]{0,200}\}", re.I),
    "jid": re.compile(rb"[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "xmpp": re.compile(rb"xmpp|jabber|conversations|gajim|pidgin|OMEMO|jitsi", re.I),
    "uuid": re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),
}
for name, rx in pats.items():
    for m in rx.finditer(raw):
        print(f"[{name}]", m.group()[:120])

# images
out = BO / "pdf_carved"
out.mkdir(exist_ok=True)
for pi, page in enumerate(reader.pages):
    try:
        for ii, img in enumerate(page.images):
            dest = out / f"p{pi+1}_{ii}_{img.name}"
            dest.write_bytes(img.data)
            print(f"img p{pi+1}/{ii} {img.name} {len(img.data)}")
            # search image bytes
            for name, rx in pats.items():
                for m in rx.finditer(img.data):
                    print(f"  img[{name}]", m.group()[:80])
            if img.data[:3] == b"\xff\xd8\xff":
                eoi = img.data.rfind(b"\xff\xd9")
                if eoi != -1 and eoi + 2 < len(img.data):
                    extra = img.data[eoi+2:]
                    print(f"  jpeg extra {len(extra)} {extra[:40]!r}")
    except Exception as e:
        print("img err", pi, e)

# zlib streams
hits = 0
for i in range(len(raw) - 2):
    if raw[i] == 0x78 and raw[i+1] in (0x01, 0x5e, 0x9c, 0xda):
        try:
            dec = zlib.decompress(raw[i:i+400000])
        except Exception:
            continue
        for name, rx in pats.items():
            for m in rx.finditer(dec):
                print(f"zlib[{name}]@{i}", m.group()[:100])
                hits += 1
print("zlib hits", hits)

# SilentDividend leftovers that might name XMPP
sd = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend")
for p in [sd/"decrypted_payload.txt", sd/"walkthroughs"/"Q05-AUTH-NAPOLEON-SR-4821.md"]:
    if p.exists():
        t = p.read_text(encoding="utf-8", errors="replace")
        if re.search(r"xmpp|jabber|@", t, re.I):
            print("SD file has @ or xmpp", p.name)
