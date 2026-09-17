"""Extract context around every 'Flag' occurrence in challenge PDFs."""
from pathlib import Path
import re
import zlib
from pypdf import PdfReader

ROOT = Path(r"C:\src\projects\HackTheBox CTF Holme")

for pdf in ROOT.rglob("*.pdf"):
    print("\n" + "="*60)
    print(pdf.name)
    data = pdf.read_bytes()
    for m in re.finditer(rb"Flag|fLaG|flag", data):
        i = m.start()
        ctx = data[max(0, i-80): i+80]
        printable = re.sub(rb"[^\x20-\x7e]", b".", ctx)
        print(f"\n@{i} match={m.group()!r}")
        print(f"  {printable.decode('ascii')}")

    # also decompress streams and search
    print("\n--- zlib streams with Flag ---")
    count = 0
    for i in range(len(data)-2):
        if data[i] == 0x78 and data[i+1] in (0x01, 0x5e, 0x9c, 0xda):
            try:
                dec = zlib.decompress(data[i:i+500000])
            except Exception:
                continue
            if b"Flag" in dec or b"HTB" in dec or b"flag{" in dec.lower():
                for m in re.finditer(rb".{0,40}(Flag|HTB\{|flag\{).{0,60}", dec, re.I):
                    print(f"  stream@{i}: {m.group()[:120]!r}")
                    count += 1
                    if count > 40:
                        break
        if count > 40:
            break
    print("stream hits", count)

    # pypdf raw content
    reader = PdfReader(str(pdf))
    for pi, page in enumerate(reader.pages):
        try:
            contents = page.get_contents()
            if contents:
                raw = contents.get_data() if hasattr(contents, "get_data") else b""
                if b"Flag" in raw or b"HTB" in raw:
                    print(f"page{pi+1} contents hit")
                    for m in re.finditer(rb".{0,30}(Flag|HTB).{0,50}", raw):
                        print(" ", m.group()[:100])
        except Exception as e:
            pass
