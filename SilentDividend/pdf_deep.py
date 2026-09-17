"""Deep PDF analysis: metadata, attachments, hidden text, images."""
from pathlib import Path
from pypdf import PdfReader
import re

pdf_path = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\Holmes CTF 2026 Sherlock 01.pdf")
reader = PdfReader(str(pdf_path))
print("pages", len(reader.pages))
print("metadata", reader.metadata)
if reader.metadata:
    for k, v in reader.metadata.items():
        print(f"  {k}={v}")

print("attachments?", getattr(reader, "attachments", None))
try:
    att = reader.attachments
    print("attachments detail", att)
    for name, files in att.items():
        print(" attachment", name, [len(x) if hasattr(x,'__len__') else x for x in files])
except Exception as e:
    print("att err", e)

# outline / names
try:
    print("outline", reader.outline)
except Exception as e:
    print("outline err", e)

for i, page in enumerate(reader.pages):
    print(f"\n--- page {i+1} ---")
    text = page.extract_text() or ""
    print(text[:500])
    # raw content streams
    try:
        if "/Annots" in page:
            print("Annots", page["/Annots"])
        if "/Contents" in page:
            contents = page.get_contents()
            if contents:
                data = contents.get_data() if hasattr(contents, "get_data") else b""
                print("content len", len(data))
                strs = re.findall(rb"[\x20-\x7e]{8,}", data)
                for s in strs[:30]:
                    print("  cstr", s.decode("latin-1")[:120])
    except Exception as e:
        print("content err", e)

# whole file as bytes for HTB / interesting
raw = pdf_path.read_bytes()
print("\nfile size", len(raw))
for pat in [rb"HTB", rb"flag\{", rb"NAPOLEON", rb"SR-4821", rb"0x[a-fA-F0-9]{40}", rb"HTB\{"]:
    print(pat, raw.find(pat), raw.rfind(pat))

# XMP
for m in re.finditer(rb"<\?xpacket[\s\S]{0,5000}?\?>", raw):
    print("XMP", m.group()[:500])

# PDF strings that look like flags
for m in re.finditer(rb"\(([^\)]{4,80})\)", raw):
    s = m.group(1)
    if any(k in s for k in [b"HTB", b"flag", b"NAPOLEON", b"Milvert", b"settlement", b"AUTH"]):
        print("paren", s[:120])
