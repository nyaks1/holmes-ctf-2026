"""Extract PDF images and regions around HTB occurrences."""
from pathlib import Path
from pypdf import PdfReader
import re

pdf_path = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\Holmes CTF 2026 Sherlock 01.pdf")
raw = pdf_path.read_bytes()
out = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\pdf_carved")
out.mkdir(exist_ok=True)

# context around HTB
for m in re.finditer(rb"HTB", raw):
    i = m.start()
    ctx = raw[max(0, i-40): i+40]
    print("HTB@", i, ctx)

# extract embedded images via pypdf
reader = PdfReader(str(pdf_path))
for pi, page in enumerate(reader.pages):
    try:
        images = page.images
        print(f"page {pi+1} images", len(images))
        for ii, img in enumerate(images):
            dest = out / f"p{pi+1}_img{ii}_{img.name}"
            dest.write_bytes(img.data)
            print("  saved", dest, len(img.data))
    except Exception as e:
        print("img err", pi, e)
        # fallback xobjects
        try:
            if "/Resources" in page and "/XObject" in page["/Resources"]:
                xobj = page["/Resources"]["/XObject"].get_object()
                for name, obj in xobj.items():
                    obj = obj.get_object()
                    if obj.get("/Subtype") == "/Image":
                        data = obj.get_data()
                        dest = out / f"p{pi+1}_{str(name).replace('/','')}.bin"
                        dest.write_bytes(data)
                        print("  xobj", dest, len(data), obj.get("/Width"), obj.get("/Height"), obj.get("/Filter"))
        except Exception as e2:
            print(" xobj err", e2)

# also carve JFIF/PNG
for magic, ext in [(b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png")]:
    start = 0
    n = 0
    while True:
        i = raw.find(magic, start)
        if i < 0:
            break
        # find end marker roughly
        if ext == "jpg":
            end = raw.find(b"\xff\xd9", i+2)
            if end < 0:
                end = min(len(raw), i + 500000)
            else:
                end += 2
        else:
            end = raw.find(b"IEND", i)
            if end < 0:
                end = min(len(raw), i + 500000)
            else:
                end += 8
        chunk = raw[i:end]
        dest = out / f"carved_{n}.{ext}"
        dest.write_bytes(chunk)
        print("carved", dest, len(chunk), "at", i)
        n += 1
        start = i + 3
        if n > 30:
            break
