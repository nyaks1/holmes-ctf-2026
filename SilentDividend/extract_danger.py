from pathlib import Path
import re
import zipfile
import os

text = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\DANGER.txt").read_text(encoding="utf-8")
print("RAW DANGER.txt:")
print(repr(text))

# password is in curly or straight quotes
m = re.search(r'password is .(.+?).', text)
print("regex1:", m.group(1) if m else None)

# more precise: between curly quotes “ ”
m2 = re.search(r'["\u201c\u201d]([^"\u201c\u201d]{6,})["\u201c\u201d]', text)
print("regex2:", m2.group(1) if m2 else None)

pw_candidates = []
if m:
    pw_candidates.append(m.group(1))
if m2:
    pw_candidates.append(m2.group(1))
# also try known from earlier read
pw_candidates.append("E9$LQ2@Mr7A!")

# dedupe
seen = set()
pws = []
for p in pw_candidates:
    if p not in seen:
        seen.add(p)
        pws.append(p)

print("candidates:", pws)

zpath = r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\danger.zip"
dest = r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted"
os.makedirs(dest, exist_ok=True)

z = zipfile.ZipFile(zpath)
print("flag_bits:", [hex(i.flag_bits) for i in z.infolist()])
print("compress:", [i.compress_type for i in z.infolist()])

for pw in pws:
    try:
        z.extractall(dest, pwd=pw.encode("utf-8"))
        print("SUCCESS with password:", repr(pw))
        for root, _, files in os.walk(dest):
            for f in files:
                p = os.path.join(root, f)
                print(p, os.path.getsize(p))
        break
    except Exception as e:
        print("FAIL", repr(pw), type(e).__name__, e)
