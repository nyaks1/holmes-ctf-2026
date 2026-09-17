"""Deep static pass: map api.txt structure + hunt Win32 names in all encodings."""
from pathlib import Path
import re
import base64
import struct

api_path = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\extraResources\api.txt")
raw = api_path.read_bytes()
text = raw.decode("utf-8", errors="replace")

print("size", len(raw), len(text))
print("head", text[:120])

# locate string table end
m = re.search(r"local z=\{", text)
print("z table at", m.start() if m else None)
if m:
    # find matching close - naive brace count from first {
    i = text.find("{", m.start())
    depth = 0
    end = None
    for j in range(i, min(len(text), i + 80000)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                end = j
                break
    print("z table end", end)
    if end:
        after = text[end:end+500]
        print("AFTER z:", after[:400])
        Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\api_after_table.txt").write_text(text[end:end+8000], encoding="utf-8")

# extract identifier-like tokens
ids = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", text)
from collections import Counter
c = Counter(ids)
print("\nTop identifiers:")
for w, n in c.most_common(40):
    print(f"  {n:4d} {w}")

# search case-insensitive interesting words in raw
needles = [
    b"FILE_NOTIFY", b"Notify", b"Directory", b"WinHttp", b"WinInet",
    b"Internet", b"HttpSend", b"HttpOpen", b"ReadDirectory",
    b"ffi", b"cdef", b"kernel32", b"wininet", b"winhttp",
    b"CreateFile", b"ReadFile", b"WSA", b"socket",
    b"TEMP", b"Public", b"powershell", b"luajit",
]
print("\nNeedle scan (raw):")
for n in needles:
    i = raw.lower().find(n.lower())
    print(f"  {n!r}: {i}")

# UTF-16LE search
print("\nUTF-16LE:")
for n in needles:
    enc = n.decode("latin-1").encode("utf-16le")
    i = raw.find(enc)
    if i >= 0:
        print(f"  FOUND {n!r} utf16 @{i}")

# split-char construction: F I L E _ N O T I F Y ...
print("\nSplit single-char sequences in source:")
for word in ["FILE_NOTIFY_INFORMATION", "WinHttpSendRequest", "InternetOpenUrl", "ReadDirectoryChangesW"]:
    # search pattern like "F"."I"."L"."E" or {"F","I","L","E"}
    letters = list(word)
    # as "F" "I" "L" "E" with optional separators
    pat = rb'".'.join(re.escape(l.encode()) for l in letters[:6])  # first 6 letters pattern
    # simpler: consecutive "X" strings
    seq = b'","'.join(l.encode() for l in letters)
    if seq in raw:
        print("  joined quotes FOUND", word)
    seq2 = b'","'.join(l.lower().encode() for l in letters)
    if seq2 in raw:
        print("  lower joined FOUND", word)

# dump all Q strings decoded with multiple alphabets
lits = re.findall(r'"((?:\\.|[^"\\])*)"', text)
print("\nQ-string decode sweep (printable only):")
alphabets = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
]

def unescape(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i+1 < len(s):
            n = s[i+1]
            mapping = {"n":"\n","t":"\t","r":"\r","\\":"\\","\"":"\"","'":"'"}
            out.append(mapping.get(n, n)); i += 2
        else:
            out.append(s[i]); i += 1
    return "".join(out)

def b64_decode_alpha(data: str, alphabet: str):
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    trans = str.maketrans(alphabet, std)
    pad = data + "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(pad.translate(trans))

interesting = []
for lit in lits:
    s = unescape(lit)
    if not s.startswith("Q") or len(s) < 8:
        continue
    body = s[1:]
    for alph in alphabets:
        try:
            d = b64_decode_alpha(body, alph)
        except Exception:
            continue
        if not d:
            continue
        pr = sum(32 <= x < 127 or x in (9,10,13) for x in d) / len(d)
        if pr > 0.85 and len(d) >= 4:
            interesting.append((s[:30], alph[:4], d))
            if any(k in d for k in [b"Win", b"FILE", b"Http", b"Internet", b"NTIFY", b"ffi", b"Public", b"TEMP"]):
                print("  HIT", s[:30], d[:80])

print("printable Q decodes", len(interesting))
for s, a, d in interesting[:25]:
    print(" ", s, a, d[:60])

# After-table analysis
after_file = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\api_after_table.txt")
if after_file.exists():
    after = after_file.read_text(encoding="utf-8", errors="replace")
    print("\nAfter-table unique words:")
    aw = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", after)
    for w, n in Counter(aw).most_common(30):
        print(f"  {n:3d} {w}")
