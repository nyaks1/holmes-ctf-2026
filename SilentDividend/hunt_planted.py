"""Hunt planted flags: encodings, JPEG tails, PE extras, more x9 probes."""
from pathlib import Path
import re
import json
import urllib.request
import hashlib
import base64
import struct

ROOT = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend")

def find_htb(label, data: bytes):
    for pat, name in [
        (rb"HTB\{[^}\x00]{0,200}\}", "htb"),
        (rb"HTB%7[Bb][^%]{0,200}%7[Dd]", "htb-url"),
        (rb"4854427[Bb][0-9a-fA-F]{4,200}7[Dd]", "htb-hex"),
    ]:
        for m in re.finditer(pat, data):
            print(f"[{label}] {name}: {m.group()[:220]!r}")
    # base64 of HTB{
    # SEJU... = HTB{
    for needle in [b"SEJU", b"SFRi", b"aHRi", b"SFRC"]:
        i = data.find(needle)
        if i >= 0:
            chunk = data[max(0,i-4):i+80]
            print(f"[{label}] b64-prefix {needle} @ {i}: {chunk!r}")
            try:
                # expand
                blob = data[i:i+200]
                pad = blob + b"=" * ((4-len(blob)%4)%4)
                dec = base64.b64decode(pad)
                if b"HTB" in dec or b"flag" in dec.lower():
                    print("  decoded", dec[:120])
            except Exception:
                pass
    # rot13 HTB
    rot = bytes((b-13) if 65<=b<=90 else (b-13) if 97<=b<=122 else b for b in b"HTB{")
    # already searching HTB{
    # xor 1-32 single byte whole file for HTB{
    target = b"HTB{"
    for key in range(1, 256):
        enc = bytes(c ^ key for c in target)
        i = data.find(enc)
        if i >= 0:
            # decode a window
            win = data[i:i+80]
            pt = bytes(c ^ key for c in win)
            print(f"[{label}] xor=0x{key:02x} @ {i}: {pt[:60]!r}")

# scan key files
files = [
    ROOT / "nsis" / "extraResources" / "api.txt",
    ROOT / "nsis" / "src" / "settlement.html",
    ROOT / "nsis" / "src" / "renderer.js",
    ROOT / "nsis" / "src" / "index.html",
    ROOT / "asar" / "main.js",
    ROOT / "asar" / "preload.js",
    ROOT / "asar" / "package.json",
    ROOT / "extracted" / "TrustSettle_1.0.0.exe",
    ROOT / "installer_tail.bin",
    ROOT / "nsis" / "resources" / "elevate.exe",
    ROOT / "nsis" / "extraResources" / "luajit.exe",
    ROOT / "nsis" / "extraResources" / "lua51.dll",
]
# add pdf images
files += list((ROOT / "pdf_carved").glob("*"))

for p in files:
    if not p.exists():
        continue
    size = p.stat().st_size
    if size > 100_000_000:
        print("skip huge", p.name)
        continue
    data = p.read_bytes()
    find_htb(p.name, data)
    # JPEG extra after FFD9
    if data[:3] == b"\xff\xd8\xff":
        eoi = data.rfind(b"\xff\xd9")
        if eoi != -1 and eoi + 2 < len(data):
            extra = data[eoi+2:]
            print(f"[{p.name}] JPEG extra after EOI: {len(extra)} bytes {extra[:80]!r}")
            find_htb(p.name + "+eoi", extra)
        # comments FFFE
        i = 0
        while True:
            j = data.find(b"\xff\xfe", i)
            if j < 0 or j+4 > len(data):
                break
            ln = int.from_bytes(data[j+2:j+4], "big")
            comment = data[j+4:j+2+ln]
            if comment and any(32<=c<127 for c in comment[:20]):
                print(f"[{p.name}] JPEG comment @ {j}: {comment[:100]!r}")
            i = j + 2
            if i > 5_000_000:
                break

print("\n=== more x9 probes ===")
RPC = "https://ethereum-sepolia-rpc.publicnode.com"
DRAIN = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"

def rpc(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())

def x9(addr):
    data = "0xf8e6e11f" + addr[2:].lower().rjust(64, "0")
    res = rpc("eth_call", [{"to": DRAIN, "data": data}, "latest"])
    val = res.get("result", "0x")
    if not val or val == "0x" or len(val) < 66:
        return val
    raw = bytes.fromhex(val[2:])
    if len(raw) >= 64:
        ln = int.from_bytes(raw[32:64], "big")
        if ln < 200:
            return raw[64:64+ln].decode("latin-1", errors="replace")
    return val[:80]

# last20 of registry keys as addresses
keys = [
    "b5209fa26dd09d3d6a000ce1fb7d8f88629986ef45823d9dad95d0ea69729d52",
    "3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4",
    "b8d65bb591ae443f301f3272efd8bb8bd24045dbe20d2ae77063d07d9a5f7af9",
    "8f1aabeb8412c3196908960250e93aa20ae7819ea3d1828541169f59fa65d641",
    "81555eea89b714fd6ad80eda5ea6c7e6cceae50193b82eabb48ced56adb81ec7",
]
addrs = ["0x"+k[-40:] for k in keys]
addrs += [
    "0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a",
    "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4",
    "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2",
    "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
    "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1",
    "0x0000000000000000000000000000000000000001",
    "0x000000000000000000000000000000000000dead",
]
for a in addrs:
    try:
        print(f"x9({a}) -> {x9(a)!r}")
    except Exception as e:
        print(f"x9({a}) ERR {e}")

# x7 / x1 already known; try x11? no write
# dump more registry storage if any
REG = "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"
print("\n=== registry storage ===")
for i in range(8):
    slot = "0x" + f"{i:064x}"
    val = rpc("eth_getStorageAt", [REG, slot, "latest"]).get("result")
    print(i, val)
