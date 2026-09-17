"""Static triage of TrustSettle 1.0.0.exe — do not execute."""
from pathlib import Path
import struct
import hashlib
import re
import math
from collections import Counter

exe_path = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted\TrustSettle_1.0.0.exe")
data = exe_path.read_bytes()
print("size", len(data))
print("md5", hashlib.md5(data).hexdigest())
print("sha1", hashlib.sha1(data).hexdigest())
print("sha256", hashlib.sha256(data).hexdigest())
print("mz", data[:2], "pe_offset_candidate", struct.unpack_from("<I", data, 0x3C)[0])

# PyInstaller magic
print("MEI at", data.find(b"MEI"))
print("pyi- at", data.find(b"pyi-"))
print("PyInstaller", data.find(b"PyInstaller"))
print("python3", data.find(b"python3"))
print("Electron markers", data.find(b"electron.asar"), data.find(b"ELECTRON"))
print("node_modules", data.find(b"node_modules"))

# .NET
print("mscoree", data.find(b"mscoree.dll"))
print("_CorExeMain", data.find(b"_CorExeMain"))

# Go
print("Go build ID", data.find(b"Go build ID:"), data.find(b"go.buildid"))

# Rust
print("rustc", data.find(b"rustc"), data.find(b"cargo"))

# section names near PE
pe_off = struct.unpack_from("<I", data, 0x3C)[0]
print("PE sig", data[pe_off:pe_off+4])
# COFF header
machine, num_sec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, pe_off+4)
print("machine", hex(machine), "sections", num_sec, "opt_size", opt_size, "chars", hex(chars))
opt_off = pe_off + 24
magic = struct.unpack_from("<H", data, opt_off)[0]
print("opt magic", hex(magic), "PE32+" if magic==0x20b else "PE32")
sec_off = opt_off + opt_size
print("sections:")
for i in range(num_sec):
    off = sec_off + i*40
    name = data[off:off+8].split(b"\x00",1)[0]
    vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off+8)
    entropy_sample = data[raddr:raddr+min(rsize, 65536)]
    if entropy_sample:
        c = Counter(entropy_sample)
        ent = -sum((n/len(entropy_sample))*math.log2(n/len(entropy_sample)) for n in c.values())
    else:
        ent = 0
    print(f"  {name!r:12} vsize={vsize:10} raw={rsize:10} raddr={raddr:#x} ent={ent:.2f}")

# high-signal string extract
print("\n=== URL-like ===")
for m in re.finditer(rb"https?://[^\x00-\x1f\x7f\"'<>]{4,200}", data):
    s = m.group().decode("latin-1", errors="replace")
    if any(k in s.lower() for k in ["http", "api", "discord", "telegram", "pastebin", "ngrok", "onion", "ipfs", "wallet", "webhook", "slack", "t.me", "duckdns", "no-ip", "heroku", "railway", "vercel", "supabase", "firebase"]):
        print(s[:200])

print("\n=== emails ===")
for m in re.finditer(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", data):
    print(m.group().decode("latin-1", errors="replace"))

print("\n=== eth/btc-looking ===")
# eth 0x + 40 hex
for m in re.finditer(rb"0x[a-fA-F0-9]{40}", data):
    print("ETH", m.group().decode())
# btc base58-ish long
for m in re.finditer(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", data):
    print("BTC?", m.group().decode())

print("\n=== interesting keywords ===")
keys = [b"PRIVATE_KEY", b"WALLET_ADDRESS", b"RPC_URL", b"metamask", b"exodus", b"atomic", b"seed", b"mnemonic", b"clipboard", b"screenshot", b"keylog", b"discord", b"telegram", b"C2", b"command", b"exfil", b"harvest", b"wallet", b"Users\\Public", b".env", b"settlement", b"TrustSettle"]
for k in keys:
    idx = 0
    hits = []
    while True:
        i = data.find(k, idx)
        if i < 0:
            break
        hits.append(i)
        idx = i + 1
        if len(hits) >= 5:
            break
    if hits:
        print(k, "count_first", len(hits), "at", [hex(h) for h in hits[:3]])
        # context
        h = hits[0]
        ctx = data[max(0,h-40):h+80]
        printable = re.sub(rb"[^\x20-\x7e]", b".", ctx)
        print("  ctx:", printable.decode("ascii", errors="replace"))
