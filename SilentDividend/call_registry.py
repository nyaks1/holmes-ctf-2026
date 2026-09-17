"""Call all StateRegistry view functions and try decoding as flags."""
import json
import urllib.request

CONTRACT = "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"
RPCS = [
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://rpc.sepolia.org",
    "https://1rpc.io/sepolia",
]

# selectors computed
import subprocess, os
from pathlib import Path

node = os.environ.get("MIMO_NODE", "node")
env = os.environ.copy()
nm = os.environ.get("MIMO_NODE_MODULES", "")
env["NODE_PATH"] = (nm + os.pathsep if nm else "") + r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\asar\node_modules"

sigs = [
    "resolveStage()",
    "resolveState()",
    "resolveStatee()",
    "resolveStates()",
    "resolveStatus()",
]
js = r'''
const { ethers } = require("ethers");
const iface = new ethers.Interface([
  "function resolveStage() view returns (bytes32)",
  "function resolveState() view returns (bytes32)",
  "function resolveStatee() view returns (bytes32)",
  "function resolveStates() view returns (bytes32)",
  "function resolveStatus() view returns (bytes32)",
]);
for (const f of ["resolveStage","resolveState","resolveStatee","resolveStates","resolveStatus"]) {
  console.log(f, iface.getFunction(f).selector);
}
'''
tmp = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\sels2.js")
tmp.write_text(js)
r = subprocess.run([node, str(tmp)], capture_output=True, text=True, env=env)
print(r.stdout, r.stderr)

sels = {}
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) == 2 and parts[1].startswith("0x"):
        sels[parts[0]] = parts[1]

def rpc(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(
        RPCS[0], data=payload,
        headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())

results = {}
for name, sel in sels.items():
    res = rpc("eth_call", [{"to": CONTRACT, "data": sel}, "latest"])
    val = res.get("result", "")
    results[name] = val
    print(f"{name} {sel} -> {val}")
    if val and val.startswith("0x") and len(val) >= 66:
        b = bytes.fromhex(val[2:66])
        ascii_s = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
        print(f"  ascii: {ascii_s}")
        # try interpret as utf-8 if ends with zeros
        try:
            t = b.rstrip(b"\x00").decode("utf-8")
            print(f"  utf8: {t!r}")
        except Exception:
            pass

# try each key decrypting ENCRYPTED_DATA
ENCRYPTED = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
MAGIC, ROT = 0x42, 7

def decrypt(data, key):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        step1 = b ^ key[i % len(key)]
        step2 = ((step1 << ROT) | (step1 >> (8 - ROT))) & 0xFF
        out[i] = step2 ^ MAGIC
    return out

print("\n=== decrypt with each key ===")
for name, val in results.items():
    if not val.startswith("0x") or len(val) < 66:
        continue
    key = bytes.fromhex(val[2:66])
    pt = decrypt(ENCRYPTED, key)
    printable = sum(1 for c in pt if 32 <= c < 127 or c in (9,10,13))
    print(name, printable, "/", len(pt), repr(pt[:80]))

# xor all five together
print("\n=== pairwise / combined ===")
keys = [bytes.fromhex(results[n][2:66]) for n in results if results[n].startswith("0x") and len(results[n])>=66]
if len(keys) >= 2:
    x = bytearray(32)
    for k in keys:
        for i in range(32):
            x[i] ^= k[i]
    print("xor all", bytes(x).hex(), "".join(chr(c) if 32<=c<127 else "." for c in x))
