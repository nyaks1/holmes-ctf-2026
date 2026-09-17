"""Recover TrustSettle encryption key from Sepolia and decrypt payload.

Does NOT execute the decrypted command.
"""
import json
import urllib.request
from pathlib import Path

CONTRACT = "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"
RPC = "https://ethereum-sepolia-rpc.publicnode.com"
# keccak256("resolveState()")[0:4]
# function selector: compute or use known
# I'll compute via web3 if available, else hardcode after computing

def keccak_selector(sig: str) -> str:
    # pure python keccak is painful; use pysha3 if available or hardcode
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(sig.encode())
        return "0x" + k.hexdigest()[:8]
    except Exception:
        pass
    try:
        import sha3
        k = sha3.keccak_256()
        k.update(sig.encode())
        return "0x" + k.hexdigest()[:8]
    except Exception:
        pass
    # precomputed: keccak256("resolveState()") = need to compute
    # I'll try node ethers if python fails
    return None

ENCRYPTED_DATA = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)

MAGIC = 0x42
ROT = 7

def decrypt(data: bytes, key: bytes) -> str:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        key_byte = key[i % len(key)]
        step1 = b ^ key_byte
        step2 = ((step1 << ROT) | (step1 >> (8 - ROT))) & 0xFF
        out[i] = step2 ^ MAGIC
    return out.decode("utf-8", errors="replace")

def rpc_call(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())

# get selector via node
import subprocess, os
node = os.environ.get("MIMO_NODE", "node")
script = r'''
const { id } = require("ethers");
// ethers v6: id("resolveState()") is keccak of full string
// selector = first 4 bytes of keccak256
try {
  const { ethers } = require("ethers");
  const iface = new ethers.Interface(["function resolveState() view returns (bytes32)"]);
  console.log(iface.getFunction("resolveState").selector);
} catch (e) {
  // standalone
  const { id } = require("ethers");
  const h = id("resolveState()");
  console.log("0x" + h.slice(2, 10));
}
'''
# write temp
tmp = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\selector.js")
tmp.write_text(script, encoding="utf-8")
# need ethers on NODE_PATH
nm = os.environ.get("MIMO_NODE_MODULES", "")
env = os.environ.copy()
if nm:
    env["NODE_PATH"] = nm
# also use asar's ethers
env["NODE_PATH"] = (nm + os.pathsep if nm else "") + r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\asar\node_modules"

r = subprocess.run([node, str(tmp)], capture_output=True, text=True, env=env)
print("selector stdout:", r.stdout)
print("selector stderr:", r.stderr[:500])
selector = (r.stdout.strip() or "").splitlines()[-1] if r.stdout.strip() else None
print("selector:", selector)

if not selector or not selector.startswith("0x"):
    raise SystemExit("could not get selector")

print("eth_getCode...")
code = rpc_call("eth_getCode", [CONTRACT, "latest"])
print("code length", len(code.get("result", "0x"))//2 - 1 if "result" in code else code)

print("eth_call resolveState...")
call = rpc_call("eth_call", [{"to": CONTRACT, "data": selector}, "latest"])
print("call result:", call)
result = call.get("result", "0x")
if result in ("0x", "0x0", None) or len(result) < 66:
    raise SystemExit("bad call result")

# bytes32 is 32 bytes, ethers returns hex
# In the JS code, state is used as encryption key via hexToBuffer which expects 0x + hex
key_hex = result
print("key_hex", key_hex, "len bytes", (len(key_hex)-2)//2)

key = bytes.fromhex(key_hex[2:])
plain = decrypt(ENCRYPTED_DATA, key)
print("=== DECRYPTED ===")
print(plain)
print("=== END ===")

out = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\decrypted_payload.txt")
out.write_text(plain, encoding="utf-8")
print("wrote", out)
