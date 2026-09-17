"""Try multiple Sepolia RPCs to call resolveState() and decrypt."""
import json
import urllib.request
from pathlib import Path

CONTRACT = "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"
SELECTOR = "0x77b3774c"
ENCRYPTED_DATA = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
MAGIC = 0x42
ROT = 7

RPCS = [
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://rpc.sepolia.org",
    "https://1rpc.io/sepolia",
    "https://sepolia.drpc.org",
    "https://rpc2.sepolia.org",
    "https://ethereum-sepolia.blockpi.network/v1/rpc/public",
    "https://sepolia.gateway.tenderly.co",
    "https://gateway.tenderly.co/public/sepolia",
]

def rpc_call(url, method, params, timeout=20):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())

def decrypt(data: bytes, key: bytes) -> str:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        key_byte = key[i % len(key)]
        step1 = b ^ key_byte
        step2 = ((step1 << ROT) | (step1 >> (8 - ROT))) & 0xFF
        out[i] = step2 ^ MAGIC
    return out.decode("utf-8", errors="replace")

result = None
for url in RPCS:
    try:
        print("trying", url)
        call = rpc_call(url, "eth_call", [{"to": CONTRACT, "data": SELECTOR}, "latest"])
        print("  response", call)
        r = call.get("result")
        if r and r not in ("0x", "0x0") and len(r) >= 66:
            result = r
            print("  SUCCESS", r)
            break
    except Exception as e:
        print("  fail", type(e).__name__, e)

if not result:
    raise SystemExit("all RPCs failed")

key = bytes.fromhex(result[2:])
print("key bytes", len(key), key.hex())
plain = decrypt(ENCRYPTED_DATA, key)
print("=== DECRYPTED ===")
print(plain)
print("=== END ===")
Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\decrypted_payload.txt").write_text(plain, encoding="utf-8")
