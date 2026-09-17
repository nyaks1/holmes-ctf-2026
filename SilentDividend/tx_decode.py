"""Compute selectors, fetch x8 tx input, try x9 carefully."""
import json
import urllib.request
import subprocess
import os
from pathlib import Path

node = os.environ.get("MIMO_NODE", "node")
env = os.environ.copy()
nm = os.environ.get("MIMO_NODE_MODULES", "")
env["NODE_PATH"] = (nm + os.pathsep if nm else "") + r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\asar\node_modules"

js = r'''
const { ethers } = require("ethers");
const iface = new ethers.Interface([
  "function x1() view returns (address)",
  "function x7() view returns (address)",
  "function x8(bytes cipherFlag)",
  "function x9(address x10) view returns (string)",
  "function x11(address x12)",
]);
for (const f of ["x1","x7","x8","x9","x11"]) {
  console.log(f, iface.getFunction(f).selector, iface.getFunction(f).format());
}
console.log("encode x9", iface.encodeFunctionData("x9", ["0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"]));
'''
tmp = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\sels3.js")
tmp.write_text(js)
r = subprocess.run([node, str(tmp)], capture_output=True, text=True, env=env)
print("STDOUT", r.stdout)
print("STDERR", r.stderr[:400])

RPC = "https://ethereum-sepolia-rpc.publicnode.com"
DRAIN = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"
TX = "0x04289e1377d35f8c28a0363aae1270c038c6b7a6c490cf0664cda7557e46e24b"
CREATOR_TX_DRAINER = "0x5eae00f8c38fabf8a7e05cd9fe7abcdf7a44ddf53cfa558075dced1860aed316"
CREATOR_TX_TOKEN = "0xc0cda2b79200d41ad673a8dd0823a0160649b1d51a5638a4109f0708742f4fe3"
REGISTRY_CREATE = "0x37829e6ce779059b6fc69fa1bee3e7edbd5884479084fe4e43ca11d4fa9e2c7b"

def rpc(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode())

for label, txh in [("x8_tx", TX), ("drainer_create", CREATOR_TX_DRAINER), ("token_create", CREATOR_TX_TOKEN), ("registry_create", REGISTRY_CREATE)]:
    try:
        res = rpc("eth_getTransactionByHash", [txh])
        tx = res.get("result") or {}
        inp = tx.get("input", "")
        print(f"\n=== {label} {txh} ===")
        print("from", tx.get("from"))
        print("to", tx.get("to"))
        print("input len", len(inp))
        print("input", inp[:500])
        if len(inp) > 10:
            raw = bytes.fromhex(inp[2:])
            # skip selector
            data = raw[4:]
            print("data ascii", "".join(chr(c) if 32<=c<127 else "." for c in data[:300]))
            # if bytes ABI: offset + length + data
            if len(data) >= 64:
                off = int.from_bytes(data[0:32], "big")
                print("off", off)
                if off == 32 and len(data) >= 64:
                    ln = int.from_bytes(data[32:64], "big")
                    print("len", ln)
                    blob = data[64:64+ln]
                    print("blob", blob)
                    print("blob ascii", blob.decode("latin-1", errors="replace"))
    except Exception as e:
        print(label, e)

# try x9 with correct selector from node output
# parse encode
enc = None
for line in r.stdout.splitlines():
    if line.startswith("encode x9"):
        enc = line.split()[-1]
print("\nencoded x9", enc)
if enc:
    res = rpc("eth_call", [{"to": DRAIN, "data": enc}, "latest"])
    print("x9 call", res)
    val = res.get("result","")
    if val and val.startswith("0x") and len(val) > 2:
        raw = bytes.fromhex(val[2:])
        print("raw", raw[:200])
        if len(raw) >= 64:
            ln = int.from_bytes(raw[32:64], "big")
            print("str", raw[64:64+ln])

# try all selectors from stdout
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) >= 2 and parts[1].startswith("0x") and len(parts[1]) >= 10:
        sel = parts[1][:10]
        data = sel if parts[0] in ("x1","x7") else None
        if parts[0] in ("x1","x7"):
            res = rpc("eth_call", [{"to": DRAIN, "data": data}, "latest"])
            print(parts[0], sel, res.get("result"))
