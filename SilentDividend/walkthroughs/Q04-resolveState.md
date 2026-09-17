# SilentDividend Q4 — Finding `resolveState()`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** Which smart contract function does the Electron application invoke to retrieve the decryption key for the encrypted payload?  
**UI type:** `(function())`  
**Answer (confirmed):** `resolveState()`  
**Format:** bare function **with parentheses** — no `HTB{}` wrap

---

## What the question is asking

Electron `preload.js` encrypts a payload locally, then **reads a key from a Sepolia contract** before decrypting. You must name that **contract view function**, in the form the UI shows: `name()`.

---

## Attack path

### 1. Open preload (not the HTML drainer)

Unpack installer → extract `app.asar` → **`asar/preload.js`**.

### 2. Find the ABI + the call

```javascript
const CONTRACT_ADDRESS =
    '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';

const CONTRACT_ABI = [
    'function resolveState() view returns (bytes32)'
];

// ...
const state = await contract.resolveState();
const decrypted = decryptEmbeddedData(ENCRYPTED_DATA, state);
exec(decrypted);
```

`state` is the **XOR key** for `ENCRYPTED_DATA`. The function that returns it is **`resolveState`**.

### 3. Confirm on-chain (optional)

Sourcify/explorer: `KeyVault.sol` → `StateRegistry` at the same address.  
`resolveState()` returns immutable `x1`. Other views (`resolveStage`, `resolveStatee`, …) are **not** wired in preload.

### 4. Submit format (confirmed)

UI hint is `(function())` → paste:

```text
resolveState()
```

Bare `resolveState` **without** `()` was rejected — concept right, format wrong.

---

## Team checklist

- [ ] Evidence file = `preload.js` (decrypt path), not `settlement.html`.
- [ ] Only contract call for the key = `resolveState`.
- [ ] Submit **`resolveState()`** including parentheses.
- [ ] Same file feeds Q5 (`AUTH=NAPOLEON…`).

---

## One-line brief

> Preload pulls the payload key with `contract.resolveState()` on Sepolia StateRegistry — submit `resolveState()`.

---

*Confirmed flag. 10/10 scenario complete.*
