# SilentDividend Q9 — Finding `BrowserProvider`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** What ethers.js v6 provider class is used to connect to the browser wallet? (string)  
**Answer (confirmed):** `BrowserProvider`  
**Format:** bare string — **do not** wrap as `HTB{BrowserProvider}`

---

## What the question is asking

The fake “settlement” client is an **Electron** app. The victim-facing page is not the payment logic — it is a **crypto drainer** written with **ethers v6**.

“Browser wallet” means an injected provider such as MetaMask (`window.ethereum`).  
In ethers **v6**, the class that wraps that injected provider is **`BrowserProvider`**.

Old tutorials use `Web3Provider` (ethers v5). That is the trap. This challenge uses **v6**.

---

## Attack path (do this in order)

### 1. Get the sample on disk (static only)

- Open `SilentDividend.zip` → story PDF + `DANGER.txt` + `danger.zip`.
- Password is in `DANGER.txt` (challenge-specific — do not invent `hackthebox` if the file says otherwise).
- **Do not run** `TrustSettle 1.0.0.exe` on a daily driver. Unpack only.

```text
SilentDividend/
  DANGER.txt
  danger.zip          → TrustSettle 1.0.0.exe  (NSIS / installer)
  Holmes CTF 2026 Sherlock 01.pdf
```

### 2. Peel the installer

`TrustSettle 1.0.0.exe` is a packed **NSIS** archive (7-Zip Type shows `7z` with a tail). Extract with `7za` / 7-Zip — still no execution.

Look for an **Electron** layout:

```text
TrustSettle.exe
resources/app.asar
src/index.html
src/settlement.html      ← drainer UI
src/renderer.js
extraResources/…
```

`settlement.html` in the **installer tree** is a strong lead even before you open the asar.

### 3. Extract `app.asar` (application source)

```bash
npx asar extract resources\app.asar asar\
# or: npm exec -- asar extract …
```

You want the **app’s own** files, not `node_modules`:

| File | Role |
|------|------|
| `asar/main.js` | Creates `BrowserWindow` (insecure prefs) |
| `asar/preload.js` | Drops payload, talks to chain, decrypts command |
| `asar/src/settlement.html` | Wallet UI + ethers calls |
| `asar/src/renderer.js` | Camouflage “game” + `appVault` IPC |

### 4. Open the wallet page source

File: `asar/src/settlement.html`

What matters is the **script**, not the fake Terms of Service text.

Search for ethers usage:

```text
ethers.
BrowserProvider
Web3Provider
JsonRpcProvider
window.ethereum
MetaMask
```

### 5. Read the exact line (this is the answer)

From the challenge package (path may vary slightly after extract):

**`SilentDividend/asar/src/settlement.html`**

```javascript
provider = new ethers.BrowserProvider(window.ethereum);
await provider.send("eth_requestAccounts", []);
signer = await provider.getSigner();
```

That single constructor is the class the question wants:

```text
ethers.BrowserProvider
```

Submit:

```text
BrowserProvider
```

### 6. Cross-check so you do not submit the wrong provider

Same file also has (for context — **not** Q9):

| Item | Where | What it is |
|------|--------|------------|
| `ethers.MaxUint256` | `requestApproval()` | Unlimited approve **amount** (Q8) |
| `token.approve(...)` | same | ERC-20 **function** (Q7) |
| `X0_CONTRACT_ADDRESS` | top of script | Drainer contract |
| `MOCK_TOKEN_ADDRESS` | top of script | Token being approved |

`preload.js` uses **`JsonRpcProvider`** to talk to **Sepolia RPC** — that is **server-side / node** JSON-RPC, **not** the browser wallet. Do not submit `JsonRpcProvider` for Q9.

```javascript
// preload.js — chain read, NOT the wallet
const provider = new ethers.JsonRpcProvider(RPC_URL);
```

---

## Tiny ethers v6 example (why the name)

```javascript
// ethers v5 (WRONG for this challenge)
// provider = new ethers.providers.Web3Provider(window.ethereum);

// ethers v6 (CORRECT)
const provider = new ethers.BrowserProvider(window.ethereum);
const accounts = await provider.send("eth_requestAccounts", []);
const signer = await provider.getSigner();
```

`BrowserProvider` = “I am in a browser; wrap `window.ethereum`.”  
`JsonRpcProvider` = “I am talking to an RPC URL.”  
The question says **browser wallet** → **`BrowserProvider`**.

---

## Team checklist

- [ ] Unpack sample **static** (no double-click on TrustSettle).
- [ ] Extract installer → find `settlement.html` / `app.asar`.
- [ ] Extract asar → open `src/settlement.html`.
- [ ] Grep `ethers.` and `Provider`.
- [ ] Confirm `new ethers.BrowserProvider(window.ethereum)`.
- [ ] Confirm ethers **v6** (`package.json` / `BrowserProvider` not `providers.Web3Provider`).
- [ ] Submit **bare** `BrowserProvider` (no `HTB{}`).
- [ ] Keep `JsonRpcProvider` out of this slot — wrong layer.

---

## Skill rules this follows

From `htb-ctf-forensics` / `eth-contract-ctf-forensics`:

1. Inventory evidence before guessing.
2. **Never invent `HTB{…}` wraps** unless the UI or decoded bytes already show that format.
3. Answer **the question asked** (wallet provider ≠ RPC provider).
4. Cite `file` + line when you brief the team.

---

## One-line brief for the team

> SilentDividend’s drainer page is ethers v6; it connects MetaMask with `new ethers.BrowserProvider(window.ethereum)` in `app.asar` → `src/settlement.html`. Submit `BrowserProvider`.

---

*Confirmed on Holmes CTF 2026 Silent Dividend Q9. Static analysis only.*
