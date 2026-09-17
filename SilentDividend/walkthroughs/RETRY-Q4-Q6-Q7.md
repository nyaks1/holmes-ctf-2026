# SilentDividend — last 3 retries (after 7/10)

Confirmed wrong: `resolveState`, `approve`, `TEMP` (bare as previously listed).

UI type hints matter:

| Q | UI hint | What we submitted | What to try now |
|---|---------|-------------------|-----------------|
| **4** | `(function())` | `resolveState` | **`resolveState()`** |
| **7** | `(function())` | `approve` | **`approve()`** |
| **6** | `(string)` | `TEMP` | **`%TEMP%`**, then others |

---

## Q4 — contract function for decrypt key

**Question:** Which smart contract function does the Electron application invoke to retrieve the decryption key for the encrypted payload?

**Evidence (unchanged — concept is correct):**

`asar/preload.js`

```javascript
const CONTRACT_ABI = [
    'function resolveState() view returns (bytes32)'
];
// ...
const state = await contract.resolveState();
```

That **is** the only contract call used to get the decrypt key.

**Why bare `resolveState` may fail:** UI type is `(function())` — they likely want the **call form**:

```text
resolveState()
```

**Retry order**

1. `resolveState()` ← do this first  
2. If still wrong: `resolveState` (already failed — skip)  
3. Only if both fail: re-read whether they want a different registry function (preload does **not** call the others)

---

## Q7 — token function for spending permission

**Question:** What token function does the HTML page call to request spending permission?

**Evidence:**

`asar/src/settlement.html`

```javascript
"name": "approve",   // MOCK_TOKEN_ABI
const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount);
```

Spending permission on ERC-20 = **`approve`**. Concept is correct.

**UI hint `(function())`** → submit:

```text
approve()
```

**Retry order**

1. `approve()`  
2. `approve(address,uint256)` (full Solidity signature) — only if (1) fails  
3. Not `requestApproval` — that’s the **JS** wrapper, not the **token** function

---

## Q6 — environment variable for HTML directory

**Question:** Which environment variable corresponds to the directory where the application copies the HTML file from its package?

**What the code actually does**

| Step | Location | Destination |
|------|----------|-------------|
| Package source | `app.asar` → `src/settlement.html` | — |
| Electron copy | `preload.js` `writeFileSync` | `process.resourcesPath/../../settlement.html` |
| Command opens | decrypted payload | `%TEMP%\settlement.html` |

`TEMP` alone was rejected.

**Retry order (string, exact)**

1. **`%TEMP%`** — form used in the decrypted command  
2. **`PUBLIC`** — env var for `C:\Users\Public` (if they treat “drop directory” loosely; Q1 path already accepted)  
3. **`TMP`**  
4. **`LOCALAPPDATA`** / **`APPDATA`** — if they map install `resources/../..` to a profile dir  
5. **`ProgramFiles`** / **`PROGRAMFILES`** — if install is under Program Files  

**Do not** resubmit bare `TEMP`.

---

## Submit now (one at a time)

```text
resolveState()
approve()
%TEMP%
PUBLIC
TMP
```

Report which line the score moves on. If `resolveState()` and `approve()` both land, format was the bug — same lesson as the `HTB{}` mistake: **match the UI type, not just the IOC**.
