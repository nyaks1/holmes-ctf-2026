# SilentDividend Q6 — Finding `%TEMP%`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** Which environment variable corresponds to the directory where the application copies the HTML file from its package?  
**UI type:** `(string)`  
**Answer (confirmed):** `%TEMP%`  
**Format:** bare string **including percent signs** — no `HTB{}` wrap

---

## What the question is asking

The Electron package ships `settlement.html`. After decrypt, the client **opens** that HTML via a shell command that uses a **Windows environment variable**. The UI wants that **variable in expanded form** (`%TEMP%`), not the bare name `TEMP`.

---

## Attack path

### 1. Where the HTML lives in the package

```text
asar/src/settlement.html
installer: src/settlement.html
```

`preload.js` reads it from the package and writes a copy:

```javascript
const indexContent = fs.readFileSync(
  path.join(__dirname, 'src', 'settlement.html'), 'utf8');
fs.writeFileSync(
  path.resolve(`${process.resourcesPath}/../../settlement.html`),
  indexContent, 'utf8');
```

That write path is **not** an env var. The **flagged** location is in the **decrypted command**.

### 2. Decrypt the payload (same key as Q4/Q5)

Key from `resolveState()` → decrypt `ENCRYPTED_DATA` (XOR + ROL7 + XOR `0x42`).

Plaintext:

```text
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

### 3. Map wording → answer

| Piece | Meaning |
|-------|---------|
| `%TEMP%` | Env var for the user temp directory |
| `settlement.html` | HTML from the package |
| `start "" "%TEMP%\settlement.html"` | Open that HTML from the temp dir |

Confirmed submit:

```text
%TEMP%
```

### 4. Why `TEMP` failed

Same variable, wrong **surface form**. Graders for `(string)` here want the **cmd-style expansion**.

**Do not** resubmit: `TEMP`, `TMP` (unless a future variant asks), `C:\Users\Public` (that is Q1 / extraResources).

---

## Team checklist

- [ ] Decrypt payload using preload + Sepolia key.
- [ ] Read `start "" "%TEMP%\settlement.html"`.
- [ ] Submit **`%TEMP%`** with percents.
- [ ] Keep Q1 (`C:\Users\Public`) separate from Q6 (HTML / temp).

---

## One-line brief

> Decrypted exec opens package HTML at `%TEMP%\settlement.html` — submit `%TEMP%`.

---

*Confirmed flag.*
