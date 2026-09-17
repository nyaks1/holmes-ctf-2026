# SilentDividend Q3 — Finding `WinHttpSendRequest`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** Which Win32 API is used by the Lua script to send an HTTP request to the remote server? (string)  
**Answer (confirmed):** `WinHttpSendRequest`  
**Format:** bare API name — **no** `HTB{}` wrap

---

## What the question is asking

Same Lua second stage as Q2 (`api.txt` via `luajit.exe`).  
After local recon (directory watch, steal, etc.), the script **exfiltrates** over **HTTP** to a remote server.

You need the **Win32 API function** that **sends** that HTTP request — not a Lua library name, not a URL.

---

## Attack path

### 1. Second stage location (from Electron preload)

```text
extraResources → C:\Users\Public\api.txt
exec: powershell … luajit.exe C:\Users\Public\api.txt
```

### 2. Think in API families

Windows HTTP from native/LuaJIT FFI is usually one of:

| Family | Typical calls | Notes |
|--------|---------------|--------|
| **WinHTTP** | `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, **`WinHttpSendRequest`**, `WinHttpReceiveResponse` | Service-oriented; common in malware |
| WinINet | `InternetOpen`, `InternetConnect`, `HttpOpenRequest`, `HttpSendRequest`, `InternetOpenUrl` | Older desktop API |

The question says **“send an HTTP request”** → the **send** step.

### 3. Match wording to the confirmed answer

| Wording | Best match |
|---------|------------|
| send an HTTP request | **`WinHttpSendRequest`** |

Pipeline the team should picture:

```text
WinHttpOpen
  → WinHttpConnect
    → WinHttpOpenRequest
      → WinHttpSendRequest    ← question target
        → WinHttpReceiveResponse
```

### 4. Why grepping `api.txt` may fail

Obfuscated Lua hides string constants. Process:

1. Static first: no plaintext `WinHttp` in the packed file is **normal**.
2. Offline decoder **or** disposable VM + API/string monitor (Procmon, API Monitor) while the script runs **with network blocked**.
3. Look for `winhttp.dll` loads and `WinHttpSendRequest`.

**Never** run package `luajit.exe api.txt` on the team’s daily hosts.

### 5. Submit

```text
WinHttpSendRequest
```

If a future variant asks for a different step:

| If the question said… | Answer |
|----------------------|--------|
| create session | `WinHttpOpen` |
| connect host | `WinHttpConnect` |
| create request handle | `WinHttpOpenRequest` |
| **send request** | **`WinHttpSendRequest`** |
| read body | `WinHttpReadData` |

Confirmed for **this** challenge: send → **`WinHttpSendRequest`**.

---

## Mini example (mental model)

```text
Lua/FFI (obfuscated)
    |
    v
winhttp.dll
    WinHttpOpen("...")
    WinHttpConnect(hSession, host, port)
    WinHttpOpenRequest(hConnect, "POST", path, ...)
    WinHttpSendRequest(hRequest, ...)   <-- Q3
    WinHttpReceiveResponse(...)
```

---

## Team checklist

- [ ] Stage is Lua under `C:\Users\Public`, not the Electron UI.
- [ ] Question = **send** HTTP, not open/connect.
- [ ] Family = **WinHTTP** (confirmed).
- [ ] Submit bare `WinHttpSendRequest`.
- [ ] Dynamic work only in a disposable VM / with API monitoring.

---

## One-line brief

> Exfil from the Lua stage uses WinHTTP; the send call is `WinHttpSendRequest`.

---

*Confirmed flag.*
