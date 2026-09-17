# SilentDividend Q2 — Finding `FILE_NOTIFY_INFORMATION`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** Which Win32 structure defines the format of the buffer returned by the Lua script when monitoring directory changes? (string)  
**Answer (confirmed):** `FILE_NOTIFY_INFORMATION`  
**Format:** bare structure name — **no** `HTB{}` wrap

---

## What the question is asking

Second stage is **Lua** (`api.txt` + `luajit.exe`) dropped to `C:\Users\Public`.  
The challenge text says the script **monitors directory changes**. In Win32, that pattern is almost always:

| Piece | Role |
|--------|------|
| `ReadDirectoryChangesW` (API) | Watch a folder |
| **`FILE_NOTIFY_INFORMATION`** | **Buffer record format** returned for each change |

The question asks for the **structure**, not the API function.

---

## Attack path

### 1. Locate the second stage

From Q1 we know the drop path:

```text
C:\Users\Public\api.txt      ← obfuscated Lua
C:\Users\Public\luajit.exe   ← interpreter (from extraResources)
```

In the package: `extraResources/api.txt` and `extraResources/luajit.exe`.

### 2. Understand what “directory change monitoring” means

Typical malware watcher:

1. Open a directory handle
2. Call **`ReadDirectoryChangesW`**
3. Receive a buffer of one or more **`FILE_NOTIFY_INFORMATION`** records
4. Each record has: `NextEntryOffset`, `Action`, `FileNameLength`, `FileName[]`

You are not looking for “who created a file” in the story PDF — you need the **C structure name** that formats that buffer.

### 3. Why static grep of `api.txt` may fail

`api.txt` is **Luraph-class** obfuscated Lua:

```text
return(function(...)local z={"n$...","Q...",...} ... VM loop ...
```

API/structure names are **not** sitting in plaintext. Finding the string in cleartext is expected to fail until you decode the string table or run under a **disposable VM** with logging.

Method for the team:

1. Do **not** execute `luajit.exe api.txt` on a daily laptop.
2. Either reconstruct the decoder offline, or run in a **snapshot VM**, dump strings, grep:

```text
FILE_NOTIFY
ReadDirectoryChanges
Directory
```

3. Map monitoring logic → `ReadDirectoryChangesW` → buffer struct.

### 4. Map question wording → structure (confirmed)

| Question wording | Win32 concept | Structure |
|------------------|---------------|-----------|
| monitoring directory changes | `ReadDirectoryChangesW` | **`FILE_NOTIFY_INFORMATION`** |
| “what happened to a file” action code | `DWORD Action` inside that struct | (not the whole answer) |

Submit:

```text
FILE_NOTIFY_INFORMATION
```

### 5. Do not confuse with

| Name | Why it’s wrong here |
|------|---------------------|
| `WIN32_FIND_DATA` | Directory **enumeration** (`FindFirstFile`), not change **notifications** |
| `OVERLAPPED` | Async I/O wrapper, not the notification payload |
| `FILE_NOTIFY_INFORMATION` vs `FILE_ACTION_*` | Action codes are **fields**, not the buffer struct |

---

## Mini example (conceptual C)

```c
typedef struct _FILE_NOTIFY_INFORMATION {
  DWORD NextEntryOffset;
  DWORD Action;           // added / removed / modified ...
  DWORD FileNameLength;
  WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;
```

LuaJIT malware often `ffi.cdef`s this and walks the buffer from `ReadDirectoryChangesW`.

---

## Team checklist

- [ ] Confirm second stage path from preload (`C:\Users\Public\api.txt`).
- [ ] Note `api.txt` is obfuscated — plan VM/decoder, not hopeful greps alone.
- [ ] Tie “directory changes” → `ReadDirectoryChangesW`.
- [ ] Answer is the **structure**: `FILE_NOTIFY_INFORMATION`.
- [ ] Submit bare name.

---

## One-line brief

> Lua stage watches folders with the Win32 change-notification API; the buffer layout is `FILE_NOTIFY_INFORMATION`.

---

*Confirmed flag. Host-safe: decode/sandbox only; never run the package Lua on the daily box.*
