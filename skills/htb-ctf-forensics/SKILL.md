---
name: htb-ctf-forensics
description: HTB Holmes CTF / Sherlock-style blue-team forensics workflow for multi-flag challenges. Use when the user mentions HTB CTF, Sherlock, Holmes CTF, Reichenbach, silent dividend, "submit flag", Flags N/10, malware samples, smart-contract forensics, or asks to solve HTB investigation challenges. Enforces format detection before submission, no invented HTB{} wraps of IOCs, stage-by-stage evidence extraction, and host-safe malware analysis. Do NOT use for generic coding, Flutter, or non-CTF app work.
---

# HTB CTF / Sherlock forensics

Blue-team multi-flag CTF methodology (Holmes CTF / HTB Sherlock style). Research-backed: auto-wrapping IOCs as `HTB{value}` fails; flags are format-specific answers or fully-formed planted tokens.

## Critical rules (never skip)

1. **Context first.** Inventory: challenge UI (full page, Tasks, description), every evidence file, flag counter, any password/readme. If UI shows `Flags N/10` with no questions, screenshot it and check Discord/support — do not invent flags.
2. **Never invent `HTB{secret}`** from interesting IOCs. Wrap **only** if decoded bytes/UI already show `HTB{` / `flag{` / explicit format instructions.
3. **Official format notes** (verify per challenge): CTF event flags may be bare date/name/IP/CVE **or** `HTB{...}`; Labs Challenges default `HTB{...}` unless description says otherwise; Labs Sherlocks are Q&A free-form answers.
4. **Do not execute malware on the analyst host.** Static first. Dynamic only in disposable VM (no real wallet, no real `.env`, snapshot first).
5. **IOCs ≠ flags.** Recover everything; submit only values that answer a task or match a planted flag token.

## Workflow

### Phase 0 — Brief compliance (first 30 min)

- State the event/challenge name and exact UI text for flag submission.
- List all evidence files + hashes; note missing packages.
- Cold-open every download link/deploy path in a fresh browser profile.
- Record: flag count, difficulty, any listed tasks, archive password source.

### Phase 1 — Format detection (before any submit)

Search evidence for fully-formed flags:

- `HTB{...}`, `flag{...}`, `HTB_...`
- base64 of `HTB{` (`SEJU`), hex `4854427b`
- XOR/encoding passes on blobs
- On-chain/view-function outputs that are already `HTB{...}`

If none found and no questions listed → **stop submitting**; escalate (UI missing tasks) or continue extraction until planted tokens appear.

### Phase 2 — Evidence extraction (layered)

| Layer | Actions |
|---|---|
| Container | unzip with correct password; list all members; note overlays/tails |
| Installer | identify NSIS/Inno/7z/PyInstaller/Electron; extract with 7za |
| App source | asar/asar extract; read main/preload/renderer/config |
| Network/chain | RPC eth_call all view functions; Sourcify verified source; storage; tx input |
| Crypto | reimplement decrypt exactly; try only keys found in evidence |
| Second stage | obfuscated scripts (Lua/JS/Python): static decoder, cribs from first stage |

Write a running IOC table: name, value, source file/line, confidence.

### Phase 3 — Obfuscated second stage (Lua/Luraph class)

1. Fingerprint: IIFE + string table + VM arithmetic.
2. Extract decoder offline (b64 / XOR / custom alphabet / RC4); use known plaintext from stage-1 (`powershell`, `luajit`, `Public`, contract strings).
3. Port decoder to Python; dump all plaintext strings; grep `HTB{`/`flag{`/unique tokens.
4. If static fails → sandbox decoder-only in Lua 5.1/LuaJIT **without** running package payload APIs (`io`, `os.execute`, network).
5. Full payload run: disposable VM only.

### Phase 4 — Submission policy

Submit **only** if one of these is true:

- UI question explicitly asks for that value, **or**
- Evidence contains a fully-formed flag token, **or**
- Challenge description states the exact format and the value matches that format.

Otherwise keep the value in the IOC table. Do not shotgun.

### Phase 5 — Re-solve checklist (failed submissions)

- Did we wrap when we should not have? → retry **bare** form of the same value.
- Are questions hidden in another panel / Discord / PDF post-solve section?
- Is a whole stage still encrypted? → finish extraction first.
- Still no tasks + all formats fail → HTB CTF support ticket.

## Examples

**User:** “Silent Dividend, Flags 0/10, no questions, HTB{NAPOLEON} wrong.”  
**Action:** Phase 0 screenshot request + Phase 1 re-scan + treat NAPOLEON as IOC not flag; extract Lua; try bare values only if format research/UI supports it.

**User:** “HTB Sherlock memory dump, 10 tasks.”  
**Action:** Map each task to evidence; submit free-form answers as the UI specifies; no auto HTB{} wrap.

## Troubleshooting

| Problem | Fix |
|---|---|
| All HTB{IOC} rejected | Stop wraps; detect format; hunt planted tokens / questions |
| Zip won’t open | Challenge password `hackthebox` vs Sherlock package `hacktheblue` vs challenge-specific (read DANGER/readme) |
| Strings encrypted on disk | Second-stage decoder / on-chain key — do not guess |
| Temptation to run sample on host | Don’t. VM or static only |
| No questions in UI | Full DOM screenshot, Discord, support — not IOC shotgun |

## Bundled references

- `references/flag-format.md` — format decision tree
- `references/extraction-checklist.md` — layer checklist
- Research notes: `C:\src\projects\HackTheBox CTF Holme\research\htb-sherlock-flags\REPORT.md`
