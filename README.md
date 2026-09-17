# Holmes CTF 2026 — The Reichenbach Directive

Team workspace for HTB Holmes CTF 2026 (Sherlock-style blue-team investigations).

**Event:** Sep 17–21, 2026 · CTF multi-flag challenges · APT narrative: NAPOLEON

## Status

| Sherlock | Name | Evidence | Status |
|----------|------|----------|--------|
| 01 | Silent Dividend — Malicious Smart Contract | `SilentDividend/` (TrustSettle sample) | **Solved 10/10** |
| 02 | Bottle Out — XMPP Server Forensics | `BottleOut/` (story PDF; **need full evidence**) | Next |
| 03 | Whisper Chain | `WhisperChain/` (story PDF only) | Not started |

## Repo map

```text
README.md                 ← you are here
skills/                   ← MiMoCode skills (also live under .mimocode/skills/)
research/                 ← flag-format research + REPORT.md
SilentDividend/
  walkthroughs/           ← per-question team writeups (10/10)
  *.py                    ← analysis scripts (static)
  *.pdf                   ← story / challenge brief
BottleOut/                ← Sherlock 02
WhisperChain/             ← Sherlock 03
tools/                    ← 7zr (local only; binaries gitignored)
```

## SilentDividend — confirmed answers

| Q | Answer |
|---|--------|
| 1 | `C:\Users\Public` |
| 2 | `FILE_NOTIFY_INFORMATION` |
| 3 | `WinHttpSendRequest` |
| 4 | `resolveState()` |
| 5 | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` |
| 6 | `%TEMP%` |
| 7 | `approve()` |
| 8 | `115792089237316195423570985008687907853269984665640564039457584007913129639935` |
| 9 | `BrowserProvider` |
| 10 | `51.5049,0.0348` |

Full paths: [SilentDividend/walkthroughs/README.md](SilentDividend/walkthroughs/README.md)

## Team rules (non-negotiable)

1. **UI type is part of the answer** — `(function())` → `name()`; watch `%VAR%` vs bare name.
2. **Never invent `HTB{...}` wraps** unless the UI or decoded bytes show that format.
3. **IOC ≠ flag** — recover everything; submit only what the question asks.
4. **Malware stays static** — unpack in analysis trees; execute only in a disposable VM.
5. **Context first** — inventory questions, evidence, format before guessing.
6. **POPIA** — this malware steals wallet keys; never run samples on machines with real data.

## Skills

| Skill | Use |
|-------|-----|
| `htb-ctf-forensics` | Multi-flag Sherlock/CTF workflow |
| `eth-contract-ctf-forensics` | Chain/drainer extraction |

Copy into `~/.config/mimocode/skills/` or use `.mimocode/skills/` in this repo.

## BottleOut — start gate

Story PDF is **not** evidence. Before analysis:

- [ ] Download full BottleOut challenge package from HTB
- [ ] Inventory files + questions on the challenge UI
- [ ] Confirm format per question
- [ ] Then extract — same skill loop as SilentDividend

## Mentor notes

- Build the man: process over pasted flags.
- Sell the shovel: these walkthroughs are the reusable product.
- Team silence ≠ your job is wrong — publish the pack, assign Qs, set a deadline.
