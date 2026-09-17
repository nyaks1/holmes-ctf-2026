# Research report — HTB Holmes CTF / Sherlock flag mechanics

Date accessed: 2026-09-17  
Workspace: `C:\src\projects\HackTheBox CTF Holme\research\htb-sherlock-flags`  
Depth: standard (4 parallel angles)

## Conclusions

1. **Auto-wrapping every IOC as `HTB{value}` is a known failure mode.** Official CTF User’s Guide: most common format is `HTB{XXXXXX}`, but flags may also be a **date, name, IP, or CVE** — bare values [1]. Labs Challenges say `HTB{...}` always **unless the challenge description says otherwise** [2]. Holmes UI (“Submit flag” + Flags 0/10, no questions) matches **CTF multi-flag checkpoints**, not Labs Sherlock Q&A [6][9].

2. **Labs Sherlocks are question/answer investigations**, not monolithic flag strings. Answers are free-form (paths, IPs, timestamps, MITRE IDs) [3][4][5]. Inventing flags from every recovered secret is a documented failure mode — only the value that answers a task is a flag [F2].

3. **Holmes CTF 2026 is live (Sep 17–21).** Public writeups/task lists are not available. Official help does **not** document “Submit flag when no questions are listed” — missing questions may be an event packaging issue, not player error [8][F1].

4. **Malware/contract flags are planted as:** literals, encodings (b64/XOR/hex), **runtime-only** strings after deobfuscation, blockchain dead-drops, or config/exfil — not always on disk in `HTB{}` form [F3]. AUTH=`NAPOLEON` and coords `51.5049,0.0348` look like **layer-1 IOCs / narrative**, not necessarily flags. Wrap only if decoded bytes already contain `HTB{` or `flag{` [F3].

5. **`api.txt` is Luraph-class obfuscated Lua.** String recovery requires decoder reconstruction (b64 / XOR / custom alphabet / RC4), known-plaintext cribs (`powershell`, `luajit`, `Public`), and **never** running package `luajit.exe` on the analyst host [F4]. Remaining flags likely live in that stage or in hidden challenge UI/tasks.

6. **Why the previous 10 submissions failed:** we submitted `HTB{IOC}` wrappers of interesting values. Research predicts **either bare answers or fully-formed planted tokens**, not invented wraps [1][3][9][F3].

## Open questions

- Where does this event list the 10 tasks if not on the challenge card? (login UI, Tasks tab, Discord, evidence README)
- Are checkpoint flags bare IOC-shaped values or planted `HTB{...}` strings in Lua/on-chain?
- Is “Flags 0/10” a packaging bug (questions missing)?

## Practical rules for re-solve

1. Inventory UI + evidence **before** any submit.
2. Detect format from sample/UI; **do not invent wraps**.
3. Extract all stages (Electron → chain → Lua) offline first.
4. Submit only evidence-backed, question-shaped or fully-formed tokens.
5. Malware execution: disposable VM only — never the daily host.
6. If UI truly has no tasks after full inventory: screenshot + HTB Discord/support — don’t shotgun IOCs.

## Sources

[1] https://help.hackthebox.com/en/articles/5200851-ctf-user-s-guide  
[2] https://help.hackthebox.com/en/articles/5185436-how-to-play-challenges  
[3] https://help.hackthebox.com/en/articles/8570249-how-to-play-sherlocks  
[4] https://help.hackthebox.com/en/articles/8570249-how-to-play-sherlocks (Play Sherlock / Linear / Free-flow)  
[5] https://help.hackthebox.com/en/articles/8463668-sherlocks-submission-requirements  
[6] https://help.hackthebox.com/en/articles/5200851-ctf-user-s-guide (multi-flag checkpoints)  
[8] HTB help collections 2919917 / 2919931  
[F1–F4] `research/htb-sherlock-flags/findings/F*.md`

## Local evidence (unchanged)

SilentDividend static findings remain valid as **IOCs**, not as flags: TrustSettle 1.0.0, Sepolia contracts, hidden owner, decrypt key, `AUTH=NAPOLEON`, `SR-4821`, `51.5049,0.0348`, drop path `C:\Users\Public`, Lua second stage still encrypted.
