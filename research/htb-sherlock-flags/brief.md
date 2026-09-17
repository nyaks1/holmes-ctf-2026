# Research brief — HTB Holmes CTF / Sherlock flag mechanics

Date: 2026-09-17
Depth: standard
Workspace: C:\src\projects\HackTheBox CTF Holme\research\htb-sherlock-flags

## Question
How do HTB multi-flag "Sherlock" style CTF challenges (Holmes CTF 2026: The Reichenbach Directive) plant and expect flags when the UI shows only "Submit flag" + Flags N/10 and no question list? Why would HTB{IOC-wrapping} of recovered secrets all fail?

## Scope
IN: HTB flag formats, Sherlock challenge structure (platform + past public events), multi-flag CTF patterns, planted-flag search methodology, obfuscated second-stage extraction, smart-contract/malware CTF answer conventions.
OUT: Writing writeups for the live 2026 event; executing malware on the analyst host; solving BottleOut/WhisperChain without evidence.

## Assumptions
- Event runs Sep 17–21 2026; public writeups likely do not exist yet.
- SilentDividend package = Sherlock 01 "Malicious Smart Contract" + TrustSettle sample; flags 0/10.
- Analyst submitted HTB{NAPOLEON}, HTB{SR-4821}, contract addresses, etc. — all rejected.
- Goal: methodology + skill, then re-solve correctly.

## Angles
- A1: HTB official/flag format conventions (Sherlock vs CTF events vs challenges).
- A2: Past public HTB Sherlock / blue-team multi-flag challenge structure (questions vs blind flags).
- A3: How CTF malware flags are planted (embedded strings, encodings, runtime-only, blockchain).
- A4: Lua/Luraph obfuscated payload extraction methods used in CTF/forensics.
- A5: Smart-contract CTF flag recovery patterns (storage, view functions, events).
- A6: What we may have missed in the local sample (format variants, non-HTB wraps, hashes).
