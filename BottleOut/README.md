# BottleOut (Sherlock 02)

**Title (from PDF metadata):** Holmes CTF 2026 - Sherlock 02 - **XMPP Server Forensics**

## Status

| Item | State |
|------|--------|
| Story PDF | Present (`Holmes CTF 2026 Sherlock 02.pdf`) |
| Evidence package | **Missing** — only narrative in local zip |
| Questions on HTB UI | Not captured yet |
| Flags | 0/N — do not invent |

## Start gate (from htb-ctf-forensics)

1. Download the **full** BottleOut challenge zip from HTB (not just the story PDF).
2. Screenshot the challenge card: questions, flag count, format hints.
3. Inventory evidence (pcap, memory, XMPP config, logs, …).
4. Only then extract / analyze — static first.

## Theme hints from the story (not flags)

- Silvertown container yards → physical lead
- Abandoned laptop, wiped activity
- One communications client left; account/server unknown
- Recover what survived the wipe → link operator to the wider operation

Expect: XMPP / chat forensics, artifact recovery, maybe TLS or XML streams.

## When evidence lands

- Follow `skills/htb-ctf-forensics`
- Mirror SilentDividend walkthrough style under `BottleOut/walkthroughs/`
- Submit **bare** answers matching UI type hints
