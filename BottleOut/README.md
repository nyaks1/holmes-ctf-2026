# BottleOut (Sherlock 02) — Phase 0 status

**Title:** Holmes CTF 2026 - Sherlock 02 - **XMPP Server Forensics**  
**Skill:** `htb-ctf-forensics` Phase 0  
**Date:** 2026-09-17

## Inventory

| Item | State |
|------|--------|
| Story PDF | ✅ `Holmes CTF 2026 Sherlock 02.pdf` (3 chapters) |
| This README | ✅ |
| XMPP/laptop/disk evidence | ❌ **Not on disk** |
| HTB download beyond PDF | ❌ User: HTB only has the PDF |
| Challenge questions (UI) | ❌ **Not captured yet** |
| Flag count / format hints | ❌ Unknown |
| Archive password | N/A — no evidence zip yet |

## Story brief (spoiler-safe — not flags)

- Continues from SilentDividend (settlement client, exfil, physical lead).
- Silvertown container: Watson recovered; guard fled.
- Abandoned **powered laptop**; hurried wipe.
- **One communications client** left; account/server/purpose unknown.
- Task: recover what survived the wipe → how the laptop tied the operator to the wider op.
- PDF metadata: **XMPP Server Forensics**.

## Phase 0 gate (do not invent flags)

Per skill: **no evidence + no questions = no submissions.**

1. Open HTB **BottleOut challenge card** (logged in).
2. Expand **every** download / Scenario Files entry — re-check for anything besides the PDF (zip, memory, pcap, “Server files”, etc.).
3. Paste **all questions verbatim** + type hints `(string)`, `(function())`, paths, etc. (same as SilentDividend).
4. Record flag count (e.g. Flags 0/10).
5. If truly PDF-only **and** questions reference laptop/XMPP artifacts we don’t have → we need another source (full challenge bundle, team copy, or HTB support). We still **cannot** answer forensics questions from the story alone.

## When evidence + questions land

- Unpack static → inventory → format detection → extract → **bare** answers matching UI type.
- Walkthroughs: `BottleOut/walkthroughs/` (same style as SilentDividend).
- XMPP forensics likely: client config, accounts, servers, streams/logs, maybe TLS or XML — **only after we have files**.

## Theme prep (study, not flags)

| Topic | Why it matters |
|-------|----------------|
| XMPP (Jabber) | Addresses `user@domain`, servers, c2s/s2s |
| Clients | Conversations, Gajim, Pidgin, Psi, Thunderbird, etc. |
| Artifacts | Profiles, logs, XML, OMEMO/OTR, prefs, accounts |
| Wipe recovery | Volume shadow, `$MFT`, memory, hiberfil, USB |
| Link to op | Operator handle, server domain, timestamps, IOCs |

## Repo

Pushed to `https://github.com/nyaks1/holmes-ctf-2026` — commit Phase 0 notes when questions arrive.
