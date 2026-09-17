# BottleOut — Phase 1 result + Phase 2 gate

**Flags:** 10 (same multi-flag CTF pattern as SilentDividend)  
**Evidence on disk:** story PDF only  
**Questions:** **not provided yet**  
**Submissions:** none — skill gate

## Phase 1 (PDF static)

Ran `phase1_pdf_scan.py`:

- No `HTB{...}` / `flag{...}` planted in PDF or images (reconfirm on this run).
- Story = Silvertown laptop + wiped comms client + XMPP forensics theme.
- No pcap, memory, client profile, or server dump on disk.

## Phase 2 gate (same loop as SilentDividend)

SilentDividend only moved when we had:

1. **Evidence** (TrustSettle sample) **and**
2. **The 10 UI questions** + type hints

BottleOut needs the same. Paste all **10 questions** with format hints. Re-check HTB Scenario Files for any non-PDF download.

## Do not submit yet

Inventing `user@domain` or server names from the story = 0/10 again.

## Prep when questions arrive

| Likely theme | Tooling |
|--------------|---------|
| XMPP account / server | client config, XML, logs |
| Hostname / JID | strings on image/disk |
| Wipe recovery | MFT, shadow, memory |
| Operator link | timestamps, artifacts, story cross-ref |

Walkthroughs target: `BottleOut/walkthroughs/` after confirmed answers.
