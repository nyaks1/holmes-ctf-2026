# BottleOut — 10 questions → required evidence

UI questions received 2026-09-17. **Flags: 10.** Local evidence: story PDF only.

| Q | Question (verbatim) | Answer type | Artifact we need |
|---|---------------------|-------------|------------------|
| 1 | Remote address and port of the VPN server the user connected to | `IPv4:port` | VPN client config, logs, connection history, memory, pcap |
| 2 | Certificate Authority (CA) that issued the VPN client certificate | `string` | Client cert / PEM / profile `ca` field, cert store |
| 3 | IP address assigned to the user by the VPN server | `IPv4` | VPN session logs, adapter config, DHCP/route, memory |
| 4 | Name and version of installed remote management agent | `Agent Name v.X.Y.Z` | Installed programs, RMM service, binary version resource |
| 5 | Domain the remote management agent connects to | `FQDN` | RMM config, DNS cache, logs, process network |
| 6 | Remote management agent Authentication Token | `SHA-1 Hash` | RMM config/db, registry, memory, logs |
| 7 | First of three commands in Operation Vanish | `*********** ************ *:\*****\****\***** ******** ******` (looks like `something something C:\path\path\file xxxxxx xxxxxx`) | Prefetch, shimcache, PowerShell history, bash history, wipe script, memory |
| 8 | Account to connect to the instant messaging server (XMPP) | `email address` | XMPP client profile (JID), logs, accounts.xml |
| 9 | Password for that account | `string` | Same client store — often cleartext or weakly protected |
| 10 | Full name of the jailer | `FirstName LastName` | User profile, documents, operator handle mapping, story-linked artifact |

## Status

| Gate | State |
|------|--------|
| Questions | ✅ Captured |
| Evidence package | ❌ Missing (PDF only on HTB per player) |
| Submissions | ⛔ Blocked — skill Phase 0/2 |

## What HTB should have shipped (typical for this question set)

- Memory dump and/or disk image of the **Silvertown laptop**
- Or: VPN profile + RMM folder + XMPP client directory
- Challenge UI “Scenario Files” beyond the PDF

## Do not

- Guess `1.2.3.4:443`, CA names, tokens, or passwords from the story
- Submit `HTB{...}` wraps
- Treat PDF image noise as JIDs
