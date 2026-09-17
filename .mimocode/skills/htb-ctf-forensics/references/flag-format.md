# Flag format decision tree

```
START
  |
  v
Does challenge UI/description state exact format?
  |-- YES --> Follow it exactly (HTB{...} or bare or custom)
  |
  v
Do decoded evidence bytes already contain HTB{ or flag{?
  |-- YES --> Submit that token as-is
  |
  v
Are there listed questions/tasks?
  |-- YES --> Submit the value that answers the task
  |            (free-form: path, IP, hash, date, name)
  |            Wrap only if the task/UI says so
  |
  v
Flags N/10 + submit box + NO questions?
  |-- Inventory UI fully (Tasks tab, expand, Discord, PDF)
  |-- Still none --> Do NOT shotgun IOCs
  |                  Prefer: extract all stages until planted
  |                  tokens appear; or try BARE forms of the
  |                  most question-shaped secrets only after
  |                  format research; or file HTB support ticket
  |
  v
Only wrap HTB{x} when:
  - description requires it, OR
  - x is already inside HTB{...} in evidence
```

## Common planted token shapes

- `HTB{snake_or_words}`
- `flag{...}`
- bare: IPv4, email, hostname, CVE, date, MITRE ID, file path
- bare hash: md5/sha256 of a known file
- fully-formed on-chain string (not every bytes32)

## Anti-patterns (caused SilentDividend 0/10)

- `HTB{` + every contract address + `}`
- `HTB{` + AUTH narrative + `}`
- Submitting story PDF names as flags
- Treating font `/Flags` in PDF as CTF flags
