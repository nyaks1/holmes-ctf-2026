# SilentDividend walkthroughs (team pack)

Holmes CTF 2026 · Sherlock 01 · **scenario solved — 10/10**  
Submit **bare** answers matching the UI type hint — never invent `HTB{...}` wraps.

| Flag # | Answer | Walkthrough |
|--------|--------|-------------|
| Q1 | `C:\Users\Public` | [Q01-Users-Public.md](./Q01-Users-Public.md) |
| Q2 | `FILE_NOTIFY_INFORMATION` | [Q02-FILE-NOTIFY-INFORMATION.md](./Q02-FILE-NOTIFY-INFORMATION.md) |
| Q3 | `WinHttpSendRequest` | [Q03-WinHttpSendRequest.md](./Q03-WinHttpSendRequest.md) |
| Q4 | `resolveState()` | [Q04-resolveState.md](./Q04-resolveState.md) |
| Q5 | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` | [Q05-AUTH-NAPOLEON-SR-4821.md](./Q05-AUTH-NAPOLEON-SR-4821.md) |
| Q6 | `%TEMP%` | [Q06-TEMP-percent.md](./Q06-TEMP-percent.md) |
| Q7 | `approve()` | [Q07-approve.md](./Q07-approve.md) |
| Q8 | `115792089237316195423570985008687907853269984665640564039457584007913129639935` | [Q08-MaxUint256-amount.md](./Q08-MaxUint256-amount.md) |
| Q9 | `BrowserProvider` | [Q09-BrowserProvider.md](./Q09-BrowserProvider.md) |
| Q10 | `51.5049,0.0348` | [Q10-coordinates-51.5049.md](./Q10-coordinates-51.5049.md) |

## Lessons (carry to BottleOut / WhisperChain)

1. **UI type is part of the answer** — `(function())` means `name()`; `(string)` may want `%TEMP%` not `TEMP`.
2. **Do not wrap IOCs** as `HTB{...}` unless the UI/evidence shows that format.
3. **Layer your file** — preload vs settlement.html vs chain vs Lua stage.
4. **Static first** — malware execution only in a disposable VM.
5. Skills: `htb-ctf-forensics` · `eth-contract-ctf-forensics`.

## Related notes

- Research: `research/htb-sherlock-flags/REPORT.md`
- Format retry sheet: [RETRY-Q4-Q6-Q7.md](./RETRY-Q4-Q6-Q7.md)
