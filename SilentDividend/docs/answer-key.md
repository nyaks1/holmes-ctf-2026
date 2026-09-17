# SilentDividend answer key (BARE — no HTB{} wrap)

UI has 10 real questions. Prior fail: submitted HTB{IOC} wraps.

| # | Question (abbrev) | Answer | Source |
|---|---|---|---|
| 1 | extraResources copy dir `*:\path\to\dir` | `C:\Users\Public` | preload.js copyFileSync |
| 2 | Win32 structure, Lua dir-change buffer | `FILE_NOTIFY_INFORMATION` | standard ReadDirectoryChangesW (try bare; verify if reject) |
| 3 | Win32 API Lua HTTP request | `WinHttpSendRequest` | try first; alts: `InternetOpenUrlA`, `HttpSendRequestA` |
| 4 | Electron contract fn for decrypt key | `resolveState` | preload.js |
| 5 | Decode encrypted data flag `****=******** **********_*********=**-****` | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` | preload decrypt + chain key |
| 6 | Env var for HTML copy dir | `TEMP` | exec `%TEMP%\settlement.html` |
| 7 | Token fn spending permission | `approve` | settlement.html |
| 8 | Exact approval amount (number) | `115792089237316195423570985008687907853269984665640564039457584007913129639935` | ethers.MaxUint256 |
| 9 | ethers v6 provider class | `BrowserProvider` | settlement.html |
| 10 | HTML contract hidden flag `**.****,*.****` | `51.5049,0.0348` | x9(hiddenOwner) keccak XOR |

Skills: `htb-ctf-forensics`, `eth-contract-ctf-forensics` in `~/.config/mimocode/skills/`.
Research: `research/htb-sherlock-flags/REPORT.md`.
