# Extraction checklist (layered)

## 0. Inventory
- [ ] Challenge UI full-page capture (flag counter, tasks, description)
- [ ] All evidence files + SHA256
- [ ] Passwords from DANGER/README/UI
- [ ] Flag format stated? Y/N — where?

## 1. Containers
- [ ] List zip members before extract
- [ ] Nested archives; tails/overlays after archive end
- [ ] Note empty decoys (.env size 0)

## 2. Installers
- [ ] Identify: NSIS / Inno / 7z SFX / MSI / PyInstaller / Electron
- [ ] Extract with 7za; save file list
- [ ] extraResources, asar, scripts, helpers (elevate.exe)

## 3. App logic
- [ ] package.json / main / preload / renderer
- [ ] Insecure Electron flags
- [ ] Hardcoded URLs, contracts, keys, decrypt algos
- [ ] Drop paths and launch commands

## 4. Network / chain
- [ ] Verified source (Sourcify / explorer)
- [ ] Every view function via eth_call
- [ ] Storage slots + constructor args
- [ ] Tx input that stored blobs (cipherFlag etc.)
- [ ] Reimplement on-chain crypto exactly

## 5. Decrypt / encode
- [ ] Only keys from evidence
- [ ] Save plaintext + sha256
- [ ] Check plaintext for HTB{/flag{ before considering submit

## 6. Second stage
- [ ] Fingerprint obfuscator
- [ ] Static string decoder + cribs from stage 1
- [ ] Dump all plaintext; grep flag tokens
- [ ] Dynamic only in disposable VM

## 7. Submit gate
- [ ] Question match OR planted token OR explicit format
- [ ] No invented wraps
- [ ] Log what was submitted and result
