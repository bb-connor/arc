### Task 2: One immutable API receipt sink and stable private custody

Files: API proxy state/new evidence module/router/mediated/config; SQLite strict
append method; CLI runtime; owner fixtures and tests.
Interfaces: shared Arc<SqliteReceiptStore> backs HTTP, direct tool and kernel
receipts. Existing private custody loads signer; no secondary kernel receipt copy.

- [ ] Reproduce duplicate replacement, missing export entries, ephemeral durable
  signer and receipt-history preload. Expected: RED.
- [ ] Implement strict atomic sidecar append, core sink composition and kernel
  persistence, existing private seed requirement and no production history mirror.
- [ ] Exercise real SQL update/delete refusal, duplicate/restart/write failures,
  stable signer, unsafe custody, mediated export and legacy row handling.
  Expected: pass without dropped legacy revocations.
