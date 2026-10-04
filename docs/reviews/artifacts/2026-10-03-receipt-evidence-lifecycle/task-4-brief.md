### Task 4: Explicit owned retention in API-protect and chio start

Files: API config/state/evidence maintenance; CLI types/dispatch/runtime; docs/tests.
Interfaces: explicit retention config consumes Tasks 2/3 sink and stable signer;
one worker per store, stop/flush tied to serving lifetime.

- [ ] Add failing CLI/config/scheduled rotation controls. Expected: RED.
- [ ] Wire days/archive/interval, pre-effect validation and owned maintenance.
- [ ] Exercise interval rotation, archive export, append/reopen, shutdown flush and
  persistent failure health. Expected: pass.
