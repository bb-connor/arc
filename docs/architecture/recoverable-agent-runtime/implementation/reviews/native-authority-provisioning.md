# Explicit Native authority page geometry

The maintained Store now provides an explicit operation for provisioning a
512-byte-page Native authority. It selects geometry before the first authority
schema write and uses the existing owner, path, identity and platform checks.
Ordinary provisioning retains its prior behavior. Existing databases with
different page geometry are refused without conversion or truncation.

This operation configures storage. It grants no financing, creates no completion
reservation and activates no previously unsupported Native producer.

Independent spec and quality reviews approved the two-file installation after
adding public API tests to the original helper tests. The reviewed source hashes
are:

- `serving_owner.rs`:
  `77683c833954ef7f3c0de4a06cda5a48c99b587a5743c83ebdf4df32aadcccad`.
- `serving_owner/native_financing_provision.rs`:
  `319dc5482fd4d81251813f7dcf73321e0fa56001c67e84fbac3a76ef037694b5`.

## Verification on installed source

Five owning tests passed with zero failures or ignored cases: both geometry
helper controls, both public provisioning controls and the existing fenced,
idempotent offline-upgrade control. The public tests use an actual authority,
write retained revocation data and reopen serving ownership. Refusal preserves
file identity, length, page count, geometry, the entire owner row, global commit
head and digest, and retained data.

The selected larger candidate separately passed all 19 budget-source, atomic
ledger and provisioning controls. That result is scoped to the candidate; only
the two provisioning files described here were installed from that Rust work.

Exact records are under
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/`:
`small-page-provisioning/` contains the preimages, source manifests and independent
reviews; `maintained-provisioning-first.json` and its log record the five installed
tests. `maintained-installation.json` pins the exact installed source.

The Native bank, full producer lifecycle, strict package lints and broader
qualification remain separate obligations. This prerequisite does not close a
canonical recovery finding or qualify the runtime.

The installed package's strict Clippy run still fails with 248 diagnostics:
228 dead-code errors, 14 unused-import errors, five large-enum errors and one
excessive-argument error. The exact result and diagnostics are retained in
`maintained-store-clippy-result.json` and `maintained-store-clippy-diagnostics.json`.
The full workspace formatting check passed. No lint suppression or deletion of
unfinished required producers was used to obtain a pass.
