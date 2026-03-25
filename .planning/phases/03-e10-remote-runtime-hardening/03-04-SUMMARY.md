# 03-04 Summary

## Scope

Close the remaining E10 lifecycle-hardening gap with deterministic hosted-session cleanup, explicit drain/delete/shutdown semantics, and operator-visible diagnostics.

## Landed

- Added idle-expiry, drain-grace, reaper-interval, and tombstone-retention lifecycle policy to the hosted remote runtime.
- Added terminal hosted session states for `deleted` and `expired` and surfaced them through lifecycle serialization and request handling.
- Added a retained terminal-session ledger so expired/deleted/shut-down sessions are distinguishable from unknown sessions for a bounded retention window.
- Added admin diagnostics at `/admin/sessions` plus explicit admin drain/shutdown actions.
- Added focused HTTP tests for idle expiry and distinct drain/shutdown/delete terminal states.
- Updated the E10 and post-review docs to match the implemented lifecycle and operator contract.

## Notes

- Tombstones are intentionally in-memory and short-lived. They improve operator diagnostics and client behavior after expiry/deletion without becoming a new durable state store.
- The conservative remote default remains one wrapped subprocess per session, but the lifecycle hardening gate itself is now closed.
