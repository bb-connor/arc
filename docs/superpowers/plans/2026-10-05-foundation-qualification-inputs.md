# Foundation qualification input repairs

Execute inline on the existing #1160 branch. Preserve unique work, existing
review history, failed evidence and all native isolation requirements.

The landing ledger and foundation acceptance scope remain authoritative. This
plan repairs failures on `b587a81cd3932aeb9580dbe55cad30fa199a3b99`; it adds no
features or landing PRs.

1. Retain the exact pinned Alpine CA package as a bounded, hash-checked build
   input. Hosted job `111617963793` received HTTP 404, while a local fetch still
   returned the original hash. Use a read-only build mount, keep APK signature
   verification and the complete installed inventory, and test tampered,
   missing, linked and oversized inputs before changing the implementation.
2. Reconcile the trust-boundary and wire-schema inventories against the actual
   new PostgreSQL resource and caller projection. Review each new decoder and
   constructor before recording it. Strengthen the nine new negative assertions
   to check the rejection variant; do not expand the weak-assertion baseline.
3. Diagnose PostgreSQL process initialization after the successful enforcing
   host and TLS component checks. Reproduce the actual failure and repair the
   owning boundary, then rerun the native handoff and uncertain recovery lanes.
4. Run the affected suites and structural checks, retain their results, update
   the ledger, commit and push. Obtain GitHub Codex review of the exact source
   before rotating trusted source authorization and launching a fresh campaign.

Review focus: build input provenance and bounded reads, unchanged package
closure, authenticated caller projection, configuration rejection reasons,
secret-free hosted diagnostics, native isolation and failed-result retention.

Completion requires native/trusted qualification and protected landing. Local
checks and a positive independent review do not satisfy that boundary alone.

## Local execution

- The six image-input regressions failed before repair and pass afterward.
  The full CI contract mutation suite passes. The original APK signature verifies
  using the official x86_64 Alpine signing key. This is portable package
  verification, not a native image or enforcement pass.
- Both new bounded document readers and the renamed caller projection were
  reviewed. All 37 boundary calibration tests pass. Wire inventory, 180 broker
  tests, strict owning Clippy, the negative-assertion gate and proof coverage pass.
- Native PostgreSQL run `37262578320` passed the enforcing-host fixture, public
  worker API and TLS resource component, then failed process initialization.
  The initializer omitted the mandatory aggregate invocation budget. The
  qualification now supplies its existing 100-call family limit explicitly;
  full native execution of this repair remains required.
- Native worker job `111613584111` failed direct CLI-module formatting. Those
  module checks now pass locally, as do workspace formatting, all 20 trusted
  definition tests and the container/committed-evidence/source-inventory checks.

Fresh independent review, supported native campaigns, authenticated publication,
strict merge-context activation and protected merge remain incomplete.
