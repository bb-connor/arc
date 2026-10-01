# Trust reader qualification

Source base: `6ef28e8f4ddccb7f344a179d2415844a3410f815`. The owning local commit
contains this record and source hashes; no candidate-SHA self-reference is needed.

All 35 pinned reader paths have semantic dispositions in
[reviewed-readers.json](reviewed-readers.json). Additional contracts are in
[supporting-owners.json](supporting-owners.json). The raw baseline falls from
166 to **131 workspace files**, with zero trust, protocol or CLI baseline files.
These are review counts, not known vulnerability counts or full threat closure.

## Terminal evidence

- [Final package campaign](qualification-final.log): **1,964 passed, 0 failed,
  3 ignored**, across 125 test binaries and 20 doctest groups in 20 packages.
  [Command, environment and exit status](qualification-final.json) record a
  242.73-second run with the packages' default features. Existing custody test
  dependencies also enable fixture support; this is not live-device validation.
- [CLI consumer check](cli-consumers.log): `cargo check --locked --offline
  -p chio-cli --tests --features iroh` passes. Its
  [terminal status](cli-consumers.json) records compile qualification, not a CLI
  test execution campaign.
- [Trust inventory](trust-check-final.log): the scanner's current snapshot and
  catalog checker report no errors. The reputation reader moved from an include
  fragment to a real input module; no unexpected raw-decoder additions remain.
- [File hygiene](hygiene-final.log), [negative assertions](negative-final.log)
  and [wire schemas](wire-check.log): pass without raised limits or exemptions.
  Existing warning/allowlist debt remains visible in those logs.
- [Changed-file formatting](format-final.log) and source/documentation diff
  whitespace checks pass. Raw command logs retain their original terminal
  newlines and are excluded from the whitespace check.
- [Qualification summary](qualification.json), [source hashes](source-hashes.json),
  [test-binary hashes](binary-hashes.json) and [test totals](test-summary.json)
  record the tested source and local evidence. The only Rust edit after the
  passing package run is the CLI test import, covered by the final consumer check.
- [Independent review](review.md): one read-only reviewer, no delegated
  implementation. Material findings were resolved, including original-input
  validation of the downloaded TUF trusted root after the final reviewer pass.

The three pre-existing ignored cases are the obsolete historical-v1 trust-bundle
case, the explicit FROST sealed-vector regeneration helper, and the reputation
configuration documentation example. They are not counted as passing tests.

Production-linked controls cover duplicate keys, original external integer loss,
native full-width signed integers, byte limits, exact canonical import equality,
strict JWT/WebAuthn/Sigstore/TUF input, bounded SQLite/NDJSON, typed parser causes,
redacted diagnostics, and delivery-report identity/completeness before success.
Existing signature, replay, issuer, receipt and federation tests remain green.

## Prior attempts retained

| Attempt | Result and remediation |
| --- | --- |
| `qualification-1` through `qualification-5` | Terminal compilation failures while reconciling changed error variants, error sources and direct consumers. Each log and JSON status is retained. |
| [Sixth campaign](qualification-6.log) | Reached all test targets; old parser-string assertions, incomplete synthetic Iroh reports and a stale proof-manifest test path required correction. Production checks were retained. |
| [Final campaign](qualification-final.log) | 1,964 passed, zero failed. |
| [Initial CLI consumer check](cli-consumers-initial.log) | Existing `process_host` integration test lacked its `ChioReceipt` import. The import is restored and final compile check passes. |
| [Initial hygiene](hygiene-initial.log) | Reputation include-fragment growth exceeded its existing cap. The input reader now has a proper module; the cap is unchanged. |
| [Initial inventory](trust-check.log) | Constructor site drift reconciled to the scanner output and checked again. |
| [Inventory update](inventory-update.log) | Initially counted the entire mobile kernel file as disposed, producing 130. Its other readers remain baseline; [inventory-summary.json](inventory-summary.json) records the corrected 131. |

The user requested action-first batching. This record does not claim per-edit
red/green runs, a second independent review of final fixes, all-feature coverage,
workspace clippy, hosted CI or full-workspace qualification. Cargo.lock did not
change; an existing core-types dependency moved into the buyer's production
dependency section.

## Acceptance boundary and next work

This is local source/package qualification. The receipt-envelope API represents
inspection only; it creates no verified receipt-chain authority. Apple packaged
XCFramework artifacts still require rebuild and native qualification. Production
Play Integrity still fails closed on the committed fixture root. Other mobile
kernel capability/passport readers, broader mechanism C error taxonomy, native
enforcement, supply-chain, hosted/M5 and operator acceptance remain separate.
No push, merge, publication or activation occurred.

Next: [33 guard and security readers](next-readers.json), covering guard loading
and external verdicts, WASM, sandbox launch/bootstrap, quarantine journals and
state, keyring checkpoints, decoys and security-type deserializers.
