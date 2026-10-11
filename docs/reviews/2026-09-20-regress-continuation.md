# September 20 execution continuation: regress backport

The later [hygiene closure](2026-09-20-hygiene-closure.md) resolves the eight
remaining size violations and records candidate `ce19d8f3f`.

## Subsequent execution batch

Continued in local commit `9f0a8a0648d126403ba5dfb4fead8c35096e770e`, on top of
the backport below. The clean execution checkout remains
`/tmp/chio-regress-repair-20260920`.

- Fixed the independent nono qualification workspace, which still selected
  registry ignore and regress despite the root workspace patches. Its manifest
  and lock now select both local repairs. Added enforcement checks and negative
  fixtures for removal of either patch.
- Moved capability and keystore unit tests into child modules. Exact comparison
  verified unchanged production prefixes and unchanged dedented test bodies.
  Size violations decreased from ten to eight without gate or cap changes.
- Updated nono source provenance, patch inventory and generated proof coverage.
- Validation passed: 625 library tests, five permission-provenance integration
  tests, strict package all-target Clippy, workspace formatting, enforcement
  fixtures, structural security contract and proof inventory (59 rows,
  170 artifacts). These are local macOS checks, not Linux acceptance.
- Verified the three AWS-LC archives against Cargo.lock and their extracted
  source trees. Saved per-file inventories and adjacent-version comparisons.
  No trusted audit baseline was found in the retained imported audit sources;
  no cargo-vet certification or exemption was added.

Current remaining work: eight Rust size violations; three AWS-LC source audits;
new execution-image validation and affected Linux qualification; designated
runner and evidence joins required for M5. The existing eb040d592 foundation
still had workspace tests active, its x86 nono tests passed and Clippy was active,
and its image build remained queued. Those results do not certify this candidate.

Evidence and a verified bundle containing both continuation commits are in
`output/process-security-20260915/continuation-next-20260920/`.
The bundle requires `0b33f3b3a737ee9f353439a7d869f719de747e43`.
No remote branch was changed. Confidence: high for the recorded local results.

## Delivered

Local commit `b36b1d5b696f70df02f4b5b16f1b18d1d26fbe5a` on `fix/regress-boundary-backport-20260920`,
based on `0b33f3b3a737ee9f353439a7d869f719de747e43`, in `/tmp/chio-regress-repair-20260920`.
The checkout is clean. No remote branch was changed.

The approved writable directories in this session include the primary ARC
checkout and /tmp, while the existing execution checkout is outside those write
roots. The repair therefore uses an isolated clone, preserving the other agent's
checkout and frozen foundation campaign.

The source imports checksum-verified regress 0.11.1 and backports the existing
upstream public search-start validation from commit
`5e5141c1f6d132f2890b09f998f6a0a93c5d94ab`. Its regression assertions are retained
in a standalone integration target because the release's surrounding test
context differs. The root, fuzz and generated Docker dependency graphs select
the patched release. Image source-input digests and generated proof coverage
are updated. No new registry certification or audit exemption is added.

The 84,656 added lines primarily retain the upstream crate, Unicode tables and
tests. The production repair is the upstream API hunk. Source comparison found
only four modified existing archive members: api.rs, Cargo.toml, Cargo.lock,
and one whitespace-only line in an inert upstream workflow. The added files
are patch provenance and the upstream boundary regression target.

## Terminal local validation

| Configuration | Passed | Existing ignored |
| --- | ---: | ---: |
| default | 532 | 1 |
| index | 532 | 1 |
| utf16 | 536 | 1 |
| checked | 532 | 1 |
| no-pike-boundary | 1 | 0 |
| miri-boundary | 1 | 0 |

Strict all-target package Clippy, direct formatting of the changed Rust files,
workspace formatting, Docker manifest/lock regeneration checks, Linux dependency
selection, Linux enforcement-input validation, the structural security checker,
and its mutation fixtures passed. The final tracked proof inventory passes
with 59 rows and 170 artifacts. The Miri run verifies the repaired public API
boundary case; it is not a proof covering every API in the library.

The unmodified upstream full harness cannot compile with PikeVM disabled because
its common test helper unconditionally names that executor. That baseline
failure remains retained. The standalone boundary target passes with PikeVM
disabled; the ordinary upstream suite exercises both backends.

The first nested-directory patch invocation silently skipped paths. Verification
caught the missing guard before any patched result was accepted. The production
hunk was reapplied with an explicit path prefix, the test was rehomed, and all
patched package results record the resulting API SHA-256. Initial unpatched
results remain labeled baseline. Final proof coverage was regenerated after
tracking the imported files; that correction supersedes local commit 918ed2c0f.

## Not merge-ready

1. Cargo-vet reports three remaining registry gaps: aws-lc-fips-sys 0.14.2,
   aws-lc-rs 1.18.1 and aws-lc-sys 0.45.0. A first-party fork disposition is not
   evidence that the original regress archive was safe or fully audited.
2. Rust file hygiene fails on five existing vendored files and five newly
   imported upstream regress files. The latter are parse.rs, unicodetables.rs,
   tests.rs, unicode_property_escapes.rs and unicodesets.rs. No caps or checker
   file-selection rules were relaxed. Resolve that integration requirement
   before merging this candidate.
3. The changed lock input requires a newly built/verified execution image and
   affected downstream Linux/cage qualification. Updating its expected input
   digest does not establish that an image exists or is authorized.
4. The frozen eb040d592 foundation has passed build, format, security vectors,
   Clippy and proof coverage; its full tests had no terminal result at the last
   check. Those results do not certify this changed dependency graph.

## Import and continue

The verified Git bundle is:

`/Users/connor/Medica/backbay/standalone/arc/output/process-security-20260915/regress-repair-continuation-20260920/regress-repair.bundle`

It requires base `0b33f3b3a737ee9f353439a7d869f719de747e43`. From the existing execution checkout,
first verify its head and preserve any new edits. If still on that base, import:

```sh
git fetch /Users/connor/Medica/backbay/standalone/arc/output/process-security-20260915/regress-repair-continuation-20260920/regress-repair.bundle HEAD
git cherry-pick b36b1d5b696f70df02f4b5b16f1b18d1d26fbe5a
```

If the execution branch has advanced, review and reconcile the source delta
before cherry-picking. Do not reset it to this snapshot. Do not restart the
already-running foundation just to obtain another pending build.

Continue with the vendored-source hygiene disposition, the remaining AWS-LC
source audits, new image/cache validation, and downstream qualification on the
selected candidate. Keep M5's designated-runner and evidence-join requirements
explicit. This checkpoint supplies an implemented, locally tested repair; it
does not close the entire roadmap.

All command records, original failures, comparisons and bundle identity are in
`output/process-security-20260915/regress-repair-continuation-20260920/`.
Confidence: high for the backport, package tests and recorded blockers.
