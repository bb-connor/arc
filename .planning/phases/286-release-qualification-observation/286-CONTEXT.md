# Phase 286 Context

## Goal

Make `scripts/qualify-release.sh` emit a signed, checksummed qualification
bundle that is suitable for hosted release observation, while preserving the
rule that release tagging only happens after a green hosted run.

## Existing Coverage

Before this phase, the release lane already ran conformance, trust-cluster
repeat-run checks, and tarpaulin coverage, but it did not emit a root checksum
bundle or use the existing `arc certify` surface to sign and verify the per-
wave conformance reports.

The repo already contains the reusable pieces needed to close that gap:

- `scripts/qualify-release.sh` stages `target/release-qualification/`
- `crates/arc-cli/src/certify.rs` already supports signed `check` and
  `verify` flows
- `docs/ARC_CERTIFY_GUIDE.md` documents the shipped certify surface

## Code Surface

- `scripts/qualify-release.sh` for artifact staging
- `crates/arc-cli/src/certify.rs` and `docs/ARC_CERTIFY_GUIDE.md` for the
  existing signing model this phase should reuse
- `target/release-qualification/` for the staged root manifest, checksums,
  conformance outputs, and coverage artifacts

## Execution Direction

- patch the release lane instead of inventing a separate qualification helper
- emit signed `certification.json` and `certification-verify.json` files for
  each wave using the existing `arc certify` command
- emit root `SHA256SUMS` and `artifact-manifest.json` files over the staged
  qualification tree
- leave CI-04 and CI-05 blocked until the same bundle is produced from a green
  hosted GitHub Actions run and a release tag is actually created
