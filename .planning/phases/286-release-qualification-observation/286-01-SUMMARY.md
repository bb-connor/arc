# Summary 286-01

Phase `286-01` closed the repo-side release-qualification gap by extending
[scripts/qualify-release.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/qualify-release.sh) to stage a signed, checksummed bundle:

- Each conformance wave now emits `certification.json`,
  `certification-report.md`, and `certification-verify.json` under
  `target/release-qualification/conformance/wave1` through `wave5`, using the
  shipped `arc certify check` and `arc certify verify` surface
- The root qualification directory now emits
  `target/release-qualification/SHA256SUMS` and
  `target/release-qualification/artifact-manifest.json`; the completed run
  recorded `65` staged artifacts and `generatedAt:
  2026-04-12T23:48:15Z`
- The final release-qualification pass finished cleanly with `67.39%`
  measured tarpaulin coverage against the enforced `67%` floor, and the staged
  verification files report `certification verified` with `verdict: pass` for
  waves 1 through 5

Verification:

- `bash -n scripts/qualify-release.sh`
- `./scripts/qualify-release.sh`
- inspected `target/release-qualification/SHA256SUMS`
- inspected `target/release-qualification/artifact-manifest.json`
- inspected `target/release-qualification/conformance/wave1` through `wave5`
  certification outputs

Remaining gap:

- CI-04 and CI-05 are still blocked on hosted GitHub observation. The staged
  manifest records `source: local`, `candidateSha: local`, and no GitHub run
  identifiers, so the release candidate tag must still wait for a green hosted
  rerun on a published commit.
