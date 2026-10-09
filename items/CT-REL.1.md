---
id: "CT-REL.1"
title: "Freeze the release channel contract (CT-REL)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["spec/release/RELEASE-CHANNEL.md", "spec/release/vectors/**", "spec/schemas/chio-release/v1/**", "scripts/tests/release-channel-vectors.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-REL ("Preview versions `0.2.0-alpha.N` (SEC-M10's developer preview widened to what HOST-M3 needs); repos: the development repo and the distribution mirror (D7); preview exception (D8); host compatibility as tested version ranges"). Decision gate: D7 and D8 are open owner decisions (parked UR-D7, UR-D8); draft the recommended options and mark the contract `0.x-draft` until both are recorded.

Contents: tag regex `^v0\.2\.0-alpha\.[1-9][0-9]*$`; GitHub Releases are built and signed only in `bb-connor/arc` (cosign identity pinned in `docs/install/VERIFY.md`); the mirror `backbay-labs/chio` receives tag and commits on every tag and the contract says whether assets are re-uploaded byte-identically; every preview is `prerelease` and never `Latest`; the asset inventory is what `.github/workflows/release-binaries.yml` already produces (archives, `.sha256`, `.sig`/`.pem`, `SHA256SUMS`, CycloneDX SBOM, SLSA provenance, `chio.rb`) plus the container image digest; the installer preview channel resolves the highest published verified alpha; the preview label and ADR-0011 claim set from roadmap section 5 (FIPS, PQ and confinement excluded, per `docs/security/launch-execution-plan.md` M10 step 4); the 0.1.x deprecation policy (D10); a host-compatibility record (harness, tested range, per-version evidence digest) replacing the exact `hostSha256`/`kernelSha256` pins in the external plugin repos' acceptance artifacts; and the D8 preview-exception record format bound to a source SHA.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Schemas registered; `bash scripts/check-chio-schema-registry.sh` passes.
- `python3 scripts/tests/release-channel-vectors.test.py` validates positive and negative vectors, rejecting `v3.20.0-trj4` and `v0.1.1-rc.1` as preview tags and accepting `v0.2.0-alpha.1`.
- The contract header states its decision gates (D7, D8) and draft status.

## Log
- 2026-10-09T04:51:58Z connor: created
