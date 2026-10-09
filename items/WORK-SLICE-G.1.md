---
id: "WORK-SLICE-G.1"
title: "Gamma: bilateral DSSE reconstruction and verifier hardening (chio-federation)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.4", "CT-CROSS.2"]
paths: ["crates/trust/chio-federation/Cargo.toml", "crates/trust/chio-federation/mutants.toml", "crates/trust/chio-federation/src/bilateral.rs", "crates/trust/chio-federation/src/bilateral_dsse.rs", "crates/trust/chio-federation/src/bilateral_dsse/**", "crates/trust/chio-federation/src/bilateral_verifier.rs", "crates/trust/chio-federation/src/bilateral_verifier/**", "crates/trust/chio-federation/src/frost/trust.rs", "crates/trust/chio-federation/src/trust_establishment.rs", "crates/trust/chio-federation/tests/bilateral_signing.rs", "crates/trust/chio-federation/tests/frost_roster.rs", "crates/trust/chio-federation/tests/trust_establishment.rs", "crates/trust/chio-federation/tests/verifier_hook_conformance.rs", "crates/trust/chio-federation/tests/verifier_hook_conformance/**", "crates/trust/chio-federation/tests/dudect/bilateral_dsse_verify.rs", "spec/CHIO_BILATERAL_COSIGN_INVOCATION.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice gamma (federation, bilateral DSSE, iroh lanes, treaty runtime-core; roadmap: after alpha and beta, needed for the remote co-signer). No crate-level conflicts with #1160. Pulled ahead of the roadmap's "after alpha and beta" because the W2.2 prototype needs `bilateral_dsse/preimage.rs::reconstruct_dsse_pae` (the co-signer must not be a signing oracle). Must pass CT-WIRE.4's frozen co-sign vectors (activate its pending positives).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-federation --test bilateral_signing` (14 tests), `cargo test -p chio-conformance --test b4_bilateral_dsse_pae_conformance` and `--test cosign_frozen_vectors` pass; the reversed-cosignature mutant survivor is killed.

## Log
- 2026-10-09T04:51:58Z connor: created
