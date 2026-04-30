# M03 P0 Implementation Notes

Scope: Wave 2 opener for M03, limited to dependency pins, default-off feature
flags, audit-doc seeding, threat-model rows, and the PQ crate ecosystem
recheck. These notes intentionally do not change code, protected milestone
narratives, decisions, freezes, owners, board, or style files.

Source files read:

- `.planning/trajectory-2/03-pq-hybrid-and-tee-quote-verifier.md`
- `.planning/trajectory-2/tickets/M03/P0.yml`
- `.planning/trajectory-2/decisions.yml`
- `.planning/trajectory-2/freezes.yml`
- `Cargo.toml`
- `crates/chio-core-types/Cargo.toml`
- `crates/chio-attest-verify/Cargo.toml`
- `crates/chio-core-types/src/crypto.rs`
- `crates/chio-attest-verify/src/lib.rs`
- `crates/chio-kernel-core/src/receipts.rs`
- `crates/chio-core-types/src/receipt.rs`
- `crates/chio-core-types/src/capability.rs`
- `crates/chio-acp-proxy/src/compliance.rs`
- `spec/SECURITY.md`
- `spec/security/chio-threat-model.v1.json`
- `spec/COMPLIANCE-CERTIFICATE.md`

## Current Surface Snapshot

- `crates/chio-attest-verify/src/lib.rs` is still 131 lines and exposes
  `AttestVerifier`, `ExpectedIdentity`, `VerifiedAttestation`, and
  `AttestError`. There is no `QuoteVerifier` trait or quote backend module.
- `crates/chio-attest-verify/src/sigstore.rs` is still 626 lines and remains
  the only production verifier implementation.
- Current `chio-attest-verify` extension points are
  `AttestVerifier::{verify_blob, verify_bytes, verify_bundle}`,
  `SigstoreVerifier::with_embedded_root`, non-exhaustive `AttestError`, and
  `VerifiedAttestation` metadata. P0 should not add `QuoteVerifier` or quote
  modules.
- `crates/chio-attest-verify/build.rs` only checks embedded
  `sigstore-root/{root.json,trusted_root.json}` presence. The trust-root files
  are evidence-sensitive and should stay out of M03 P0.
- `crates/chio-core-types/src/crypto.rs` is 1252 lines in this worktree. It
  has Ed25519, P-256, and P-384 key and signature material, plus the
  `SigningBackend` abstraction. There is no hybrid or PQ variant.
- `crates/chio-core-types/Cargo.toml` has `default = ["std"]` and `fips`
  only. There is no `pq` feature yet.
- `crates/chio-attest-verify/Cargo.toml` has no feature table today.
- `find crates/chio-attest-verify -path '*/fixtures/*' -name '*.bin'` returns
  zero quote fixtures.
- `spec/security/chio-threat-model.v1.json` does not contain
  `pq_signature_downgrade` or `tee_quote_forgery`.
- Compliance certificates currently live in `crates/chio-acp-proxy/src/compliance.rs`
  as `ComplianceCertificateBody` and `ComplianceCertificate`. M03 narrative
  wording says `SessionComplianceCertificate`; P0 agents should use the live
  type names in code and avoid renaming in this phase.

## Decision Reference Hygiene

Decision ids observed in `.planning/trajectory-2/decisions.yml`: D08, D09,
D10. P0 implementation notes, PR descriptions, and the audit opener should
cite these ids by id only. If day-of evidence conflicts with one of those ids,
pause for a decision amendment before merging dependency or threat-model
changes.

## Dependency Version Recheck

`cargo search` results on 2026-04-30:

- `fips204 = "0.4.6"`
- `fips204_rs = "1.0.1"`
- `ml-dsa = "0.1.0-rc.9"`
- `dcap-rs = "0.1.0"`
- `sev = "7.1.0"`
- `coset = "0.4.2"`

Treat these search results as a drift warning, not authority to change a
locked decision inside P0. P0.T5 must rerun the search on the opener branch,
cite D08 by id, and record whether the observed patch set still matches the
locked decision.

## M03.P0.T1 - Pin PQ and TEE Crates

Expected files:

- `Cargo.toml`
- `Cargo.lock`
- Possibly `crates/chio-core-types/Cargo.toml`
- Possibly `crates/chio-attest-verify/Cargo.toml`

Inspect first:

- Root `[workspace.dependencies]` in `Cargo.toml`.
- Existing no-std dependency comments in `crates/chio-core-types/Cargo.toml`.
- Existing verifier dependencies in `crates/chio-attest-verify/Cargo.toml`.
- `Cargo.lock` churn after `cargo update -p ...` or build-driven resolution.

Implementation notes:

- Put shared pins in root `[workspace.dependencies]` where later tickets can
  consume them consistently.
- Keep direct member dependencies optional until P1/P3 actually uses them.
- Be careful with `chio-core-types`: it supports `no_std + alloc`; any `pq`
  dependency added there must compile with `default-features = false` or be
  gated so default builds remain unchanged.
- `chio-attest-verify` is `std` and can carry quote verifier dependencies
  more directly, but still needs `#![forbid(unsafe_code)]` compatibility.
- Serialize all P0.T1 work because the ticket owns root `Cargo.toml` and
  `Cargo.lock`.

Gate command:

```bash
cargo build -p chio-core-types --quiet && cargo build -p chio-attest-verify --quiet && cargo tree -p chio-attest-verify -d
```

Risk notes:

- `sev` has drifted beyond the narrative's `sev = "5"` target. A direct jump
  to `7.1.0` should be reviewed for API and transitive dependency changes.
- `coset` has drifted beyond `0.3`. Nitro parsing may still prefer latest
  patch, but P0 should document the choice in the audit doc before merge.
- `cargo tree -d` may surface duplicate crypto or x509 stacks because
  `sigstore`, `webpki`, and COSE dependencies overlap.

Reviewer focus:

- Confirm no new dependency introduces unsafe code into `chio-core-types`.
- Confirm `Cargo.lock` changes are dependency resolution only.
- Confirm P0 does not start quote-verifier or hybrid-signature implementation.

## M03.P0.T2 - Add Default-Off pq Features

Expected files:

- `crates/chio-core-types/Cargo.toml`
- `crates/chio-attest-verify/Cargo.toml`

Inspect first:

- `crates/chio-core-types/Cargo.toml` feature table.
- `crates/chio-attest-verify/Cargo.toml`, which currently has no features.
- `crates/chio-core-types/src/lib.rs` exports, but do not edit code in P0
  unless the implementation ticket explicitly chooses to add feature-only
  dependency plumbing.

Implementation notes:

- Add `pq = [...]` without adding it to `default`.
- For `chio-core-types`, keep `default = ["std"]` byte-for-byte in behavior.
  `cargo build -p chio-core-types --no-default-features --quiet` must keep
  passing.
- If `fips204` requires `std`, P0 should not force it into no-default builds.
  Prefer optional dependency wiring behind `pq` and call out any `std`
  coupling in the audit doc.
- For `chio-attest-verify`, add an explicit feature table even if the first
  version is only `default = []` and `pq = [...]`.

Gate command:

```bash
cargo build -p chio-core-types --no-default-features --quiet && cargo build -p chio-core-types --features pq --quiet && cargo build -p chio-attest-verify --features pq --quiet
```

Risk notes:

- Feature unification can accidentally enable PQ dependencies in default
  workspace builds if a member uses an unguarded dependency.
- `chio-core-types` no-std behavior is easy to regress with default features
  from transitive crypto crates.

Reviewer focus:

- Confirm `pq` is default-off in both crates.
- Confirm `--no-default-features` still compiles for `chio-core-types`.
- Confirm no public API is exposed prematurely without tests.

## M03.P0.T3 - Open Audit Doc

Expected file:

- `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md`

Inspect first:

- Existing `.planning/audits/` format from other milestones.
- Hard counts in the M03 narrative.
- Live counts from this worktree.

Implementation notes:

- Seed the audit doc with starting counts and commands used to reproduce
  them.
- Use the live `crypto.rs` count from this worktree, not the stale narrative
  count, if it differs. Current measured values are:
  - `crates/chio-attest-verify/src/lib.rs`: 131 lines.
  - `crates/chio-attest-verify/src/sigstore.rs`: 626 lines.
  - `crates/chio-core-types/src/crypto.rs`: 1252 lines.
  - Quote fixture binaries under `crates/chio-attest-verify`: 0.
- Record the dependency version recheck output and date.

Gate command:

```bash
test -f .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md && grep -q 'starting counts' .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md
```

Risk notes:

- The phrase `starting counts` is part of the gate. Include it literally.
- The audit doc is not one of the protected paths listed in this research
  assignment, but it is still planning state. P0 implementation should keep
  it factual and narrow.

Reviewer focus:

- Confirm measured counts are reproducible.
- Confirm no claims are copied from the narrative without checking live code.
- Confirm the audit doc records unresolved version drift rather than silently
  choosing a new cryptography stack.

## M03.P0.T4 - Add Threat-Model Rows

Expected files:

- `spec/security/chio-threat-model.v1.json`
- `spec/SECURITY.md`

Inspect first:

- Existing JSON schema and row shape in `spec/security/chio-threat-model.v1.json`.
- Existing threat-model table format in `spec/SECURITY.md`.
- `crates/chio-core-types/tests/threat_model_artifacts.rs`, which validates
  the threat model artifact.
- M05 freeze entry, because M05 later consumes these IDs as coverage inputs.

Implementation notes:

- Add only two IDs: `pq_signature_downgrade` and `tee_quote_forgery`.
- Keep JSON ordering and formatting consistent with adjacent entries.
- The rows should describe fail-closed mitigations expected from M03, but
  should not claim the implementation exists before later phases land.
- Do not rewrite existing threat rows.

Gate command:

```bash
grep -q 'pq_signature_downgrade' spec/security/chio-threat-model.v1.json && grep -q 'tee_quote_forgery' spec/security/chio-threat-model.v1.json && grep -q 'pq_signature_downgrade' spec/SECURITY.md && grep -q 'tee_quote_forgery' spec/SECURITY.md
```

Additional recommended gate:

```bash
cargo test -p chio-core-types threat_model_artifacts --quiet
```

Risk notes:

- This touches a later M05 freeze path, but the freeze starts at M05.P1.T1.
  P0 agents should still coordinate because M05 will consume these exact IDs.
- JSON schema drift can break tests even if the grep gate passes.

Reviewer focus:

- Confirm the two IDs are exact and stable.
- Confirm the JSON remains valid and the Markdown table stays synchronized.
- Confirm rows are threat-model coverage seeds, not premature acceptance
  criteria.

## M03.P0.T5 - Recheck fips204 vs RustCrypto ml-dsa

Expected file:

- `.planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md`

Inspect first:

- D08 in `.planning/trajectory-2/decisions.yml`.
- Latest crates.io state for `fips204`, `fips204_rs`, `ml-dsa`, and
  `pqcrypto-mldsa`.
- Any security/advisory notes available through local tooling.

Implementation notes:

- Record a line matching the ticket gate, for example:
  `fips204 re-check 2026-04-30: ...`
- If the implementation wants to change away from the locked primitive, do not
  do that silently in P0. It requires a D08 amendment, which is outside the
  normal ticket path unless the orchestrator approves it.
- If only a patch-level `fips204` update is chosen, state why it remains
  consistent with D08.
- If RustCrypto `ml-dsa = "0.1.0-rc.9"` is still pre-release, record that as
  the reason to keep D08 unless deeper review finds otherwise.

Gate command:

```bash
grep -qE 'fips204 (re-check|recheck) [0-9]{4}-[0-9]{2}-[0-9]{2}' .planning/audits/M03-pq-hybrid-and-tee-quote-verifier.md
```

Recommended evidence commands:

```bash
cargo search fips204 --limit 5
cargo search ml-dsa --limit 10
cargo search pqcrypto-mldsa --limit 5
cargo search dcap-rs --limit 5
cargo search sev --limit 5
cargo search coset --limit 5
```

Risk notes:

- P0.T5 can become a decision-governance issue if the crate recommendation
  changes. Keep that separate from mechanical dependency pinning.
- `cargo info` was slow in this research worktree after `cargo search`
  succeeded. Agents should retry it with a timeout before merging a pin.

Reviewer focus:

- Confirm the audit doc distinguishes observed ecosystem drift from approved
  decision changes.
- Confirm the reviewer can reproduce the version evidence.
- Confirm no dependency choice conflicts with the workspace's unsafe-free and
  default-off PQ posture.

## Cross-Ticket Gate Bundle

Run the ticket gates exactly, then add these local checks before asking for
review:

```bash
cargo fmt --all -- --check
cargo build -p chio-core-types --no-default-features --quiet
cargo build -p chio-core-types --features pq --quiet
cargo build -p chio-attest-verify --features pq --quiet
cargo test -p chio-core-types threat_model_artifacts --quiet
cargo tree -p chio-attest-verify -d
```

If broad workspace checks are affordable after the dependency bump:

```bash
cargo clippy -p chio-core-types --features pq -- -D warnings
cargo clippy -p chio-attest-verify --features pq -- -D warnings
```

## Wave 2 Coordination Notes

- Do not open M03 implementation branches while `.planning/trajectory-2/EXECUTION-STATE.json`
  still says `current_wave: "W1"` unless the execution log contains a passing
  Wave 1 `wave_gate_run` and the orchestrator has advanced W2 scheduling.
- Wave 1 drain evidence expected before M03 P0 opens: workspace one-liner
  green, mutation baseline for the six trust-boundary crates, verdict-matrix
  scaffold present, and `CanonicalBytes` byte-identity through the M01 vector
  corpus.
- P0 serializes through root `Cargo.toml` and `Cargo.lock`. Do not split P0.T1
  into concurrent branches that both refresh the lockfile.
- M03 freezes begin in P1, not P0, but P0 choices determine the dependency
  surface used by the trust-boundary freeze windows.
- Later source workers should treat `crates/chio-attest-verify/src/lib.rs` as
  the `QuoteVerifier` API choke point and `src/sigstore.rs` as preserved unless
  a ticket explicitly targets Sigstore regression protection.
- `crates/chio-attest-verify/sigstore-root/**` and `build.rs` are outside the
  registered M03 freeze globs, but they are trust-root evidence. Keep them out
  of M03 P0 and require a separate trust-root re-bake review if they change.
- M06 `CanonicalBytes` is a P1 soft dependency, not a P0 blocker.
- M05 consumes the two threat IDs later, so exact spelling matters.
- M10 custody work depends on the later quote-binding and hybrid-signing
  surface. P0 should avoid broadening scope into custody envelope design.

## Same-Day Opener Checklist

For `wave/W2/m03/p0.t1-pin-pq-and-tee-crates`:

- Confirm M03 is still `phase: ready_for_p0` and every P0 ticket remains
  `status: pending`.
- Re-run the crate-version searches in the branch and paste a short evidence
  table into the audit doc for P0.T5.
- Keep the first PR to root dependency pins and lockfile resolution unless the
  orchestrator explicitly bundles another P0 ticket.
- Run the exact P0.T1 `gate_check.cmd` plus `cargo fmt --all -- --check`.
- Add security x2 reviewers and `@bb-connor`.
- Defer `cargo build ... --features pq` gates until P0.T2 creates the feature.

## Review Checklist

- No behavior implementation in P0 unless explicitly required by a ticket.
- No default-on PQ feature.
- No edits to milestone narratives, `decisions.yml`, `freezes.yml`,
  `OWNERS.toml`, `EXECUTION-BOARD.md`, `STYLE.md`, or unrelated code.
- No Sigstore behavior changes.
- No TEE container or frame schema changes.
- No Kyber, ML-KEM, HSM-backed PQ signer, Apple SEP, SGX, or ZK verifier work.
- Exact threat IDs present in both machine and human security docs.
- Audit doc contains starting counts, date, crate recheck evidence, and any
  unresolved decision drift.
