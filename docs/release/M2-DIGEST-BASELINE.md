# M2 Digest Baseline (WS-CL-DIGEST-BASELINE, task M2-3)

Status: CONFIRMED green and DIFF-clean. The per-crate digest-diff harness, frozen as
the M1 acceptance bar (see `docs/release/M1-DIGEST-BASELINE.md`), is re-confirmed as the
M2 acceptance bar after the wave-1 merges (M2-1 netting, M2-2 recompute gate, M2-10
verifiability-graded pricing). This record stamps the M2 baseline commit, states that
the launch-acceptance gate runs green and DIFF-clean against the M1 signed-body baseline
after wave-1, restates the acceptance bar for the rest of M2, and records why M2-1's new
netted-view schema needs no signed-artifact registration.

This is a docs-only freeze record. It does not change code.

## 1. The M2 baseline commit

```
4cc39fbeb5674efd12846430111307da38f16310
merge: M2-10 verifiability-graded pricing  (Fri Jun 26 18:22:38 2026)
branch: chio/m2-3-baseline (off chio/m2-build, which carries merged M2-1/M2-2/M2-10)
```

This commit is the HEAD of the wave-1 line: it carries the three additive wave-1 merges
on top of the M1 launch line.

```
4cc39fbeb merge: M2-10 verifiability-graded pricing
9567e95d8 merge: M2-2 recompute-gate keystone + fail-closed negatives
acef4d340 merge: M2-1 off-chain netting collapse (kill-evidence)
```

The M1 keystone (RED -> GREEN) baseline commit
`3931b972f1ce8856ec125ba78d7c6f98b911256a` (RR3-T07-01, "fix: close launch remediation
gates") is an ANCESTOR of this M2 baseline. The M1 signed-body line of history is
preserved unbroken: the wave-1 merges did not rewrite or reseal any M1 signed body.

## 2. The gate is green and DIFF-clean after wave-1

All three gate commands run GREEN in the `chio/m2-3-baseline` worktree once `dist/` is
built (node v24.16.0, npm 11.13.0 via mise; the `tsc -b && vite build` transformed 1896
modules in ~3.6s):

- `cargo run -p xtask -- verify launch-acceptance --out /tmp/m2_baseline` exits 0. The
  aggregate `verifier/report.json` verdict is `verified`, as are all four stage
  sub-bundle verdicts (single-call-authority, disclosure-and-agent-web-envelope,
  commerce-transaction-passport, recursive-runtime-swarm).
- `scripts/check-chio-proof-room-release-truth.sh` exits 0 ("OK Proof Room release
  truth").
- `scripts/check-chio-transaction-passport.sh` exits 0 ("OK transaction-passport
  verifier gate: 30 positive, 109 negative, 4 proof-room").

DIFF-clean evidence: the passport verifier counts (30 positive, 109 negative, 4
proof-room) are IDENTICAL to the M1 baseline recorded in
`docs/release/M1-DIGEST-BASELINE.md`. There is no net-new failing fixture and no digest
mismatch. The launch-acceptance gate recomputes the embedded signed-body digests
(content_hash and the dependent graph / manifest / passport / report hashes) and verifies
them; a `verified` verdict means every M1 signed body's canonical-JSON encoding is
byte-stable under wave-1. Had any signed body drifted (field reorder, serde rename,
Option omission, enum repr, manual-vs-derive Serialize), the embedded fixture digest would
mismatch and the verdict would be `rejected`. It is not. `cargo check --workspace` also
passes.

This is expected: the wave-1 merges are ADDITIVE. M2-1 adds a new netting module
(`crates/economy/chio-credit/src/netting.rs`), M2-2 adds doc-only verifier contracts plus
tests, and M2-10 adds a new verifiability module. None reorders or retypes an existing
signed-body struct.

## 3. M2-1's netted-view schema needs NO signed-artifact registration

M2-1 introduces `EXPOSURE_LEDGER_NETTED_VIEW_SCHEMA =
"chio.credit.exposure-ledger-netted-view.v1"` for `ExposureLedgerNettedView`
(`crates/economy/chio-credit/src/netting.rs`). It does NOT need a row in
`spec/schemas/registry.json` and does NOT need to be added to
`KNOWN_SIGNED_ARTIFACT_SCHEMAS`
(`crates/core/chio-core-types/src/signed_artifact.rs`), because the netted view is a
READ-ONLY off-chain PROJECTION, not a signed artifact:

- `ExposureLedgerNettedView` has NO `signature` field, no `sign()` constructor, and no
  `verify_signature()`. It derives only `Serialize`/`Deserialize`; it is never signed.
- It is computed off-chain from the already-signed per-currency
  `ExposureLedgerCurrencyPosition` entries. The collapse reads the three prudential
  support-boundary flags (`cross_currency_netting_supported`,
  `capital_allocation_supported`, `mixed_currency_netting_supported`) straight off their
  fail-closed defaults and never sets them.
- It is referenced only inside the `chio-credit` crate (its own module plus the crate
  re-export). It is NOT carried in any proof-room fixture, the xtask launch-acceptance
  bundle, or any signed envelope.

The registration gate that would otherwise apply is the test
`known_signed_artifact_schemas_match_public_registry_or_internal_exemption`
(`crates/core/chio-core-types/tests/signed_artifact_schema.rs`). It requires only that
schemas already in `KNOWN_SIGNED_ARTIFACT_SCHEMAS` appear in `registry.json` (or the
internal-exemption list). Since the netted-view schema is not a signed artifact and is not
in that list, the test passes unchanged (it passed in the green run above). Registering a
read-only projection as a signed artifact would be an over-broadening of the signed-artifact
surface, not a fail-closed tightening, so it is correctly omitted.

Conclusion: no schema-registration change was required for M2-3. This record is the only
file added.

## 4. The acceptance bar for the rest of M2 (unchanged from M1)

For every signed-body-touching change in M2 (and for any fixture-touching swarm work):

- Build the gitignored Proof Room export, then run the three gate commands in Section 5
  and DIFF the resulting failing-fixture / digest set against this M2 baseline at commit
  `4cc39fbeb`.
- Any net-new failing fixture OR any digest mismatch FAILS the change. A digest mismatch
  means a signed body's canonical-JSON encoding drifted, which silently breaks the
  embedded launch-acceptance fixtures even while `cargo test --workspace` stays green.
- `cargo test --workspace` green is EXPLICITLY DECLARED INSUFFICIENT for the signed-body
  crates (`chio-anchor`, `chio-credit`, `chio-market`, `chio-underwriting`,
  `chio-open-market`, `chio-appraisal`, `chio-settle`, plus `chio-web3` and the ABI-locked
  `chio-web3-bindings/src/interfaces.rs`). Fail-closed: if the baseline cannot be
  re-established, the work does not land.

## 5. Exact commands to run the M2 digest gate

Prerequisite (the Proof Room static UI export; gitignored Vite build, not committed):

```bash
cd crates/products/chio-cli/dashboard
npm ci          # installs the locked dependency set from package-lock.json
npm run build   # runs "tsc -b && vite build"; writes dist/
```

Then run the three gate commands from the repo root:

```bash
# 1. Aggregate launch-acceptance bundle (must exit 0, verdict "verified")
cargo run -p xtask -- verify launch-acceptance --out /tmp/m2_baseline

# 2. Proof Room release-truth gate (must exit 0)
bash scripts/check-chio-proof-room-release-truth.sh

# 3. Transaction-passport verifier gate (must exit 0)
bash scripts/check-chio-transaction-passport.sh
```

The `--out` directory is a throwaway build target (here `/tmp/m2_baseline`); the gate
writes the bundle and `<out>.tar.zst` there and verifies in place. `dist/` stays
gitignored and is regenerated by the documented build; nothing in the export is committed.
