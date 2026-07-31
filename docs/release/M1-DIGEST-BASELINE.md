# M1 Digest Baseline (WS-CL-DIGEST-BASELINE keystone, task M1-8)

Status: CONFIRMED committed. The per-crate digest-diff harness is frozen as the M1
acceptance bar. This record establishes the baseline commit, the artifact(s) that hold
the per-crate signed-body digests, the exact gate commands (including the
`dashboard/dist` prerequisite), and whether the gate runs green in this environment.

This is a docs-only freeze record. It does not change code. The acceptance bar for every
signed-body edit (M1-9, M1-13, M1-15, M1-20) and for the cleanup swarm (M1-21) is a
per-crate digest-diff against the baseline below, NOT `cargo test --workspace` green.

## 1. The committed baseline

### 1.1 The RED baseline label: RR3-T07-01

`RR3-T07-01` is the named launch-acceptance RED finding recorded in
`docs/superpowers/research/chio-launch/PR-937-remediation-roadmap.md:465`. It states that
`cargo xtask verify launch-acceptance` was RED at the pre-keystone HEAD because the Stage 1
settlement bundle
`fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle/settlement-proof-bundle.json`
carried a stale anchor-receipt `content_hash` (`1ff0dfe4...`) that was not resealed after the
strict `settlement.rs` content-hash binding landed. RR3-T07-01 is the keystone marker: it is
the last RED signed-body finding whose closure establishes the GREEN baseline that every
later signed-body change must diff clean against.

### 1.2 The baseline (keystone) commit

```
3931b972f1ce8856ec125ba78d7c6f98b911256a
fix: close launch remediation gates  (Wed Jun 24 23:37:03 2026)
```

This commit reseals the Stage 1 settlement bundle and its dependent evidence-graph / manifest
/ passport / report digests, bringing `cargo xtask verify launch-acceptance` to exit 0. After
this commit the Stage 1 bundle anchor-receipt `content_hash` is
`5e74c65ed50fb26585825e1bca068b65bff562e9d781605efa46c1fb4fbffae1` (the resealed value, no
longer the stale `1ff0dfe4...`). Commit `3931b972f` is an ancestor of the current
`chio/m1-launch` HEAD, so the baseline is in the M1 line of history. Its commit message
records the same gate commands listed in Section 3 as passing at reseal time.

### 1.3 What files hold the per-crate signed-body digests

There is no single hash-list file. The baseline is the committed state of two artifact sets at
commit `3931b972f`; the harness materializes the digests at gate-run time and diffs the
resulting failing-fixture / digest set against this committed state:

- Embedded signed bundles under `fixtures/proof-room/**`. These carry the actual signed-body
  digests as `content_hash` (and dependent graph / manifest / passport / report hash) fields.
  The Stage 1 anchor is
  `fixtures/proof-room/public-stages/commerce-transaction-passport/proof-room-bundle/settlement-proof-bundle.json`.
- The signed struct bodies in the economy crates whose canonical-JSON encoding feeds those
  fixtures (per `docs/brainstorm/CHIO-EXECUTION-ROADMAP.md` WS-CL-DIGEST-BASELINE and the
  `CHIO-TOKEN-COMMERCE-ALIGNMENT.md` per-crate DO-NOT-reorder/rename/retype list):
  `crates/economy/chio-anchor`, `chio-credit`, `chio-market`, `chio-underwriting`,
  `chio-open-market`, `chio-appraisal`, `chio-settle` (the seven signed-body economy crates),
  plus `crates/economy/chio-web3` and the ABI-locked
  `crates/economy/chio-web3-bindings/src/interfaces.rs`.

The harness itself is `xtask/src/launch_acceptance.rs` plus the two release scripts in
Section 3. The acceptance contract is defined in
`docs/brainstorm/CHIO-EXECUTION-ROADMAP.md` (WS-CL-DIGEST-BASELINE, "THE keystone") and
`docs/brainstorm/CHIO-TOKEN-COMMERCE-ALIGNMENT.md` Section 6.

## 2. The acceptance bar (per-crate digest-diff, NOT cargo-test-green)

The M1 acceptance bar for signed-body work is:

- After each crate's cleanup or signed-body edit, run the three gate commands in Section 3 and
  DIFF the resulting failing-fixture / digest set against the baseline at commit `3931b972f`.
- Any net-new failing fixture or any digest mismatch FAILS the change. A digest mismatch means
  the canonical-JSON encoding of a signed body drifted (field order, serde rename, `Option`
  omission, enum repr, manual-vs-derive `Serialize`), which silently breaks the embedded
  launch-acceptance fixtures even while `cargo test --workspace` stays green.
- `cargo test --workspace` green is EXPLICITLY DECLARED INSUFFICIENT for the signed-body
  crates. Fail-closed: if the baseline cannot be established, the swarm does not start.

## 3. Exact commands to run the gate

Prerequisite (the Proof Room static UI export). The gate copies
`crates/products/chio-cli/dashboard/dist` into the bundle and fails closed with
"Proof Room static UI export is missing: crates/products/chio-cli/dashboard/dist" if it is
absent (`xtask/src/launch_acceptance.rs`, `copy_static_ui`). `dist/` is a gitignored Vite build
artifact (`.gitignore:109`), NOT committed, so it must be built before the gate:

```bash
cd crates/products/chio-cli/dashboard
npm ci          # installs the locked dependency set from package-lock.json
npm run build   # runs "tsc -b && vite build"; writes dist/
```

Then run the three gate commands from the repo root:

```bash
# 1. Aggregate launch-acceptance bundle (must exit 0)
cargo run -p xtask -- verify launch-acceptance --out target/proof-room/public-bundle

# 2. Proof Room release-truth gate (must exit 0)
bash scripts/check-chio-proof-room-release-truth.sh

# 3. Transaction-passport verifier gate (must exit 0)
bash scripts/check-chio-transaction-passport.sh
```

The swarm guardrail in `CHIO-TOKEN-COMMERCE-ALIGNMENT.md` also names
`provider-fixture-claims.test.sh` as a per-crate gate alongside the three above; run it the
same way when present.

## 4. Can the gate run green in THIS environment?

YES. All three gate commands run GREEN in this worktree once `dist/` is built, with no missing
prerequisite. Verified results:

- `npm ci` + `npm run build` in the dashboard crate succeeded with the installed toolchain
  (node v24.16.0, npm 11.13.0 via mise), producing `crates/products/chio-cli/dashboard/dist`
  (`index.html` + `assets/`). The `tsc -b && vite build` build transformed 1896 modules in
  ~3s.
- `cargo run -p xtask -- verify launch-acceptance --out <bundle>` then exited 0 and wrote the
  bundle and `public-bundle.tar.zst`. It progressed past the previously failing dashboard
  check. The generated `verifier/report.json` verdict is `verified`, and the static UI was
  copied to `ui/proof-room-static/` in the bundle.
- `scripts/check-chio-proof-room-release-truth.sh` exited 0 ("OK Proof Room release truth").
- `scripts/check-chio-transaction-passport.sh` exited 0 ("OK transaction-passport verifier
  gate: 30 positive, 109 negative, 4 proof-room").

The only prerequisite is the one-time `npm ci && npm run build` of the dashboard, which needs
network access to the npm registry to fetch the locked dependency set on a cold checkout.
After that the gate is fully reproducible offline. No part of the export was faked; `dist/`
remains gitignored and is regenerated by the documented build.
