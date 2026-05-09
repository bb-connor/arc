# v0.1.0-bounded-chiodome

**Release tag (planned):** `v0.1.0-bounded-chiodome`
**Status:** release-candidate notes; final tag not cut
**Style:** bounded-claim release notes
**Predecessor:** last green release on `main`
**Scope:** bounded-chiodome release surface

## Release Truth Boundary

These notes describe the bounded release surface and artifact claims only.
They intentionally do not encode active review topology, merge order, or
integration state as release truth. Those belong in planning and review
ledgers, not in the release notes.

`releases.toml` currently has no `[v0_1_0_bounded_chiodome]` block and
no fixture-hash data for this planned tag. Until that metadata exists, the
only pinned fixture hashes in this package are the hashes recorded in
`examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/README.md`.

## What this release is

`v0.1.0-bounded-chiodome` packages the chiodome bilateral demo
plus the four Lane B primitives that protect it. The bilateral demo is a
single-process, single-kernel Rust binary that produces a DSSE
signature-slice envelope (not the strict CHIODOS section 6 predicate schema), a
`chio.receipt_v1` receipt, and a single-leaf `chio.checkpoint_statement.v1`
for one synthetic cross-org refund. The four Lane B primitives (B0
async-trait migration, B1 single-entry capability verifier, B2 receipt v2
fail-closed under negotiated v2, B3 anchor-batch async-only when public
witness is required, B4 DSSE signature-slice bilateral signing) provide the
protocol-level fail-closed posture the demo depends on. Lane A2 threat
evidence is PARTIAL: 18 rows are covered and 2 rows remain partial. Lane
C4 ships a receipt-explain CLI command. Lane C5 is PARTIAL: it ships only
a selective-disclosure structural placeholder behind the `chio-federation`
`bbs-stub` cargo feature.

## Bounded claims (read this first)

**This release qualifies the following claims:**

- Chio ships a cryptographically signed, fail-closed governance and
  evidence control plane with signed receipts, checkpoints, bounded
  delegated-authority semantics, and explicit provenance classes on the
  current ship-facing surfaces.
- Bilateral cosigning over a DSSE signature-slice envelope works as a
  single-process, single-kernel local proof of the cosign surface with
  two in-process Ed25519 keypairs. Strict CHIODOS section 6 predicate-schema
  completion is deferred.
- Receipt v2 fail-closes under a negotiated v2 surface (Lane B2).
- Anchor-batch publication is async-only when
  `require_public_witness=true` (Lane B3).
- A single-entry capability verifier rejects mismatched chains (Lane B1).
- A partial local section 7 verifier subset inspects the bilateral envelope on
  the demo path (Lane C2). Full predicate-schema completion is
  deferred.

**This release explicitly does NOT claim:**

- Transparency-log inclusion. There is no Rekor or public-log witness on
  the C1 demo path; the checkpoint statement is signed locally and is
  not bound to a public transparency log.
- Consensus-grade HA. The "two kernels" are two `Keypair` identities in
  one process; cross-host bilateral cosigning over the wire is a future release
  follow-up (DSSE-aware `BilateralCoSigningProtocol` over a real
  transport).
- Distributed-linearizable spend. Budget authority remains single-node
  atomic; the clustered overrun bound is the same explicit bound called
  out in v3.18.
- Production-grade KB MCP integration. The KB tool surface and the
  `mcp-remote` bridge in the C3 half are demo artifacts; production
  deployments must review the bearer-token, retry, and tool-allow-list
  semantics. **C3 ships PARTIAL** in this release: the default
  `run-with-kb-mcp.sh --check` smoke gate produces mediation
  transcripts via `chio mcp wrap --e2e-fixture`, not kernel-signed
  Chio receipts; the full `chio mcp serve` path against a running KB
  MCP is documented in `--full` mode but is not auto-driven by CI.
  Packaging a self-contained KB-MCP stub binary so `--check` can drive
  the kernel-signed serve path end-to-end is a future release deliverable.
- Verifier-backed runtime assurance as the sole admission boundary.
- Authenticated recursive delegation ancestry beyond the preserved
  presented chain.
- Multi-witness consensus or chain-bound finality.
- Production-grade selective-disclosure cryptography. The `bbs-stub`
  feature in Lane C5 is a structural placeholder for future BBS+
  integration; real BBS+ wiring is a future release follow-up.

## Lane B primitives enforced

Each row below maps a Lane B primitive to its release evidence and the
protocol section it is anchored to.

| Lane | Primitive                                           | Fixture path                                                                                                          | Spec citation                |
|------|-----------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|------------------------------|
| B0   | async-trait migration of ToolServerConnection       | (refactor; conformance through the four signed negative fixtures below)                                               | spec/PROTOCOL.md (transport) |
| B1   | single-entry capability verifier                    | `crates/chio-conformance/tests/` (B1 signed negative fixture)                                                         | spec/PROTOCOL.md section 5          |
| B2   | receipt v2 fail-closed under negotiated v2          | `crates/chio-conformance/tests/` (B2 signed negative fixture)                                                         | spec/PROTOCOL.md section 6.2        |
| B3   | anchor-batch async-only when require_public_witness | `crates/chio-conformance/tests/` (B3 signed negative fixture)                                                         | spec/PROTOCOL.md section 8 (anchor) |
| B4   | DSSE signature-slice bilateral signing              | `crates/chio-conformance/tests/` (B4 signed negative fixture) and `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/envelope.json` | DSSE PAE/signature-slice; strict CHIODOS section 6 predicate schema deferred |

The conformance fixtures are signed negative cases proving the verifier
rejects malformed inputs.

## Lane A floor

| Bar                                | Status    | Evidence                                                                                                                                                |
|------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Mutation (Bar 1)                   | PARTIAL   | `chio-credentials` measured at **74.07%** caught (caught=20 missed=0 timeout=7 unviable=1). The other five trust-boundary crates (`chio-policy`, `chio-attest-verify`, `chio-kernel-core`, `chio-guards`, `chio-anchor`) carry a BASELINE-GAP forward; per-crate full-sweep measurement is queued for the future release follow-up batch. |
| Threat evidence (18 covered + 2 partial) | PARTIAL | Lane A2 backfills 18 rows of the threat-evidence matrix and leaves 2 rows partial. This is not a full-closure release claim. |
| Kani (3 crates)                    | PARTIAL   | `chio-attest-verify` remains DEFERRED-PARTIAL/MODEL-PARTIAL. The current harnesses and workflow coverage do not make Kani release evidence full. |
| TLA+ (4 properties)                | PARTIAL   | The bounded receipt-before-allow and revocation-cut rewrites are model/snippet scoped and not implementation-complete. |
| Lean4 negotiation_safety           | PARTIAL   | `negotiation_safety` is re-proved against the executable model. This is implementation-linked bounded evidence, not a first-principles production proof. |

The mutation and threat-evidence rows are the bars most likely to be
misread. Both are **PARTIAL**.

## Demo summary

The chiodome bilateral demo is two halves:

1. **Cross-org refund (C1):** an end-to-end Rust runner
   (`examples/chiodome-bilateral/`) that produces a DSSE
   signature-slice bilateral envelope plus a single-leaf
   `chio.checkpoint_statement.v1` for one synthetic refund. The
   cosigning surface is `chio_federation::bilateral_dsse::sign_dsse_envelope`.
   The legacy `co_sign_with_origin` path is explicitly avoided because the
   two preimages are different wire formats.
2. **KB MCP integration (C3, PARTIAL):** an `mcp-remote` stdio-to-HTTP
   bridge plus a `chio mcp serve` policy wrapper around the local KB
   MCP at `:8111/mcp/`. The **default** smoke gate
   (`run-with-kb-mcp.sh --check`) drives a noninteractive replay
   through `chio mcp wrap --e2e-fixture` against a stub KB-MCP
   fixture, persists one mediation transcript per response frame to
   `${CHIO_RECEIPT_DIR}`, and asserts at least one transcript landed
   plus that the `_meta.chio_verified` attestation header was
   observed. This works WITHOUT a running KB MCP. The full
   `chio mcp serve --policy ./policy.yaml -- mcp-remote ...` path
   that produces kernel-signed Chio receipts is documented in `--full`
   mode but requires a running KB MCP backend; it is not auto-driven
   by this release. C3 is therefore PARTIAL; future release deliverables include
   a self-contained KB-MCP stub binary so the kernel-signed path can
   run as a default CI smoke gate.

The pinned demo run for this release lives at
`examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/`. Three
files (`receipt.json`, `envelope.json`, `checkpoint.json`) are recorded
with sha256 hashes documented in the directory's `README.md`. The
regeneration command is

```
CHIODOME_DEMO_OUT=examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome \
    cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
```

`--release-fixture-seed=42` (or the equivalent
`CHIODOME_DEMO_FIXTURE_SEED=42` env var) seeds both demo keypairs from
a deterministic 32-byte seed so reruns produce byte-identical fixtures.
Seed 42 is the seed under which the pinned fixtures here were captured.

Receipts are explained with the `chio receipt explain` command:

```
cargo run -p chio-cli -- receipt explain \
    bilateral \
    --input-file examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json
```

The CLI prints decision provenance, evidence, financial metadata, and
the canonical-JSON digest the DSSE envelope subject claims to bind. The
`bbs-stub` cargo feature on `chio-federation`, not `chio-cli`, gates the
C5 selective-disclosure placeholder; without the feature, that
placeholder path is not compiled. C5 remains PARTIAL until real BBS+
wiring replaces the stub.

## Ship-bar reconciliation

| Bar | Description                                                                 | Status   |
|-----|-----------------------------------------------------------------------------|----------|
| 1   | Mutation kill-rate floor across the six trust-boundary crates               | PARTIAL |
| 2   | Conformance fixtures across B1+B2+B3+B4 lock in the negotiated-v2 surface   | PARTIAL |
| 3   | Demo runs end-to-end, receipts via `chio receipt explain`, fixtures pinned  | PARTIAL |

Bar 1 is partial because only `chio-credentials` has a measured per-crate
caught-ratio (74.07%) on the v3.18-aligned cycle; the other five
trust-boundary crates carry a BASELINE-GAP forward. The release tracker
explicitly records this and queues mutation-continuation as a follow-up
batch for a future release.

## Honest deferrals to future release

The following are explicitly carried forward and are **not** in
`v0.1.0-bounded-chiodome`:

1. Mutation full-sweep measurement on `chio-policy`, `chio-attest-verify`,
   `chio-kernel-core`, `chio-guards`, and `chio-anchor`.
2. Cross-host bilateral cosigning over a real transport (DSSE-aware
   `BilateralCoSigningProtocol` over the wire). Today the demo is
   single-process.
3. Real BBS+ wiring behind the `bbs-stub` feature gate in Lane C5. The
   current feature is a structural placeholder.
4. Distributed `ReceiptStore` and quorum-aware checkpoint publication.
5. Sync-evaluator migration follow-up (the async-trait B0 surface lands
   here; downstream callers and the synchronous evaluator paths are
   queued for future release).
6. Public transparency-log integration. The current checkpoint is signed
   locally; Rekor or equivalent witness binding is future release.
7. First-principles theorem-prover completion for concrete crypto, OS,
   storage, transport, subprocess, hosted-registry, chain, or settlement
   implementations.
8. HITRUST i1 issued certificate. The existing readiness package is not
   an issued certificate.
9. External-vendor crypto-protocol review on letterhead. Existing
   internal review material is not a vendor letterhead review.
10. Comptroller-grade or universal-control-plane packaging claims as a
    ship-facing release boundary.
11. Self-contained KB-MCP stub binary so
    `examples/chiodome-bilateral/scripts/run-with-kb-mcp.sh --check`
    can drive the kernel-signed `chio mcp serve` path end-to-end (and
    thus produce kernel-signed Chio receipts) as a default CI smoke
    gate. Today's `--check` runs the wrap-mode mediation-transcript
    path; the kernel-signed path requires `make -C ops/knowledge-base
    run` plus `npx -y mcp-remote ...` out-of-band. C3 is PARTIAL
    pending this work.

## Artifact metadata

The planned tag is `v0.1.0-bounded-chiodome`. The tag is **not pushed**
by this package. This package also does not define release-ledger keys in
`releases.toml`; if a future release process requires a
`[v0_1_0_bounded_chiodome]` block or fixture-hash keys, add those keys
before tagging.

## Verification commands

These commands are the bounded local-go gate for the release. They are
the same shape as the v3.18 bounded-ship gates.

```
# Workspace correctness
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check

# Demo run (regenerates the pinned fixtures into a scratch dir under the
# pinned seed; the resulting hashes MUST match the values recorded in
# fixtures/v0.1.0-bounded-chiodome/README.md).
CHIO_FIXTURE_REGEN_DIR=target/chiodome-regen/v0.1.0-bounded-chiodome
CHIODOME_DEMO_OUT="${CHIO_FIXTURE_REGEN_DIR}" \
    cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
shasum -a 256 "${CHIO_FIXTURE_REGEN_DIR}"/{receipt,envelope,checkpoint}.json

# Receipt explainer.
cargo run -p chio-cli -- receipt explain \
    bilateral \
    --input-file examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json

# KB MCP integration smoke gate. The default mode does NOT require a
# running KB MCP and exits 1 if no mediation transcript landed.
bash examples/chiodome-bilateral/scripts/run-with-kb-mcp.sh --check
```

The `cargo build --workspace` cold cache run can take several minutes.

## Changelog summary

- Adds Lane A2 threat evidence as PARTIAL: 18 covered rows and 2 partial
  rows.
- Adds Kani harnesses across `chio-attest-verify`, `chio-anchor`, and
  `chio-weights`; lands the multi-crate Kani CI workflow. Release
  evidence remains PARTIAL because the `chio-attest-verify` model is
  DEFERRED-PARTIAL/MODEL-PARTIAL.
- Adds TLA+ rewrites for the receipt-before-allow split and the
  revocation-cut completeness property as bounded model evidence.
- Re-proves Lean4 `negotiation_safety` against the executable model
  as bounded formal evidence.
- Adds per-crate mutation baseline (`chio-credentials` measured at
  74.07%) and a `.cargo/mutants.toml` exclusion rationale.
- Migrates `ToolServerConnection` to async-trait.
- Adds the single-entry capability verifier, receipt v2 fail-closed,
  anchor-batch async-only, and DSSE signature-slice bilateral signing.
- Adds the chiodome bilateral demo, a partial section 7 verifier subset, the
  `chio receipt explain` command, and the `chio-federation` `bbs-stub`
  placeholder for selective disclosure.
- Pins canonical demo fixtures at
  `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/`.
- Leaves v0.1.0 release-ledger metadata out of `releases.toml` until a
  real metadata block exists.
