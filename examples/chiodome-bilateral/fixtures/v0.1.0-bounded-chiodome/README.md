# Pinned demo fixtures: v0.1.0-bounded-chiodome

This directory contains the canonical demo run captured for the
`v0.1.0-bounded-chiodome` release. The three files are produced by the
single-process Rust demo defined in `examples/chiodome-bilateral/` and are
signed by deterministic synthetic keypairs emitted by the seeded demo
runner. The fixtures are pinned here so that downstream verifiers,
conformance harnesses, and reviewers have a stable, hash-addressable
reference for the release.

## Files

| File              | Producer                                                              | Schema                                                          | sha256                                                              |
|-------------------|-----------------------------------------------------------------------|-----------------------------------------------------------------|---------------------------------------------------------------------|
| `receipt.json`    | `chio_core::receipt::ChioReceipt::sign`                               | `chio.receipt_v1`                                               | `2e299d17846bbe940f1d579cfa0ceff9d3c7ad07a3f57e63b741aa81144ef323`  |
| `envelope.json`   | `chio_federation::bilateral_dsse::sign_dsse_envelope`                 | DSSE v1 + `chio.bilateral-cosign-signature-slice.v1` predicate  | `c26cf69fbb7702359efc44cf6c75a8f9d19d3b2cd0421ff556ca5824196316f2`  |
| `checkpoint.json` | demo runner, single-leaf root                                         | `chio.checkpoint_statement.v1`                                  | `64d0c8809641872ca14476009f5cd7bf669adc8ed9e63a507111074b1bd2a097`  |

The hashes above were computed with `shasum -a 256 <file>` on the
files committed to this directory.

## Regeneration command

The demo is deterministic when run with the pinned synthetic timestamp
and keypairs that the runner ships with. To regenerate fixtures into
this directory:

```
CHIODOME_DEMO_OUT=examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome \
    cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
```

The `--release-fixture-seed=42` flag (also settable via
`CHIODOME_DEMO_FIXTURE_SEED=42`) is the seed used to capture these
fixtures and is the only mode in which the demo emits byte-stable
keypairs and signatures. Omitting the flag generates fresh random
keypairs and the regenerated hashes will not match the committed
fixtures even though both runs are otherwise identical.

If a regeneration with the seed drifts from the recorded hashes, the
demo runner must be inspected for non-deterministic input (system
clock, RNG that is not seed-derived, or ordering). The release-notes
file at `releases/v0.1.0-bounded-chiodome/RELEASE-NOTES.md` is the
canonical record of the pinned run.

## Bounded claims

These fixtures are a single-kernel local proof of the section 6 DSSE
bilateral-cosign envelope and the receipt-and-checkpoint surface. They
do **not** establish:

- Transparency-log inclusion (no public log; no Rekor or witness on
  the C1 path).
- Distributed-quorum or HA semantics. The two cosigners are two
  `Keypair` identities in one process.
- Cross-host transport finality. DSSE-aware
  `BilateralCoSigningProtocol` over the wire is a future release follow-up.

See `releases/v0.1.0-bounded-chiodome/RELEASE-NOTES.md` for the full
bounded-claim envelope this release ships under.
