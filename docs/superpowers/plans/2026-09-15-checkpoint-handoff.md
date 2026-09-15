# Checkpoint handoff implementation plan

**Design:** ../specs/2026-09-15-checkpoint-handoff-design.md

**Constraints:** original identities; one allocation/log; canonical bounded JSON;
fail closed; no em dashes; no sub-agents; preserve previous evidence and source
checkout; local qualification only.

## 1. Provider handoff and strict public protocol

Create `src/funded_work/checkpoint_handoff.rs` and tests under
`src/funded_work/tests/checkpoint_handoff.rs` in `examples/federated-work`.
Expose `export(native, request) -> Request` and
`import(native, request, bundle) -> Result<()>`. `Request` carries schema,
context_sha256 and receipt. Extract read-only `Native::original_evidence` from
existing evidence collection. Retain `execution-request` in the funding journal;
the ordinary evidence path must reject pending handoffs without reading keys.
Test a real native execution with checkpoint/status directories moved away:

```rust
let request = checkpoint_handoff::export(&f.native, &f.request)?;
assert!(f.native.evidence(&f.request).is_err());
assert_eq!(request.receipt.tool_name, "review");
assert_eq!(f.native.journal.execution_count()?, 1);
```

Watch the missing handoff behavior fail, implement, then test foreign signed
sources, changed context, invalid/revoked standing and changed checkpoints.

## 2. Durable separate operator and CLI

Create `checkpoint_operator.rs` and CLI init/sign commands. Enrollment pins
context plus authority UUID, separately from the provider request. Initialize only
through exclusive file creation with already provisioned checkpoint/status keys.
Signing opens existing regular SQLite state, serializes writers, validates all
pins and keys, and commits a complete response before returning. Exact request
replay validates and returns original response without signing.

```rust
let first = checkpoint_operator::sign(operator.path(), &request)?;
std::fs::remove_file(operator.path().join("checkpoint/key.seed"))?;
let replay = checkpoint_operator::sign(operator.path(), &request)?;
assert_eq!(canonical_json_bytes(&first)?, canonical_json_bytes(&replay)?);
```

Tests must detect missing state being recreated, changed receipt acceptance,
fresh signing with rotated keys, response tampering and ambiguous ingress. Wire
commands write canonical response files only after custody commit. Include new
source files in the native implementation digest.

## 3. Process and settlement integration

Run the actual CLI as a separate process against a distinct operator directory.
Export from a native funded operation, sign externally, import, and drive existing
Finding/claim/decision/payout or rejected-output/refund paths. Delete original
operator keys after response custody and verify exact process replay. Run the
existing Python verifier against public Rust-produced witness and external pins.
Retain a current qualification report and hashes in a new evidence directory.

## 4. Inline review and closeout

Review request provenance, key pinning, state-loss semantics, commit ordering,
canonical bounds and fresh versus historical validation. Run standalone Rust
tests and Clippy, formatting and file hygiene; run relevant existing process
regressions after rebuilding the normal executable. Any production correction
requires rerunning affected checks. Commit conventionally only after successful
checks, verify clean integration status and preserve the original checkout.

## Completion

All four tasks are implemented and locally qualified. The
[delivery report](../../market/open-agent-work/execution/27-checkpoint-operator-handoff.md)
records the actual commands, trust boundaries and next operator-provisioning
gate; its evidence manifest binds the selected passing checks and source hashes.
Execution and review were performed inline without sub-agents.
