# chio-proof-room

`chio-proof-room` verifies Proof Room bundles from their source artifacts and
serves their dashboard, declared assets, and fixture reports over HTTP.
It provides the focused quickstart binary and library entrypoints used to
inspect transaction-passport evidence.

## Usage

Run this offline verification from the workspace root with Bash. The helper
loads checked-in fixture trust anchors for local verification. The report is
written to a fresh temporary directory; the command does not open a listener.

```bash
source scripts/proof-room-quickstart-env.sh
proof_room_example_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-proof-room-example.XXXXXX")"
trap 'rm -rf -- "$proof_room_example_dir"' EXIT
cargo run -p chio-proof-room -- \
  --bundle fixtures/proof-room/first-run/single-call-authority/proof-room-bundle \
  --verify-only \
  --doctor-report "$proof_room_example_dir/doctor.json"
```

Serving requires `--bundle` and a dashboard `--ui-dir` containing `index.html`.
`CHIO_PROOF_ROOM_UI_DIR` and `CHIO_PROOF_FIXTURE_ROOT` supply optional directory
defaults; command-line flags override them. The listener defaults to
`0.0.0.0:7391`; use `--listen 127.0.0.1:7391` for local inspection.
`--verify-only` requires no UI directory. Invalid arguments exit with code 2;
verification and serving errors exit with code 1.

## Guarantees

- `verify_proof_room_bundle` returns `VerifiedProofRoomBundle`, which retains
  the authenticated bundle ID and hash of the exact manifest bytes.
- `verify_bundle_signature` checks detached DSSE signatures over manifest
  bytes and requires each signer in both bundle-declared and operator-trusted
  key sets. Configure `CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS` and
  `CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS` independently.
- `verify_source_verifier_report` recomputes reports from passport artifacts.
  Claim routing invokes the required domain verifiers and rejects unsupported
  required claims.
- `input::read` bounds individual artifacts to 16 MiB before JSON allocation;
  signed JSON parsing rejects duplicate keys.
- `serve_proof_room` verifies the UI and bundle before binding. Router
  constructors build routes and asset allow-lists; callers embedding them
  must arrange full bundle verification.

`verify_proof_room_quickstart` writes a doctor report after verification.
`build_proof_room_source_verifier_report` returns a recomputed JSON report;
`validate_proof_room_bundle_relative_path` checks lexical path safety.
All three functions return `ProofRoomError` on rejection.

## Status

Implemented as a fixture-oriented verifier and HTTP inspection service.
It verifies existing evidence without issuing capabilities or mediating tool
execution. Serving uses in-memory route state and files on disk; there is no
receipt-store flush or durable upload repository. Multipart uploads are verified
in temporary directories removed when their owning object drops.

There are no package-defined Cargo features. BBS support is enabled on the
selective-disclosure dependency. Tests cover the checked-in bundle, negative
replay, source-report drift, receipt coverage, route assets, and CLI behavior.
These tests exercise local evidence and server behavior.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Transaction passport](../../platform/chio-transaction-passport/README.md)
- [Chio CLI](../chio-cli/README.md)
- [License](../../../LICENSE)
