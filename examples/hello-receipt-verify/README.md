# hello-receipt-verify

Minimal offline evidence verification example using a checked-in, deterministically generated evidence package.

This example does not start trust, issue capabilities, or run an app surface. It starts from an already-exported evidence package and shows how to:

- verify the package offline with `chio evidence verify` against a pinned kernel key
- inspect one receipt and its capability lineage
- prove that tampering breaks verification

## What It Demonstrates

- receipt verification from a static exported package
- local lineage inspection without any live service
- tamper detection through manifest-backed file hashes

## Files

```text
ARCHITECTURE.md
README.md
fixtures/minimal-evidence/
smoke.sh
test_verify_artifacts.py
verify_artifacts.py
```

## Run

Verify the checked-in package and run the tamper check:

```bash
./smoke.sh
```

Run the offline artifact verifier tests:

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```

## Regenerate The Fixture

`fixtures/minimal-evidence/` is written by the real evidence export path from fixed
Ed25519 seeds and fixed timestamps, so it is byte-reproducible:

```bash
CHIO_WRITE_HELLO_RECEIPT_FIXTURES=1 cargo test -p chio-control-plane --lib \
  committed_hello_receipt_fixture_is_the_generator_output
```

The same test without the variable fails when the committed bytes drift.

## Note

This example stops at offline verification. `chio evidence import` is intentionally stricter and requires a signed bilateral federation policy, so it belongs in a federation-focused example rather than this minimal offline verifier.
