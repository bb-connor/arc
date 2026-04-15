# hello-receipt-verify

Minimal offline evidence verification example using a checked-in captured bundle.

This example does not start trust, issue capabilities, or run an app surface. It starts from an already-captured evidence package and shows how to:

- verify the package offline with `arc evidence verify`
- inspect one receipt and its capability lineage
- prove that tampering breaks verification

## What It Demonstrates

- receipt verification from a static captured package
- local lineage inspection without any live service
- tamper detection through manifest-backed file hashes

## Files

```text
README.md
fixtures/minimal-evidence/
smoke.sh
```

## Run

Verify the captured package and run the tamper check:

```bash
./smoke.sh
```

## Note

This example stops at offline verification. `arc evidence import` is intentionally stricter and requires a signed bilateral federation policy, so it belongs in a federation-focused example rather than this minimal offline verifier.
