# hello-receipt-verify

Minimal offline evidence verification example using a checked-in, deterministically generated evidence package.

This example does not start trust, issue capabilities, or run an app surface. It starts from an already-exported evidence package and shows how to:

- verify the package offline with `chio evidence verify` against a pinned kernel key
- inspect one receipt and its capability lineage
- prove that tampering breaks verification

## What It Demonstrates

- receipt verification from a static exported package
- local lineage inspection without any live service
- tamper detection through manifest-backed file hashes: the tampered copy exits 20 with `urn:chio:error:attest:bundle-file-hash-mismatch`
- an export envelope signed by a committed kernel seed, so the trust file pins a key derived from that seed rather than one read from the package

## Files

`verifier-trust.json` is the `chio.verifier-trust.v1` file `chio evidence verify --trust` reads. It pins the public key of `fixtures/kernel.seed`, the example kernel seed that signed the captured receipt and the package's `export-envelope.json`.

```text
ARCHITECTURE.md
README.md
fixtures/kernel.seed
fixtures/minimal-evidence/
smoke.sh
verifier-trust.json
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

## Regenerate the fixture

The fixture is one `read_file` decision under `examples/policies/default.yaml`, exported with the committed seed. From the workspace root, with a fresh private directory in `$dir`:

```bash
install -m 600 examples/hello-receipt-verify/fixtures/kernel.seed "$dir/session.sqlite3.kernel.seed"
chio --receipt-db "$dir/receipts.sqlite3" --session-db "$dir/session.sqlite3" \
  check --policy examples/policies/default.yaml --server '*' --tool read_file \
  --params '{"path":"README.md"}'
chio --receipt-db "$dir/receipts.sqlite3" evidence export --admin-all \
  --kernel-seed-file "$dir/session.sqlite3.kernel.seed" \
  --output "$dir/minimal-evidence"
```

The seed copy is mode 0600 because `evidence export` refuses a seed any other user can read.

Replace `fixtures/minimal-evidence/` with `$dir/minimal-evidence/`. The seed's public key does not change, so `verifier-trust.json` stays as it is.

## Note

This example stops at offline verification. `chio evidence import` is intentionally stricter and requires a signed bilateral federation policy, so it belongs in a federation-focused example rather than this minimal offline verifier.
