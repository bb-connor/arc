# `chio proof verify`

`chio proof verify <bundle>` verifies a transaction passport or a Proof Room
bundle and prints a verifier report. With `--json`, a rejection is printed to
stderr as one JSON error report whose `code` names the rejection.

## Exit codes

The exit code is a function of the rejection's registry code alone; the
message is never read. A rejection that carries a `transaction:*` registry code,
or one of the parse codes listed for 30, exits with that code's class. Any other
error exits 1.

Exit 20 means the evidence presented for verification failed integrity. A
failure of the verifier's own configured trust context, such as a bad signature
on a deployment-supplied trust document, exits 50.

| Code | Class | Registry codes |
| ---- | ----- | -------------- |
| 0 | verified | none |
| 1 | unclassified | an error with no transaction code, such as an unreadable input path or a failed settlement RPC call |
| 10 | required claim | `transaction:required-claim-missing`, `claim-rejected`, `identity-not-bound`, `authorization-not-bound`, `receipt-uncheckpointed`, `runtime-proof-rejected`, `buyer-review-rejected`, `settlement-unverified`, `dispute-unbound`, `transparency-preview-not-allowed` |
| 20 | integrity | `transaction:passport-hash-mismatch`, `artifact-hash-mismatch`, `graph-not-closed`, `graph-cycle`, `signature-invalid` |
| 30 | parse or schema | `transaction:passport-schema-unsupported`, `artifact-schema-invalid`, `CHIO-CLI-JSON`, `attest:signed-json-*` |
| 40 | negative case mismatch | `transaction:negative-case-mismatch`: a Proof Room negative case verified, or failed for a reason other than the one it declares |
| 50 | unsupported verifier feature | `transaction:verifier-feature-unsupported`: the verifier lacks pinned trust context, or the bundle needs a feature the verifier does not support; `transaction:verifier-context-invalid`: the pinned trust context is malformed or inconsistent |

Every `transaction:*` code maps to exactly one of 10, 20, 30, 40 or 50. Usage
errors exit 2.

`scripts/check-chio-transaction-passport.sh` requires every negative fixture in
`fixtures/proof-room/catalog.json` to exit with 10, 20, 30 or 50.
