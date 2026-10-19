# `chio proof verify`

`chio proof verify <bundle>` verifies a transaction passport or a Proof Room
bundle and prints a verifier report. With `--json`, a rejection is printed to
stderr as one JSON error report whose `code` names the rejection.

## Exit codes

A rejection that carries a `transaction:*` registry code exits with that
code's class, whatever its message says. A rejection without one, such as a
missing trust-root environment variable, is classed from its message, and one
that matches no class exits 1.

| Code | Class | Registry codes |
| ---- | ----- | -------------- |
| 0 | verified | none |
| 1 | unclassified | an error with no transaction code whose message matches no class, such as an unreadable input path |
| 10 | required claim | `transaction:required-claim-missing`, `claim-rejected`, `identity-not-bound`, `authorization-not-bound`, `receipt-uncheckpointed`, `runtime-proof-rejected`, `buyer-review-rejected`, `settlement-unverified`, `dispute-unbound`, `transparency-preview-not-allowed` |
| 20 | integrity | `transaction:passport-hash-mismatch`, `artifact-hash-mismatch`, `graph-not-closed`, `graph-cycle`, `signature-invalid` |
| 30 | parse or schema | `transaction:passport-schema-unsupported`, `artifact-schema-invalid`, `CHIO-CLI-JSON`, `attest:signed-json-*` |
| 40 | negative case mismatch | `transaction:negative-case-mismatch`: a Proof Room negative case verified, or failed for a reason other than the one it declares |
| 50 | unsupported verifier feature | `transaction:verifier-feature-unsupported`: the verifier lacks pinned trust context, or the bundle needs a feature the verifier does not support |

Every `transaction:*` code maps to exactly one of 10, 20, 30, 40 or 50. Usage
errors exit 2.

`scripts/check-chio-transaction-passport.sh` requires every negative fixture in
`fixtures/proof-room/catalog.json` to exit with 10, 20, 30 or 50.
