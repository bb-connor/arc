# chio-verify and chio evidence verify

`chio-verify` (crate `chio-bundle-verify`, Apache-2.0) verifies an exported
evidence package offline. `chio evidence verify` and `chio evidence import` run
the same verifier.

```text
chio-verify <BUNDLE_DIR> --trust <FILE> [--json]
chio evidence verify --input <BUNDLE_DIR> --trust <FILE>
chio evidence import --input <BUNDLE_DIR> --trust <FILE>
```

- `<BUNDLE_DIR>`: an exported package directory (`manifest.json`,
  `export-envelope.json` and every file the manifest lists).
- `--trust`: a `chio.verifier-trust.v1` file. Required; there is no default
  trust. Every key the verifier accepts comes from this file, never from the
  package.
- `--json` (`chio-verify`): print `chio.bundle-verify-report.v1` on stdout and a
  rejection as one JSON object on stderr whose `code` names it.

The verifier reads no clock and opens no network or database connection.

## Trust file

`kernel_keys` holds 1 to 64 keys: the package envelope, every tool receipt,
every child receipt and every checkpoint must be signed by one of them
(`checkpoint_keys` may add checkpoint-only signers); a signer outside them
refuses with `attest:bundle-trust-missing`. `exchange_keys` and
`root_policy_keys` hold 0 to 64 keys for anchored roots, which this verifier
does not read. `checkpoint_trust_anchor` is the only input that
can make publication claims `trust_anchored`; every publication must carry
exactly that binding. No key may be pinned in two roles, and weak Ed25519 keys
refuse.

`required_columns` names the report columns that must be `verified` for every
receipt.

## Report

One row per tool receipt with five columns, each `verified`, `observed`,
`asserted`, `unverifiable` or `rejected`:

| Column | `verified` when |
|---|---|
| `identity_root` | the receipt's root authority verifies against pinned exchange and root policy keys |
| `delegation_chain` | every hop of the presented chain verifies and no exported revocation covers it |
| `decision` | the receipt signature verifies under a pinned kernel key and the receipt is a mediated decision that carries its decision; trace observations and advisory evaluations report `observed` |
| `content` | the receipt's commitments open from data the verifier holds |
| `settlement` | not supported by this verifier; requiring it exits 50 |

Receipts without root authority report `identity_root`, `delegation_chain` and
`content` as `unverifiable`.

## Exit codes

The exit code is a function of the rejection's registry code alone; the
message is never read. The numbers and meanings are those of
`chio proof verify` (see `proof-verify.md`).

| Code | Class | Registry codes |
|---|---|---|
| 0 | verified | none; every column named in `required_columns` is `verified` |
| 1 | unclassified | an error with no registry code, such as an unreadable bundle path |
| 2 | usage | argument errors |
| 10 | required column | `attest:bundle-required-column-unverified` |
| 20 | integrity | `attest:bundle-envelope-invalid`, `bundle-file-hash-mismatch`, `bundle-signature-invalid`, `bundle-evidence-inconsistent` |
| 30 | parse or schema | `attest:bundle-schema-invalid`, `attest:signed-json-*` |
| 40 | negative case mismatch | reserved; this verifier never exits 40 |
| 50 | verifier context or unsupported feature | `attest:bundle-trust-invalid`, `bundle-trust-missing`, `bundle-feature-unsupported` |

Parse, schema and trust failures stop before any column is computed. A signer
outside the pinned keys is `bundle-trust-missing`. A receipt that embeds an
HTTP receipt needs the embedded-receipt check that `chio evidence verify`
supplies; the standalone `chio-verify` refuses it with
`bundle-feature-unsupported`.
