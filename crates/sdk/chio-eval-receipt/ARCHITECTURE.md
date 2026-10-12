# chio-eval-receipt architecture

## Responsibility and boundary

This crate owns unsigned eval-report bundle construction and reference
verification. `Bundle` wraps receipt payload text, scenario labels, eval-run
metadata, and the compiled verdict-matrix corpus identity.
`VerifiedBundle` returns an id and receipt/signature counts after verification.
There is no kernel dependency, receipt signing, or persistence layer.

The root also re-exports authoritative-spend checks from `chio-core-types`.
They are separate from bundle verification: consumers supply admitted kernel
keys and a `PresentedNonceView` to check spend authority.

## Structure and dependencies

| Path | Role |
|------|------|
| `src/lib.rs` | Module exports, schema constants, spend-contract re-exports, and contract tests. |
| `src/export.rs` | Input constructors, bundle types, payload SHA-256, and unsigned export. |
| `src/verify.rs` | Envelope, corpus, receipt, review, and outer-signature checks. |
| `src/bin/cli.rs` | `verify`, `verify-fixture`, and synthetic `verify-memo` commands. |
| `tests/` | Export preservation, schema pin, and golden fixture checks. |

`chio-core-types` supplies RFC 8785 canonicalization, signed JSON decoding,
receipt signature verification, and spend predicates. `serde_json` parses
outer bundle JSON. `sha2` hashes payload bytes and synthetic signatures.
No Cargo features are declared. The separate `py/` package uses PyO3 to
call `verify_bundle` and translate errors into Python `ValueError`.

## Export and verification flow

`EvalRunMeta::from_parts` and `Receipt::from_parts` own borrowed strings,
rejecting empty or padded identity fields. Payloads need only contain
non-whitespace text and are copied exactly. `export_scenario_run` hashes
those bytes, pins the corpus metadata, and leaves signatures empty.
It accepts an empty receipt slice. The public fields can bypass or undo
constructor validation; export does not revalidate them or inner signatures.
Bundle types have no Serde derives or built-in JSON writer.

Both verifier entry points parse the outer JSON into `serde_json::Value`,
check the schema id and closed envelope, then check corpus identity,
receipts, optional partner review, and signatures in that order.
Receipt and signature arrays must be nonempty. Pipeline language is one of
`python`, `go`, or `rust`; receipt verdict is `allow` or `deny`.
Partner review, when present, requires a window of 1 through 7 days and
one of the three accepted disposition strings.

Each receipt wrapper's SHA-256 must match its exact payload text.
`UntrustedJsonText::decode_signed` parses embedded `ChioReceipt` bytes with
duplicate-key rejection before signature verification. Fixture mode can
accept a failing embedded receipt check only for one of three fixed
scenario-id/payload-hash pairs.

Outer signatures cover RFC 8785 JSON after removing `signatures`.
`test_signature_for_bundle_json` computes its deterministic SHA-256 and
does not validate the envelope. Fixture mode compares `test-sha256`
values and requires `signed_payload = bundle_without_signatures:rfc8785`.
Production mode accepts no outer signature kind, including that fixture kind.

## Trust and invariants

The corpus check compares constants; it does not recompute the digest from
files or require one receipt for every corpus scenario. Wrapper scenario
ids and verdicts are not cross-checked against embedded receipt decisions.
Embedded signature verification uses the receipt's key; bundle verification
does not check that key against an operator trust set.

Outer JSON uses ordinary `serde_json` parsing, so its duplicate object keys
collapse before envelope checking. The CLI reads whole files without a
size limit. Input size limits and authoritative signer admission remain
caller responsibilities. The library forbids unsafe code.

`is_authoritative_spend_receipt` checks the receipt signature, admitted
kernel key, mediated prevent/allow semantics, reconciled budget metadata,
positive exposure, frozen spend profile, and nonce links. It matches
capability, server, tool, parameter hash, and an optional reserved hold,
then verifies the nonce under the receipt key. The supplied nonce trait
owns its signature-verification behavior. `PresentedNonceView` exposes no
subject or request accessors, so this helper does not establish the subject
and request bindings required by protocol 6.2. Consumers requiring that
authority must verify them through an authoritative nonce/admission path.
`receipt_meets_guarantee_floor` checks recognized levels and their ordering
separately; it does not verify a receipt signature or inspect the backing store.

The memo CLI accepts only `synthetic-test-sample`, checks a hash of memo
bytes and signer text, and rejects duplicate or unknown signature-file
fields. Its deterministic hash does not authenticate partner identity.

## Verification

Run `cargo test -p chio-eval-receipt`. Unit tests cover payload preservation,
constructor errors, canonical ordering, envelope mutations, forged receipts,
production rejection of fixture signatures, embedded duplicate keys, and
receipt binding vectors with full-width integer fields.

`tests/export_roundtrip.rs` checks three wrapped payloads and empty outer
signatures. `tests/schema_lint.rs` pins schema identifiers and verifies the
three-receipt golden fixture. CLI tests check memo scheme labels and reject
duplicate fields, unknown fields, comments, and unsupported schemes.
The [README](README.md) runs that fixture through the public verifier.
