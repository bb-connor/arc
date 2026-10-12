# chio-finding architecture

## Responsibility and boundary

The crate owns serializable finding-family types, structural validation,
canonical identities, signatures, and portable proof checks. `Finding` is
the inline-signed information good. `SignedFindingAdmission`, purchase and
challenge envelopes, audit artifacts, and status artifacts carry the
surrounding market statements. Unsigned recipe, purchase, observation, and
recovery carriers preserve inputs for downstream verification.

All checks operate on supplied values. The crate has no database or network
client. Consumer policy determines whether an authenticated signer can make
a statement and whether referenced evidence supports its claim.

## Structure

`types.rs` defines the core descriptor, finding, and classification enums.
`validate.rs` implements identity, inline signing, signature checks, and
shared field bounds. `reveal.rs` constructs the two-field reveal envelope.
`envelope.rs` supplies pinned envelope verification and full-envelope hashes.

Publication artifacts live in `profile`, `terms`, `authorization`, `backing`,
`report`, and `admission`. Purchase carriers and terminals have separate
`purchase_context`, `purchase_record`, and `failed_delivery` modules.
The challenge, enforcement, finalized-bond, audit, and replay modules define
their own identities and binding validators.

`status.rs` handles sparse status epochs and proof carriers.
`status_admission.rs` makes a status decision from a `FindingStatusSource`.
`key_revocation.rs` carries signed key revocation and authority status.
`hosted.rs` defines claim allocation, purchase results, verified-fix
submission, voluntary retraction, and liability lifecycle bodies.

## Data and control flow

1. Construct a `Finding` draft with an empty identifier and signature.
2. Commit the reveal using `finding_payload_sha256`, which hashes canonical
   JSON containing `media_type` and standard-base64 `payload_b64`.
3. Set the identifier with `compute_finding_id`, then call `sign_finding`
   to check issuer equality, validate the body, and sign it inline.
4. A reader validates raw JSON at its input boundary, deserializes it, and
   calls `verify_finding` for structural and signature integrity.
5. Market consumers resolve the artifact references and establish authority,
   evidence validity, collateral, status, and current-time eligibility.

Supporting signed families use `SignedExportEnvelope<T>`. Family verifiers
validate their bodies and apply their signer binding. Seller terms and
authorization use body-declared subjects; consumers must connect those
subjects to the finding. Venue, collateral, purchase, and verifier roles
require the appropriate external authority inputs.

## Trust and invariants

`compute_finding_id` clears both `finding_id` and `signature` to empty
strings, retains both members, and hashes canonical JSON. Inline signing
retains the populated identifier and clears only the signature. Verification
requires a lowercase 128-character signature and strict Ed25519 checking.

`Finding::validate` rejects weak issuers, integers beyond the I-JSON safe
range, duplicate evidence receipts, missing replay digests for deterministic
replay, and unsupported explicit no-assurance encoding. Non-asserted classes
or a present assurance tier require receipt references. Receipt authentication
remains a consumer obligation. The validity-window check is clockless.

Identity rules are family-specific. `derive_purchase_key` binds the accepted
bid envelope digest and authoritative payment operation. Challenge outcomes
use a domain-separated body preimage. `signed_envelope_sha256` hashes the
complete envelope, including its signer and signature.

`verify_signed_status_epoch` binds the feed, operator, key epoch, authority
window, and revocation cutoff. `verify_status_proof_input` checks epoch
identity, freshness, and sparse inclusion or non-inclusion. The consuming
service supplies the trusted authorization and time. `decide_finding_status`
uses sticky status, retained epoch floors, and verified proof facts supplied
by its source; it does not fetch or cryptographically verify those facts.

## Dependencies

`chio-core-types` provides canonical JSON, keys, signatures, monetary amounts,
and export envelopes. `chio-revocation-oracle` supplies sparse status-map
primitives. `base64` and `hex` support carriers and digest encodings. `serde`
and `serde_json` implement typed wire forms; `thiserror` exposes rejections.
The development dependency `chio-spec-validate` checks schema agreement.

## Verification

`tests/finding.rs` exercises schema, signature, identity, encoding, and size
rejections. `tests/market_families.rs` checks pinned signers, content tampering,
profile roles, recipe ordering, backing arithmetic, and admission bindings.
Purchase, challenge, recovery, and status suites cover their respective
carriers and terminal shapes. Reveal unit tests bind media type and canonical
base64 to the payload commitment.

Run `cargo test -p chio-finding` for the crate's unit and integration tests.
Those tests do not exercise a running venue, persistent allocation store,
external collateral rail, or live status-feed service.
