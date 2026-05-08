# Chio v0.1.0-bounded-chiodome — Release Notes

These notes record the closeout for the bounded-chiodome release.
Each gate (C1..C8) is marked with one of:

- **MET**: the gate's normative behaviour is implemented and covered
  by a passing conformance fixture.
- **PARTIAL**: the gate's *workflow* is implemented and covered, but
  one or more honesty caveats apply (see the gate row).
- **DEFERRED**: the gate is not implemented in this release; the
  scope is recorded against follow-up work.

## Gate matrix

| Gate | Title | Status | Notes |
| ---- | ----- | ------ | ----- |
| C5   | Selective-disclosure auditor view | **PARTIAL** | See "C5 PARTIAL" below. |

## C5 PARTIAL — selective-disclosure auditor view

The selective-disclosure surface lives in
`crates/chio-federation/src/selective_disclosure.rs` behind the
`bbs-stub` Cargo feature (formerly `zk`). The implementation:

- emits the deterministic alphabetical-by-serde-field-name §5.2
  projection of `ChioReceiptBody` to a 14-message vector,
- exposes a `BbsAuditView` carrying the disclosed subset plus a
  SHA-256 commitment over `(disclosed_indices, withheld_messages,
  disclosed_encodings)`,
- and verifies under a pinned receipt body via
  `verify_audit_view`, rejecting tampered subjects, substituted
  disclosed bytes, substituted encodings, and malformed `Hx`
  fields.

Honesty caveats:

1. **No zero-knowledge property.** The proof bytes are a SHA-256
   commitment, not a BLS12-381 BBS+ signature. A verifier that holds
   the full receipt body can reconstruct withheld messages and
   re-hash. The Cargo feature is named **`bbs-stub`** (renamed from
   `zk` to avoid lying about ZK semantics). The `zk` (or `bbs-real`)
   feature name is reserved for real BBS+/BLS12-381 in follow-up work.
2. **Strict `Hx` decoding.** The silent-rehash fallback on malformed
   `content_hash` / `policy_hash` is closed. Malformed input
   (non-hex, wrong length, empty) now fails closed with
   `SelectiveDisclosureError::MalformedHexField { field, reason }`.
3. **Encoding bound into the proof.** The per-disclosed-index
   `encoding` string is bound into the SHA-256 commitment and a typed
   `SelectiveDisclosureError::DisclosedEncodingMismatch` gate fails
   closed so producers cannot relabel `S` (utf-8) bytes as `Hx` (or
   vice versa) at the verifier.
4. **Predicate language v1 not yet wired.** `eq` / `cmp` / `member`
   predicates per spec §5.6 require BBS+ commitments and
   Bulletproofs RangeStatements; those land in follow-up alongside
   real BBS+.

Conformance fixture:
`crates/chio-conformance/tests/c5_selective_disclosure_stub.rs`
(renamed from `c5_selective_disclosure_zk.rs`). Run with:

```
cargo test -p chio-conformance --features bbs-stub --test c5_selective_disclosure_stub
```

The fixture covers the round-trip plus tamper-detection negatives:
malformed Hx (invalid hex, short hex, empty string), policy-hash
length mismatch, and disclosed-encoding substitution.

## Cross-PR coordination

The `zk` Cargo feature was renamed to `bbs-stub` on both
`chio-federation` and `chio-conformance`. Downstream consumers that
previously enabled `--features chio-federation/zk` or
`--features chio-conformance/zk` MUST switch to the `bbs-stub`
feature name. No CI workflow files referenced the old `zk` feature
at the time of the rename.

The `zk` feature name is intentionally not aliased - reserving it
for the real BBS+ implementation prevents the next implementation
from inheriting the stub's honesty footnote.
