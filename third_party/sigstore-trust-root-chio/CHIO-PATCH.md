# Chio Sigstore trust-root validity repair

This unpublished fork retains the sigstore-trust-root 0.6.3 API and rejects
malformed or reversed authority validity periods.

- Registry archive SHA-256:
  `ee8762a4813252faffdf6f7e2040213078eb2482fbc351381134f3fc60c1be9c`.
- Release source: `f9821a44bbb711b09aff29162e8d925f1de5d485` in
  [prefix-dev/sigstore-rust](https://github.com/prefix-dev/sigstore-rust/tree/f9821a44bbb711b09aff29162e8d925f1de5d485/crates/sigstore-trust-root).
- License: BSD-3-Clause, retained from that release commit.

Only `src/trusted_root.rs` changes production behavior. One checked parser
handles validity bounds. `from_json` (and consequently file/TUF loading) rejects
invalid dates and reversed intervals for Fulcio authorities, timestamp
authorities, Rekor keys and CT keys. Timestamp certificate/range helpers return
an error for invalid bounds. The boolean timestamp helper returns false when
it encounters invalid bounds. Absent limits retain their existing meaning.

The public structs still allow direct construction and mutation. Callers must
bind the actual signing authority and verify certificates, signatures and
trusted time; a true result from an any-authority helper does not establish
those facts. Chio's verifier retains its separate strict checks.

All upstream source, embedded trust data and tests are retained. Five regression
tests cover malformed bounds, reversed intervals, loader validation, open
intervals and inclusive endpoints. The original registry bytes are not audited.
The main and fuzz workspaces explicitly select the repaired source.

```sh
cargo test --locked --all-features --manifest-path third_party/sigstore-trust-root-chio/Cargo.toml
cargo clippy --locked --all-targets --all-features --manifest-path third_party/sigstore-trust-root-chio/Cargo.toml -- -D warnings
```

Two upstream integration tests return early without an external conformance
checkout. Their harness success is not conformance evidence. See
`supply-chain/reviews/sigstore-trust-root-0.6.3.md` for results and limitations.
