# Chio Sigstore prehashed verification repair

This unpublished fork preserves the sigstore-crypto 0.6.6 API and backports the
prehashed-verification correction from upstream without its API expansion.

- Registry archive SHA-256:
  `da90c3d9af638898a5fdc347479b18f950bb0dde11ecf2244f94cd28135da53b`.
- Original release commit: `c9d76063833cb58a06483b181096294524d2dbf1`.
- Upstream repair:
  [267dacdb172e590c2081c1480a8c5a0555e89b2a](https://github.com/prefix-dev/sigstore-rust/commit/267dacdb172e590c2081c1480a8c5a0555e89b2a).
- License: Apache-2.0. The release repository's license text is retained.

Only `src/verification.rs` changes production behavior. The SHA-256 digest API
passes the supplied digest directly to AWS-LC for ECDSA P-256, RSA PKCS#1 v1.5
and RSA-PSS SHA-256. It rejects Ed25519 and schemes requiring SHA-384/SHA-512.
It no longer treats a digest as a new message and hashes it again.

All upstream source and tests are retained. Four added tests cover RSA artifact
signatures versus signatures over digest bytes, ECDSA binding, Ed25519 rejection
and rejection of incompatible digest algorithms. The main and fuzz workspaces
select this owned source explicitly. No audit certifies the original defective
registry bytes.

```sh
cargo test --locked --all-features --manifest-path third_party/sigstore-crypto-chio/Cargo.toml
cargo clippy --locked --all-targets --all-features --manifest-path third_party/sigstore-crypto-chio/Cargo.toml -- -D warnings
```

See `supply-chain/reviews/sigstore-crypto-0.6.6.md` for scope and retained evidence.
