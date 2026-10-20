# chio-bundle-verify

Offline verifier for exported Chio evidence bundles, licensed Apache-2.0.

`chio-verify <BUNDLE_DIR> --trust <FILE> [--json]` checks an exported
evidence package against a `chio.verifier-trust.v1` file that the verifying
party writes and controls:

- the kernel-signed export envelope commits to the manifest and the decoded
  payload, and its signer is a pinned kernel key;
- every listed file matches its manifest digest and length, and the manifest
  lists every file exactly once;
- every receipt and checkpoint signature verifies under a pinned key;
- the checkpoint chain, consistency proofs, inclusion proofs and
  transparency records agree with the signed checkpoints;
- publication claims count as trust-anchored only under the trust file's
  `checkpoint_trust_anchor`;
- every exported record lies inside the query the package claims.

The verifier reads no clock and opens no network or database connection. Its
normal dependency closure contains no async runtime, HTTP client or SQLite
binding; `scripts/check-offline-verifier-deps.py` enforces this.

Exit codes match `chio proof verify`; see `docs/cli/bundle-verify.md`.
