# Chio Merkle proof-length repair

This unpublished fork selects the compatible sigstore-merkle 0.6.6 source with
the upstream overflow repair. It does not certify the original registry bytes.

- Registry archive SHA-256:
  `7c0d53558825c77716855c13794306fff766854c1bf92948e77d7890da3f2455`.
- Release source: `c9d76063833cb58a06483b181096294524d2dbf1`.
- Upstream repair:
  [`eed06c33736b1bb36298facaf89c763de00f721b`](https://github.com/prefix-dev/sigstore-rust/commit/eed06c33736b1bb36298facaf89c763de00f721b).
- License: Apache-2.0. The license text is retained from the release source.

The sole production change computes the ceiling half of a tree size as
`size / 2 + size % 2`. The original `size + 1` overflows at `u64::MAX`.
Public helper APIs removed by the upstream cleanup remain intact here.

The retained upstream vector inventory is supplemented with maximum-size
positive and negative proofs, and recursive reference trees for every size
from 1 through 65. Those trees cover every leaf and every nonempty prefix,
including substituted roots, leaves and proof hashes, extra hashes and
truncations. The recursive definitions are independent of the verifier's
iterative calculation.

```sh
cargo test --locked --all-features --manifest-path third_party/sigstore-merkle-chio/Cargo.toml
cargo clippy --locked --all-targets --all-features --manifest-path third_party/sigstore-merkle-chio/Cargo.toml -- -D warnings
```
