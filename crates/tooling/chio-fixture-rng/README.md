# chio-fixture-rng

`chio-fixture-rng` supplies `FixtureRng`, a deterministic implementation of
`chio_core_types::rng::Rng` for fixture generators and tests. Each fixture
gets its own ChaCha20 keystream, so regenerating a fixture reproduces the same
receipt identifiers, nonces and salts.

## Usage

Add the crate as a development dependency, or as an optional dependency of a
generator binary, and build one stream per fixture:

```rust
use chio_core_types::rng::{Rng, RngError};
use chio_fixture_rng::FixtureRng;

fn fixture_salt() -> Result<[u8; 32], RngError> {
    let rng = FixtureRng::for_fixture("receipt-salt", "fixture-a")?;
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt)?;
    Ok(salt)
}
```

## Guarantees

- The seed is `SHA-256("chio.fixture-rng.v1\0" || label || 0x00 || fixture_id)`
  and keys a ChaCha20 stream with a zero nonce and counter.
- Successive fills continue one keystream; the same sequence of fill lengths
  from the same `(label, fixture_id)` yields the same bytes.
- A label that contains a NUL byte is refused, so the seed encoding is
  unambiguous.
- A poisoned stream lock returns `RngError`; the crate never panics on a fill.

## Status

This unpublished library holds fixture material only. Release producers draw
from an operating-system or platform CSPRNG, and this crate must not appear in
the normal dependency graph of a release binary. There are no Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Test support](../chio-test-support/README.md)
- [License](../../../LICENSE)
