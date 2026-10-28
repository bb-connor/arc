# chio-fixture-rng architecture

## Responsibility and boundary

The crate owns one type, `FixtureRng`, which implements the core-types `Rng`
seam with a deterministic stream. Its public surface is `FixtureRng`,
`FixtureRng::for_fixture` and the `FIXTURE_RNG_DOMAIN` seed prefix. It does not
own any production entropy source: hosted producers use `OsEntropyRng` from
`chio-kernel`, and browser and mobile adapters use their platform CSPRNG.
The crate is a development or generator-only dependency and is never linked
into a release build.

## Structure

[src/lib.rs](src/lib.rs) contains the seed derivation, the `Rng` impl and the
inline unit tests. The crate forbids unsafe code and declares no features.

## Data and control flow

`for_fixture` hashes the domain prefix, the label, one zero byte and the
fixture id with SHA-256, and keys a `rand_chacha::ChaCha20Rng` with the digest.
The stream sits behind a mutex so the type is `Send + Sync` and fills through
`&self`, matching the trait. Each `fill_bytes` call continues the keystream.

## Trust and invariants

Fixture output is predictable by design, so it carries no security weight.
The seed encoding is injective because a label containing NUL is refused and
the fixture id is the final component. A poisoned lock is reported as
`RngError` and is never recovered into a silent restart of the stream, which
would repeat earlier bytes. No path zero-fills a buffer on failure.

## Dependencies

`chio-core-types` supplies the `Rng` trait and `RngError`. `rand_chacha`
supplies the ChaCha20 stream and `sha2` the seed digest.

## Verification

Unit tests cover per-fixture determinism, distinct streams for distinct labels
and fixture ids, NUL-label refusal, and a known-answer test that pins the first
80 bytes of one stream against an independent ChaCha20 reference computed from
the same seed. Run `cargo test -p chio-fixture-rng` for this coverage.
