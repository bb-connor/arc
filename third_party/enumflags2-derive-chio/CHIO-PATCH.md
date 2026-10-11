# Chio enumflags derive repair

This is a Chio-maintained fork of the published `enumflags2_derive` 0.7.12
package. The root workspace selects it with `[patch.crates-io]`; it is not a
certification of the unmodified registry package.

- Upstream: <https://github.com/meithecatte/enumflags2>
- Release commit: `332c37f47577e5f6b7104419da7e761963032086`
- Registry archive SHA-256: `67c78a4d8fdf9953a5c9d458f9efe940fd97a0cab0941c075a813ac594733827`
- Selected `src/lib.rs` SHA-256: `c3e29ff53abcc1efd70fda2ad67769b3455cadb5b7437cf26b29edad07ba41cd`
- License: MIT OR Apache-2.0 (both license texts retained; one upstream trailing space removed).

The generated `RawBitFlags::DEFAULT` now assigns each selected constant to a
local of type `Self` before casting to the unsigned representation. This
rejects numeric and foreign-enum constants that could previously manufacture
invalid bits in safe code. Valid variants and associated aliases retain their
behavior. The enumflags library's exact-version requirement remains satisfied.

The production source differs from the published package by that expression
and a documentation include carrying three compile-fail regressions. The
standalone manifest adds `publish = false`, a self-patch, and the pinned
enumflags library as a development dependency for five positive width tests.
`Cargo.toml.orig` retains the original upstream manifest. No build script,
network access, process invocation or runtime implementation is added.

Run the fork's owned regressions with the repository toolchain:

```sh
cargo test --locked --manifest-path third_party/enumflags2-derive-chio/Cargo.toml
```

The source-review record and upstream inventory results are maintained in
`supply-chain/reviews/enumflags2-0.7.12.md`. Changed native binaries require fresh
downstream cage qualification before acceptance.
