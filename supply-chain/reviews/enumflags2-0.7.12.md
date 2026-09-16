# enumflags2 0.7.12 custom-default invariant failure

Recorded September 16, 2026 UTC by the single executing Codex agent. This is a
source review and local reproduction, not an independent human certification.
No cargo-vet certification was added for either crate.

## Finding

**High confidence:** an entirely safe custom-default declaration can construct
`BitFlags<T>` containing a bit that is not an enum variant. The local reproduction
observes this invalid mask without iterating it or executing an invalid enum
conversion. Source inspection shows that `Iter::next` later uses
`transmute_copy` on each selected bit, relying on the violated invariant.

`enumflags2_derive/src/lib.rs` accepts arbitrary identifiers in `default`. It
generates `RawBitFlags::DEFAULT` using `Self::<identifier> as <repr>` without
requiring the value to have the enum type. A numeric associated constant is
therefore accepted. `enumflags2/src/lib.rs` copies this constant directly into
`BitFlags::default`, without checking it against `ALL_BITS`.

## Exact reviewed inputs

The registry archives were copied from the Linux qualification guest. Their
SHA-256 values match the workspace lockfile, and every regular archive member
was compared byte-for-byte with the extracted review source before reproduction.

| Crate | Version | Registry archive SHA-256 |
| --- | --- | --- |
| enumflags2 | 0.7.12 | `1027f7680c853e056ebcec683615fb6fbbc07dbaa13b4d5d9442b146ded4ecef` |
| enumflags2_derive | 0.7.12 | `67c78a4d8fdf9953a5c9d458f9efe940fd97a0cab0941c075a813ac594733827` |

The reproduction uses Rust 1.94.1 and an isolated workspace with path dependencies
to those exact sources. It does not modify the qualification candidate or its
dependency lockfile.

```rust
use enumflags2::{bitflags, BitFlags};

#[bitflags(default = INVALID_DEFAULT)]
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum Flag {
    A = 1,
}

impl Flag {
    const INVALID_DEFAULT: u8 = 128;
}

fn main() {
    let defaults = BitFlags::<Flag>::default();
    let valid = BitFlags::<Flag>::all().bits();
    println!(
        "default_bits={}, valid_mask={}, invalid_bits={}",
        defaults.bits(), valid, defaults.bits() & !valid
    );
    assert_eq!(defaults.bits() & !valid, 128);
}
```

Observed output, exit zero:

```text
default_bits=128, valid_mask=1, invalid_bits=128
```

Retained evidence under the primary checkout's
`output/process-security-20260915/dependency-audit-enumflags-0.7.12/` includes
the archives, extracted sources, isolated reproduction manifest/lock/source,
`default-invariant-reproduction.log`, and `inverse-tree.txt`.

## Current Chio reachability

The Linux native-target inverse dependency tree at `c11aaf538` reaches
`enumflags2` through `landlock 0.4.4`, then `nono`, `nono-chio`, and `chio-cage`.
Landlock's three declarations (`AccessFs`, `AccessNet`, and `Scope`) use plain
`#[bitflags]` without custom defaults. No direct enumflags2 declaration was found
in the Chio workspace source.

This identifies no runtime-input path to this specific custom-default defect
in the current native dependency closure. It does not establish that the crates
are sound in general, that every cross-target dependency was reviewed, or that
Chio's whole confinement stack is qualified. The all-target inverse-tree attempt
could not run offline because `android_system_properties` was absent; the
native-target tree completed.

## Disposition

### Prepared repair

[The local repair patch](enumflags2-0.7.12-default-type.patch) requires every
custom-default item to type-check as the enum before conversion to its unsigned
representation. This preserves valid enum variants and typed associated aliases,
and rejects numeric associated constants. It follows the type check already
used by the crate's `make_bitflags!` macro.

The patch was applied to a separate copy of the exact reviewed derive source.
With Rust 1.94.1, the original invalid-default example now fails compilation
with `expected Flag, found u8`. A positive executable passes for `u8`, `u16`,
`u32`, `u64` and `u128`, covering combined defaults, typed enum aliases, empty
defaults, iteration, `exactly_one` and checked numeric conversion. The original
unpatched reproduction remains unchanged and retained separately.
`repair-results.json`, `repair-valid-defaults.log` and
`repair-invalid-default.log` in the evidence directory retain the commands and
terminal results. The invalid case is expected to exit 101; no invalid enum
value is evaluated at runtime.

The continued source review covers the library constructors, constant APIs,
operators, serde conversion, fallible conversions, formatting and iteration,
plus the derive generator. `exactly_one` also relies on the same valid-bit
invariant as iteration. Formatting delegates to iteration. Checked numeric and
serde inputs use `from_bits`, which rejects unknown bits; truncating inputs mask
them. These paths do not repair a bad `DEFAULT` generated earlier.

This is a tested repair proposal. It is not installed in Chio's dependency graph
and does not certify either unpatched crate. Dependency ownership, the actual
selected package revision and affected native qualification remain open.

Keep certification pending. The complete upstream regression suite and
downstream native qualification remain required before certifying a selected
patched revision. No upstream issue, advisory identifier, fixed release, or
external disclosure is asserted here.
