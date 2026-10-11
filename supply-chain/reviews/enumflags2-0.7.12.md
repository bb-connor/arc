# enumflags2 0.7.12 custom-default invariant failure

Recorded September 16, 2026 UTC by the single executing Codex agent. This is a
source review and local reproduction, not an independent human certification.
The original registry derive package remains uncertified. The selected repair
and library-only certification are recorded below.

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

The retained patch uses zero context so blank context markers do not become
trailing whitespace when the patch file is added to a candidate. From the
checksum-verified `enumflags2_derive` source directory, apply it with
`git apply --unidiff-zero --whitespace=error-all /path/to/enumflags2-0.7.12-default-type.patch`.
Its output is byte-identical to the previously reviewed repaired source.

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

The published library source also passes its complete available test inventory
with this patched derive crate: two unit tests and 29 documentation tests, with
two pre-existing ignored documentation examples. This used an isolated copy of
the exact published library, a manifest-only workspace/patch override, and
`cargo +1.94.1 test --locked --offline --all-features`.
`repair-published-tests-retry1.log` and its JSON record retain the result. The
first invocation failed because Cargo does not allow selecting dependency
features from outside its workspace; that command failure is retained separately.
The published archive does not contain the complete upstream repository test
suite, so that result alone does not cover the repository inventory.

### Upstream repository comparison

The exact release commit `332c37f47577e5f6b7104419da7e761963032086` was then
fetched from the declared upstream repository. Every published Rust source file
matches that commit byte-for-byte. The repository suite ran first unchanged,
then with only the reviewed derive repair, using the same generated lockfile
(`ec913e3f7519c2f5b0c6a6295241cf90ceeea0de37789fb018d362a34628a233`).
Both runs used Rust 1.94.1 with `--workspace --all-features --no-fail-fast`.

Both runs pass 89 non-UI tests, retain two existing ignored documentation
examples, and fail the UI target on the same five diagnostic snapshots out of
14 cases. The complete UI diagnostic output is byte-identical between baseline
and repair. The mismatches involve diagnostic spans/help text in
`multiple_bits`, `multiple_bits_deferred`, `shift_out_of_range`,
`zero_disciminant` and `zero_discriminant_deferred`; they are not new acceptance
of invalid flags. The upstream release's CI runs these snapshots on nightly
and skips the UI target on stable/MSRV. This comparison deliberately ran the
whole inventory and did not change snapshots or set `TRYBUILD=overwrite`.
`upstream-baseline.log`, `upstream-patched.log`, `upstream-applied-repair.patch`
and `upstream-repair-comparison.json` retain the commands, changes and results.
Neither overall exit 101 is represented as a passing full suite.

The continued source review covers the library constructors, constant APIs,
operators, serde conversion, fallible conversions, formatting and iteration,
plus the derive generator. `exactly_one` also relies on the same valid-bit
invariant as iteration. Formatting delegates to iteration. Checked numeric and
serde inputs use `from_bits`, which rejects unknown bits; truncating inputs mask
them. These paths do not repair a bad `DEFAULT` generated earlier.

At the original review checkpoint this was a tested proposal outside Chio's
dependency graph. The selected local fork below supersedes that selection
status; affected native qualification remains a separate requirement.

No upstream issue, advisory identifier, fixed release, or external disclosure
is asserted here.

## Selected local repair, September 16 continuation

The main, generated Docker and fuzz workspaces now select
`third_party/enumflags2-derive-chio` through an explicit crates.io patch. Their
lockfile package changes are limited to replacing the registry derive source
with the local fork; the library remains exactly 0.7.12. The fork retains the
original licenses and manifest and documents its complete production delta in
`CHIO-PATCH.md`. Chio owns and reviews the fork as local source, so cargo-vet
does not apply registry certificates to its modified bytes. Its registry
dependencies still require ordinary deployment audits.

The fork adds five positive width tests and three compile-fail cases: the
original invalid numeric default, a numeric constant that happens to name a
valid bit, and a constant of another enum type. All eight pass on Rust 1.94.1.
Reverting only the repaired expression in an isolated copy makes all three
compile-fail cases fail because the invalid declarations compile. The local
source remains repaired; mutation results are retained separately.

The eight regressions also pass with proc-macro2 1.0.106, quote 1.0.45 and syn
2.0.117, matching the application lockfile. Locked metadata confirms selection
of the same local derive source in the main, fuzz and staged Docker workspaces;
the Docker manifest regeneration check passes. Workspace formatting, accumulated
whitespace validation and the confinement provenance check pass. These are
source and dependency checks, not a new native runtime acceptance result.

After the library audit, explicit fork ownership and the separately reviewed
trusted-feed refresh, `cargo vet check --locked --no-minimize-exemptions` reports
22 unvetted dependencies. It still fails; the remaining confinement and other
dependency audits are open.

The full upstream inventory also ran on nightly-2026-04-21 and the release-date
nightly-2025-06-10. Both retain diagnostic snapshot failures. On the April
nightly, eleven of fourteen UI snapshots match; the three mismatches concern
qualified trait names and constant-evaluation diagnostic wording. All fourteen
invalid declarations are rejected, and all 89 non-UI tests pass with the same
two existing documentation ignores. No upstream snapshot was overwritten and
neither overall exit 101 is described as a passing full suite.

### Library source audit

The `enumflags2` 0.7.12 library audit covers all five Rust source files and its
published manifest, using the checksum-verified archive above. It has no build
script, process execution, filesystem/network operations or cryptographic
implementation. Review followed every bitset constructor, conversion, operator,
constant API, iterator, formatting path and optional serde implementation.

- Checked numeric and serde conversion reject unknown bits. Truncating and
  complement operations mask with `ALL_BITS`; union, intersection and xor
  preserve an existing valid-bit set.
- `make_bitflags!` requires each selected item to have the enum type. The
  repaired derive now applies that same condition to custom defaults.
- Iteration and `exactly_one` use `transmute_copy` only on one valid bit. Their
  safety depends on the documented unsafe `RawBitFlags` implementation and
  valid constructors; the default-generation defect was in the derive package.
- Arbitrary unchecked masks and handwritten incorrect `RawBitFlags`
  implementations require unsafe caller code. Public bitset fields are private.
- Constant tokens carry the enum and representation type; checked constant
  construction and complement use their valid mask. Formatting consumes the
  checked iterator; fallible conversion delegates to the checked constructor.

The library-only `safe-to-deploy` record applies with independently admitted
dependencies, including this selected repaired derive. It does not approve the
unmodified derive package, certify the entire confinement chain, or replace
downstream cage qualification on the resulting binary.

Retained continuation evidence lives under
`output/process-security-20260915/selected-enumflags-derive-validation/`,
`confinement-audit-471e91ef0/`, and the two `upstream-*-nightly-repair/`
directories within the original dependency review evidence directory.
