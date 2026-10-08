# Owned cpp_demangle representation repair

This unpublished path fork preserves cpp_demangle 0.5.1's version, public
API, features and MIT/Apache-2.0 licenses. It backports the upstream
single-field representation fix and adds local layout/borrow tests.

The registry archive at
<https://static.crates.io/crates/cpp_demangle/cpp_demangle-0.5.1.crate>
has SHA-256
`0667304c32ea56cb4cd6d2d7c0cfe9a2f8041229db8c033af7f8d69492429def`.
Its recorded upstream commit is
`6fc3a53ba2ae11bdcf470ed44058a233af517160`. All nine source, build-script
and original-manifest files match that upstream commit.

The production fix is exactly the `repr(transparent)` annotation merged
upstream in commit
<https://github.com/gimli-rs/cpp_demangle/commit/0aabe553c667bf2241d8c65aef5526a8c968398e>.
It supplies the layout guarantee required by three existing immutable
newtype reference casts, including the unsized slice wrapper. The added
safety comment records layout, preserved metadata and inherited lifetime.
No new ownership or mutable alias is created; the returned borrow cannot
outlive its original input. The wrappers remain private and are never
constructed as owned values through this path.

`CHIO-PATCH.patch` records every change from the registry payload:
unpublished manifest metadata, the representation annotation, its safety
comment and two bounded storage/layout tests. The payload hash manifest
covers every original package file. The original registry release receives
no new safe-to-deploy certificate or exemption.

The full upstream test harness was restored separately from the exact
recorded commit because crates.io excludes `tests/` and `in/`. Its restored
source was checked against the archive before modification. The original
suite passes 57 unit, 78 AFL-seed, 163 regression, one large fixture and
175 libiberty compatibility tests. With the owned repair it passes the same
suite plus two new vector/slice layout and borrowed-storage tests (59 unit
tests). Those concrete layout tests are not claimed to fail against the
old pinned compiler; the language representation guarantee supplies the
portable correction.

Raw evidence is retained under
`target/recovery-pr/dependency-security/cpp-demangle-review/` in
`upstream-tests.log` and `patched-tests.log`. Fresh cross-platform execution
is not inferred from these macOS arm64 runs.
