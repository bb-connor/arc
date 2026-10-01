# Chio seccompiler length repair

This fork repairs the filter-length conversion in the selected seccompiler
0.5.0 API. The registry package is not certified by this local source
selection.

- Release commit: `c3cf77d65815037931ae5bc2fca010713defdc8c`.
- Registry archive SHA-256:
  `a4ae55de56877481d112a559bbc12667635fdaf5e005712fd4e2b2fa50ffc884`.
- License: Apache-2.0 OR BSD-3-Clause, original license texts retained.

The production change converts the slice length to the kernel ABI's `u16`
field with `try_into()` before changing process state. Values that cannot be
represented return the existing `BackendError::FilterTooLarge` error. The
registry release uses `as u16`; 65,537 instructions therefore become a
one-instruction program and can report successful installation of a different
filter.

Regression coverage exercises both the calling-thread and all-thread APIs,
checks the exact rejected length, and proves the invalid input leaves seccomp
mode unchanged. All upstream tests are retained. The manifest makes the fork
unpublished and independently testable.

One documentation-list indentation is normalized so the retained upstream
documentation passes current strict Clippy. It has no runtime effect.
Whitespace in retained platform and syscall-table generator metadata is also
normalized for the repository whitespace gate; neither file is built.

```sh
cargo test --locked --all-features --manifest-path third_party/seccompiler-chio/Cargo.toml
```
