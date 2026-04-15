# Summary 284-01

Phase `284-01` converted the concrete hosted GitHub Actions failures from
`CI` run `24311566689` and `Release Qualification` run `24311566699` into
small repo-side fixes:

- [scripts/check-workspace-layering.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/check-workspace-layering.sh) no longer hard-requires `rg`; it now falls back to portable `grep -nE`, so the workspace layering gate survives plain hosted runners
- [crates/arc-core/tests/monetary_types.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core/tests/monetary_types.rs) no longer carries the unused `make_grant_no_monetary` helper that became a hard MSRV failure under `RUSTFLAGS="-D warnings"`
- [.github/workflows/release-qualification.yml](/Users/connor/Medica/backbay/standalone/arc/.github/workflows/release-qualification.yml) no longer asks `actions/setup-node@v4` for `pnpm` caching before `pnpm` exists on `PATH`
- [scripts/ci-workspace.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/ci-workspace.sh) now keeps the clippy gate on shipping targets (`--lib --bins --examples`), and the resulting warning-clean pass required repo-owned clippy hygiene across the ARC surfaces exercised by that lane

Verification:

- `env PATH="/usr/bin:/bin" ./scripts/check-workspace-layering.sh`
- `cargo +1.93.0 test -p arc-core --test monetary_types -- --nocapture`
- `cargo clippy --workspace --lib --bins --examples -- -D warnings`
- `./scripts/ci-workspace.sh`
- `cargo fmt --all -- --check`

Remaining gap:

- The repo-side breakpoints are fixed locally, but CI-01 and CI-02 still need a published commit and fresh hosted GitHub Actions rerun before they can be marked complete.
