---
id: "SHARE-4.3"
title: "Make web3 and finding-market off by default for kernel, core, control plane and CLI"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-4.2"]
paths: ["crates/core/chio-core/Cargo.toml", "crates/core/chio-core/src/lib.rs", "crates/platform/chio-control-plane/Cargo.toml", "crates/platform/chio-store-sqlite/Cargo.toml", "crates/products/chio-cli/Cargo.toml", "crates/economy/chio-anchor/Cargo.toml", "crates/economy/chio-link/Cargo.toml", "crates/economy/chio-settle/Cargo.toml", "crates/economy/chio-web3-bindings/Cargo.toml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-4 ("make finding-market and web3 off by default"), ADR-0035. On #1160 head: `chio-kernel`'s `finding-market` feature is already default-off, but `chio-control-plane` and `chio-store-sqlite` enable it unconditionally; `web3` is a default feature in `chio-anchor`, `chio-link`, `chio-settle` and `chio-web3-bindings`; `chio-core` depends on `chio-web3`; `chio-cli` depends on `chio-web3` and `chio-settle`. Introduce opt-in features in the four distribution crates, cfg-gate the code paths (CLI subcommands, control-plane routes), and make `cargo build -p chio-cli --no-default-features` and the default build free of web3 crates. Keep `cargo test --workspace` building everything via a CI feature matrix.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo tree -p chio-cli -e normal | grep -E "chio-web3|alloy"` is empty for the default build; same for `chio-control-plane` and `chio-core`.
- `cargo build --workspace --all-features` and `cargo test --workspace` still pass.
- Commands and routes behind the features return a clear "feature not compiled" error (fail closed), covered by one test each.

## Log
- 2026-10-09T04:51:58Z connor: created
