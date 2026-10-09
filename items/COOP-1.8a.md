---
id: "COOP-1.8a"
title: "OS key custody in signing_custody on Linux (credential:, systemd-creds, Secret Service)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["COOP-1.0"]
paths: ["crates/platform/chio-control-plane/src/signing_custody.rs", "crates/platform/chio-control-plane/src/signing_custody/**", "crates/platform/chio-control-plane/src/lib.rs", "crates/platform/chio-control-plane/Cargo.toml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Roadmap COOP-1 ("OS key custody built on #1160's `signing_custody`: `credential:` or systemd-creds on headless hosts, Keychain or Secret Service on desktops. Plaintext seed files are labelled development-only"). `signing_custody.rs` enforces regular file, nlink 1, mode 0600, owner euid, `O_NOFOLLOW` (27 + 11 call sites), but `load_or_create_authority_keypair` (`lib.rs:477`, 22 call sites) and `authority_public_key_from_seed_file` (`lib.rs:461`) still use plain `fs::read`. Add key refs `credential:` (use `chio_secure_ipc::credentials::{is_systemd_credential, is_sealed_credential}`) and `secret-service:` (via `secret-tool`, seed on stdin). File paths keep every check and are labelled "plaintext file (development only)"; `CHIO_KEY_CUSTODY=required` refuses files. Route both plain loaders through `signing_custody`; OS refs are never auto-created; refuse key refs while the keyring profile owns the seed. Only `lib.rs` lines 461-517 change.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-control-plane signing_custody` passes including `missing_os_reference_never_creates_a_key`, `credential_requires_systemd_custody`, `required_policy_refuses_plain_files`.

## Log
- 2026-10-09T04:51:58Z connor: created
