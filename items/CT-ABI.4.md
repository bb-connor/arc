---
id: "CT-ABI.4"
title: "Process ABI vectors and conformance across Rust, spec validator and Python SDK"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-ABI.3"]
paths: ["tests/bindings/vectors/process/v1.json", "crates/kernel/chio-process/tests/worker_protocol_vectors.rs", "crates/tooling/chio-spec-validate/tests/process_v1.rs", "sdks/python/chio-process/tests/test_protocol_vectors.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 (contracts merged with schemas and vectors). Freeze positive and negative vectors for every worker frame and digest domain; update `tests/bindings/vectors/MANIFEST.sha256` with `cargo xtask freeze-vectors` (no self-hash, so additions in different directories merge cleanly).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-process --features worker-server --test worker_protocol_vectors`; `cargo test -p chio-spec-validate --test process_v1`; `cargo xtask freeze-vectors --check`; `python3 -m pytest sdks/python/chio-process/tests/test_protocol_vectors.py` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
