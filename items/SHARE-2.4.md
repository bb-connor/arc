---
id: "SHARE-2.4"
title: "Replace the Hermes SDK model-relay request counter with kernel-held spend"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-2.1"]
paths: ["sdks/python/chio-hermes/src/chio_hermes/model_relay.py", "sdks/python/chio-hermes/tests/test_model_relay.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-2 ("today's model relay is a Python request counter inside the Hermes SDK"). `sdks/python/chio-hermes/src/chio_hermes/model_relay.py` counts requests locally. Route each relayed model call through the broker's kernel-held spend path (SHARE-2.1) and keep the local count only as a display. Fail closed when the broker is unreachable.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `sdks/python/chio-hermes/tests/test_model_relay.py` covers: spend held in the kernel, broker unavailable refuses, display count matches kernel count.
- `python3 -m pytest sdks/python/chio-hermes/tests/test_model_relay.py` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
