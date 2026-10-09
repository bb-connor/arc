---
id: "REL-3.4"
title: "Linux restricted launchers for Pi and Hermes"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-3.2"]
paths: ["integrations/linux/launchers/pi/**", "integrations/linux/launchers/hermes/**", "sdks/python/chio-hermes/src/chio_hermes/restricted.py", "tests/integration/linux/test_host_launcher_pi_hermes.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-3, D12 recommendation (Pi and Hermes as additional HOST-M2 harnesses). Hermes is Seatbelt-only today (`sdks/python/chio-hermes/src/chio_hermes/restricted.py`); add a Linux bubblewrap path with the same refusals. Pi already has bubblewrap in its external plugin repo; this item provides the in-repo launcher used by the process host and records KSPEC-07 evidence.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 -m unittest tests/integration/linux/test_host_launcher_pi_hermes.py` passes on Linux; `python3 -m pytest sdks/python/chio-hermes/tests/test_restricted.py` still passes on macOS.

## Log
- 2026-10-09T04:51:58Z connor: created
