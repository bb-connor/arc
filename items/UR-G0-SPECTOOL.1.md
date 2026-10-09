---
id: "UR-G0-SPECTOOL.1"
title: "Schema manifest regeneration and manifest-only schema roots"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["scripts/check-chio-schema-registry.sh", "scripts/tests/check-chio-schema-registry.test.sh"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 (every contract lands "with schemas and test vectors under `spec/`"). `spec/schemas/MANIFEST.sha256` contains a self-hash line plus `registry.json` and `VERSION` hashes, so any two concurrent schema additions conflict; there is no `--write` mode. Add `--write` for deterministic regeneration including the self-hash; add a `manifest_only_schema_roots` tuple (`spec/schemas/chio-process/`, `spec/schemas/chio-work/`: tracked and hashed but not registry artifacts, because worker frames are not signed artifacts); add `spec/schemas/chio-evidence/` to the registry roots; document that rebase conflicts on the manifest are resolved by regeneration, never by hand. Note: `spec/schemas/VERSION` is 1.0.0 while the roadmap calls contracts 0.x previews; the preview version is carried by the CT-WIRE freeze file, not VERSION.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Both scripts pass; new cases: `--write` is idempotent; a manifest-only file passes without a registry entry; a registry-root file without an entry fails.

## Log
- 2026-10-09T04:51:58Z connor: created
