---
id: "UR-1177-FOLLOWUP"
title: "Native host docs follow-up: 9 review-bot P2 findings deferred from PR #1177 (mostly checker edge cases)"
severity: "P2"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["scripts/check-native-host-docs.py", "scripts/tests/check-native-host-docs.test.sh", ".github/workflows/native-host-docs.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Deferred under decision docs-pr-p2-followup-rule (2026-10-09): review-bot P2 findings on PR #1177 heads 8b22f175 and 01666b33, on lines the final push did not change. Most are edge cases in `scripts/check-native-host-docs.py`. Verify each on main, fix it with a regression case in the checker's test script, or answer with the reason.

- https://github.com/bb-connor/arc/pull/1177#discussion_r4229269411 (scripts/check-native-host-docs.py:304 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Preserve text continuity across SVG elements)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229269422 (scripts/check-native-host-docs.py:351 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Check case references in research and review d)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229269431 (scripts/check-native-host-docs.py:318 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Scope retired-phrase exemptions to known quota)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229269439 (scripts/check-native-host-docs.py:278 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Exclude footnote definitions from link targets)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229269447 (scripts/check-native-host-docs.py:309 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Decode entities before retired-phrase matching)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229395957 (.github/workflows/native-host-docs.yml:34 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Watch external targets of program links)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229395968 (scripts/check-native-host-docs.py:278 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Preserve the first reference definition)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229395977 (scripts/check-native-host-docs.py:55 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Do not treat top-level indented code as a fenc)
- https://github.com/bb-connor/arc/pull/1177#discussion_r4229395987 (scripts/check-native-host-docs.py:343 ![P2 Badge](https://img.shields.io/badge/P2-yellow?style=flat)  Ignore fenced examples when collecting case de)

## Acceptance

- Each finding is fixed with a regression case (a test that fails before the fix) or answered with a concrete reason on its thread.
- `bash scripts/tests/check-native-host-docs.test.sh` and `python3 scripts/check-native-host-docs.py --scope program` pass.

## Log
- 2026-10-09T15:39:36Z connor: created
