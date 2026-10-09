# Docs PRs: P2 review-bot findings become follow-up items

Decided by Connor on 2026-10-09. For docs-only PRs, once required CI is green and the cross-vendor review has accepted the head: P0 and P1 review-bot findings, and P2 findings on lines the latest push changed, still block the merge. Other P2 findings become tracked swarm items (one follow-up item per PR listing them) and are closed on the PR as won't-fix with that reason. Code PRs, including #1160, keep the strict no-P0-P2 rule.

Why: on spec-heavy docs the review bot raises new P2s on unchanged text every pass (#1196: 6, 1, 6, 1, 13), and each fix restarts multi-hour CI, so the strict rule never converges.
