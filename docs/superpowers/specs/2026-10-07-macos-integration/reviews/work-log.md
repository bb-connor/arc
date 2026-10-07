# Specification production record

Local specification and planning work completed on 2026-10-07. Publication and current-head hosted review are tracked on the live pull request, rather than frozen into this document as a future approval claim.

- Read approved research, applicable repository instructions, memory routing and live source baselines.
- Applied Superpowers brainstorming, worktrees, parallel research, writing-plans, review and verification workflows.
- Preserved unrelated checkout work in an isolated branch.
- Produced 19 subsystem specifications, nine implementation plans, six source/decision research documents, a source registry, machine-readable contracts and a complete requirement-to-acceptance/plan map.
- Validated requirement coverage, contracts, adversarial synthetic fixtures, embedded example syntax and cross-document consistency; see [validation](validation.md).
- Independently reviewed authority/protocol/recovery and Apple platform/execution boundaries. Corrected stop durability, read-only stop recovery, terminal event projection, retry method identity, the external test oracle and explicit guest image/supervisor ownership. Both reviewers reinspected their findings.

The user explicitly authorized specification, planning, commit, push, PR publication and a hosted bot-review repair loop. Product implementation and runtime qualification remain separate work. The loop's completion requires current-head bot approval and closure of every actionable review finding; local review or a successful review check alone is insufficient.

## First hosted review repair

Addressed nine distinct findings reported in ten comments across both hosted bots: stop/review reply binding, exact review-content delivery, retained-action plan coverage, a packed-only Git success control, nonblocking special-file evidence handling, reproducible internal-source locators, consistent virtualenv regeneration, a complete lifecycle matrix and profile-identity uniqueness. The coverage audit closed additional concrete implementation omissions in the owning plans. Each hosted comment receives its own disposition after the repair is pushed; final bot approval remains a live current-head PR fact.
