# Codebase Concerns

**Analysis Date:** 2026-03-19

## Tech Debt

**Split policy surface:**
- Issue: The operator-facing YAML path still exposes fewer guards than the richer HushSpec/compiler path
- Why: Runtime/compiler evolution outpaced the older CLI policy loader
- Impact: Operators and adopters do not have one obvious supported policy story
- Fix approach: Phase 5 should freeze one canonical authoring path and expose all shipped guards through it

**Hosted runtime ownership shape:**
- Issue: Remote hosted ownership still leans heavily on one subprocess per session
- Why: It was sufficient to prove the remote/runtime edge and conformance story
- Impact: Scalability and lifecycle semantics remain weaker than a production hosted runtime should allow
- Fix approach: Phase 3 should formalize broader hosted ownership and reconnect-safe lifecycle rules

**Closing-cycle planning lived only in `docs/` before this scaffold:**
- Issue: The repo had rich epic docs but no `.planning` execution memory for GSD
- Why: Planning evolved organically before being routed into the GSD workflow
- Impact: Autonomous execution would have had to rediscover scope and milestone order
- Fix approach: Keep `.planning` in sync with the post-review epic sequence

## Known Bugs

**Trust-cluster leader-side budget visibility flake:**
- Symptoms: `cargo test --workspace` is not reliably green; a clustered trust-control test can time out on budget visibility
- Trigger: Full-suite load exercising leader/follower replication and failover timing
- Workaround: Targeted reruns may pass, but that is not an acceptable release gate
- Root cause: Likely timing-sensitive visibility, replication ordering, or failover semantics in clustered trust-control behavior
- Blocked by: Phase 1

## Security Considerations

**Roots still metadata-only:**
- Risk: Filesystem-shaped tools or resources may not be constrained by negotiated roots in the way operators expect
- Current mitigation: Roots are tracked in session state, but enforcement is incomplete
- Recommendations: Phase 2 should normalize roots, enforce them fail-closed, and include deny-receipt evidence

**Transport and lifecycle semantics are still maturing:**
- Risk: Remote reconnect, late events, or cancellation races could produce semantic surprises or ambiguous ownership
- Current mitigation: Stronger session/task support already exists, but gaps remain
- Recommendations: Complete Phase 3 and Phase 4 before claiming deployment-hard remote behavior

## Performance Bottlenecks

**Trust-control and hosted-runtime limits are not yet baselined:**
- Problem: The repo lacks a final supported limits/performance story
- Measurement: No release-quality baseline captured yet
- Cause: Correctness, security, and operability have taken priority over benchmarking
- Improvement path: Phase 6 should define supported limits after the semantic work is stable

## Fragile Areas

**`crates/arc-cli/src/trust_control.rs`:**
- Why fragile: Leader forwarding, replication, repair sync, and failover behavior interact with persistent state and timing
- Common failures: Flaky visibility, convergence ambiguity, hard-to-localize cluster issues
- Safe modification: Freeze the external write/visibility contract first, then adjust internals with targeted stress coverage
- Test coverage: Good integration coverage exists, but repeat-run and stress confidence are still insufficient

**Cross-transport task/session ownership:**
- Why fragile: Direct, wrapped, and remote paths each accumulated pieces of task/late-event behavior over time
- Common failures: Cancellation races, late-event delivery surprises, transport-specific semantic drift
- Safe modification: Establish the ownership state machine before rewriting transport code
- Test coverage: Conformance is meaningful, but remote `tasks-cancel` and some late-event behavior remain gaps

## Scaling Limits

**Hosted runtime process model:**
- Current capacity: Works for demos, harnesses, and controlled deployments
- Limit: One subprocess per session is not the intended long-term default for serious hosted use
- Symptoms at limit: Operational complexity, weaker lifecycle ownership, poor scaling shape
- Scaling path: Broader worker/provider ownership model in Phase 3

**SQLite-backed trust state:**
- Current capacity: Adequate for the current milestone and local/hosted trust-control behavior
- Limit: Not designed as the end-state distributed-control architecture
- Symptoms at limit: Write/replication contention and future distribution constraints
- Scaling path: First stabilize HA semantics; consider stronger distributed designs in a later milestone

## Missing Critical Features

**Remote resumability and GET/SSE support:**
- Problem: Remote HTTP hosting is credible but not yet deployment-hard
- Current workaround: Use the current Streamable HTTP path in controlled environments
- Blocks: Stronger hosted-runtime and reconnect claims
- Implementation complexity: Medium to high; depends on lifecycle and ownership clarity

**Root enforcement:**
- Problem: Negotiated roots do not yet act as a true security boundary
- Current workaround: Treat roots as informative session context rather than hard enforcement
- Blocks: Strong security claims around filesystem-shaped access
- Implementation complexity: Medium; depends on normalization, classification, and receipt evidence

## Test Coverage Gaps

**Repeated-run HA qualification:**
- What's not tested: A reliable repeated-run proof that trust-control remains stable under workspace load
- Risk: CI and local qualification remain flaky even when point fixes seem green
- Priority: High
- Difficulty to test: Medium; requires repeatability harnesses and better observability

**Cross-transport root enforcement and `tasks-cancel`:**
- What's not tested: Final transport matrix for enforced roots and remote cancellation semantics
- Risk: Closing-cycle claims diverge from actual behavior
- Priority: High
- Difficulty to test: Medium to high; spans direct, wrapped, and remote paths

---
*Concerns audit: 2026-03-19*
*Update as issues are fixed or new ones discovered*
