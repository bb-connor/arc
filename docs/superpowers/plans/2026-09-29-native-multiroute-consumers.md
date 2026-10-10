# Native broker routes and consumer integration

> **For agentic workers:** Use superpowers:executing-plans inline in the existing isolated worktree. The user authorized the complete remaining native-consumer batch. Minimize delegation; use one final independent reviewer.

**Goal:** Complete the native mini-SWE and consumer integration left open by the preceding owner batch.

**Architecture:** A bounded installed route set binds verifier configuration and authenticated registration peers as one authority generation. Each route retains its original server/tool, provider identity, prepared stream and receipt signer. Routing never rewrites a verified context or falls back to a different participant. Privileged Docker and provider effects run in host-owned adapters after original durable capture; caged tools receive only their prepared stream.

**Tech stack:** Rust broker, kernel and process host, Python process/mini-SWE SDK, native OCI qualification.

**Spec:** `docs/reviews/2026-09-29-native-consumers-acp-errors-openapi-execution.md`, `docs/reviews/2026-09-28-remaining-security-work.md`.

**Base:** `95f04d5d74`, `packet/3-retention-accounting`, `/tmp/arc-security-launch`.

## Constraints

- Fail closed; no compatibility aliases, uncaged fallback or blanket syscall/filesystem grants.
- Preserve original signed requests, operation identity, quota ownership and uncertain-effect recovery.
- Keep Docker sockets, provider secrets and ambient network authority outside cages.
- Bound routes to 1..=16, reject duplicate destinations and pin the complete route set into retained authority.
- Use native source and binary identities for qualification. Preserve failed/interrupted outcomes.
- Preserve preexisting `output/`. Batch code before focused tests; avoid broad workspace campaigns.
- Local commits and OCI lifecycle actions are authorized. Do not push, merge or publish.

## Work

- [x] 1. Add bounded broker verifier/participant route owners in `chio-secret-broker/src/kernel_admission/routes.rs`. Update process-host composition, authority RPC endpoints, security profile routing and completion verification. Exercise cross-route substitution, duplicates, reordering and changed peer/configuration.
- [x] 2. Implement host-owned Docker/provider transport adapters with bounded request/response handling, pinned resource identity, no automatic retry and durable original capture. Keep privileged transports out of native target permissions.
- [x] 3. Migrate mini-SWE request preparation, tool callers, retained recovery state and campaign provisioning. Complete required dependency closure and explicit configuration for the remaining packaged consumers.
- [x] 4. Execute native mini-SWE and packaged-consumer campaigns on the retained OCI worker, repair demonstrated faults, preserve terminal evidence and update CI inputs. Keep native discovery/recovery regressions.

## Review focus

Cross-route authority or receipt substitution; hidden single-route assumptions in restart and offline verification; failures after an effect with no response; changed Docker container/daemon identity; provider credentials escaping into tool input, output or logs; unbounded interpreter closure; incomplete native evidence mislabeled as acceptance.

## Acceptance

Finish each implementation contract and verify its boundary. Archive source/binary identities and terminal results, update both task and roadmap queues, commit locally, report each task's actual state and propose the next remaining roadmap batch. No global roadmap or hosted/release claim follows from these focused checks.

## Execution state

The [execution record](../../reviews/2026-09-29-native-multiroute-consumers-execution.md)
records all four tasks complete for their focused implementation and local/native
acceptance boundaries. The September 30 continuation delivers consumer migration,
host-owned repository execution, bounded Python/SQLite resources and native CI
inputs. Baseline, crash/unknown, session, operator, repository scope and packaged
consumer campaigns pass. Comparison passes eight cases across two trials; the
final large-output campaign passes exact ASCII/escaped output, restart replay and
offline patch proof. Source overlays and binary generations are explicitly pinned.
Historical failed operations remain retained without redispatch. Hosted exact-
candidate, M5 and the broader roadmap remain separate open gates.

## Execution review (October 1, 2026)

Reviewed at `a2630c20a1` in the [native consumers review](../../reviews/2026-10-01-execution-review-native-consumers.md), [campaign audit](../../reviews/2026-10-01-execution-review-campaign-audit.md). The cross-cutting verdict is in the [pass 9 execution review](../../reviews/2026-10-01-execution-review.md).

**Verdict:** Tasks 1 to 3 conform; route bounds, duplicate rejection and the pinned route set are verified. Task 4's native campaigns are real, but its claim of updated CI inputs is contradicted: the lane cannot pass.

Open findings against this plan:

- **NC1, Medium.** The native fixture action calls its script with no read grants and uses `rg`, which the runner lacks; the lane is not required and has never run.
- **NC2, Medium.** A provider response with a repeated header such as `Vary` is refused after the provider acted, leaving an unknown outcome and a consumed capability.
- **NC3, Medium.** The MCP read limit rose from 1 to 4 MiB for every native tool, raising the worst-case unread notification queue to about 8 GiB of host memory.
- **NC4, Low.** Docker output over 512 KiB turns a finished command into an unknown outcome.
- **NC5, Low.** The repository adapter's hash pin covers only the pip launcher script.
- **NC8, Low.** Broker capability issuance reads the system clock directly and has no unit tests.
- **CA6, Medium.** This plan's commits added 63 cause-discarding `map_err(|_| ...)` sites to the secret broker, against the dispatch plan's rule.

**Next:** Repair the CI fixture action and run it once on GitHub (NC1); accept repeated list-valued headers (NC2).
