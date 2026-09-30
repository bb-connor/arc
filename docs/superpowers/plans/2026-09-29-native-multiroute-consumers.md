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
- [ ] 3. Migrate mini-SWE request preparation, tool callers, retained recovery state and campaign provisioning. Complete required dependency closure and explicit configuration for the remaining packaged consumers.
- [ ] 4. Execute native mini-SWE and packaged-consumer campaigns on the retained OCI worker, repair demonstrated faults, preserve terminal evidence and update CI inputs. Keep native discovery/recovery regressions.

## Review focus

Cross-route authority or receipt substitution; hidden single-route assumptions in restart and offline verification; failures after an effect with no response; changed Docker container/daemon identity; provider credentials escaping into tool input, output or logs; unbounded interpreter closure; incomplete native evidence mislabeled as acceptance.

## Acceptance

Finish each implementation contract and verify its boundary. Archive source/binary identities and terminal results, update both task and roadmap queues, commit locally, report each task's actual state and propose the next remaining roadmap batch. No global roadmap or hosted/release claim follows from these focused checks.

## Execution state

The [execution record](../../reviews/2026-09-29-native-multiroute-consumers-execution.md)
records completed tasks 1 and 2 and partial tasks 3 and 4. Prepared request
custody, mini-SWE callers and the explicit runtime package are implemented.
The native budget recovery campaign passes. Mini-SWE's fifth-call lifecycle
handoff still fails as retained history grows; session/repository, packaged
consumers and complete native CI acceptance remain required.
