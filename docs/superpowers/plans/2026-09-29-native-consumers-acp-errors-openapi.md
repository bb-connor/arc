# Native consumers, ACP errors and OpenAPI input implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline in the existing isolated worktree. The user authorized this four-task continuation. Use one final reviewer.

**Goal:** Complete the next native-consumer, ACP clock/error and OpenAPI ingress boundaries.

**Architecture:** Keep Docker/provider authority outside native cages behind explicit mediated transports. Share an injected fenced clock across ACP audit/signing/certificate owners. Preserve domain errors and native sources locally, exposing registered redacted codes. Parse bounded original OpenAPI bytes before semantic projection.

**Tech Stack:** Rust, shared security clocks and canonical input types, Python process SDK, GitHub Actions.

**Spec:** `docs/reviews/2026-09-28-remaining-security-work.md`, `docs/reviews/2026-09-29-remote-lifecycle-acp-native-ci-execution.md`.

**Base:** `cacaf69fc9`, `packet/3-retention-accounting`, `/tmp/arc-security-launch`.

## Global constraints

Fail closed, no legacy aliases or bypasses, no source-cap increases, no em dashes.
Preserve preexisting `output/`. Batch implementation before focused verification;
use `CARGO_INCREMENTAL=0`. Do not claim native or hosted execution from portable
tests or compilation. Local commits are authorized; preserve the worktree.

## Review focus

- Clock regression or failure must not mint receipts/certificates or consume authorization custody.
- Malformed and future audit timestamps must not be silently repaired or trusted.
- Local errors retain native sources while public errors omit input and filesystem secrets.
- OpenAPI duplicate keys, oversized documents and YAML alias expansion fail before projection.
- Native consumer transport must not expose Docker sockets, provider credentials or arbitrary network authority to caged tools.

## Tasks

- [ ] 1. Complete mini-SWE native dependencies and mediated Docker/provider transport inputs. Update portable integration tests and CI campaign inputs. Execute available qualification and record unsupported-host gates.
- [x] 2. Add an ACP clock owner and migrate audit logging, kernel receipt signing and compliance generation. Remove timestamp fallback; use checked sequence/time arithmetic and preserved sources. Test faults, regression, restart and custody.
- [x] 3. Introduce domain errors for remote MCP/ACP semantic rejection paths and receipt completion, retaining source chains and registered redacted codes. Migrate callers and focused assertions.
- [x] 4. Bound original OpenAPI bytes and preserve decoder errors through the bridge and actual conformance/fuzz callers. Add duplicate, oversize, malformed and YAML regressions; update reviewed-owner inventories.

## Execution and acceptance

Implement tasks 2-4 together first because clock/error APIs share ACP callers;
then complete task 1 while Rust checks compile. Run owning suites and relevant
source gates once implementation is ready, repairing actual failures. Perform
one independent final review and verify substantive repairs. Archive terminal
results and superseded failures, update the remaining-work queue, commit locally,
confirm each task's actual state and propose the next batch.

## Recorded continuation

Tasks 2-4 are implemented and locally verified. Task 1 remains open at the full
mini-SWE integration boundary. The authorized OCI restore made native testing
possible. Real discovery and process recovery exposed and repaired static-helper
packaging, discovery authority exclusions, exact-file fixture grants, fsync and
fcntl restrictions. The native discovery and two recovery campaigns pass.

The remaining task 1 work requires multi-route broker composition and host-owned
Docker/provider adapters; Python tools cannot obtain Docker sockets, provider
credentials or ambient network access inside NativeMinimal cages. Do not mark
that task complete from the static fixture or the broker provisioning API.

See [the execution record](../../reviews/2026-09-29-native-consumers-acp-errors-openapi-execution.md)
for terminal checks, bounded native source identity and the remaining queue.
