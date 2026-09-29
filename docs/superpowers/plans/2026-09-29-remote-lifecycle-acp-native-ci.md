# Remote lifecycle, ACP boundaries and native CI implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline in the existing isolated worktree. The user approved these four tasks. Use one final reviewer.

**Goal:** Close remote MCP clock custody, ACP invocation and input boundaries, and enforced native consumer CI wiring.

**Architecture:** Share a fenced fallible clock across remote runtime owners and kernel admission. Remove ACP direct invocation rather than preserve compatibility. Decode bounded original bytes before projection, preserve typed local causes, and make native qualification an explicit enforcing-host job.

**Tech Stack:** Rust, Tokio, Axum, shared security clock/input types, Python fixtures, GitHub Actions.

**Spec:** `docs/reviews/2026-09-28-remaining-security-work.md` (approved next batch), `docs/superpowers/plans/2026-09-26-security-engineering-excellence.md`, `docs/superpowers/plans/2026-09-25-security-assurance-closeout.md`.

**Base:** `723bf9ee97`, `/tmp/arc-security-launch`, `packet/3-retention-accounting`.

## Global constraints

Fail closed; canonical signed JSON; no compatibility surface, cap increases or em dashes. Preserve existing `output/`. Use `CARGO_INCREMENTAL=0`, focused verification and honest local versus native-host qualification evidence.

## Review focus

- Faulting or regressing clocks must retain grants, sessions and replay custody (task 1).
- Exact expiry and counter overflow must not mint authority or extend lifetimes (task 1).
- ACP notifications and asynchronous tasks must traverse kernel admission (task 2).
- Duplicate JSON keys, oversized frames and malformed projections must preserve typed causes and never reinterpret a rejected frame tail (task 3).
- Native recovery evidence must require a qualified host and independent anchor/read grants, while ordinary worker tests remain runnable (task 4).

## Tasks

- [x] 1. Add a remote clock owner module and inject it through `RemoteServeHttpConfig`, factory, OAuth, stores, sessions and rate limiter. Replace five ambient production reads, use checked lifecycle/counter operations and preserve custody on failure. Add focused rollback, expiry, restart and concurrency regressions; run the remote owning suite and affected consumer checks.
- [x] 2. Remove ACP edge `compatibility-surface`, wrapper and direct server invocation. Migrate behavioral scenarios to kernel execution or explicit mocks. Keep notification/task lifecycle coverage and update the no-bypass contracts.
- [x] 3. Add bounded original-byte ingress and typed local error owners to ACP edge/proxy. Bound framed transport, kernel checker and capability projection before allocation/projection. Add malformed/duplicate/oversize caller tests; run owning suites and applicable source gates.
- [x] 4. Provision explicit enforced fixtures for native process-host, SDK/example and conformance jobs, including helper, independent anchor and read grants. Separate ordinary worker coverage; run fixture checks and available native qualification, recording unavailable host evidence honestly.

## Completion

Run one independent final review and repair substantive findings. Record exact focused check results and residual gates, archive task evidence, make local conventional commits, reconcile the remaining-work queue and propose the next batch. Do not claim hosted, release or M5 completion.

## Acceptance boundary

Implementation and available local checks are recorded in
`docs/reviews/2026-09-29-remote-lifecycle-acp-native-ci-execution.md`.
The task-4 checkbox covers fixture wiring and portable validation. Native
Linux x86_64 execution, Docker/provider campaign qualification and hosted CI
remain open. This host is aarch64 with uid 1000; no native qualification is
claimed. Remaining mini-SWE dependencies require broker integration, not
broader filesystem or network authority.
