# PR1173 A2A approval continuation implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline. The user prohibits subagents and authorizes repair, verification, commits and the existing PR update.

**Goal:** Complete an approval-blocked A2A v1 task through an explicit owner-authorized continuation while preserving observational polling.

**Architecture:** Extend the existing v1 SendMessage projection with optional message.taskId and contextId. Reuse its bounded retained task, original kernel request identity, existing orchestration and signed approval validation. Only approval artifacts may differ from the frozen request; the original invocation and output mode remain fixed. GetTask remains read-only and no background executor is introduced.

**Tech stack:** Existing Rust A2A edge, cross-protocol request projection, kernel, SQLite consumer fixture and signed threshold approvals. No new dependencies or durable schema.

**Spec:** Existing `2026-10-05-pr1173-review-closure.md` A2A execution contract and [A2A task identifier semantics](https://a2a-protocol.org/latest/specification/#342-task-identifier-semantics). Review thread `PRRT_kwDOR0fQBc6pkBjE` at candidate15d5b373a8 identifies liveness loss, but its proposed polling execution contradicts the reviewed observational profile.

## Global constraints

- GetTask must not invoke tools, mint receipts or attach fresh approvals. Existing legacy slash-form behavior remains unchanged.
- Preserve both retained agent label and capability subject. An absent, legacy-only or inaccessible continuation task returns the same standard TaskNotFoundError.
- Continuation preserves the original messageId, tool target, arguments, capability, governed intent, nonce, proof, supplemental authority and model metadata. Compare the canonical complete kernel request after clearing only the three approval fields; compare bridge and source-envelope bindings separately. This uses the shared request projection instead of inventing an authority hash.
- A supplied contextId must match the generated context of its task. New client-created contexts remain unsupported. Reject malformed identifiers before any task mutation.
- Reuse the existing task deadline, quota and output mode. A continuation must not allocate another task, extend the deadline, reset cancellation or replace frozen authority.
- Reuse complete_task with a temporary approved request. Restore the preceding request and response on protocol/execution/projection errors while retaining the original deadline. An authoritative terminal kernel denial remains terminal. Successful terminal SendMessage results retain the existing direct-delivery retirement behavior.
- Pending approval projects to TASK_STATE_INPUT_REQUIRED, reflecting that the client must submit the signed approval continuation.
- Fail closed. No new audit exemptions, authority-variable edits or qualification bypasses. Keep every old source, failure and unavailable case scoped honestly.
- No em dashes. No unwrap/expect in production. No subagents, merges or publication.

## Review focus

- Another subject using the same agent label cannot resume or observe the task.
- Argument, capability, intent, output-mode, context or message-ID substitution cannot change the retained invocation.
- Expired, cancelled, legacy-only and missing tasks cannot begin new work.
- Polling with a fresh approved context still cannot dispatch or mint new receipts.
- Failed continuation validation or transport execution preserves the original task and a later valid continuation; successful replay produces one durable invocation and capture.

### Task 1: Reproduce approval continuation loss

**Files:** Existing `crates/tooling/chio-conformance/tests/consumer_boundary/a2a_v1.rs`, `support.rs` and `consumer_boundary.rs`.

**Interfaces:** Reuse Fixture::approval_request, signed ThresholdApprovalProposal and the existing two-approver token construction. Extract that test-only construction into Fixture::approved_request without changing existing threshold assertions.

- [x] Add actual SQLite-backed v1 SendMessage approval continuation. First require pending custody and signed proposal, then poll with signed approvals and require unchanged response/receipt count and zero effects. Submit the original message with taskId and approvals; require the same task/context, signed Allow, one invocation/capture and original request-bound receipt. The current source must reject the new taskId field and fail the completion assertion.
- [x] Add independently derived refusals for owner/subject substitution, changed arguments/capability/intent/messageId/context/output mode, expired or cancelled tasks and legacy-only tasks. Require no new receipt/effect, and a subsequent valid continuation where applicable.
- [x] Preserve existing observational tests and update only the pending-state wire expectation to the correct interrupted state after the implementation is changed.
- [x] Run focused actual red campaigns and retain source/log hashes, terminal Cargo status and exact selected test identities.

### Task 2: Implement the retained continuation

**Files:** Existing `crates/protocol/chio-a2a-edge/src/v1.rs`, private `src/v1/continuation.rs`, edge unit tests in `src/tests/v1.rs`, crate README, consumer producer and its self-test.

**Interfaces:** Parse optional taskId/contextId into the private v1 request. Use existing build_execution_request and chio_cross_protocol::execution::kernel_tool_call_request for complete canonical comparison, with only approval_token, approval_tokens and threshold_approval_proposal removed. Complete the owned retained task using its original IDs and restore the original request if continuation fails.

- [x] Preserve the new-task path; validate owned v1 continuation before changing its request or task slot.
- [x] Bind the original output mode and context. Distinguish continuation cleanup from initial task cleanup so an error cannot discard earlier pending custody.
- [x] Require red regressions to pass; run complete A2A edge/adapter and consumer-boundary suites, strict all-target edge/adapter Clippy and the consumer test target Clippy, formatting, diff and the actual14-case consumer inventory. Locally execute the consumer producer prefix; its remaining native MCP fixtures require physical Linux x86 and remain mandatory in final-head hosted CI. Preserve any failure separately.
- [x] Review the complete repair inline against the five focus conditions, then freeze all source/plan edits and commit the tested source checkpoint.

### Task 3: Repair newly published dependency advisories

**Files:** Existing root and TypeScript SDK `package.json` overrides, generated `bun.lock` and SDK `package-lock.json`; a focused dependency regression fixture if the upstream proof of concept requires it.

**Trigger:** Candidate15d5 hosted Cargo audit passed, but authenticated filtered and unfiltered OSV artifacts fail on sharp0.35.4 (GHSA-wq5f-xc86-pv6w, fixed0.35.5) and shell-quote1.9.0 (GHSA-pqg4-j6r4-53mv, fixed1.11.0), newly indexed October6. Preserve the original artifact ZIP digest and actual findings.

- [x] Verify maintainer advisories and registry metadata; update the existing overrides to fixed upstream packages without adding accepted-risk entries.
- [x] Regenerate both lockfiles using their package managers. Inspect the complete dependency delta and authenticate new registry integrity values.
- [x] Run current fork-authentication/regression checks, the upstream shell-quote regression and sharp runtime/decode checks, plus both complete filtered and unfiltered OSV producer commands. Require zero findings, no scan-error acceptance and no unrelated dependency drift.
- [x] Include the dependency source changes and exact failures/qualification in the frozen checkpoint and final hosted acceptance.

### Task 4: Renew artifacts and exact-head acceptance

**Files:** Existing derived research qualification and paper evidence package; source is frozen before renewal.

- [ ] Renew the source-bound native21 inventory and fresh verifier. Preserve the completed d187/15d5 source and artifact evidence rather than relabeling it.
- [ ] Append the actual continuation red/green and preceding hosted/review records without changing any of the existing697 raw records. Rebuild the PDF twice and require byte equality; publication remains gated by the existing four independent research requirements.
- [ ] Commit only derived outputs, push normally and update the existing PR body. Resolve the continuation thread only after the pushed, verified repair. The actual native lifetime thread still requires unignored final-head x86 acceptance.
- [ ] Read all final-head CI and automatic-review results. Keep the security-owned source/definition/signed-Linux-package/policy handoff explicit. Do not claim production acceptance while required checks or that handoff remain incomplete.
