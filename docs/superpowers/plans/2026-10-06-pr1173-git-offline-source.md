# Offline security source Git implementation plan

> Execute with superpowers:executing-plans inline. The user authorizes production-block remediation and prohibits subagents.

**Goal:** Prevent source inspection, blob projection and evidence aggregation from invoking Git transports or configured host programs before isolation.

**Architecture:** Extend the existing shared `clean_host_env()` with an empty `GIT_ALLOW_PROTOCOL` transport allowlist and `GIT_NO_LAZY_FETCH=1`. The environment already governs normal and batch source readers and aggregate operations. Retain the existing names-only configuration preflight. Keep valid fully materialized repositories, object-identity checks, filters/signature/hook protections, all package pins and signed-output boundaries unchanged. No new helper module or transport fallback.

**Spec:** The existing data-only security source boundary. Actual candidate `15ffb08fe7cf8cd1a25bef7692515839fe3e3d47` accepts an approved commit with a missing blob and a configured promisor remote, then invokes the source's `core.sshCommand` before rejecting the missing object. The real Git2.43 reproduction executes only a private temporary marker callback, without network I/O. A source inspection failure cannot authorize a host callback.

**Constraints:** Preserve all preceding source-specific results and failures. Do not change Rust, runtime authorities, package graphs, authorized source variables, evidence policy, signed campaign bindings or audit exemptions. The security agent owns the genuine v7 Linux package and policy handoff. An empty protocol allowlist must override repository-level protocol permission even on older Git versions that ignore the newer lazy-fetch environment control.

## Review focus

- Real missing-object source projection and aggregate reads must fail without executing the configured transport.
- The batch reader must remain safe if configuration changes after preflight.
- An explicit `protocol.ssh.allow=always` must not override the host's transport boundary.
- Valid local source projection, worktrees, object substitution controls and shard rollback semantics must continue working.

### Task 1: Reproduce and close implicit and explicit transports

**Files:** Existing `scripts/tests/check-security-git-source-identity.test.py`, `scripts/run-security-execution-container.py`, `scripts/check-security-ci-contract.py` and `scripts/tests/run-security-execution-container.test.py`.

- [x] Add real temporary-repository regressions for missing-object projection, batch reads and aggregate reads, and direct transport permission override. Keep Git real and replace only the external SSH program with a private marker callback. Preserve local projection with fully present promisor objects.
- [x] Run the whole existing source-identity suite before implementation and retain the actual callback failures.
- [x] Close transports in the shared controlled environment. Preserve the existing preflight and configuration-value redaction; the environment must also protect readers after configuration changes.
- [x] Run the complete source-identity suite, execution-container and shard controls, actual CI contract and its complete test suite. Review every host Git invocation's environment, syntax and diff.
- [x] Commit the verified source checkpoint without editing primary inputs during renewal.

### Task 2: Renew the derived candidate and accept its actual gates

**Files:** Existing native21, receipt verifier, paper/research artifacts and PR description.

- [ ] Renew source-bound qualification and the verifier; preserve all 1,087 preceding raw records, existing source scopes and failures. Rebuild/freeze the PDF twice and retain all publication requirements.
- [ ] Commit derived outputs, push normally and preserve the automated PR footer. Collect final-head hosted image, supply-chain/advisory, proof, full fuzz, actual PostgreSQL lifetime and all mandatory CI results.
- [ ] Resolve the lifetime review thread only after authenticated final-head native acceptance. Require the security-owned coherent source/definition, genuine v7 campaigns, signed package and policy before production acceptance.

Ruling: the reproduced host-execution flaw is within the user's existing authorization to repair all production blockers. Reuse the shared Git environment rather than adding a new reader or fetching missing source automatically. Transport denial also protects post-preflight configuration changes and preserves fully materialized checkouts that retain promisor metadata, so adding another configuration refusal is unnecessary. No additional approval loop or delegation is introduced.

Reference: [Git transport and lazy-fetch controls](https://git-scm.com/docs/git). The empty transport allowlist is the compatibility boundary; the real regression exercises the installed Git2.43.

Broader verification retained two initial failures. The CI ratchet correctly refuses the changed host runner until its independently reviewed source commitment is updated. The execution-container suite also retains a legacy direct-package Docker assertion from before complete package closure. Its old bash-string assertion is replaced by execution of the real three-case APK instruction suite; all other tooling assertions remain. Native campaign bindings, source authorization and evidence policy remain unchanged.

## Supporting hosted qualification repairs

Fresh candidate CI also exposes two existing inventory mismatches. Include these in Task 1's qualification boundary before source freeze:

- Regenerate Python bindings through the existing datamodel-code-generator0.34 pipeline for the already committed DPoP schema. Preserve all schemas, generator code and dependency pins. Require the initial real generation check to fail, two subsequent byte-stable checks to pass and the full Python SDK suite to pass. Review schema-derived nested syscall argument groups and generated helper-name changes rather than assuming every change is a header.
- Correct the active-defense conformance gate's exact expected name to `partial_rollback::partial_rollback_truth` and recognize module separators. Preserve all ten named cases, unique execution, unknown-case rejection and the exact zero-failure/ignore/filter summary. Keep the existing shell gate and controls; add unscoped/wrong-namespace refusal and repair the ignored-case fixture's out-of-range index so it exercises validator refusal rather than a fake Cargo crash.
- Retain the original portable-generation and active-defense CI failures in their actual candidate scope. Run the combined final source controls and complete CI contract after these repairs. Do not weaken assertions, relabel native evidence or change Rust execution behavior.

Execution evidence: all eight final boundary commands and the complete CI contract suite pass against37,337 unchanged primary inputs. Actual Git regressions RED12/five failures and GREEN13, native conformance RED/GREEN/eight controls and real Cargo10/0ignore/0filter, pinned Python regeneration/two byte-stable checks and SDK216 passes remain source-scoped. Original failures are preserved. The final checklist edit affects only this plan and precedes source freeze. Signed Linux and final-head hosted acceptance remain open.
