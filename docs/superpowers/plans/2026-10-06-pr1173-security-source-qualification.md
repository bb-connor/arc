# PR1173 security source qualification implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline. The user explicitly authorizes production-block remediation, plans, implementation, review, commits and the existing PR update, and prohibits subagents.

**Goal:** Bind security execution to the actual approved Git objects and reconcile the complete source prerequisites of the repository-authorized enterprise workflow.

**Architecture:** Keep the existing private source projection, credential-free execution boundary and closed evidence inventory. Integrate the supporting code from repository-authorized source `d0496c14d824a327f00b98576132834306ff6694`, preserving this branch's audited dependencies and image repairs. Reuse the source lane's shard producer, bounded host runner and isolated aggregate validation. The security agent retains ownership of source authorization, the signed Linux package and its policy.

**Tech stack:** Existing Python security execution tooling, Git plumbing, Docker boundary controls and portable unittest/contract fixtures. No Rust API, dependency or durable schema changes.

**Spec:** `2026-10-05-pr1173-review-closure.md`, the closed-source prerequisites and workflow definition `c009aced79d69f01880b5f7c53ed3c1754e3b7da`, and the approved source above.

## Global constraints

- Do not edit authority variables, fabricate signed evidence, downgrade workflow pins, add audit exemptions or suppress a failing producer.
- Git replacement refs cannot change the committed bytes selected by an approved SHA. Preserve the existing filesystem, byte and timeout bounds.
- Candidate code and shard artifacts remain data until the existing isolated execution boundary. Git hooks, filesystem monitor callbacks and content filters must not run during host-side aggregation.
- Partition exactly 35 campaigns and 28 cases into seven fixed shards of five campaigns each; compose exactly 64 derived paths. A partial shard cannot claim complete evidence.
- Preserve canonical inventory, exact paths, source/image/tool identities, patch hashes, regular-file checks and the complete isolated validation before publishing an unsigned aggregate.
- The approved source introduces input binding v7 and excludes the three closed signed Linux output files from candidate execution. Retain all v6 evidence in its historical scope. Never retag its digest or report it as a fresh v7 campaign.
- Keep current Rust 1.95 image inputs and the audited Cargo checksum. Do not overwrite this branch's unrelated source-policy, inventory, Kani or dependency repairs.
- Keep every failed, cancelled, ignored, unavailable and interrupted campaign distinct. No merges, publication, subagents or messages to other operators.
- No em dashes, new dependencies or unnecessary Rust retesting when compiled inputs remain unchanged.

## Review focus

- A replace ref names an approved commit but changes its tree or blob. The copied bytes must remain those of the original object.
- Local Git configuration supplies a filter, include, external attribute file or redirected worktree. Source identity and aggregation must share the same guard. Git object inspection must also disable configured signature-verification programs. Aggregation must refuse executable or redirected configuration before checkout or publication.
- Missing, duplicate, substituted, cross-source or cross-image shards cannot become a full inventory.
- Signed output files, symlinks, executable outputs or an unclosed output directory cannot become source inputs or an authorized evidence descendant.
- A composition or complete validator failure must leave the caller's source unchanged and publish no aggregate.

### Task 1: Close Git source identity substitution

**Files:** Existing `scripts/run-security-execution-container.py`; new `scripts/tests/check-security-git-source-identity.test.py`.

**Interfaces:** Exercise actual `repository_identity`, `parse_tree`, `read_git_blobs` and `materialize_private_copy`. Use the existing controlled Git environment for every subprocess, including batch blob reads.

- [x] Add a real temporary-repository regression with approved and substituted commits, a replace ref and unchanged reported HEAD. Require copied approved bytes and the actual approved tree; retain the current failure. Keep a normal source-copy control.
- [x] Disable replacement-object interpretation in the controlled Git environment and all relevant source readers. Preserve the existing hook/fsmonitor controls and byte limits.
- [x] Require the new regression and controls to pass without running candidate code or Docker. Review every Git invocation in the host source reader for the same environment.

### Task 2: Integrate the coherent approved prerequisite closure

**Files:** New `scripts/aggregate-security-evidence-shards.py` and `scripts/tests/security-evidence-shards.test.py`; existing `scripts/check-security-adversarial-evidence.py`, `scripts/run-security-execution-container.py`, `scripts/security-execution-container-entrypoint.py`, `scripts/check-secret-broker-boundary.sh` and the matching `scripts/check-security-ci-contract.py` contract tests. Reconcile `scripts/check-keyring-transparency.sh` and `scripts/tests/check-security-wire-lane.test.py` with their already implemented source inventories. Bring the matching derived-input, source-path, control-package and refresh-scope tests from the approved source, and reconcile the existing adversarial and execution-container contract tests without removing this branch's assertions.

**Interfaces:** Preserve `refresh_shard(index)`, the closed `OUTPUT_SPECS`, `validate-committed-evidence`, `aggregate(..., authorized_source=...)` and the complete source lane's validation path. Extend the Git regression to the aggregate reader. Preserve the current public command arguments and ownership of all signed outputs.

- [x] Record the current portable failure at PR merge `a4787e835ea9c39a755bfda2689f3376c589bb11` and verify the omitted source prerequisite locally. Record approved-source blob hashes before importing.
- [x] Read and reconcile the complete prerequisite deltas and their transitive helper/test dependencies. Import code and controls together; do not copy only the missing test or replace unrelated fixed files with older snapshots.
- [x] Carry Task 1's source-identity protection through aggregation. Add actual Git callback/filter/configuration refusal tests and enforce the data-only precondition before creating a worktree. Keep operator configuration values out of diagnostics.
- [x] Run the entire shard, source identity, derived-input, normalized-path, control-package, refresh-scope, adversarial and execution-container portable controls. Require omission/substitution, incomplete validation, descendant and source-input refusal controls to pass.
- [x] Keep v7 evidence capture incomplete until the owning lane produces genuine source-bound Linux outcomes and a signed package. Do not rewrite any old campaign record or acceptance flag.

### Task 3: Review and qualify the changed boundaries

**Files:** The imported and repaired scripts/tests, this plan and the existing production review plan.

- [x] Execute every command in the current definition's portable producer inventory with retained identities, logs and terminal status. Reverify changed boundaries after repairs. Preserve the initial failing sequences and classify native/authority/package prerequisites separately.
- [x] Review Git configuration, object identity, input closure, shard partition, output import and aggregate publication inline. Run applicable script syntax, hygiene, formal coverage, formatting and diff checks without repeating unchanged Rust suites.
- [x] Freeze source and commit the verified checkpoint. Preserve all preceding qualification, failed CI and diagnostic evidence; no claim of independent approval.

### Task 4: Renew reproducibility and final acceptance

**Files:** Existing source-bound native21, receipt verifier, derived research/paper evidence and PR description.

- [ ] Renew the source-bound native21 inventory and verifier without editing primary inputs during the campaign. Preserve all preceding 870 raw records and append only terminal evidence. Rebuild the PDF twice and retain the publication gates.
- [ ] Commit derived outputs, push normally, preserve the automated PR summary and refresh CI/review on the final head. Use the completed preceding x86/proof/advisory results only in their original scope.
- [ ] Require actual unignored final-head native broker lifetime acceptance, all mandatory CI and no unresolved P0/P1/P2. Authenticate intentional event-conditioned skips from their current workflows.
- [ ] Retain the security agent's coherent authorized source/definition, genuine v7 campaign, signed Linux package and policy handoff as mandatory. Production acceptance remains incomplete until that handoff and all required final-head checks succeed.

Ruling: the user's existing direction explicitly authorizes writing and executing remediation plans inline, so this bounded integration and reproduced source-identity repair proceed without another approval loop. The prior instruction to wait for the source lane is preserved for signed package production and authority updates. Approved supporting source is now available and its candidate integration is independently reviewable.

Execution evidence: retained actual failing commit/tree/blob replacement, source clean-filter, aggregate smudge-filter and signature-program regressions. The final portable controls campaign passes all nine commands, including eight actual Git regressions, 14 shard controls, derived-input controls and the exact adversarial fixture heredoc. The full adversarial producer remains failed because committed native outcomes have the preceding source binding; its failure is retained and no outcome digest is retagged. The source lane must renew genuine v7 outcomes and the signed package.

CI reconciliation preserves this branch's actual Rust1.95 image, APK and Cargo pins, mandatory branch coverage and publisher failure propagation. The imported supporting source introduces attached execution diagnostics and closed helper targets; only those corresponding CI assertions, reviewed source commitments and aggregate fixture are evolved here. No workflow authority or policy is changed.

Portable producer evidence: the first 11 contract gates pass in `security-prerequisites-portable-v1`, then that campaign fails at the stale CI contract. The repaired complete CI contract suite passes in `security-prerequisites-ci-contract-green-v2.log`. The final nine-command controls campaign requalifies the changed shard/source boundaries. All eight remaining portable producer commands pass in `security-prerequisites-portable-tail-v4` under the isolated Python3.12 environment with jsonschema4.26.0 and PyYAML6.0.2. Wire and keyring stale inventory failures and the initial missing-validator environment failure remain separately retained. There is no single all-green record for the original failed sequences.

Final source verification: all six formal-mirror, coverage refresh/check, Rust hygiene, formatting and diff commands pass in `security-prerequisites-finish-final`. The new modules parse, shell scripts parse and all touched text is em-dash-free. No Rust source changes are present. Source checkpoint and derived-evidence renewal preserve the strict native/package gates.
