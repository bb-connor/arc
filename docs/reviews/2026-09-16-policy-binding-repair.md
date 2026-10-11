# Launch-policy binding repair and qualification

Follow-up to [the progress review](2026-09-16-progress-review.md).
The integration candidate remains a draft. No merge or M5 acceptance is claimed.

## Reproduced defect and repair

The original macOS observer accepted separately signed argv, working-directory
and resource-limit substitutions while the original cage receipt stayed
unchanged. Its target-digest negative control failed as expected.

Production repair: `f3a9a558eab15751c092f73c17e90a3ce93eb179`.

- The authenticated policy loader hashes the exact canonical signed envelope
  after checking its operator signature. This includes every policy field,
  the operator public key and its signature.
- The launcher's receipt-signing context retains that digest through descriptor
  preparation. `admitted_policy_digest` is covered by the receipt content hash
  and signature on enforcement and terminal receipts.
  The existing `policy_hash` still binds the compiled cage profile; the complete
  signed-policy commitment is additional.
- The common verifier requires equality with the submitted signed policy's
  digest. Completed-run, incomplete-observation and standalone launch
  verification all use this check. Terminal evidence must agree with the
  enforcement receipt's policy commitment.
- Generic cage decoding still accepts historical receipts without this field.
  Native policy verification rejects them. No commitment is inferred, added to
  old evidence or retrospectively signed on its behalf.

The same-operator regression retains the original signed receipt and substitutes
argv, cwd, limits, timeout, operator ceilings, receipt-store location and
migration-store location. Additional cases reject a different policy signer,
absent legacy commitments and mismatched terminal commitments. The original
combination remains valid in the synthetic signing fixture. The cage tests
also cover tampering and preservation through descriptor rebinding.

## Completed local checks

Evidence paths below are relative to `output/process-security-20260915/`.

| Check | Result | Evidence |
| --- | --- | --- |
| Original reproduction, retained observer | Baseline and three substitutions pass; target change fails | `progress-review-20260916/native-policy-before-repair.json` |
| Cage receipt tests at repair source | 8 passed, no failures or ignores | `macos-policy-binding-f3a9a558e/cage-evidence.json` |
| CLI policy tests at repair source | 14 passed, no failures or ignores | `macos-policy-binding-f3a9a558e/native-observations.json` |
| CLI build and strict CLI/cage all-target Clippy | Passed | `macos-policy-binding-f3a9a558e/{build,strict-clippy}.json` |
| Workspace format and regenerated proof coverage | Passed; coverage refresh updates the Rust file inventory digest | `macos-policy-binding-f3a9a558e/workspace-fmt.json`, `policy-binding-proof-coverage-f3a9a558e/results.json` |
| Original reproduction, repaired observer | All old-policy/receipt pairs rejected for missing exact policy commitment | `progress-review-20260916/native-policy-after-f3a9a558e.json` |
| Historical real fixture | Complete-policy verification rejects its missing commitment; original signature and fixture retained | `macos-policy-binding-f3a9a558e/legacy-fixture-before-refresh.json` |

The macOS verifier SHA-256 is
`4bd0253dc3655154a4a910faf515538843478dcd36bdbd2430eb68cb2e7e405c`.
Rejecting the old baseline is an intentional compatibility boundary, not the
fresh positive runtime control. The fresh positive runtime control below closes that specific repair check.

The broader macOS CLI sweep reported 621 passes and five failures. One is the
historical native fixture's now-invalid complete-policy claim. The other four
are in unchanged finding-sandbox code. Three pass when `TMPDIR=/private/tmp`
avoids macOS's `/var` and `/tmp` aliases in test fixture expectations. The
remaining `sandbox_mounts_only_explicit_runtime_components` case invokes Linux's
`ldd`, which is absent on macOS. All four passed in the original Linux foundation
run, and their owning finding module has no changes since that source. This is
not a passing complete macOS CLI suite; preserve
`cli-all-before-fixture.log` and `finding-tests-canonical-tmp.log` under the
macOS repair evidence directory.

## Foundation failure reproduction

The original workspace run finished with exactly two failed targets: the
control-plane library (1,132 passes and six failures) and anchored-root tamper
tests (four missing-Bun failures). The control-plane error details include
expired native policy, decision-clock,
trusted-clock and recovery-lease windows. The nested nonce case reported an
authoritative recovery denial. Those original failures remain in the log.

All six named cases subsequently passed individually from the **same original
test executable**, with no source, deadline, assertion or feature changes.
Source: `810664017dffa38235e3914a0a4477c8345cf359`. Executable SHA-256:
`b2ee99851b010dd434101f2cf72cea71b7e5c47252f7a84ed9d56a56100d2db7`.

The rerun held only the Cargo driver, allowed its current test target to finish,
then ran the six exact cases serially before resuming the original workspace
command. No active test clock was paused. Commands, load observations, binary
identity, original deadlines and per-test logs are retained under
`linux-foundation-review-retry-810664017/`. The six cases took 121.98, 105.25,
45.97, 16.76, 2.87 and 9.10 seconds respectively. This establishes successful
unchanged-case reruns; it does not convert the original workspace run into a
pass or prove every original failure had the same cause.
Both original failure-target executables were copied and hash-verified under
`foundation-review-original-binaries-810664017/` before further builds.

Four additional anchored-root differential failures explicitly report missing
Bun. The repository's CI pin is Bun 1.3.3. The Linux/aarch64 release archive was
downloaded and checked against release digest
`41b9f4f25256db897c2c135320e4f96c373e20ae6f06d8015187dac83591efc8`.
After the original workspace owner finished, all four cases passed using the
same anchored-root test executable with that prerequisite on its scoped PATH.
Evidence: `linux-foundation-bun-retry-810664017/result.json`. No test was skipped
to accommodate the missing executable. All ten originally failed cases now
have passing targeted reruns; the original workspace result remains failed.

## Fresh repaired-runtime evidence

All seven scenarios passed with the repaired Linux/x86_64 runtime: reference,
authority, revocation, filesystem, network, host crash and shared budget. The
matrix includes 17 worker outcomes. The separate macOS observer verified the
whole matrix and rejected all 15 existing evidence substitutions.

Against one fresh, unchanged signed enforcement receipt, the original policy
passed and three different policies signed by the same operator failed:
arguments, working directory and resource limits. Both Linux and macOS reject
those substitutions at the complete-policy commitment check. The retained
receipt SHA-256 is
`ac489c3118cd2f637ec7eb0af5592a40eefde0b4daa9371a133c23f26f27f706`.
No private signing material was exported.

| Evidence | Location |
| --- | --- |
| Frozen runtime and static executable build | `cross-x86-policy-binding-f3a9a558e/`, `x86-executables-policy-binding-f3a9a558e/manifest.json` |
| Fresh seven-scenario matrix, operator pins and Linux verification | `linux-x86-policy-binding-matrix-f3a9a558e/` |
| Fresh original and substituted signed policies with unchanged receipt | `fresh-native-policy-fixture-f3a9a558e/same-operator-regression/` |
| Separate macOS matrix and substitution verification | `macos-fresh-policy-binding-f3a9a558e/` |

The fresh public budget fixture is retained byte-for-byte as
`crates/products/chio-cli/tests/fixtures/process-worker-outcomes/v2-policy-bound-budget.json`,
with its public kernel key, operator pins and provenance. Its SHA-256 is
`8e3f2679fe1b6206ef553dea654df2e668af2dd5670b12f891f6c78abf81927a`.
The old `v2-budget` fixture is unchanged and now has an explicit rejection test.
The fresh fixture retains the existing positive and substitution checks,
including incomplete launches without invented terminal evidence. Synthetic
receipt tests also assert that the matching complete-policy commitment does
not replace observed helper, target and execution-identity checks.
The final fixture/test checkpoint still requires its targeted test run.

## Remaining qualification

The original cage source `221c3c19d4995e425849d1cdc36a66ad546e4a7d`
finished with all 69 tests and all ten mutation probes passing. Evidence:
`linux-x86-221c3c19d-optimized-debug/completed.json`. It precedes the repair;
the repaired-source cage run and complete candidate workspace qualification
remain distinct requirements.

M7 component expansion and the remaining M8 history campaign were deferred
while idle so these review failures take priority. The successful million-row
append gate and 1,000-row history-recovery calibration remain separate evidence;
the full history recovery campaign and retention issue remain open. The macOS
fuzz build failed because `chio-finding-worker` exports are Linux-only; no fuzz
corpus execution or fuzz-campaign pass is claimed from that run.

Publish the repaired candidate as a reviewable draft checkpoint. Preserve the
protected execution-image pins, missing supply-chain audits, designated-runner
requirements and remaining M5 acceptance boundaries. M6/M7 composition, M8
recovery and further product integration follow qualification of this candidate.
