# Mac Host Adapters and Delegation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect exact qualified agent hosts to native Chio execution, private model/resource custody and bounded delegated workers, with independently verifiable outcomes and selective Clawdstrike reuse.

**Architecture:** The shared Rust controller translates host requests to the single native authority and exposes observations through `chio.desktop.operator.v1`. Native owners retain approvals, ledger, stop, dispatch and output custody; adapters cannot authorize through callbacks or local counters. Pi SDK/print in a qualified VM is the first candidate, while other hosts, remote workers, relocation and native providers retain separate qualification gates.

**Tech Stack:** Rust controller and native kernel; TypeScript Pi adapter; Python acceptance evidence checks; Swift native provider bridges; canonical JSON contracts; signed receipts and the M6 independent verifier.

---

This is a future implementation plan. No command below has been executed as product validation by writing it. At MAC-BASE `6573b8980a1e5331028b7e688169f033a39d0384`, `integrations/macos/` and `crates/products/chio-desktop/` are proposed paths. M2 creates the shared controller scaffold; this track extends it. Missing native primitives must be completed in their existing owners through M0, not implemented as a desktop authority shim.

Read [host requirements](../../specs/2026-10-07-macos-integration/15-host-adapters.md), [delegation requirements](../../specs/2026-10-07-macos-integration/16-delegation.md), [reuse requirements](../../specs/2026-10-07-macos-integration/18-clawdstrike-reuse.md), [source review](../../specs/2026-10-07-macos-integration/research/clawdstrike.md), and plans [00](00-kernel-prerequisites.md), [02](02-protocol-controller.md), [03](03-vm-project.md), [04](04-resources-publication.md), [05](05-native-enforcement.md), [06](06-recovery-evidence.md), [08](08-distribution-qualification.md).

M7 execution starts only after M3, M4 and M6 applicable gates pass. Native provider reuse also waits for M5. Read-only inventory and failing prerequisite tests can be implemented earlier, but cannot enable an execution profile. Commit instructions below apply during authorized implementation; this document-writing task makes no commit.

## File and ownership map

| Path | Status and responsibility |
| --- | --- |
| `crates/products/chio-desktop/src/hosts/{mod.rs,descriptor.rs,prepare.rs,delivery.rs,delegation.rs,remote.rs,detection_response.rs,coexistence.rs}` | Proposed M7 modules in the M2 scaffold: installed tuple, frozen adapter state and translation to native owner contracts, authenticated remote worker transport, detector response requests and independent product coexistence. |
| `crates/products/chio-desktop/tests/{mac_host_contract.rs,mac_host_delivery.rs,mac_delegation_contract.rs}` | Proposed controller integration regressions, using actual installed native bindings for authority assertions. |
| `integrations/macos/adapters/pi/{package.json,package-lock.json,src/worker.ts,src/native-bridge.ts,test/private-input.test.mjs,test/host-contract.test.mjs}` | Proposed exact Pi guest integration and private input, without local admission or credential ownership. |
| `integrations/macos/contracts/host-installation.schema.json` | Proposed closed descriptor schema; opaque native references follow M2, not a second wire protocol. |
| `integrations/macos/contracts/delegation-profile.schema.json` | Proposed bounded worker/profile/lease descriptor, not a signed capability schema. |
| `integrations/macos/qualification/adapters/{source-inventory.json,host-matrix.json,case-catalog.json}` | Proposed pins, exact unavailable/qualified rows and executable acceptance cases. |
| `integrations/macos/qualification/adapters/{run.py,check_evidence.py}` | Proposed real-run orchestrator and structural/invariant evidence checker. Cryptographic verification uses the M6 verifier; these files cannot mint qualifications. |
| `integrations/macos/tests/adapters/{test_private_input.py,test_release.py,test_delegation.py,test_projection.py}` | Proposed independent acceptance assertions over real endpoint/process/native evidence. |
| `crates/guards/chio-policy/src/{models.rs,compiler.rs,validate.rs,resolve.rs}` | Existing native policy owners at MAC-BASE. Integrate validated projection without replacing approvals or integrity. |
| `crates/guards/chio-policy/tests/macos_projection.rs` | Proposed policy regression file; existing `tests/human_in_loop.rs`, `tests/compile_policy.rs`, `tests/validate_boundary.rs` remain required. |
| `integrations/macos/native/Tests/{EndpointSecurityTests/ReuseCoverageTests.swift,NetworkExtensionTests/ReuseScopeTests.swift}` | Proposed tests under the M5 package, for measured reused-provider configuration and scope. |
| `integrations/macos/qualification/reuse/{upstream.json,projection-cases.json,coexistence-cases.json}` | Proposed reviewed source/license/patch inventory and policy/co-installation corpus. |

Native prerequisite ownership remains in `crates/kernel/chio-kernel/`, `crates/kernel/chio-kernel-core/`, `crates/core/chio-core-types/`, `crates/platform/chio-store-sqlite/` and the delivered north-star owners recorded by M0. This plan does not claim that a `spawn`, renewal, relocation or model-release API exists in those modules today. M0's actual closed ABI and implementation mapping are mandatory inputs before linking these adapters.

The VM guest implementation is owned by [M3 Task 0](03-vm-project.md). This plan consumes its supervisor, one-shot bounded FD 3 task-input contract and separate FD 4 resource-request channel; it does not assume an unowned guest client or inherit the supervisor control descriptor into a worker. Guest-side invocation claims require the separately qualified supervisory lane and cannot establish verified test results after guest compromise.

## Task 1: Freeze source inventory, exact tuples and prerequisite refusals

Coverage: host 001-003, 016, 018; delegation 001, 016; reuse 001, 014.

- [ ] Read current `AGENTS.md`, `CLAUDE.md`, the M0 delivered ABI/evidence mapping and M2 controller modules. Record the exact verified public Pi pin `4214a5a8ddec776a5ff9ec78007442683fd8df03`, Clawdstrike pin `b9515321f4a20bd676dfef88bdf3ba4d015bc6e9`, source hashes, lockfiles and license files in `source-inventory.json`. Do not substitute the older local Pi checkout or a floating tag.
- [ ] Create `host-installation.schema.json` with closed objects and required adapter/runtime/build/lock/profile/OS/architecture/image/registry/native/provider/disclosure/qualification identities. The qualification reference is absent for an unavailable row; there is no `qualified: true` client assertion. Initialize `host-matrix.json` with the exact source-supported Pi versions and every runtime qualification absent.

The first refusal fixture is concrete JSON under `integrations/macos/qualification/adapters/cases/pi-no-native.json`:

```json
{
  "case": "AT-MAC-HST-003",
  "host": {"adapter": "@chio/pi-plugin", "version": "0.2.0", "pi": "1.0.2"},
  "selection": {"profile": "vm-project-v1", "disclosure": "required"},
  "native_installation": null,
  "expected": {"result": "unavailable", "credential_reads": 0, "provider_requests": 0, "worker_launches": 0}
}
```

- [ ] Define the proposed `CaseEvidence` reader in `check_evidence.py`. It reads a run directory containing `case.json`, `observations.json` and `native-verification.json`; the latter must be emitted by the M6 verifier. It rejects missing files, changed case/tuple digests and nonzero verifier exit. It never treats a JSON field as signature verification. Add the following invariant helper and test its failures with mutated evidence:

```python
def require_refusal_before_secrets(observed):
    assert observed["result"] == "unavailable"
    assert observed["credential_reads"] == 0
    assert observed["provider_requests"] == 0
    assert observed["worker_launches"] == 0
```

- [ ] Introduce `hosts::descriptor` and `hosts::prepare` in the M2 crate. Preparation compares the frozen tuple against the authenticated installed native owner and verified qualification registry. Retain opaque M2/M0 references; return the existing typed unavailable outcome on absent native support. Do not introduce an alternate `admit()` implementation.
- [ ] Add `mac_host_contract.rs` cases for every changed tuple field, required feature, foreign owner and stale generation. The positive preparation case may run only with the delivered M0 owner and M3 installation. A fixture provider listener and credential-read observer independently verify the refusal fixture.
- [ ] Implement the proposed `run.py` command interface: `--case` selects a catalogued case; `--installation` names the verified installation manifest; `--output` is a new private run directory. It launches the case's named native/profile/endpoint observers, writes raw provenance references, invokes the M6 verifier and exits nonzero on missing installation or failed assertions. It refuses host/argv supplied inside case input. No `--pretend-qualified` option exists.
- [ ] Run `cargo test -p chio-desktop --test mac_host_contract` and `python3 integrations/macos/qualification/adapters/run.py --case AT-MAC-HST-003 --installation output/macos-m7/installation.json --output output/macos-m7/preflight`. Before implementation or without installation, expect nonzero with no credential reads or worker launches. After real prerequisite delivery, expect refusal cases to pass and only the exact positive tuple to prepare.
- [ ] Commit the scoped descriptor/preflight work with `git commit -m "feat(macos): gate host adapters on exact native qualification"` after staging only the task's listed files.

## Task 2: Private Pi input and closed host surface

Coverage: host 002, 005-007, 013, 017.

- [ ] Create the Pi adapter package with exact `@chio/pi-plugin` provenance and Pi `1.0.2`; write a consumer lockfile and record the selected exact Node binary hash. Version ranges or optional Durable inclusion cannot silently define runtime qualification. Install only the frozen inline extension/tool registry in the M3 guest.
- [ ] Add the complete proposed private-input reader to `src/worker.ts`, separate from any credential acquisition. The trusted supervisor supplies a dedicated pipe on FD 3. The reader accepts at most 256 KiB of UTF-8 JSON and has no argv prompt fallback:

```typescript
import { createReadStream } from "node:fs";
import { TextDecoder } from "node:util";

export async function readPrivateInput(fd = 3): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  const input = createReadStream("", { fd, autoClose: true });
  try {
    for await (const chunk of input) {
      const bytes = Buffer.from(chunk);
      size += bytes.length;
      if (size > 262144) throw new Error("private_input_too_large");
      chunks.push(bytes);
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("invalid_private_input");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    input.destroy();
  }
}
```

This is bounded transfer and safe-error behavior, not a guarantee of erased runtime memory. Validate the parsed shape against the M4 private-input contract before use. Never stringify the rejected input in errors.

- [ ] Add `test/private-input.test.mjs` using actual pipes/temp descriptors for empty, exact-limit, over-limit, malformed UTF-8 and truncated JSON. The test runner uses its own synthetic prompt and verifies output/errors exclude that value. Add the independent live-process test in `test_private_input.py` to inspect argv/environment/diagnostics while input is held.
- [ ] In `src/native-bridge.ts`, bind only the actual delivered M0/M2 native transport references. Use Pi's restricted SDK entry, immutable registry and current lifecycle hooks. Set no project/global discovery or ordinary profile loading. Freeze caller-owned inputs before asynchronous preparation and preserve cancellation across it. Reapply/verify restrictions on reload, compaction, branch/session switch and replacement.
- [ ] Implement canonical argument equality in `src/native-bridge.ts` before native dispatch: retain the original model-emitted tool name and arguments, validate the frozen registry/schema without coercion, and compare RFC 8785 canonical arguments with the exact native request binding. Refuse changed types, injected fields, aliases or registry generation before any effect. Add `test/host-contract.test.mjs` cases for numeric-to-string coercion, added properties, alias substitution and post-reload mutation; the independent native dispatch counter must remain zero for every mismatch.
- [ ] Add closed reverse-channel dispatch in `src/native-bridge.ts`: sampling, elicitation, resource reads, attachment/URL requests and nested delegation resolve only to an installed typed native contract with current disclosure/effect authority. Unregistered channels refuse before model, browser, network or child launch; MCP metadata is only input to that lookup. Test one registered fixture through its native owner plus every unknown channel, forged callback allow and direct transport bypass using independent receiver and launch counters.
- [ ] Seed guest-visible hostile config, package hooks, MCP servers and undeclared tools. Add catalog cases that try raw shell/network, provider SDK, filesystem and reverse-protocol calls outside the registry. A bypass failure means the profile stays unavailable; removing its test is not an acceptable fix.
- [ ] Run `npm --prefix integrations/macos/adapters/pi ci`, `npm --prefix integrations/macos/adapters/pi test`, then `python3 integrations/macos/qualification/adapters/run.py --case AT-MAC-HST-007 --installation output/macos-m7/installation.json --output output/macos-m7/private-input`. Expect all private-input boundary tests to pass, no secret in OS-visible arguments and no provider traffic for rejected input. Run the catalogued 002/005/013/017 cases through the same runner before activation.
- [ ] Commit with `git commit -m "feat(macos): add private bounded Pi worker input"` after staging only the adapter, catalog and tests.

## Task 3: Native model gateway and durable limits

Coverage: host 003-004, 006, 008-010, 016; delegation 005, 009.

- [ ] Add native-owner acceptance work to M0 if exact model release is absent: require retained final request bytes, knowledge/influence join, serving-writer crossing, commit acknowledgement, provider submission by that owner, credential generation and original recovery. The owner implementation remains a dependency; a `NativeModelPort`-shaped mock cannot close it.
- [ ] Extend `hosts::prepare` to freeze route/model/API contract/account-selection rule, credential generation, registry, disclosure mode and limits against that native binding. Keep execution-only explicitly limited. Required mode refuses until the actual native release path and exact profile evidence exist.
- [ ] Add `cases/model-release-cutpoints.json` with these concrete cases and external observations:

```json
[
  {"cut": "before_intent_commit", "provider_requests": 0, "permitted_followup": "reconcile_original"},
  {"cut": "after_commit_before_ack", "provider_requests": 0, "permitted_followup": "reconcile_original"},
  {"cut": "after_provider_accept_before_return", "provider_requests": 1, "permitted_followup": "reconcile_original"},
  {"cut": "foreign_account", "provider_requests": 0, "permitted_followup": "new_admission"},
  {"cut": "undeclared_remote_reference", "provider_requests": 0, "permitted_followup": "refuse"}
]
```

- [ ] Wire `src/native-bridge.ts` to the actual native model owner, preserving its original-operation identity and opaque release handle. It must return the owner's response without a caller-side fetch fallback. Add route/model/body mutation, redirect, hosted-tool and alternate-credential cases. The provider test server captures final bytes independently; compare its digest with the native retained release commitment.
- [ ] Bind child/model reservations to the native hierarchical ledger. Declare exact hard bounds and unavailable fields per provider. Subscription hard-token guarantees remain unavailable unless independently delivered. Use fixture bounds of three requests and 1,024 response bytes to exercise exhaustion; these are test parameters, not release defaults.
- [ ] Add `test_release.py` with the following invariant over independently captured provider/native observations:

```python
def assert_same_original_after_retry(first, resumed):
    assert first["authority_store"] == resumed["authority_store"]
    assert first["operation_id"] == resumed["operation_id"]
    assert first["request_digest"] == resumed["request_digest"]
    assert resumed["provider_effect_count"] == first["provider_effect_count"]
    assert resumed["remaining_requests"] <= first["remaining_requests"]
```

- [ ] Run `cargo test -p chio-desktop --test mac_host_contract` and catalog cases 008/009/010 through `run.py` with real owner/provider observers. Expect the initial missing-owner case to remain unavailable; after owner delivery, exact byte equality and all cutpoint invariants pass. Reconcile unknown provider outcomes without fresh dispatch.
- [ ] Commit with `git commit -m "feat(macos): bind host model traffic to native release custody"` only after the real owner dependency is present; otherwise commit refusal coverage and leave the capability unavailable.

## Task 4: Safe output, exact delivery ACK and lifecycle recovery

Coverage: host 011-015; delegation 010-011, 015; reuse 009, 015.

- [ ] Create `hosts/delivery.rs` and `mac_host_delivery.rs`. Keep signed native objects opaque to Swift/TypeScript and use M6's actual verifier before result admission. Map only verified native operation/result/recipient references into the M2 projection. Retain delivery custody through detached observers and pending ACK.
- [ ] Add malicious-output fixtures for forged signer, changed result commitment, wrong recipient, stale generation, terminal escape `\u001b]52;c;YXR0YWNr\u0007`, remote image URL and HTML script. Use M1's inert renderer and M4 artifact boundary; do not create a host adapter HTML interpreter. Unqualified streaming buffers within its admitted cap or refuses.
- [ ] Add explicit fault cutpoints before return retention, after retention before release, after consumer delivery before ACK, and after ACK commit before response. The external effect counter and native original record must remain stable through restart. Stop is checked at later release even when intent preceded it.
- [ ] Connect `hosts/delivery.rs` to the native owner's delivery latch so an unresolved original or pending consumer ACK fences every dependent effect before admission. Reconciliation may reopen the lane only after the native owner verifies original delivery or its explicit terminal disposition; adapter display/export, timeout and a new transport session cannot clear it. Add held-result, lost-ACK, observer-detach and restart cases that request a second effect: its independent effect counter stays zero until the original latch is authoritatively cleared, and the first effect is never repeated.
- [ ] Add the following output assertions to `test_release.py`; M6 verifies cryptography separately before these checks:

```python
def assert_withheld_output(evidence):
    assert evidence["native_verifier_exit"] == 0
    assert evidence["release_disposition"] == "withheld"
    assert evidence["consumer_bytes"] == 0
    assert evidence["delivery_ack_count"] == 0
    assert evidence["preview_network_requests"] == 0
    assert evidence["preview_process_launches"] == 0
```

- [ ] Add resume/reload/compaction/close tests preserving history influence, native owner generation, original mappings and absolute limits. Denials and advisory receipts cannot become completion ACK. Closure of Pi's session waits for callbacks and pending owner observers without erasing retained uncertainty.
- [ ] Route checkpoint restore, import, compaction and branch/session replacement through the delivered native session/knowledge custody owner before exposing transformed context. Recheck frozen account/disclosure/registry/owner bindings and retain or strengthen relevant influence; absent transformation contracts refuse without a raw transcript fallback. Add stale checkpoint, foreign import, changed account and influence-erasing summary cases, verifying parent/model context receives no rejected bytes and existing custody remains intact.
- [ ] Run `cargo test -p chio-desktop --test mac_host_delivery` and catalog host 011-015, delegation 010-011 cases with native store/effect/consumer observers. Expected: forged output never reaches context, held output remains withheld, ACK retries reconcile the original and zero host exit cannot report success over a failed required test.
- [ ] Commit with `git commit -m "feat(macos): verify host output and retain native delivery custody"`.

## Task 5: Child admission, attenuation and conserved ledger

Coverage: delegation 001-005, 008, 012; host 010, 014.

- [ ] Read M0's implemented child, ledger and stop contracts and record their exact modules/build/ABI in the case catalog. If any is absent, add its acceptance work to M0 and keep child launch unavailable. Existing signed attenuation types alone are not a process host.
- [ ] Create `delegation-profile.schema.json` with closed template/runtime/target/lease/limit descriptors. Add `hosts/delegation.rs` as a translator to the native child owner; no desktop signer, allocation database or retry identity generator. Fixed templates are administrator-installed and digest-bound, not selected by guest executable/argv/environment values.
- [ ] Require the M0 child owner to implement one atomic admission transaction retaining original request, parent, exact input/template/target commitments, child signer custody and sealed ledger allocation before launch. Verify every signed attenuation hop preserves issuer, tenant, budget family, resource constraints, parent validity and ancestor revocation. Equal replay returns the original; changed bindings conflict. Add namespace/issuer/budget-family substitution, missing-hop, sibling-parent, broader-scope and later-expiry cases plus crash-before/after-commit barriers; no invalid child obtains a key, allocation or launch.
- [ ] Write `mac_delegation_contract.rs` and the finite fixture below, then attempt one valid child followed by every invalid mutation:

```json
{
  "case": "AT-MAC-DEL-005",
  "limits": {"processes_including_root": 3, "depth": 2, "active_children": 2, "logical_calls": 5, "model_requests": 3},
  "attempts": ["equal_replay", "changed_input_replay", "third_child", "wider_scope", "later_expiry", "foreign_issuer", "revoked_parent", "refund_unknown_child", "restart_budget_reset"],
  "expected": {"maximum_admitted_processes": 3, "new_identity_on_equal_replay": false, "unknown_refund": false}
}
```

- [ ] Exercise crash after child admission before launch and after possible launch before owner response. Observe the guest process independently. Require one original child/launch identity and native sealed reservation; changed replay conflicts. Do not make launch success atomic by assumption.
- [ ] Add `test_delegation.py` invariants over the independently read native ledger: admitted allocations and in-flight holds fit each ancestor; unknown reservations persist; denied or replayed requests do not create a second allocation. Add dependency-cycle, undeclared wait, required test failure and optional unknown-effect cases; unknown effects prevent clean root completion.
- [ ] Integrate the actual native dependency registry and bounded wait/settle operations in `hosts/delegation.rs`; only admitted descendants/dependencies can be selected, cycles refuse before waiting, and each wait has the frozen deadline plus native cancellation. Compute root completion from verified required child outcomes/artifacts and all effect obligations, never child prose. Missing native graph or settlement contracts keep that feature unavailable. Exercise a hung child, expiry, undeclared dependency, failed required artifact and optional child with unknown effect; none produces unbounded wait or false clean success.
- [ ] Run existing native regressions `cargo test -p chio-core-types capability::` and `cargo test -p chio-kernel --features delegation`, then `cargo test -p chio-desktop --test mac_delegation_contract`. These component tests do not replace real `run.py` cases AT-MAC-DEL-002 through 005, 008 and 012 with the installed owner/guest.
- [ ] Commit with `git commit -m "feat(macos): connect bounded native child admission"` after native dependency and real confinement evidence pass.

## Task 6: Worker leases, partition recovery and optional relocation

Coverage: delegation 006-010, 013-016; host 012, 014.

- [ ] Extend the M0 native prerequisite artifact with actual issuance/renewal/replacement/retirement ABI bindings and clock semantics. The serving writer must own generation and lease changes. Leave disconnected execution and relocation disabled if their native protocols are absent.
- [ ] Extend the native lease-owner handoff and `hosts/delegation.rs` renewal integration to require same-writer rechecks of authenticated authority, parent validity and ancestor revocation, current policy, exact installation, owner generation and durable stop at renewal commit. Bind only the actual delivered M0 ABI; missing checks keep remote execution unavailable. Add native barrier cases changing each binding immediately before renewal, including parent expiry, and verify independently that no renewed lease or new crossing is issued; a transport heartbeat never substitutes for that commit.
- [ ] Implement `hosts/remote.rs` against the delivered native worker transport contract: mutually authenticate enrolled host and worker identity, bind authority/store/run/owner generation and original operation to replay-protected messages, and restrict routes to the admitted worker and resource endpoints. Before context transfer, require the native release owner to verify exact content commitments, recipient and current disclosure authority; exclude ambient parent transcripts, credentials and host-control sockets. Add wrong-host/worker/authority/generation, replay, changed-context, expired-disclosure and raw-control-route cases with a receiver outside both workers proving zero prohibited bytes or effects. Missing native authentication or release contracts leave the remote profile unavailable; the adapter does not invent a remote grant or signer.
- [ ] Add proposed test profile values to the qualification fixture: 30-second admission lease, renewal by 10 seconds, maximum uncertainty 2 seconds. These deliberately finite experiment settings require verification; they are not inherited Mac guarantees. Record authority and both hosts' monotonic/boot observations independently.
- [ ] Create `cases/partition.json` with cutpoints `renewal_partition`, `sleep_past_expiry`, `policy_change_before_renewal`, `stop_before_renewal`, `reboot_same_pid`, `old_owner_reconnect` and `concurrent_replacement`. For each, record actual new-crossing counts, old/new owner generations, outstanding effects and process liveness separately.
- [ ] Route subtree stop and ancestor revocation through the native owner, then request actual VM/supervisor termination separately. Preserve native ordering: post-fence crossings refuse, precommitted intents retain possible effects, permitted progress-only return records remain retainable, and later output release rechecks current stop/revocation. Add barriers before intent, after intent, before return and before release plus a surviving worker; independent native journal, process and receiver observations must distinguish fenced admission, actual termination, retained return, withheld delivery and unresolved effects.
- [ ] Bind remote settlement to each original resource owner's qualified lookup/finality contract in `hosts/remote.rs`. Retain unknown state when dispatch may have occurred and authoritative lookup is absent; neither worker death, disconnect, cancellation nor reuse of a provider idempotency key creates finality or permission to redispatch. Add receiver-observed effect with lost reply, unavailable lookup, forged result and later verified original evidence; count one observed effect, retain the original identity and obligations, and permit only the native owner's proven reconciliation transition.
- [ ] Add the concrete invariant checker below. It supplements native signature/clock verification and does not turn Python comparisons into a lease authority:

```python
def assert_fenced_replacement(evidence):
    assert evidence["old_generation_new_crossings_after_fence"] == 0
    assert evidence["simultaneous_serving_writers"] <= 1
    assert evidence["fresh_ids_for_uncertain_effects"] == 0
    assert evidence["heartbeat_renewals_without_native_commit"] == 0
    assert evidence["unknown_effects_after"] >= evidence["unknown_effects_not_reconciled"]
```

- [ ] For optional stopped relocation, build a complete inventory from M6 native custody, Pi gateway/model/history/ACK state and M4 resource owners. Test missing entry, corruption, interrupted import and simultaneous source/destination. Copying only receipts or VM snapshots must fail. Native transfer seals retire the source before destination service; exact original transfer identity survives retries.
- [ ] Run `python3 integrations/macos/qualification/adapters/run.py --case AT-MAC-DEL-007 --installation output/macos-m7/two-host-installation.json --output output/macos-m7/partition`, then cases 006/008/009/010/013/014/015/016. Missing second-host evidence must fail rather than skip. Expected: stale/partitioned workers initiate no new crossing and all admitted unknown effects remain visible; relocation stays unavailable until the complete transfer passes.
- [ ] Commit with `git commit -m "feat(macos): fence delegated worker ownership and recovery"`; keep unsupported relocation visibly unavailable in the matrix.

## Task 7: Fail-closed policy projection and scoped Clawdstrike reuse

Coverage: reuse 001-015; host 004.

- [ ] Populate `qualification/reuse/upstream.json` from the eleven exact reviewed source hashes, license inventory and intended copied/library boundaries. Record original source, local patch and resulting artifact digests. Make ES/NE code changes in M5's owned modules after coordinating file ownership; this task never installs a second Chio authority daemon.
- [ ] Implement `hosts/detection_response.rs` as a bounded observation-to-native-request adapter. Preserve producer identity, sensor clock/sequence, gaps and exact finding commitment separately from native receipts; resolve any requested remediation through the registered native action owner and current admission, approval, budget, integrity and stop checks. A finding or external allow cannot authorize the action. Add forged/stale/duplicate findings, missing sequence, foreign user and stopped/revoked authority cases; an independent effect counter must remain zero for refused requests, while equal admitted retries reconcile one original operation and its separate authoritative receipt.
- [ ] Create `projection-cases.json` and `crates/guards/chio-policy/tests/macos_projection.rs`. Call existing `HushSpec::parse`, native validation/resolution and `compile_policy_with_approver_directory` as appropriate; do not route through lower-level compilation to evade validation. Define a new proposed `ProjectionDisposition` enum in the policy owner with `Preserved`, `MoreRestrictive`, `Unsupported`. Unsupported fields prevent activation, even if a preview can describe them.
- [ ] Implement a native policy-owner projection record binding source/target dialect and version, exact compiler builds, source/inheritance digests, target policy commitment and declared semantic subset. Resolve all inheritance against pinned bounded inputs, retain authenticated approver-directory and integrity/output requirements, and reject unresolved, unknown or weakening features before activation. Test changed dialect/compiler, remote inheritance drift, unsupported defaults, omitted output rule and directory substitution; no lossy export may replace the installed native policy.
- [ ] Use this finite semantic check in `test_projection.py`, fed by independent source/target evaluator runs on the declared subset:

```python
def assert_no_weakening(cases):
    for case in cases:
        if case["disposition"] == "unsupported":
            assert case["activated"] is False
        elif case["source_decision"] == "deny":
            assert case["target_decision"] == "deny"
        assert case["external_allow_bypassed_native_authority"] is False
        assert case["external_approval_became_native_endorsement"] is False
```

Include inheritance, path glob/case/symlink behavior, default actions, output rules, unknown extension, threshold directory substitution and lossy decompilation. Label this as bounded conformance evidence; unsupported semantics remain refused.

- [ ] Add `ReuseCoverageTests.swift` to observe real ES subscription and handler configuration. Verify AUTH_OPEN observer evidence never enables broader events/profile claims. Add `ReuseScopeTests.swift` for the actual NE target policy and expiration behavior, plus real M5 cases for per-task attribution, existing HTTP/2/UDP flows and unrelated apps. Missing/unsynced policy scope must be tested, not called safe because it blocks something.
- [ ] Reproduce the stale PID-incarnation fixture from the source review. Implement process targeting only in the proper native supervisor owner, proving that the replacement PID cannot receive a stale signal across the check-to-signal race. If that proof is unavailable, disable the response capability while retaining observation.
- [ ] Add co-installation cases for independent opposing restrictions, separate approvals/signers, provider crash, Fast User Switching, independent update/uninstall and rollback of only the original issuer's rule. Supply source-to-prebuilt-extension evidence and same-host real block/restore through M8. Events entering Chio remain bounded/redacted sensor evidence and never auto-enter model context.
- [ ] Implement `hosts/coexistence.rs` as an observation/restriction boundary with separate product identities, authenticated observation channels, policy stores, signers and namespaced operation history. Effective access remains constrained by native Chio admission and every applicable independent restriction; external approval cannot satisfy Chio endorsement. Permit rollback only through the original restriction issuer's contract and retain unresolved native custody through either product's update/removal. Inject a foreign rule ID, substituted signer and external allow while Chio is stopped; no foreign mutation, authority expansion or shared-transaction claim is produced.
- [ ] Run `cargo test -p chio-policy --test macos_projection`, `cargo test -p chio-policy --test human_in_loop`, `cargo test -p chio-policy --test compile_policy`, `cargo test -p chio-policy --test validate_boundary`, and `swift test --package-path integrations/macos/native --filter Reuse`. Then execute AT-MAC-CLW-001 through 015 with the applicable signed installation. Expected: component tests cannot promote installed or task coverage; all unproved provider/packaging/coexistence cases remain unavailable.
- [ ] Commit with `git commit -m "feat(macos): constrain selective policy and provider reuse"` after staging only coordinated policy/reuse changes.

## Task 8: Execute the complete matrix and publish truthful capability state

Coverage: all requirements and acceptance definitions in host, delegation and selective reuse specifications.

- [ ] Enumerate every acceptance ID from the three specifications into `case-catalog.json`; assign its real runner, independent observer and applicable profile. Map host 001-018, delegation 001-016 and reuse 001-015 with no empty or fixture-only substitute for installed cases. Link each result to the M8 tuple and M6 cryptographic verification artifact.
- [ ] Run the docs validator, then the exact component checks and real acceptance catalog. Future commands:

```bash
python3 docs/superpowers/specs/2026-10-07-macos-integration/verify.py
cargo test -p chio-desktop --test mac_host_contract
cargo test -p chio-desktop --test mac_host_delivery
cargo test -p chio-desktop --test mac_delegation_contract
npm --prefix integrations/macos/adapters/pi test
python3 integrations/macos/qualification/adapters/run.py --case all --installation output/macos-m7/installation.json --output output/macos-m7/final
```

`--case all` runs the selected installation's applicable cases and reports every non-applicable/unavailable case explicitly. It cannot create a qualified remote or native-provider row from a VM-only installation. The runner must fail if an advertised required case lacks evidence; it may retain an honest unavailable feature without advertising it.

- [ ] Update the matrix with independent verified evidence references only after exact positive and negative cases pass. Re-run changed-boundary cases after any adapter, native ABI, model contract, policy, image, OS or provider binary change. A new framework's version must be exact and independently installed; dependency ranges and source receipts remain insufficient.
- [ ] Verify through the M1 app that unavailable reasons, disclosure mode, model account, child tree, stop/termination distinction, unknown effects and withheld results match native state. Show no broad protected-host badge based solely on a callback or external health response.
- [ ] Run required repository checks for implemented code: `cargo fmt --all -- --check`, `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace -- -D warnings`. Record missing toolchain/installed-host prerequisites separately from passing local checks. A docs-only plan review does not run or claim these product checks.
- [ ] Commit the qualification artifacts and truthful matrix with `git commit -m "test(macos): qualify selected host and delegation tuples"`. Release remains subject to M8 distribution and public artifact provenance; do not publish private-only checkout revisions or imply runtime delivery from this plan.

## Completion criteria and unresolved gates

The track is complete only for the specifically selected tuples whose actual native owner, confinement, provider, disclosure, output and recovery contracts pass applicable acceptance. The matrix can honestly ship an unavailable remote/relocation/framework/native-response feature, but it cannot list that feature as qualified. An unresolved capability owner is recorded in M0 with its concrete failing case and disabled product behavior; it is never replaced with an adapter-local authority implementation.

No separate request for implementation follows from this document. The current authorized deliverable is the specification and detailed plan; later execution follows the approved project phase and preserves unrelated worktrees.
