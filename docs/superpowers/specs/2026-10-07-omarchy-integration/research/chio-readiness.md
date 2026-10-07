# Chio readiness and source crosswalk

Status: Proposed research baseline, inspected 2026-10-07.

Confidence: high for the source and artifact distinctions below, based on direct file inspection, Git tree comparisons, public GitHub API responses and retained qualification records. Moderate for the proposed integration effort. Unknown for a complete Omarchy installation running the selected native combination: this research did not execute that combination.

Scope: the Chio authority, process host, restricted Pi host and their missing delivery prerequisites. Dependencies: the package architecture, host adapter contract and phase plan. Research completion closes no runtime or release gate.

## What can be built on

Chio's modern Rust kernel provides the authority foundation for an agentic operating system: capabilities, guarded dispatch, durable operation identities, signed outcomes, revocation and budget enforcement. Omarchy can present that authority through a native desktop interface. Its QML plugin and desktop controller must remain clients of that foundation. Installing another host wrapper does not make it an issuer, a receipt signer or a recovery coordinator.

The implementation surfaces are distributed across different source snapshots. Public Chio main, the documentation branch baseline, the developed native qualification candidate, and current public Pi main do not identify one compatible installation. This is the first P0 constraint.

## Inspected source identities

| Source ID | Pinned identity or reproducible scope | Interpretation |
| --- | --- | --- |
| CORE-PUBLIC | Public Chio main resolved through GitHub API to `5b8bec41d32f3838b880576fe6123c983ecebf8d`; complete recursive tree returned `truncated=false` | Public source reference, not a claimed downloadable compatible native host |
| CORE-BASE | Current documentation branch baseline, inspected locally on 2026-10-07 | Existing paths in this checkout; individual public/common blobs were compared where cited |
| NQ-CANDIDATE | Developed native qualification source inspected on 2026-10-07; selected file SHA-256 identities below | Candidate implementation, distinct from both main snapshots; no release instruction points at this source |
| PI-PUBLIC | Public Pi main `4214a5a8ddec776a5ff9ec78007442683fd8df03` | Public `@chio/pi-plugin` 0.2.0 candidate source; exact tree equals the locally inspected developed Pi tree |
| PI-HOST | Exact peers `@earendil-works/pi-coding-agent@1.0.2` and optional `@earendil-works/pi-durable@1.0.2` | Version checks and consumer lockfiles matter; peer versions do not pin the full transitive graph |
| PI-BRIDGE | Vendored `chio-bridge-0.3.0-7d9e34f7408a.tgz`, SHA-256 `7d9e34f7408a316e35125982a23faaecfd2f31f4da6b50ca8eab287c2c918f67` | Actual installed bridge contract; another archive reporting 0.3.0 is not interchangeable |
| RECOVERY-REPORTED | Additional recovery/knowledge/semantic source described by PI-PUBLIC's prerequisite document | Not present in either inspected main or NQ-CANDIDATE at the cited locations; separate source and delivery qualification required |

Public references: [Chio pinned tree](https://github.com/backbay-labs/chio/tree/5b8bec41d32f3838b880576fe6123c983ecebf8d), [Pi pinned package manifest](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/package.json), [Pi native prerequisites](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/NATIVE-PREREQUISITES.md). References were checked through GitHub's API; the source inventory is not a release availability check.

Selected NQ-CANDIDATE file fingerprints identify exactly the inspected contents without presenting a candidate-only revision as a public checkout instruction:

| Source map | SHA-256 |
| --- | --- |
| NQ-01, process runtime `src/lib.rs` | `ec6dc924f363b7bdc1ef381005951c0aaf1ba9a9bfedd7b896a5fdc712581624` |
| NQ-02, process registry `src/registry.rs` | `12054fd4b55c53222a8ec3449902836c77f21a1e67fd92ce503fe4eac58750ef` |
| NQ-03, process host lifecycle | `c5c46f0d2a076de9bab0bf5c51d71beab59737421b6e7e7a4801353692965155` |
| NQ-04, retained session credentials | `c96eda62442fff6caa1b9241bb63b55eef09b37e0a352b668c031cc8eb7511d0` |
| NQ-05, cage library entrypoint | `8b5372939ec280f37876d4dbf3a4f694b2baa1c9846b238d255d89315c2a379d` |

These fingerprints support source review only. They do not identify an executable, complete dependency graph or qualified runtime bundle.

## Existing, candidate and absent matrix

Locations marked candidate are source-map locations in NQ-CANDIDATE, not links to nonexistent files on this documentation branch. `Present` describes inspected source only.

| Map | Capability and concrete source/API | CORE-BASE | CORE-PUBLIC | Developed source or Pi | Omarchy consequence |
| --- | --- | --- | --- | --- | --- |
| CORE-01 | `crates/core/chio-core-types/src/capability/attenuation.rs`; `crates/kernel/chio-kernel/src/kernel/delegation.rs`, `consult_revocation_view` | Present | Present, compared blobs identical | Present | Existing attenuation and revocation primitives can underlie policy; they do not deliver the Pi child launcher |
| CORE-02 | `crates/kernel/chio-kernel/src/approval.rs`, `ApprovalRequest`, `ApprovalDecision`, `ApprovalToken::verify_against` | Present | Present, compared blob identical | Present | Exact native approval must be reused; desktop clicks cannot substitute for signed decision retention |
| CORE-03 | `crates/kernel/chio-kernel/src/admission_operation/identity.rs`, `AdmissionOperationId`, `AdmissionOperationBindingV1`, `DurableAdmissionMode` | Present | Present, compared blob identical | Present | Preserve immutable request/authority bindings across restart and controller retries |
| CORE-04 | `crates/platform/chio-store-sqlite/src/serving_owner.rs`, `SqliteAuthorityStore`; `serving_owner/relocation.rs` | Present | Present, serving-owner blob differs | Present | Select and qualify one exact authority-store build; path presence does not establish store/ABI compatibility |
| NQ-01 | Candidate `crates/kernel/chio-process/src/lib.rs`, `ProcessRuntime::{open,create_root,spawn,tool_request,invoke,checkpoint,cancel}` | Absent | Absent | Present in NQ-CANDIDATE | Durable process host prerequisite; no public-main installer assumption |
| NQ-02 | Candidate `crates/kernel/chio-process/src/registry.rs`, `ProcessRegistry::{open,submit_child,provision_signers}`; `src/store/children.rs` | Absent | Absent | Present in NQ-CANDIDATE | Native child admission and signer custody exist in source; Pi must receive a qualified facade |
| NQ-03 | Candidate `crates/products/chio-cli/src/cli/process_host/lifecycle.rs`, `Service::{activate,dispatch}`, `spawn_<template>`, `wait_children`, `settle_children` | Absent | Absent | Present in NQ-CANDIDATE | Delegation requires an active native run, selected templates and durable registry; serving alone does not enable it |
| NQ-04 | Candidate `crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials.rs`, `install_routes`, call reservation, signed delivery latch and ACK | Absent | Absent | Present in NQ-CANDIDATE | Scoped retained-session transport, distinct admin authentication and durable delivery are native prerequisites |
| NQ-05 | Candidate `crates/security/chio-cage/src/lib.rs`, launch/enforcement modules; `integrations/required-agents/{serve-filesystem.py,prepare-session.py}` | Absent | Absent | Present in NQ-CANDIDATE | Launch constraints must be qualified for the chosen Node owner and x64 Omarchy environment; an existing example is insufficient |
| NQ-06 | Candidate `crates/protocol/chio-mcp-adapter/src/transport/utils.rs`, native request metadata; `process_host/relocation.rs`, export/import | Transport module present, newer contract not presumed | Transport module present, newer contract not presumed | Inspected candidate provides metadata; relocation source present | Caller capability digest must originate on kernel-owned transport. Stopped-state relocation is not live migration |
| PI-01 | PI-PUBLIC `src/session.ts`, `createChioPiSession`, `createChioPiRuntime`, `createRestrictedSession`; `src/tool-registry.ts`, `createToolRegistry` | Separate package | Separate package | Present | Exact Pi 1.0.2 SDK, immutable declared tools and disabled discovery; protected print/SDK surface, no interactive TUI qualification |
| PI-02 | PI-PUBLIC `src/model-relay.ts`, `startModelRelay`; `src/run-limits.ts`, `openRunBudget`, `providerProfile` | Separate package | Separate package | Present | Fixed relay routes and parent accounting; actual budget dimensions depend on provider |
| PI-03 | PI-PUBLIC `src/host-delivery.ts`, `createHostDeliveryObserver`; `src/continuation.ts`, native original-operation ports; `src/durable.ts`, `createChioDurableTools` | Separate package | Separate package | Present | Verified native history precedes completed-result ACK; observer lifetime and gateway ownership matter |
| PI-04 | PI-PUBLIC `src/operator-cli.ts`, `runOperatorCommand`; `src/operator.ts`, `inspectOperation`, `invokeNative` | Separate package | Separate package | Present with explicit refusal | `approval-decide` unavailable. Status/export is not ACK, authority or proof of no prior effect |
| PI-05 | PI-PUBLIC `src/governance.ts`, `createNativeEmbedding`, `nativeFeatureAvailability`, `releaseGovernedModel`; `src/delegation.ts`, `submitNativeChild` | Separate package | Separate package | Composition contracts present | Complete callback objects still report `native-qualification-required`; unavailable native services stay unavailable |
| PI-06 | PI-PUBLIC `src/coding-resource/participant.ts`, `CodingResource`; `ledger.ts`, `ResourceLedger` | Separate package | Separate package | Present | Resource retention and fixed recipes are useful candidate components; unsigned resource artifacts do not become kernel receipts |
| GAP-01 | RECOVERY-REPORTED `NativeKnowledgeRuntime`, `NativeSemanticRuntime`, `RecoveryClient.explain`; cited `knowledge.rs`, `semantic.rs`, node-http `recovery.ts` | Cited locations absent | Cited locations absent | Cited locations absent in NQ-CANDIDATE | Do not invent HTTP routes for these. Require a separately pinned native facade and source crosswalk before required governance |
| GAP-02 | Omarchy QML plugin, desktop controller, versioned operator protocol and host capability negotiation | Proposed in this package | No claim | Not implemented by this work | All new service/executable names are proposed until delivery evidence exists |

Public code anchors: [core attenuation](https://github.com/backbay-labs/chio/blob/5b8bec41d32f3838b880576fe6123c983ecebf8d/crates/core/chio-core-types/src/capability/attenuation.rs), [approval](https://github.com/backbay-labs/chio/blob/5b8bec41d32f3838b880576fe6123c983ecebf8d/crates/kernel/chio-kernel/src/approval.rs), [admission identities](https://github.com/backbay-labs/chio/blob/5b8bec41d32f3838b880576fe6123c983ecebf8d/crates/kernel/chio-kernel/src/admission_operation/identity.rs), [Pi sessions](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/session.ts), [Pi model relay](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/model-relay.ts), [Pi native composition contracts](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/governance.ts).

## Actual authority and recovery flow

1. A trusted operator selects the native authority store, independent trust roots, resource identity, exact policy, retained caller/session and explicit inventory. The guest cannot create an operator capability by supplying the same fields in JSON.
2. NQ-04's admin credential exchange requires a distinct admin token, static operator authentication, a shared hosted owner and durable storage. It issues transport authority for one existing active retained session, with an explicit tool list and bounded lifetime. It replaces that session's transport credential; it does not create a child capability or reset its delivery latch.
3. The Pi parent owns provider credentials, native credentials, private journals, model reservations and the selected gateways. The guest receives only narrowly scoped transport access. Linux code confines the guest to selected runtime files and individual parent socket leaves. File modes do not defend against the trusted desktop user or malicious same-UID shell plugins.
4. A model proposes a call from the immutable registry. Pi validates the original arguments before native coercion, runs tools sequentially, and submits the exact request through the gateway. Chio admits and owns resource dispatch. Checking an authorization predicate and executing locally would bypass this flow.
5. A completion is usable only after the original request, caller, capability, resource, arguments, receipt, result and delivery proof are checked. The trusted history observer confirms the exact result in native host history before asking the native owner to ACK. A verified tool error is still a tool error. A denial has no completed-result ACK contract and does not clear an earlier unknown fence.
6. A lost response after dispatch remains an unknown original operation. A new conversation, a rotated token, a copied profile, an empty status list or a restarted QML panel cannot prove absence of an effect. Native lookup/reconciliation keeps the original identity. Import, where supplied by a separately qualified operator artifact, verifies the owner-signed original result before acknowledgement.

NQ-01's process runtime requires `DurableAdmissionMode::All`, a durable authority UUID and pinned kernel signer. It registers immutable root limits and child lineage, reserves a shared logical-call slot, then goes through kernel admission for both initial execution and recovery. Its registry explicitly cannot execute tools or reconcile admission. A completed original can replay its stored signed result. An unknown effect remains fenced.

The candidate has a narrowly scoped retry path for declared side-effect-free tools without request-bound authorization artifacts, bounded to three attempts. It changes the derived dispatch attempt while retaining the logical key and earlier unknown records. The proposed Omarchy profile does not enable that exception automatically; the applicable resource and fresh-attempt semantics need separate qualification. Cancellation stops new runtime admissions and can withhold results, while previously admitted effects may complete. OS termination is a separate launcher responsibility.

## Evidence boundaries and contradictions

| Evidence inspected | What it supports | What it does not support |
| --- | --- | --- |
| PI-PUBLIC release guide and retained cold-consumer records | Exact package peers, installed exports/binaries, source tests and consumer dependency lock replay | A compatible current native kernel or an installed Omarchy profile |
| Historical Pi `FINAL-QUALIFICATION.md` | Finite recorded four-tool observations for plugin 0.1.0, Pi 0.85.1 and its pinned kernel/bridge combination | Transfer of I01-I08 acceptance to plugin 0.2.0 / Pi 1.0.2, the nine-tool coding participant or another kernel |
| Current Pi review validation record | Recorded macOS/hosted source and package checks; explicitly retained skips | A new live provider, native kernel, native knowledge/confinement facade or whole-guest Linux pass |
| Linux whole-Pi probe records | Recorded arm64 namespace, filesystem, network, syscall, private-relay and supervision observations under a privileged outer container | Native x64 Omarchy, ordinary Docker defaults, native kernel effects or live model egress |
| Latest confined Linux rerun | An inconclusive rerun with delayed startup and a failed recipe; preserved as inconclusive | A renewed confinement qualification at the reviewed final source |
| Pi `approval-decide` component reproduction | The directly callable bundled `chio-gateway-operator` utility can retain a signed approved credential despite requested denial because requested decision and approval ID are not compared before retention; the current `chio-pi` wrapper already refuses this action before configuration/native work | A live-kernel exploit claim, a claim that the wrapper refusal repairs the bundled utility, or permission to expose desktop approval decisions |
| Native facade TypeScript tests | Ownership checks, frozen binding data and refusal paths | Native authority, cryptographic verification, committed model release, cross-host custody or running services |

Current-source recheck on 2026-10-07 confirms PI-PUBLIC still resolves to the
pinned source. The [wrapper parser](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/operator-cli.ts#L39)
refuses decision retention, but its shipped bridge archive still declares the
separately callable native operator. Archive SHA-256:
`7d9e34f7408a316e35125982a23faaecfd2f31f4da6b50ca8eab287c2c918f67`.
Inside it, `package/dist/gateway-operator.js:147-174` reaches artifact retention
without comparing the signed decision and token ID to the requested values.
The [retained reproduction and mitigation](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/superpowers/evidence/2026-10-04-task2-operator.md#L108)
separate those two surfaces. Remediation belongs to the native bridge owner:
verify both bindings before retention, replace the pinned archive, and test the
direct binary for denial/ID mismatch with no credential retention or subsequent
dispatch. P3 remains blocked until the selected installed replacement passes
that qualification; this research records neither an upstream fix nor a filed
upstream issue.

NQ-05 cage source currently requires Linux x86_64, Linux 6.7 or newer and Landlock ABI 4 or newer. Its retained-file profile rejects writable directory grants and excludes ordinary socket/process creation. Pi's measured whole-guest arm64 bubblewrap profile and a Node coding-resource owner therefore need distinct qualification; they cannot inherit this cage profile by sharing the word confinement.

The CLI's `execution-only` profile still exposes prompts and returned tool content to the selected provider without native knowledge/disclosure governance. `required` refuses before credentials or provider egress when the facade is absent; it must never silently become `execution-only`. The existing protected CLI also accepts the task through `--prompt`; private desktop prompt transport needs an adapter/launcher change or qualified SDK embedding that avoids process argument exposure.

The fixed Codex subscription profile lacks an enforceable hard output-token ceiling. Its time, request and byte bounds remain useful, but bytes are not tokens and a disconnect is not proof that provider computation or billing stopped. The ordinary Responses profile reserves supported output ceilings, including reasoning output, before submission. This still does not create a precise total monetary budget for unknown input/cached-token costs. See [official Responses output-ceiling semantics](https://developers.openai.com/api/reference/python/resources/responses/methods/create) and the pinned [Pi limits contract](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/RUN-LIMITS-LINUX.md). Current [ChatGPT-plan documentation](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations) also lists `max_output_tokens` as unsupported, but describes the `api.openai.com/v1` route, whereas the pinned Pi candidate selects its native Codex backend route. That documentation is not live qualification of the candidate endpoint; route compatibility must be rechecked for the selected installation.

Additional public evidence anchors: [frozen historical qualification](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/FINAL-QUALIFICATION.md), [current release qualification scope](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/RELEASE-QUALIFICATION.md), [retained latest review validation](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/superpowers/evidence/2026-10-05-pr3-review/validation.json), [operator refusal and recovery contract](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/OPERATOR.md). The validation file records past tests; this research did not rerun them.

## Blocking artifacts and responsible owners

All artifacts in this table are proposed deliverables, not files asserted to exist. Owners are responsibility roles to be assigned during implementation.

| Artifact | Responsible owner | Required contents and closure evidence | Blocks |
| --- | --- | --- | --- |
| `native-compatibility-manifest.json` | Chio runtime/release maintainer | Public source identity and delivered binary hashes; native authority/store/process ABI, bridge/operator archives, exact Pi 1.0.2 consumer lock, resource manifest, policies, trust roots and target platform; startup rejection of every incompatible substitution | P0 compatibility; P2 |
| `native-approval-decision-binding.json` | Chio approval/bridge maintainer | Replacement utility archive; pre-retention comparison of decision, approval ID, original request digest, subject/authority and expiry; negative mismatched-approved-token-on-deny case with no retained credential or dispatch | P3 approvals/publication, then P4/P5/P6 |
| `omarchy-x64-confinement.json` | Linux confinement maintainer plus independent verifier | Exact Omarchy/Hyprland/Quickshell/kernel/bubblewrap/Node/loader/seccomp pins; real x64 positive workflow and independent forbidden filesystem, raw socket, subprocess, namespace, `/proc`, restart and link-attack observations | P2 and every released protected x64 profile |
| `pi-current-native-workflow.json` | Pi adapter and coding resource maintainers | Actual kernel plus Pi 1.0.2 task: source read, edit, fixed tests, review artifact, native receipts/history/ACK, cancel and post-effect response loss, restart and exact original recovery; publication absent for P2 | P2; historical four-tool tests do not close it |
| `pi-private-input-transport.json` | Pi launcher/desktop adapter maintainer | Fixed executable and bounded private stdin/FD input; no prompt, context or credential in argv/env/ordinary logs; stock protected SDK behavior and confinement retained | P2 private desktop tasks |
| `native-model-release-profile.json` | Native governance and provider adapter maintainers | Selected native facade/source, runtime writer, installed provider sink, exact frozen prompt/context binding, account identity, commit-before-egress proof, continuation and disclosure enforcement | Any `required` governance claim |
| `provider-limits-profile.json` | Provider adapter maintainer | Per-route supported hard limits, unavailable dimensions, reservations, usage provenance, conservative uncertainty and final billing reconciliation; live route/API behavior rechecked | Per-provider P2 admission and P7 |
| `native-delegation-profile.json` | Process host and Pi adapter maintainers | Native child facade, persistent signing custody, attenuation, aggregate budgets, expiry/cancel races, confined fixed templates and subtree settlement | P6 |
| `cross-host-custody-profile.json` | Durable authority/process maintainer | One selected relocation or remote-worker mode, no overlapping owners, store/ABI validation, fencing, complete original operation transfer and interrupted-handoff recovery | P6 multihost; no live-migration claim by default |
| `omarchy-clean-install-report.json` | Release maintainer plus independent verifier | Clean x64 install of one named profile using only public artifacts; all applicable earlier gates, upgrade/removal/recovery and provenance verified | P7 public availability and support claims |

A read-only P1 desktop prototype can progress while these artifacts are open, provided it labels projections and refuses every unsupported mutation. P2 requires the current native coding and confinement gates. P3 requires the approval replacement. P6 additionally requires actual native child and custody support. P7 names exactly the profile qualified; a release of P2 does not imply optional delegated workers or required disclosure governance.
