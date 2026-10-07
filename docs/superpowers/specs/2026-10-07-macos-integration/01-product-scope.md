# Chio for Mac: product scope and release contract

Status: proposed normative design, 2026-10-07. This document specifies future behavior. It is not evidence of an installed app, implemented north-star kernel, confinement, entitlement approval, or a qualified execution profile. Confidence: high in the approved architectural constraints; moderate in the product sequencing; unknown in the eventual supported OS, entitlement, and runtime matrix.

## Product outcome

Chio.app is a native Mac operator for a modern Rust kernel for agentic operating systems. It lets a person give an agent a bounded job, understand which resources and effects that job can use, review its consequential output, and recover the original outcome after interruption. The first useful demonstration is a real project change that survives malicious repository instructions without exposing unrelated private files or publishing to an unapproved destination.

The initial user is a developer with a committed Git project and a portable toolchain. The product is successful when that person can start useful work from Finder, see an honest account of progress and authority, inspect a sealed result with fixed test evidence, and separately endorse one exact publication. Extension installation is subordinate to that outcome.

Approved basis: [research brief](research/decision-record.md), especially sections 2, 3, 5, 9, and 10; [Mac workflow/API research](research/macos-workflow.md). Architectural prerequisites are owned by [kernel contracts](03-kernel-contracts.md) and [authority and integrity](04-authority-integrity.md). The current source pins are recorded by the program's [source registry](research/source-pins.json), not inferred from historical measurements.

The initial qualification candidate is macOS 15 or newer on Apple Silicon (arm64), subject to the exact OS/build matrix in [qualification](17-qualification.md). This is not a supported-release claim. Older macOS and Intel cells remain deferred until explicitly qualified.

## First workflow

1. A person selects one project folder in Finder and invokes **Run with Chio** through the app's Services entry, or uses the equivalent native Open Project action. Selection opens a task configuration window; it does not start an unbounded shell.
2. The person selects a committed Git revision, enters a bounded task objective, and selects the `project-change-v1` task template. Native capture seals the objective as a separate task-input resource and joins its bootstrap influence before worker readiness. The window displays the full source commit and tree identities, input inventory summary, ignored dirty state, permitted file edits, immutable test command, chosen qualified profile, model/provider, export destination, and budget.
3. The host broker imports the named Git objects into a sealed source generation. The worker receives that generation in an isolated filesystem, no ambient user credentials, no host home mount, and no unrestricted guest egress. The baseline is `vm-project-v1` once qualified. A separately qualified `remote-project-v1` requires visible destination and data-export authority.
4. The agent proposes a change within the template's edit allowlist. A trusted fixed data-only oracle runs outside the candidate worker and guest. Candidate code executes only in the isolated worker; a qualified supervisory lane binds each fixed invocation to the exact sealed candidate artifact and captures bounded attributable outputs for external comparison. The oracle never imports candidate code or executes repository test scripts. Exit code zero, an immutable runner inside the same Python process, or worker-reported PASS cannot establish success. Missing output, premature exit and incomplete or unattributable invocation evidence cannot pass; an unavailable supervisory proof yields unverified. Dependency packages come from a pinned preprovisioned image/cache; arbitrary install hooks and live package downloads are outside this first template.
5. The result is a sealed local artifact consisting of an exact output tree/diff, original source generation, fixed invocation and external oracle identities, exact tested-artifact binding, attributable outputs/completion, execution outcome, relevant influence commitments, and evidence references. The user reviews the result in a native window. Test failure, missing evidence, and an unresolved operation remain visible and prevent a success claim.
6. A separate **Publish…** action creates a concrete proposal under `publication-v1`. The initial target is an explicitly chosen new local artifact or patch file in a selected destination. It never overwrites the live checkout. Git branch publication follows only when its broker has qualified expected-old-revision comparison and original-operation reconciliation. Resource access is not publication approval.
7. A lost response causes the app to query the original native operation identity. The app displays committed, failed, or unresolved outcome and does not replay an uncertain effect with a fresh identity.

`project-change-v1` is a product template identifier introduced by this specification, not an existing kernel API. Its versioned definition contains a reference to the separately sealed user objective, exact edit allowlist, immutable input/case generation, trusted external data-only oracle, exact candidate-artifact and fixed executable/argv binding, wall/CPU/memory/output/spend limits, and required evidence. The shared wire representation and native opaque references are defined only in [operator protocol](06-operator-protocol.md). The app cannot create native authority by constructing a template or an identifier.

## Scope and profile claims

| Profile or feature | Intended value | Required claim boundary |
| --- | --- | --- |
| `observe-v1` | Inspect existing task and host evidence. | Observation has no claim to mediate arbitrary processes or prevent effects. |
| `brokered-v1` | Fixed trusted host operations on bounded resources. | Covers those broker routes only; not arbitrary native code confinement. |
| `vm-project-v1` | Local isolated portable project work. | Qualify the exact host, guest architecture/image, import, transport, network, brokers, lifecycle, and evidence. |
| `remote-project-v1` | Project work at an explicit remote location. | Qualify remote confinement and delegation separately; disclose data export and cost. |
| `native-descendant-v1` | Later Mac-native project work. | Independent coverage and lifecycle gate; cannot inherit VM or Linux evidence. Beta macOS 27 APIs do not establish release support. |
| `managed-endpoint-v1` | Optional organizational restrictions and visibility. | Separate managed-device deployment, multi-user, privacy, operations, and evidence contract. |
| `publication-v1` | Release one reviewed artifact or brokered effect. | Separately gated feature, not an execution profile or automatic consequence of task success. |

The initial project workflow does not promise Xcode/Simulator, host signing identities, arbitrary GUI automation, continuous clipboard ingestion, mailbox reading, or machine-wide protection. Native app capture/drafts and GUI effects have independent contracts in [project resources](10-project-resources.md) and [host adapters](15-host-adapters.md). A later app integration can be useful before its publication route is qualified.

## Threat and trust boundary

Adversarial inputs include repository content and configuration, worker code, model responses, filenames, browser/clipboard/app captures, stale UI state, and restored caches. The qualified profile must prevent those inputs from obtaining new grants, replacing destinations, accessing ambient credentials, or laundering influence through summaries. The design trusts the host OS, selected kernel implementation, trusted brokers and deployment administrator within the stated matrix. Host-root compromise, a compromised authority kernel, and a user deliberately removing the installation are outside the first profile's guarantee.

One Rust kernel owns positive authority, exact endorsement, budgets, stop generations, integrity, and durable operations. Swift displays and requests transitions. Native ES/NE gates can impose additional restrictions. OS permissions, Chio resource grants, and exact endorsements are three independent facts. None substitutes for the other two.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-PRD-001 | The product MUST lead with bounded useful agent work and offer the same task model from Finder, the app, and an authenticated CLI. | AT-MAC-PRD-001 |
| MAC-PRD-002 | The first runnable template MUST use one immutable committed Git tree, a declared edit allowlist, pinned portable toolchain, and fixed tests whose data-only oracle runs outside the candidate worker/guest and evaluates attributable outputs of the exact sealed artifact. | AT-MAC-PRD-002 |
| MAC-PRD-003 | Task configuration MUST disclose input generation, sealed user objective, profile/location, model export, limits, resources, and required review before admission. | AT-MAC-PRD-003 |
| MAC-PRD-004 | Every execution profile MUST remain unavailable until its own exact installed-runtime qualification record passes. | AT-MAC-PRD-004 |
| MAC-PRD-005 | The first workflow MUST keep host credentials, unrelated user files, host service sockets, and unrestricted networking outside worker authority. | AT-MAC-PRD-005 |
| MAC-PRD-006 | Local result creation MUST produce a sealed review artifact, with publication separately gated and no automatic live-checkout overwrite. | AT-MAC-PRD-006 |
| MAC-PRD-007 | OS consent, Chio resource grant, and exact endorsement MUST remain separately explained, represented, and enforced. | AT-MAC-PRD-007 |
| MAC-PRD-008 | The operator and native integrations MUST consume the kernel's positive authority and MUST NOT introduce a Swift approval signer or second authority ledger. | AT-MAC-PRD-008 |
| MAC-PRD-009 | Task state MUST distinguish work, review, blocked permissions, degraded coverage, stop progress, and unresolved external outcome. | AT-MAC-PRD-009 |
| MAC-PRD-010 | Failed, changed, missing, incomplete or unattributable test evidence MUST prevent a verified-result claim; worker PASS text and exit code zero MUST NOT substitute for the trusted external oracle. | AT-MAC-PRD-010 |
| MAC-PRD-011 | Recovery MUST reconcile the original operation and preserve the distinction between admission fenced, worker closed, and remote outcome known. | AT-MAC-PRD-011 |
| MAC-PRD-012 | Scope expansion to dirty imports, native app drafts, GUI actions, or managed deployment MUST require its own resource and qualification gates. | AT-MAC-PRD-012 |
| MAC-PRD-013 | Release copy MUST distinguish source findings, component checks, installed runtime, profile qualification, and public availability. | AT-MAC-PRD-013 |
| MAC-PRD-014 | First-run onboarding MUST request only permissions needed for the selected feature and MUST preserve read-only status/evidence access when optional permissions are declined. | AT-MAC-PRD-014 |
| MAC-PRD-015 | The workflow MUST support keyboard, VoiceOver, privacy-preserving status, localization, and explicit recovery actions before pilot acceptance. | AT-MAC-PRD-015 |
| MAC-PRD-016 | Product acceptance MUST demonstrate useful change completion and blocked malicious effects on the same qualified profile and record actual limits of that evidence. | AT-MAC-PRD-016 |

## Acceptance procedures

All procedures are prospective. The operator recording alone is insufficient when the oracle requires kernel, filesystem, provider, or network evidence.

| Acceptance | Setup/action | Expected independent evidence |
| --- | --- | --- |
| AT-MAC-PRD-001 | Launch the same pinned project/template via Finder Services, native Open Project, and the authenticated CLI in separate fresh runs. | Controller records show the same validated template and source generation semantics; all routes reach preflight; none executes raw incoming text. |
| AT-MAC-PRD-002 | Run the portable fixture after changing its working tree and repository test script. Attempt an out-of-allowlist edit and command replacement. | Imported blob manifest matches the selected committed tree, excluded dirty changes are visible, external oracle/case commitments and supervised candidate invocation match their pins, and out-of-scope changes fail validation; no candidate code loads into the oracle process. |
| AT-MAC-PRD-003 | Compare preflight to the authority record for local and remote configurations; change the selected provider after reviewing. | Every disclosed quantity maps to the admitted native record; provider change forces refreshed preflight and data-export evaluation. |
| AT-MAC-PRD-004 | Remove qualification evidence for ARM64 guest, then install an x64-only record and a source-only record. | VM task start stays unavailable in all three cases with exact missing gate; observing tasks still works. |
| AT-MAC-PRD-005 | Insert instructions and code attempting home/Keychain/socket reads, arbitrary DNS/HTTPS, and raw provider use. | External canaries remain untouched, no uncontrolled egress appears in the controlled capture, and each denial has attributable evidence; a log statement alone does not pass. |
| AT-MAC-PRD-006 | Complete a valid task, inspect the selected live checkout, then export a reviewed artifact to a new file. | Live checkout byte/inode inventory is unchanged; result manifest verifies; export uses a distinct admitted operation and exact reviewed artifact. |
| AT-MAC-PRD-007 | Grant folder OS access but no run grant; grant read authority but no publish endorsement; then issue a valid exact endorsement. | The first two effect requests deny independently; only the exact third request can proceed under the authority contract. |
| AT-MAC-PRD-008 | Inspect built app/extension entitlements, storage, signer use and IPC traces; attempt a forged UI approval. | No app-owned approval private key or independent authority store exists; native verifier rejects forged references and stale binding. |
| AT-MAC-PRD-009 | Drive each state with scripted controller fixtures and real interruption cases. | Labels and enabled actions match the authoritative state; missing permission never appears as awaiting human effect approval; unresolved never appears successful. |
| AT-MAC-PRD-010 | Run greeting variants that patch unittest.TestCase.assertEqual then return wrong bytes, call os._exit(0), print PASS or a forged pass object, and return empty output. Alter oracle/artifact identity, omit completion, truncate output and replay another invocation. | Every malicious case is failed or unverified with no passed result; the host oracle remains intact and only exact expected data from the attributed sealed-artifact invocation can pass. Unproved supervisory attribution remains unverified. |
| AT-MAC-PRD-011 | Lose a response after publication intent and kill/relaunch the operator. | Query targets the original native operation; one effect and one budget charge at most; UI retains unknown outcome until broker reconciliation establishes it. |
| AT-MAC-PRD-012 | Request dirty import, GUI send, and app draft with only first-profile gates present. | Each unavailable feature has a named missing contract; there is no permissive fallback to live directory copying or generic AppleScript. |
| AT-MAC-PRD-013 | Audit app About, website release copy, generated evidence labels, and support diagnostics against the release manifest. | Every enabled claim has exact matrix evidence and public availability proof; proposed design and beta APIs stay labeled. No private repository URLs appear in public material. |
| AT-MAC-PRD-014 | On a clean user account deny notifications and optional endpoint approvals, then inspect status/evidence and start the project preflight. | Base UI remains usable; only dependent features block; permission prompts occur only after the relevant action. |
| AT-MAC-PRD-015 | Perform configure, review, decline, stop and recovery using keyboard and VoiceOver; repeat with long localized strings and privacy mode. | Recorded task completion, readable exact destinations, no focus traps, no hidden approval button, and no confidential status preview. |
| AT-MAC-PRD-016 | Complete one useful portable change and the hostile variant under the same versioned host/guest image. | Accepted diff, protected-test pass, blocked canary attacks, separately approved exact export, and independently verified evidence bundle identify the exact matrix and unresolved gaps. |

## Delivery dependency

M1 can build a read-only native operator. After M0 kernel prerequisites, M2 authenticated protocol/controller and M6 durable recovery, M4 resource/provider foundation supplies sealed task input, immutable import, path/materialization validation and native model access before M3 runs its first useful project task. In the resource plan these are Tasks 1, 3, 2 and 5 in dependency order. M3 backend Tasks 1-7 can then provide VM transport, native dispatch and lifecycle; M4 Task 4 integrates external-oracle output sealing on that backend. VM qualification and M4 publication/integrated acceptance follow. M3 does not depend on completed M4 publication, and M4 foundation does not depend on a VM. Numeric work-package identifiers are tracks, not an instruction to bypass their dependencies. Profile release is owned by [qualification](17-qualification.md); product usefulness does not waive any profile gate.
