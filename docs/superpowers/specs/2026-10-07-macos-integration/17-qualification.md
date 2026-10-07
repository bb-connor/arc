# 17. Independent profile qualification and release evidence

Status: proposed normative design. No Mac profile is qualified by these specifications, source inspection, schema validation, or synthetic fixtures. Confidence: high in the need for independently observed enforcement and exact tuple binding; unknown for the eventual installed results. Dependencies: every selected profile's applicable specifications, [distribution](12-distribution.md), [privacy/performance](13-privacy-performance.md), [operations](14-operations.md), and the native kernel prerequisite track.

## Evidence ladder and release decision

`source` means an inspected pinned implementation contains a mechanism. `component` means a bounded harness exercised a component. `installed_runtime` means the signed installed composition was observed on a recorded host. `qualified` is a separate conclusion produced only by semantic verification and independent review of the complete selected profile. A source branch, passing Swift test, signed provider, activation callback, or fixture result cannot be relabeled as runtime qualification.

The [release evidence schema](contracts/release-evidence.schema.json) describes a **candidate** evidence envelope. Its `status` is `candidate`; it cannot self-assert qualified status. The document checker validates structure, references, and synthetic rejection examples only. The future semantic verifier must independently consume artifact bytes, trusted native proofs, the immutable applied profile manifest, installed observations, and externally configured trust roots. Only its separate verified-qualification artifact may be admitted through the native evidence path for compatibility's `qualified_for_tuple` state. A JSON schema accepting a digest-shaped string proves nothing about the referenced bytes.

## Qualification bootstrap without a production bypass

Production profile admission requires the actual verified-qualification artifact for the exact installed tuple. Before that artifact exists, initial installed evidence comes from a dedicated signed laboratory probe with a distinct code identity, executing the exact installed driver/runtime bytes under explicit native fixture authority. The probe runs on an isolated test-user or VM-host environment, restricted to enumerated synthetic resources, test accounts, and controlled receivers. Its fixture authority binds the probe identity, run nonce, installed tuple, resource/destination scope, budgets, and expiry. Native approval, integrity, crossing, stop, and recovery checks continue to apply. Missing fixture authority closes the experiment.

The probe is not a user-profile launch, does not set `qualified_for_tuple`, and cannot report release success. Production app/controller binaries expose no `--skip-qualification`, unsafe feature flag, environment override, test principal impersonation, or equivalent bypass. The probe cannot silently rebuild a different driver for successful cases; separately altered negative-control fixtures carry their own code digests and cannot be substituted for the exact installed candidate. A native fixture-authority contract must be delivered and verified by the kernel prerequisite owner if none exists; the probe does not invent a local grant facade.

The immutable manifest separates candidate-evidence requirements from a final production-admission confirmation gate, avoiding a circular prerequisite. First, independent semantic verification evaluates the full candidate-evidence set and constructs the scoped verified-qualification artifact. Then the lab re-exercises the ordinary production admission path with that actual artifact, exact installed bytes, and narrowly scoped ordinary native test authority. Missing, forged, wrong-tuple, or revoked qualification references must still refuse admission. The confirmation records the immutable artifact digest and outside useful-effect/denied-effect controls; it neither rewrites the artifact nor replaces the original evidence. Final release approval requires both the independently verified artifact and this passing production-path confirmation.

The envelope's `synthetic` flag distinguishes fabricated/component fixture evidence from real installed observations. Real observations obtained using synthetic test documents, secrets, accounts, and controlled receivers remain installed evidence when their provenance and controls are verified; choosing safe test data does not make the observations fabricated.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-VER-001 | Evidence MUST distinguish source, component, installed runtime, and independently qualified conclusions; the candidate schema and document validator MUST NOT issue runtime qualification. | AT-MAC-VER-001 |
| MAC-VER-002 | Every profile candidate MUST bind `appliedProfileManifestDigest` to an immutable pre-run applicability manifest containing the exact tuple, required case set, observation class, controls, and release gates; omitted required cases MUST fail. | AT-MAC-VER-002 |
| MAC-VER-003 | Qualification MUST pin source revisions, patches, final installed code, signing and provisioning evidence, active provider versions, host/guest architecture, exact OS build, SDK/toolchain, policy, native generation, and harness/observer identities. | AT-MAC-VER-003 |
| MAC-VER-004 | Every security-critical installed test MUST include an independent positive control and an intentional negative control proving the oracle can detect the prohibited effect or broken guarantee. | AT-MAC-VER-004 |
| MAC-VER-005 | Profile and publication claims MUST follow the explicit matrix below; evidence from VM, native, managed, remote, another architecture, or another OS/provider tuple MUST NOT substitute without new applicable acceptance. | AT-MAC-VER-005 |
| MAC-VER-006 | Native kernel prerequisites MUST verify exact approval, integrity, budgets, stop order, crossing ownership, and original-operation recovery; initial installed evidence MUST use the dedicated signed probe and explicit scoped native fixture authority, while production profile admission MUST require verified qualification with no bypass. | AT-MAC-VER-006 |
| MAC-VER-007 | Project, VM, broker, and remote qualification MUST attempt real boundary bypasses and observe external effects, including direct egress, inherited handles, resource substitution, credential access, and unknown-outcome replay. | AT-MAC-VER-007 |
| MAC-VER-008 | ES/NE-dependent profiles MUST separately qualify identity, coverage, queue gaps, deadline misses, provider death, stale policy, cached authorization, existing flows, and unrelated host behavior. | AT-MAC-VER-008 |
| MAC-VER-009 | Approval, integrity, delegation, and publication qualification MUST include adversarial input and changed-binding races with independently observed destination and payload. | AT-MAC-VER-009 |
| MAC-VER-010 | Stop, revocation, logout, sleep, restart, backup restore, and downgrade qualification MUST distinguish intent order, actual process/network closure, authoritative freshness, and unresolved external effects. | AT-MAC-VER-010 |
| MAC-VER-011 | Multi-user and permissions qualification MUST cover standard/admin accounts, lock, fast switching, logout, no logged-in user, denial/revocation, and managed/unmanaged deployment where claimed. | AT-MAC-VER-011 |
| MAC-VER-012 | Distribution qualification MUST start from a clean consumer installation with normal security settings and test update, rollback, interruption, removal, and retained data using the final signed bytes. | AT-MAC-VER-012 |
| MAC-VER-013 | Privacy and performance qualification MUST use the same installed profile and exact workload baseline as the release claim, with raw samples, secret canaries, retention tests, and explicit inconclusive energy results. | AT-MAC-VER-013 |
| MAC-VER-014 | The semantic verifier MUST independently validate artifact hashes, signer trust and native proofs, tuple/order/identity consistency, required coverage, control efficacy, expectation-to-observation predicates, freshness, and missing evidence; candidate booleans MUST NOT suffice. | AT-MAC-VER-014 |
| MAC-VER-015 | Qualification artifacts MUST be content-addressed, provenance-preserving, bounded, safely parsed, privacy-reviewed, and reproducible from a documented runbook with source and installed evidence kept separate. | AT-MAC-VER-015 |
| MAC-VER-016 | A failed, skipped, unavailable, gapped, synthetic, or inconclusive required case MUST close the affected release gate; selective reruns MUST retain prior failures and a reasoned invalidation scope. | AT-MAC-VER-016 |
| MAC-VER-017 | Installed drift, revoked trust, schema change, provider replacement, policy change, and relevant OS updates MUST invalidate affected qualification until the predefined rerun policy passes. | AT-MAC-VER-017 |
| MAC-VER-018 | Final release review MUST be independent of the implementer, require a passing ordinary production-admission confirmation using the actual verified-qualification artifact, and reconcile user-visible claims with its exact scope, exclusions, and unresolved outcomes. | AT-MAC-VER-018 |
| MAC-VER-019 | The macOS 27 descendant track MUST resolve documentation/SDK metadata drift and pass final-OS descendant-specific adversarial cases independently; another profile's success MUST NOT open it. | AT-MAC-VER-019 |
| MAC-VER-020 | Regression tooling MUST include malformed and semantically fraudulent candidate bundles that pass basic shape checks, demonstrating that structural validation cannot become a release oracle. | AT-MAC-VER-020 |

## Immutable applicability and support matrix

The release owner signs or otherwise authenticates the applied profile manifest under a reviewed release policy before the run. It enumerates exact acceptance IDs and subcases from this specification set, their required evidence classification, expected predicate, prerequisite case edges, oracle implementation digest, positive/negative control fixture digests, and fixed thresholds. Group labels below are planning aids; the actual manifest expands them into concrete acceptance IDs. The semantic verifier rejects duplicate case identities, missing required subcases, unexpected profile substitution, unbound additional cases, and an untrusted or post hoc changed applicability manifest.

A case may be genuinely not applicable only when the pre-run profile manifest explains the absence of that capability. For example, no ES provider is required for a VM profile that never claims ES enforcement. That is not a skipped required test. Each profile manifest must still include a negative case proving absent capabilities cannot be selected or advertised. Feature `publication-v1` adds its full publication/resource/approval/recovery cases to the chosen execution profile. It is not a seventh execution profile.

`restore_freshness_ref` may be `null` only when the approved pre-run manifest excludes authority restoration and requires an installed refusal test for attempted authority restore. Any authority-restore claim requires a non-null current proof validated by the native freshness owner. Historical inspection and an application's ability to read a backup do not satisfy that proof requirement.

| Profile or feature | Required installed scope beyond common operator/distribution/privacy/operations | Mandatory attack and independent oracle | Explicit exclusion until separately qualified |
| --- | --- | --- | --- |
| `observe-v1` | Authenticated read-only views, evidence inspection, bounded sensors actually selected | Forged task create/approval/publish requests produce no native authority commit; external effect counter remains zero; known synthetic events verify observation gaps honestly | No mediated execution or confinement claim; observation does not become protection. |
| `brokered-v1` | Exact typed host broker routes, credential isolation, native crossing/return/output-release records | Allowed broker effect succeeds; bypass through direct socket, alternate API, changed handle/destination, or stale approval is refused at the declared boundary; destination observes exact payload | Arbitrary unmediated agent process behavior outside those routes. |
| `vm-project-v1` | Qualified Virtualization guest architecture/image, launch and lifetime identity, guest transport, import/export, guest network/devices/shares and brokers | Compromised guest attempts host path/socket access, direct egress, credential theft, forged broker request, and snapshot replay; outside host sentinel and destination counters prove denial; useful task still completes | Native process confinement or Intel support inferred from Apple silicon; host brokers retain their own trusted boundary. |
| `remote-project-v1` | Both local and remote tuples, identity/transport binding, remote runtime custody and route, remote stop and reconciliation | Disconnect/replay/reorder replies, duplicate client intent, stale remote generation, and local stop while remote intent is precommitted; remote independent observer and destination counter establish actual effects | Local VM evidence substituting for remote confinement; local disconnect proving remote termination. |
| `native-descendant-v1` | Final SDK/OS-specific descendant ES semantics plus every required native filesystem/network/broker boundary | Pre-existing child, fork/exec, reparenting, delegated service, inherited FD/socket, client death, deadline miss, PID reuse, and coverage gap; independent host observer verifies actual side effects | System-wide managed endpoint coverage or protection after an unproven client-loss window. |
| `managed-endpoint-v1` | Real managed payloads, global ES/NE identities, multi-user routing, no-user behavior, admin-policy precedence | Wrong-team policy, user withdrawal, provider crash, stale policy, global queue pressure, cross-user query, and unrelated app availability; outside process/network observers plus MDM records | Task approval from MDM; semantic control of arbitrary app actions not mediated by a native contract. |
| `publication-v1` | Exact preview/binding, current resource generation, final destination/payload, budget and stop recheck, reconciliable external effect | Change diff, recipient, branch, policy, relevant influence, or generation after review; lose effect reply; independent destination records zero changed-binding effects and one original permitted effect | General GUI publish where stable operation identity and outcome reconciliation are absent. |

Proposed base app experiment uses arm64/macOS 15.0 deployment target. Qualification is per exact OS build, not simply “15+”. Each selected supported final OS build gets a separate row. Intel/x86_64 and Rosetta rows remain unavailable until actual installed execution, guest architecture, and dependencies pass. ARM64 Linux guest evidence cannot borrow x86_64 cage qualification. An OS build that compiles a symbol but lacks the qualified runtime behavior is closed. Provider code, subscription/policy configuration, guest image, and dependency changes can invalidate a row even when the app version is unchanged.

Model/provider adapters also bind endpoint/account scope, SDK and adapter version, requested model identifier, server-returned model/version where supplied, and request/response semantics used by the case. A moving remote model alias cannot establish reproducible model behavior; qualify the broker's enforced boundary separately and state the remote uncertainty. Do not confuse a model-service provider with the local ES/NE provider components. Compatibility equivalence after a version change requires a reviewed impact map and new applicable installed cases, not a version-range assumption.

## Adversarial case families

Each family below has distinct same-run controls. The positive control demonstrates useful allowed behavior. The negative control deliberately removes or corrupts one enforcement mechanism in a disposable harness outside production release configuration, so the outside oracle sees the forbidden effect or the verifier rejects the claim. Negative controls may never be shipped as a production runtime toggle. Use synthetic secrets and destinations only.

| Family | Adversarial procedure | Outside evidence required |
| --- | --- | --- |
| Authority and review | Commit approval for action A, mutate one bound field to B, supply attacker instructions in repo/document/browser return, race stop before/after intent | Native signature/proof verification plus external destination request identity, payload digest, order, and count. |
| Resource generation | Concurrent dirty writer, held writable FD, symlink substitution, rename/mount change, changed checkout before artifact application | Independent content snapshots and outside sentinel files; a self-reported pre/post hash does not prove a coherent snapshot. |
| Identity | Two identical runtimes, PID reuse, exec transition, launch reparenting, spoofed XPC principal, stale session mapping | OS process/audit identity captured outside the component; native run association verified through trusted record. |
| Network | Direct IP, DNS rotation, UDP/QUIC, HTTP keep-alive, HTTP/2 multiplexing, inherited socket, loopback and Unix sockets, bytes released before stop | Controlled receiver with connection/request/byte timestamps and packet observer; no “socket closed” inference from missing log messages. |
| Native callback failure | Omit reply, exceed deadline, saturate queue, kill/disconnect client, drop events, withdraw extension, change cache/policy generation | External file/exec/network effect measurement, actual callback deadlines, gap counters, active provider state; deadline miss and client death are different cases. |
| Recovery | Lost broker response, controller power loss, guest crash, sleep/reboot, keychain loss, old database/VM snapshot/full-home restore, code downgrade | External effect counter plus current native custody/freshness owner independent of restored state; no green result from a consistent but stale hash chain. |
| Shared Mac | Simultaneous users, active-user switch, lock/logout, no user logged in, reused account UID | Cross-user canaries, protected-path permissions, notification recordings, authenticated requester identity, and external task-effect counters. |
| Supply chain | Wrong signer, missing entitlement, altered nested helper, stale provisioning, replayed release manifest, retained old provider after update | Independent platform code assessment and extracted entitlements/profile, active installed code census, authenticated release metadata. |
| Evidence fraud | Valid-shaped random hashes, missing artifacts, forged pass booleans, duplicate/omitted cases, wrong tuple, stale run replay, fabricated observer signature | Verifier rejection against separately configured trust and actual artifact store; mutable fixture expectations cannot authorize themselves. |

## Semantic verifier algorithm

Proposed implementation belongs under `integrations/macos/qualification/verifier/`, separate from document validation. Native cryptographic verification delegates to the existing native verifier API or a prerequisite delivered by the kernel track; a Python/Swift parser cannot mint a substitute proof. If the native API is unavailable, verification returns unavailable and qualification stays closed.

Before step 1 reads candidate bytes, the signed LabCurator must supply held-root custody through the proposed native [`MacQualificationCaptureV1` read/capture contract](03-kernel-contracts.md#mac-operation-disposition-crosswalk), delivered by [M0 Task 3](../../plans/2026-10-07-macos-integration/00-kernel-prerequisites.md#task-3-issue-precise-native-owner-handoffs). It enrolls the private root before candidate ingestion, seals its inventory and candidate/manifest/policy commitments, and launches the pinned verifier with inherited `rootFD`/`proofFD`. Native consumption verifies the actual child incarnation and fresh native challenge, enrolled root generation, current read boundary and validity, then atomically consumes the one-use attestation. Missing support returns `native_capture_contract_unavailable` before parsing; a CLI path, matching inode, candidate-provided signature or component fixture cannot satisfy custody. The verified context establishes provenance and bounded read permission only. It cannot authorize lab fixture execution, production work or its own qualification verdict.

1. Parse bounded candidate bytes with duplicate-key rejection, supported schema version, and exact profile enumeration. Reject `synthetic=true` for release. Read trusted roots and approved profile-manifest digest from verifier configuration outside the candidate bundle; do not trust the candidate's requested verifier identity.
2. Resolve `appliedProfileManifestDigest` from an immutable content-addressed store. Rehash its bytes, verify its publisher policy/signature and pre-run binding, and load its explicit required case/subcase set, tuple, thresholds, observer contracts, controls, and freshness policy. An attacker-authored manifest containing one passing test is insufficient.
3. Resolve every artifact under a safe bounded root, rejecting missing content, traversal, symlinks, hash mismatches, decompression bombs, duplicate conflicting records, and prohibited secret material. Recompute bytes rather than trusting names or lengths.
4. Reconstruct the installed tuple from independent signing/provisioning and active-runtime observations. Check downloaded/installed/active code correspondence; host and guest architectures; OS/SDK/toolchain; native generation; policy; run nonce; authenticated host pseudonym; boot/session associations; and observation times. Reject a source digest substituted for an installed measurement.
5. Verify native signatures, hash-chain relationships, receipt commitments, exact approval/influence binding, stop order, original-operation identity, budgets, and applicable current restore freshness through native verifier contracts. Validate native fixture authority for each initial lab-probe observation, including code identity and resource/destination scope. A null restore reference is accepted only under the manifest's authority-restoration exclusion and passing refusal case. Sensor event numbers are not native crossing order, and local transport request IDs are not operation IDs. A presented chain must not establish its own freshness.
6. Verify independent observer identity and its captured transcript, expected predicate digest, and same-run controls. The observer must be outside the component whose statement it tests. A provider's own denial counter is not an outside filesystem/network oracle. Native verifier proof is an authority oracle, not proof that a downstream system actually performed or blocked an effect.
7. Derive verdicts from observed records and immutable expected predicates, not the candidate's `result` strings. Require successful useful positive controls and effective intentional negative controls. A negative control that also observes no effect cannot validate a no-effect oracle. Handle pre-stop committed intent according to native semantics instead of falsely demanding zero effects after the user's click.
8. Compare complete required candidate-evidence coverage and classifications, enforce its gates, and preserve failure/gap/unavailable/skipped status. Recompute percentiles, performance thresholds, and energy uncertainty. Missing proof of closure remains unknown. Retain all attempts and explain the rerun's supersession boundary. Do not omit candidate cases by relabeling them as final production confirmation.
9. Emit a separate verified-qualification report binding candidate digest, applied profile manifest digest, exact tuple, trusted verifier identity/version, trust-root digest, complete derived candidate-case outcomes, limitations, valid claim set, and invalidation policy. The native compatibility owner accepts only its verified evidence reference. Re-exercise ordinary production admission using this immutable report, then separately verify the manifest's final production-confirmation gate before release approval. A review signature attests this scoped conclusion, not arbitrary runtime behavior on other machines.

The verifier can conclude an enforcement test passed only if the actual expected effect was absent under enforcement and present in the intentional bypass control, or another independently sufficient oracle explicitly defined by the case established the guarantee. Some cases instead expect explicit refusal or unverifiable evidence; their negative controls corrupt that predicate and demonstrate rejection. Timing assertions require known clock-domain mapping and uncertainty. Callback sensor time, app UI time, native commit order, and remote receiver time must not be silently treated as one perfectly synchronized clock.

## Invalidation and result handling

A required unavailable entitlement, inaccessible clean host, missing external observer, invalid native proof, dropped required observation, or missing current freshness proof is a closed gate. It is not a waiver. The optional profile may be removed from the release claim through a new reviewed applicability manifest, with its unavailable status retained in the evidence history. Changing the claim is different from passing its tests.

OS/provider/runtime changes rerun all cases whose mechanism or environment can change; the predeclared impact map must include installation, permissions, identity, failure behavior, and negative controls when their component changes. Narrow component tests may triage a regression but never renew the installed profile alone. New release candidates rebind final signed bytes and installed observation. Historical Linux or source-component measurements remain reference material.

## Acceptance procedures

### AT-MAC-VER-001: Evidence class laundering

Take a source-only and component-only result, alter the surrounding candidate to request a runtime claim, and run both the structural and semantic validators. Oracle: shape may pass for valid envelopes, but semantic verification refuses the missing installed evidence and emits no qualified artifact. Artifact: `evidence-classification-controls.json`.

### AT-MAC-VER-002: Immutable applicability enforcement

Use an approved pre-run manifest, then remove one required case, substitute a one-case attacker manifest, alter thresholds after the run, and duplicate a case under another name. Oracle: each negative is rejected by content/signature/pre-run binding or coverage checks; exact complete case set passes this stage. Artifact: `applicability-controls.json`.

### AT-MAC-VER-003: One-dimension tuple substitution

Mutate each tuple dimension separately, including active provider digest while preserving embedded provider bytes and guest architecture while keeping host architecture. Oracle: semantic verification names the mismatched dimension and refuses the release conclusion. Artifact: `tuple-substitution.json` with one immutable original installed transcript.

### AT-MAC-VER-004: Oracle efficacy controls

Run an allowed synthetic write/network request, a correctly denied forbidden request, and a disposable bypass fixture that performs the forbidden effect. Disconnect the outside receiver for a negative oracle-health case. Oracle: expected useful and forbidden effects are distinguishable; absent/unhealthy receiver makes the result inconclusive instead of a false deny pass. Artifact: `oracle-efficacy.json`.

### AT-MAC-VER-005: No inherited profile qualification

Supply a VM candidate to a native profile, arm64 evidence to x86_64, local results to remote, and execution-only evidence to `publication-v1`. Oracle: all substitutions fail exact profile and applicability checks, while the original scoped candidate remains unchanged. Artifact: `profile-substitution.json`.

### AT-MAC-VER-006: Native prerequisite proof

Verify the prerequisite kernel suite, then replace its proof with a design document, forged signature, stale policy, stale approval, or reused budget evidence. Before qualification exists, run the exact installed bytes through the signed lab probe with scoped native fixture authority; omit that authority, substitute probe identity, target an unlisted resource, and request an ordinary production launch in negative cases. Oracle: native verification rejects every substitute; only properly authorized lab probes execute synthetic-resource tests, and production admission remains closed. Inspect production binary/options and exercise attempted `--skip-qualification`/environment overrides to confirm no bypass exists. Artifact: `native-prerequisite-binding.json` with probe signature, driver digest, fixture-authority proof, and outside effect counters.

### AT-MAC-VER-007: Actual execution bypass suite

For each applicable broker/VM/remote row, complete one useful project and attempt the listed direct host/egress/credential/snapshot bypasses with outside sentinels. Oracle: allowed work completes, forbidden destinations remain untouched under enforcement, bypass controls touch them, and original-operation retry cannot duplicate the effect. Artifact: `execution-boundary-matrix.json`.

### AT-MAC-VER-008: Provider failure distinction

Exercise callback deadline miss, queue flood, provider process death, disconnect, stale policy, cache reuse, existing-flow revocation, and unrelated app activity separately. Oracle: independent filesystem/network effects match each declared failure policy; no deadline-mode evidence is reused as client-death proof; attribution gaps fail coverage. Artifact: `provider-failure-matrix.json`.

### AT-MAC-VER-009: Adversarial review and publication

Inject task-hostile instructions through repository, document, browser, and delegated return; after exact review change destination, diff, policy, or relevant influence. Oracle: native binding rejects stale endorsement and independent receiver records no changed-action publication; original approved action succeeds once. Artifact: `review-publication-adversarial.json`.

### AT-MAC-VER-010: Lifecycle and restore matrix

Race stop at each intent boundary, hold child/flow/remote reply, then sleep, reboot, restore pre-spend state, and downgrade code. Oracle: native ordering and current freshness reconcile originals; process/network/external states remain distinct; stale authority cannot produce a new effect. Artifact: `lifecycle-restore-matrix.json`.

### AT-MAC-VER-011: Shared user and permission matrix

Run standard/admin, two-user, locked, logged-out, switched-user, and no-user cases with each claimed consumer/managed policy. Revoke each required OS permission in turn. Oracle: independent user-specific canaries and effect counters show isolation and precise profile closure without permission escalation. Artifact: `user-permission-matrix.json`.

### AT-MAC-VER-012: Final artifact consumer cycle

An independent tester downloads and installs only final signed bytes on the approved clean image, runs allowed and denied work, upgrades, interrupts upgrade, rolls back, and uninstalls. Oracle: platform assessments, active component census, outside effects, and retained-data inventory satisfy the distribution contract. Artifact: `consumer-cycle.json`.

### AT-MAC-VER-013: Same-profile privacy and cost

Run privacy canaries, retention overflow, 30-sample latency workloads, and paired energy sessions on the exact installed candidate; substitute a faster unconfined baseline result as a negative. Oracle: verifier rejects tuple/workload mismatch and reports real privacy/budget failures and inconclusive energy honestly. Artifact: `privacy-performance-binding.json`.

### AT-MAC-VER-014: Independent semantic verdict

Provide a fully populated candidate with `pass` everywhere but altered artifact bytes, fabricated signature, stale freshness proof, broken control, or contradicted observation. Oracle: semantic verifier derives rejection independently and returns no accepted native qualification reference. A valid synthetic fixture may validate the verifier in component mode but cannot release a profile. Artifact: `semantic-verifier-adversarial.json`.

### AT-MAC-VER-015: Safe artifact replay

Replay a public synthetic runbook from its pinned inputs; attempt path traversal, oversized compression, symlinked artifact, missing content, and secret-bearing evidence. Oracle: verifier safely rejects malformed artifacts and privacy review blocks disclosure; complete bytes reproduce the same scoped verdict. Artifact: `artifact-custody.json`.

### AT-MAC-VER-016: Failure and rerun honesty

Mark a required case failed, skipped, unavailable, gapped, and inconclusive across separate candidates; rerun only a passing subset. Oracle: all required gates remain closed, prior attempts remain retained, and a fresh complete impacted-case run is needed before a successor verdict. Artifact: `result-accounting.json`.

### AT-MAC-VER-017: Qualification invalidation

After a valid installed fixture result, replace provider code, policy, OS build, trusted key, schema, and broker dependency separately. Oracle: compatibility no longer serves the old qualified tuple for affected work and requires the predeclared impacted cases; read-only history remains accessible. Artifact: `invalidation-matrix.json`.

### AT-MAC-VER-018: Independent release review

After independent verification constructs the scoped qualification artifact, use its actual native-verified reference in the ordinary production admission path on the same exact installed tuple with bounded ordinary native test authority. Complete one useful allowed effect and one denied-effect control, then repeat with missing, forged, wrong-tuple, and revoked qualification references. Oracle: valid qualification and native task authority are both necessary, denied variants cause no outside effect, and probe-only evidence cannot itself select a user profile. A reviewer who did not implement the profile compares this confirmation, artifact digest, case manifest, public instructions, UI availability, and release claims. Every advertised capability needs the exact verified reference and passing production confirmation; unavailable rows and unresolved remote outcomes remain explicit. Artifact: `production-admission-confirmation.json` plus `release-review.json` with reviewer identity and scoped decision.

### AT-MAC-VER-019: Final descendant qualification

Save rendered Apple metadata and DocC metadata, inspect final selected SDK availability, then execute descendants created before/after client creation, recursion, exec, reparenting, delegated services, inherited handles, client death, and deadline stress. Oracle: exact observed coverage and failure states meet the selected native contract or the profile stays closed; beta labels or source presence alone cannot pass. Artifact: `descendant-final-os.json`.

### AT-MAC-VER-020: Shape-valid fraud corpus

Construct schema-valid candidates containing digest-shaped random values, all-pass cases with no bytes, attacker trust root, substituted profile manifest, fabricated observer transcript, stale native proof, and relabeled component evidence. Oracle: document checker accepts shape where appropriate, while semantic verifier rejects every fraudulent release claim with a specific reason. Artifact: `shape-versus-semantic.json` and mutation corpus.
