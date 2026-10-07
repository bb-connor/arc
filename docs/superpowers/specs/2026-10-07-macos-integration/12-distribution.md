# 12. Distribution, installation, and release lifecycle

Status: proposed normative design, not a shipping support claim. Confidence: high in Apple's cited lifecycle requirements, moderate in this packaging proposal, unknown for entitlement grants and installed acceptance. Dependencies: [host architecture](05-host-architecture.md), [operator protocol](06-operator-protocol.md), [recovery](11-state-recovery.md), [operations](14-operations.md), and [qualification](17-qualification.md). Primary-source findings and explicit proposed decisions are recorded in [distribution research](research/distribution.md).

Chio is a modern Rust kernel for agentic operating systems. The Mac app distributes a native operator and the qualified runtime needed for bounded work. Packaging cannot supply missing kernel authority, and a signed application cannot turn an unqualified execution profile into a supported one.

## Package and compatibility model

The initial candidate is a Developer ID signed and notarized direct-distribution app delivered in a signed disk image. A managed package may install that same verified app but receives separate lifecycle acceptance. Proposed contents are `Chio.app/Contents/MacOS/Chio`, bundled controller and broker helpers under `Contents/Library`, and selected system extensions under `Contents/Library/SystemExtensions`. Runtime and guest image assets have fixed manifest digests. Exact bundle IDs and Team ID come from the real signing allocation; example strings are never an entitlement grant.

Proposed first build target: macOS 15.0, arm64, Swift native UI with a Rust controller. This is a deliberately selected experiment baseline, not an API minimum or current support promise. Release candidates must pass exact final OS builds selected in the immutable profile manifest. x86_64, Rosetta-hosted execution, earlier systems, and macOS 27 descendant execution are separate rows, closed by default. Public requirements list only rows with qualified installed evidence. Native providers are optional per profile, so observation and VM capabilities do not automatically require ES, NE, Full Disk Access, Accessibility, or screen capture.

Apple requires containing-app embedding and checks activation eligibility. System-extension activation is performed by the app using the SystemExtensions framework, while `SMAppService` manages the chosen background helper. The app records separate installation, signature validity, entitlement availability, registration, user approval, activation, configuration, convergence, and qualified-runtime states. [Apple extension installation](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers), [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-DST-001 | Every distributed candidate MUST bind immutable public source revisions, dependency locks, vendored patches, build tools, unsigned content digests, final signed artifact digests, licenses, and an SBOM; unpublished revisions MUST NOT appear in public checkout instructions. | AT-MAC-DST-001 |
| MAC-DST-002 | Every executable and nested bundle MUST pass the selected Developer ID, hardened-runtime, timestamp, entitlement allowlist, and nested-signature checks before submission; development debug entitlements MUST be absent. | AT-MAC-DST-002 |
| MAC-DST-003 | The final distribution artifact MUST have a successful notarization record and applicable stapled-ticket validation, followed by clean consumer launch with normal platform security settings. | AT-MAC-DST-003 |
| MAC-DST-004 | Provider packaging MUST use the containing app, allowed embedding location, matching publisher identity, granted capabilities, and exact provisioning profile for each direct-distribution extension type. | AT-MAC-DST-004 |
| MAC-DST-005 | Installation MUST leave optional execution profiles unavailable until their individual OS permissions, provider activation, configuration, and runtime gates pass; denied permissions MUST preserve useful permitted features. | AT-MAC-DST-005 |
| MAC-DST-006 | Supported OS, hardware, architecture, guest, provider, protocol, and state-schema combinations MUST be an explicit immutable matrix; missing or changed dimensions MUST invalidate the affected profile. | AT-MAC-DST-006 |
| MAC-DST-007 | Installed runtime selection MUST use package-owned absolute paths and manifest-pinned code; ambient PATH, user shell files, dynamic library injection, and floating downloads MUST NOT select executable authority components. | AT-MAC-DST-007 |
| MAC-DST-008 | Updates MUST verify publisher trust, payload digests, signed metadata generation, expiry policy, and compatibility before activation; rejected updates MUST leave the prior compatible custody path available. | AT-MAC-DST-008 |
| MAC-DST-009 | An update MUST durably fence affected new admission, reconcile original operations, and journal staging, migration, provider replacement, remeasurement, and activation; a mixed generation MUST NOT admit governed work. | AT-MAC-DST-009 |
| MAC-DST-010 | Provider replacement MUST confirm the active installed code and policy generation, not merely the embedded version; pending approval, restart, rejection, or nonconvergence MUST keep dependent profiles unavailable. | AT-MAC-DST-010 |
| MAC-DST-011 | Downgrade or rollback MUST satisfy signed security floor and state read/write compatibility without restoring authority state, freshness anchors, spent budgets, approvals, stop generations, or effect custody from an older snapshot. | AT-MAC-DST-011 |
| MAC-DST-012 | Code-signing or update-key rotation and revocation MUST use independently authenticated publisher policy, bounded offline behavior, and explicit successor trust; a same-named bundle or TLS connection MUST NOT establish successor trust. | AT-MAC-DST-012 |
| MAC-DST-013 | Disable and uninstall MUST fence admission, reconcile or preserve unknown operations, stop owned workers, request provider deactivation, unregister helpers, and report actual residual components before claiming completion. | AT-MAC-DST-013 |
| MAC-DST-014 | Uninstall MUST preserve user projects, receipts, unresolved custody, and recovery metadata by default; a separate explicit purge MUST identify retained obligations and MUST NOT rewrite unknown external effects as absent. | AT-MAC-DST-014 |
| MAC-DST-015 | Managed deployment MUST use separately tested extension, privacy, background-service, and removal policies bound to exact identities; MDM approval MUST NOT grant Chio task or publication authority. | AT-MAC-DST-015 |
| MAC-DST-016 | Installation, update, and removal MUST fail safely under full disk, read-only storage, signature failure, process death, and restart, retaining a bounded diagnostic recovery route without permission or enforcement downgrades. | AT-MAC-DST-016 |
| MAC-DST-017 | A release MUST publish only individually qualified profile claims, verify instructed revisions exist in the public repository, and identify unavailable features and the exact evidence scope. | AT-MAC-DST-017 |
| MAC-DST-018 | Descendant-scoped execution MUST remain a separate macOS 27 investigation until final SDK and OS availability, entitlement access, failure behavior, and profile-specific acceptance are verified; metadata labels alone MUST NOT open the profile. | AT-MAC-DST-018 |

## Release and update transaction

The release manifest declares supported protocol and state read/write ranges, required migration sequence, kernel/native ABI, required helpers and guest images, provider extension point and entitlement set, security floor, rollback candidates, and exact qualified profile-manifest digests. A downloaded artifact's metadata cannot choose its own trust root. Trusted release metadata and freshness policy belong to installation policy, separate from native task authority.

Proposed update-channel policy sets signed metadata validity to at most seven days. After expiry, a downloaded update cannot activate until authenticated metadata is refreshed; a previously installed qualified generation follows its existing authority and invalidation rules. Offline operation cannot promise immediate knowledge of newly published revocations. Once an applicable revocation is authenticated, affected new admission fences and code cannot roll below the recorded security floor. Restore of that local floor is governed by the native freshness/inspection-only rule, not assumed rollback resistance from a file timestamp.

Proposed update states are `downloaded`, `verified`, `admission-fenced`, `operations-reconciled`, `migration-prepared`, `bundle-installed`, `provider-pending`, `runtime-remeasured`, `generation-active`, and `recovery-required`. Every transition records old/new content digests, transaction identity, native fence reference where applicable, migration journal reference, and observed installed generation. This is an updater journal, not a new authority ledger. Effects already committed before fencing retain their native outcome and reconciliation rules.

Do not call OS provider replacement atomic. A provider can remain old while the containing app is new. During that gap, diagnostics can remain available through a read-compatible path, but governed admission requiring that provider stays fenced. A compatible UI rollback can occur independently only when the current controller/native state remains authoritative. A migration backup supports repair of bytes; it does not prove a backup's authority generation remains current. See [recovery](11-state-recovery.md).

For direct distribution, the app handles the system-extension replacement delegate using the validated compatibility decision. It does not accept an arbitrary lower version merely because Apple's delegate permits replacement. Deactivation can require restart, so `removal-pending-restart` is a real state. [Apple replacement delegate](https://developer.apple.com/documentation/systemextensions/ossystemextensionrequestdelegate/request%28_%3Aactionforreplacingextension%3Awithextension%3A%29), [deactivation](https://developer.apple.com/documentation/systemextensions/ossystemextensionrequest/deactivationrequest%28forextensionwithidentifier%3Aqueue%3A%29).

Initial permission flow is feature-specific: install and open the app, inspect read-only tasks, select a profile, then request only that profile's required capability. Activation errors retain Apple's bounded error code and the local reason without logging task payloads. ES entitlement requests and NE Developer ID provisioning must be completed against the actual team. [ES entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client), [NE entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension).

## Acceptance procedures

All artifacts below are future outputs under `integrations/macos/qualification/results/<run-id>/distribution/`. Each test records exact candidate and installed digests and uses the qualification manifest's independent observer. No test was executed by this document.

### AT-MAC-DST-001: Source to artifact closure

Build twice in isolated clean environments from the same pinned public sources, locks, and toolchains. Independently inventory unsigned content, dependencies, licenses, scripts, and final signed bytes. Oracle: every executable maps to an immutable source input; unrecorded patch or dependency fails closure. Record reproducibility differences honestly; only matching unsigned bytes justify that layer's reproducibility claim. Artifact: `source-artifact-closure.json` plus SBOM and build logs.

### AT-MAC-DST-002: Nested signature rejection

Inspect all executable Mach-O slices and nested bundles in the candidate, then replace one helper, enable `get-task-allow`, add an undeclared entitlement, and substitute a different-team provider in separate fixtures. Oracle: independent signature and entitlement inspection rejects each altered candidate before release. The unchanged candidate passes all declared checks. Artifact: `nested-signature-controls.json` and raw signing output.

### AT-MAC-DST-003: Notarized consumer launch

Download final bytes on a clean test Mac, preserve quarantine provenance, validate the ticket, and launch online and offline after stapling. Repeat with a corrupted artifact and a non-notarized fixture. Oracle: Gatekeeper and ticket observations agree with expected outcomes, with SIP and normal security settings recorded. A notarization success without consumer launch is incomplete. Artifact: `consumer-launch.json` with submission log and externally collected assessment output.

### AT-MAC-DST-004: Real provider eligibility

Attempt activation from the correct app location with the granted profile, then wrong location, missing entitlement, wrong bundle identifier, and wrong-team fixtures. Oracle: OS activation and separately observed provider identity match eligibility; application self-report is insufficient. Artifact: `provider-eligibility.json`, extracted profiles, and signing digests. Lack of team access is `unavailable`, never `pass`.

### AT-MAC-DST-005: Denied approvals remain precise

For each selected profile deny background service, extension activation, filter configuration, and required privacy permission independently, then revoke them during a task. Oracle: the affected admission path closes with its specific reason; the permitted read-only UI still works; no broader permission is requested as fallback. External effect counters show no new post-fence intent. Artifact: `permission-denial-matrix.json`.

### AT-MAC-DST-006: Support tuple drift

Run on each manifest tuple; independently alter OS build, host architecture, guest image, provider version, protocol, or state schema one at a time. Oracle: an unqualified row stays unavailable and displays the mismatched dimension; no arm64 evidence is relabeled x86_64 and no VM evidence is relabeled native. Artifact: `support-tuple-matrix.json`.

### AT-MAC-DST-007: Ambient runtime substitution

Prepend fake tools to PATH, add shell initialization commands, modify a bundled helper, and set injected-library environment variables. Oracle: approved launches execute only pinned package-owned bytes; changed closure refuses admission; the fake tool's outside sentinel remains absent. Artifact: `runtime-selection.json` and independent process/code census.

### AT-MAC-DST-008: Hostile update metadata

Offer valid successor, corrupt payload, wrong publisher, expired metadata, replayed older metadata, and protocol-incompatible successor. Oracle: only the supported authenticated successor enters staging, and rejected cases preserve original operation custody with no effect replay. Artifact: `update-authentication.json` from a verifier with trust roots configured outside each fixture.

### AT-MAC-DST-009: Every-stage crash recovery

Inject process death and restart before and after each listed durable update transition while an external fixture holds one operation's reply. Oracle: recovery finds one valid generation or `recovery-required`; the external counter is at most one for the original operation; unresolved remains unresolved; mixed components admit nothing. Artifact: `update-crash-matrix.json`, journal snapshots, and external counter transcript.

### AT-MAC-DST-010: Embedded and active version divergence

Hold the old provider active while replacing the app, deny replacement, return restart-required, and restart during convergence. Oracle: the active provider digest and policy generation are independently inspected; `generation-active` never appears before agreement. Artifact: `provider-handover.json` with installed/embedded/active identities separately recorded.

### AT-MAC-DST-011: Rollback cannot restore authority

Spend a grant and stop a task, install a successor, then try an allowed code rollback, incompatible schema rollback, security-revoked build, and pre-spend state restore. Oracle: compatible code retains the newest native custody; all stale-authority paths refuse admission and the external effect count remains unchanged. Artifact: `rollback-authority.json` with native freshness verification reference.

### AT-MAC-DST-012: Publisher rotation and offline policy

Rotate a fixture update key through the approved authenticated path; try an unrelated new key, replay an old signed manifest, revoke a candidate, and test online/offline after metadata expiry. Oracle: exact configured rotation/freshness rules hold; expiry never silently becomes infinite validity. Artifact: `publisher-trust.json`; fresh installation and installed-update paths are both covered.

### AT-MAC-DST-013: Removal while work exists

Remove with active local workers, an open network flow, and a delayed remote result. Deny deactivation and simulate restart-required. Oracle: admission fences, local closure facts remain separate, helpers/providers are inventoried, and removal stays pending if a component survives. Remote effect uncertainty is retained. Artifact: `removal-lifecycle.json` with outside process, flow, and provider census.

### AT-MAC-DST-014: Preserve and purge inventory

Uninstall with synthetic project, evidence, secret, and unknown-operation fixtures; inspect retained paths. Invoke the separate purge flow using its exact inventory. Oracle: default removal preserves user assets; purge removes only enumerated Chio-owned data permitted by unresolved-custody policy and reports residual OS logs/backups separately. Artifact: `uninstall-data-inventory.json` with before/after hashes.

### AT-MAC-DST-015: Managed and consumer independence

Install identical bytes on unmanaged and managed test machines. Apply exact-identity managed payloads, a wrong-team payload, and policy withdrawal. Oracle: OS approval results match each deployment, while no task grant or publication endorsement appears from MDM configuration. Artifact: `managed-deployment.json` with payload digests and independent native authority history.

### AT-MAC-DST-016: Storage fault recovery

Inject ENOSPC, EIO, read-only state, extraction truncation, and helper death during install/update/remove. Oracle: no invalid generation becomes active; a bounded recovery view references original journal and operation identities; no database reset or weakened profile appears. Artifact: `distribution-storage-faults.json` and outside effect counters.

### AT-MAC-DST-017: Public claim audit

An independent reviewer uses only the candidate's public installation instructions and release artifacts. Verify each instructed revision is present in `https://github.com/backbay-labs/chio`, each profile claim maps to a passing exact installed tuple, and failed or unavailable rows remain excluded. Oracle: the claim-to-evidence map has no uncovered assertion. Artifact: `public-release-claims.json`.

### AT-MAC-DST-018: Descendant gate isolation

Record rendered documentation and DocC metadata disagreement, inspect the selected final SDK headers, and run the descendant suite on the exact OS build. Remove that result and attempt a release using only VM or managed evidence. Oracle: `native-descendant-v1` remains closed without its own complete evidence; base app claims are unaffected by the experiment's absence. Artifact: `descendant-release-gate.json` with final SDK and OS observations.
