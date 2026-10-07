# 14. Service operations, shared Macs, and recovery custody

Status: proposed normative design. Confidence: high in the separation of user authority and global providers, moderate in the lifecycle adapter design until tested on the exact supported OS builds. Dependencies: [architecture](05-host-architecture.md), [operator protocol](06-operator-protocol.md), [VM](07-vm-execution.md), [ES](08-endpoint-security.md), [NE](09-network-extension.md), [state recovery](11-state-recovery.md), and [distribution](12-distribution.md).

## Service and identity policy

The proposed controller is a per-user bundled LaunchAgent registered through `SMAppService`. The native authority writer remains the owner of approvals, durable stop generations, budgets, integrity, and operation custody. The Swift app is an authenticated operator. A globally available ES or NE provider may impose further restriction and emit observations; it never becomes a global task-authority database or a credential proxy for every user.

An OS process identity, Unix user ID, audit-session identity, boot identity, and native run identity have different lifetimes. Connection acceptance authenticates the audit token, code requirement, allowed signing identity, and actual connection identity using [the protocol contract](06-operator-protocol.md). A request body cannot select its principal by submitting a UID, path, or claimed run ID. Provider routing uses the authenticated owner association and native generation, and unknown/ambiguous association cannot receive positive task authority.

System extensions are globally available once activated. `SMAppService` registration and helper approval are separate from extension activation. Neither fact proves a user is present or that a task may continue. [Apple system extensions](https://developer.apple.com/documentation/systemextensions), [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-OPS-001 | Per-user controller, native authority, resource brokers, global providers, and managed policy MUST have explicit separate custody and authenticated interfaces; no provider MUST mint grants or user approvals. | AT-MAC-OPS-001 |
| MAC-OPS-002 | Every connection and routed observation MUST bind its authenticated user/session/process incarnation and native scope; client-supplied identity fields MUST NOT select authority. | AT-MAC-OPS-002 |
| MAC-OPS-003 | Installation and service registration MUST respect explicit background-service choice and approval state, avoid prompt loops, and permit read-only diagnosis when execution is unavailable. | AT-MAC-OPS-003 |
| MAC-OPS-004 | Controller and helper restarts MUST be bounded and recover original native operations without replay; multiple app instances MUST converge on one serving writer per native authority scope. | AT-MAC-OPS-004 |
| MAC-OPS-005 | Session lock, unknown lock state, logout, fast user switching away, and loss of authenticated session custody MUST fence affected new consequential crossings and invalidate open reviews under the native lifecycle contract. | AT-MAC-OPS-005 |
| MAC-OPS-006 | No-user-logged-in and different-active-user states MUST preserve restrictive global policy without exposing another user's data or borrowing that user's credentials; autonomous logged-out execution MUST remain unavailable in the initial profiles. | AT-MAC-OPS-006 |
| MAC-OPS-007 | Sleep, wake, reboot, provider restart, and clock discontinuity MUST trigger bounded reconciliation and remeasurement before affected admission, with durable deadlines evaluated by the native owner. | AT-MAC-OPS-007 |
| MAC-OPS-008 | Secrets MUST remain in a deliberately selected per-user keychain implementation and broker scope, with minimal accessibility, no synchronization by default, and precise failure on locked, missing, denied, or migrated items. | AT-MAC-OPS-008 |
| MAC-OPS-009 | Secret rotation, removal, and session fencing MUST invalidate broker caches and new uses; already-dispatched external effects MUST retain their known or unknown native outcome. | AT-MAC-OPS-009 |
| MAC-OPS-010 | Backups MUST distinguish configuration, presentation state, protected payload, native authority, and secret custody, and MUST declare completeness and consistency without treating copied bytes as fresh authority. | AT-MAC-OPS-010 |
| MAC-OPS-011 | Restore or clone MUST remain quarantined until native freshness and original-operation reconciliation succeed; backup, keychain, database, VM snapshot, or local hash-chain restoration MUST NOT resurrect authority. | AT-MAC-OPS-011 |
| MAC-OPS-012 | Health MUST expose separate connectivity, authentication, compatibility, permission, activation, convergence, observation coverage, storage, authority, and closure dimensions with bounded age and explicit unknowns. | AT-MAC-OPS-012 |
| MAC-OPS-013 | Runbooks MUST use specific reason codes, evidence locations, exact recovery actions, and independent closure checks; no recovery action MUST reset authority or broaden permissions to make a warning disappear. | AT-MAC-OPS-013 |
| MAC-OPS-014 | Stop and uninstall MUST independently track durable admission fence, worker termination, existing-flow closure, resource cleanup, provider removal, and external outcome, without conflating acknowledgments or sensor silence with closure. | AT-MAC-OPS-014 |
| MAC-OPS-015 | Storage faults, corrupt state, lost keys, and inconsistent provider mappings MUST produce quarantined diagnosis and affected-scope denial; automated repair MUST NOT discard unresolved custody. | AT-MAC-OPS-015 |
| MAC-OPS-016 | Managed host restrictions and administrator policy MUST be independently attributable and restrictive; changing management state MUST invalidate affected qualification without expanding native authority. | AT-MAC-OPS-016 |
| MAC-OPS-017 | Cross-user diagnostics, evidence exports, notification delivery, temporary files, and support queries MUST preserve per-user isolation even when tasks have identical labels or UIDs are reused. | AT-MAC-OPS-017 |
| MAC-OPS-018 | Security incident and compromised-component response MUST fence affected scopes, preserve minimal verifiable evidence, rotate affected trust through its owner, and resume only after exact-profile requalification. | AT-MAC-OPS-018 |

## Session transition contract

| Transition | Proposed operational action | Residual truth |
| --- | --- | --- |
| Close window or quit presentation app | Controller can retain custody if approved to run; no implied task cancellation | UI absence is not session loss. Review handles remain native-bound and expire normally. |
| Lock, fast user switch away, unknown ownership | Native fence for new consequential crossings; invalidate reviews, clear sensitive UI, stop owned execution according to profile | Intent committed before the fence may still complete; separately gate later release. |
| Logout | Same native fence; stop local workers, detach per-user brokers, clear in-memory credentials; retain minimal durable custody | Per-user service termination is not proof all descendants or remote effects stopped. |
| Sleep requested or detected | Fence and reconcile as far as schedulability permits; record incomplete closure | The host may sleep before callbacks finish; do not invent a pre-sleep fence acknowledgment. |
| Wake or login | Reauthenticate session, create fresh launch/session association, remeasure permissions/providers, reconcile originals | No automatic task replay or approval reuse. Existing compatible task history remains inspectable. |
| Reboot | Recover from durable native state; new boot/process identities; verify anti-rollback freshness | Provider auto-start does not restore user task authority. |
| Global provider death | Affected profile closes; surviving broker/VM gate behavior is separately measured | No claim that a terminated ES client still denies events. |

The initial consumer profiles do not support unattended authority across locked or logged-out sessions. Adding such behavior requires a new explicit lifecycle policy and qualification on the selected profile, not an implicit `KeepAlive` tweak. A managed device may retain independently restrictive host policy when no user is logged in. That host policy has no permission to spend a user's task budget, decrypt their provider secret, or publish their artifacts.

Proposed restart policy: at most three automatic attempts in 60 seconds with minimum five-second backoff, then `recovery-required`. Restarts recover custody/diagnostics only. The implementation must enforce the bound even if the chosen launchd configuration cannot directly express the entire policy. Never assume a LaunchAgent automatically binds all work to lock/logout; the adapter must prove the actual transition events and missing-event behavior. Unknown ownership fences; mere missed heartbeat is a liveness signal that triggers native reconciliation.

## Keychain and restore policy

Propose `SecItem` with `kSecUseDataProtectionKeychain=true`, `kSecAttrSynchronizable=false`, an explicit narrowly scoped access group, and the most restrictive validated `kSecAttrAccessible` choice appropriate for interactive task brokering. A `WhenUnlockedThisDeviceOnly` candidate must pass actual Mac tests before it is selected. No assumption that iOS locking semantics apply on macOS is permitted. The app-like broker packaging and entitlements must support that access group, and the global system provider must never be given the user's secret. Native endorsement keys remain under the existing native authority, not a new Swift signer. [Apple Mac keychain distinctions](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), [data protection keychain attribute](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain), [accessibility attribute](https://developer.apple.com/documentation/security/ksecattraccessible).

Backups carry a manifest of component/schema identities, consistent native snapshot reference if one is supported, payload digests, unresolved original operations, required key custody, and known verification dependencies. Exclude live sockets, transient locks, raw provider credentials, and guest launch identities. A copy of the native database or its signing key does not prove the copy is current. A hash chain authenticates ordering within its presented history; it cannot detect an omitted later tail without an independent freshness anchor.

Restore begins in staging with safe archive extraction and no executable authority. Verify native recovery using the accepted anti-rollback mechanism from [state recovery](11-state-recovery.md), whose freshness state must survive outside the rollback domain being tested. If no such mechanism is available, close the affected execution profile and permit only verified historical inspection. New enrollment requires the native owner's disposition of old authority and unresolved effects; renaming a task, generating a new local database, or logging in again cannot bypass the obligation. Time Machine, Migration Assistant, copied home directories, restored keychains, app downgrade, and VM snapshots all receive this rule.

## Operational diagnosis

Proposed stable reasons include `background_service_denied`, `session_custody_unknown`, `keychain_unavailable`, `provider_approval_pending`, `provider_generation_mismatch`, `observation_gap`, `authority_unreachable`, `restore_freshness_unproven`, `storage_commit_failed`, `external_outcome_unknown`, and `removal_pending_restart`. These are presentation reason codes, not a duplicate wire schema; the protocol owns their envelope and source attribution.

| Reason | User-visible recovery action | Required independent check |
| --- | --- | --- |
| `background_service_denied` | Show current system approval status and open the relevant settings through the platform API on explicit action | Re-read OS service status and authenticate the returned controller before showing availability. |
| `provider_generation_mismatch` | Keep task fenced; finish the verified update or return to a supported compatible generation | Inspect active provider code identity and policy generation, not only the embedded app. |
| `restore_freshness_unproven` | Open read-only historical evidence and connect to the native recovery owner | Verify current independent anchor and original-operation reconciliation; never delete the database. |
| `keychain_unavailable` | Unlock/reconnect/re-authorize the scoped credential through native platform UI | Retry with original operation identity only if the contract permits; distinguish no-dispatch from unknown dispatch. |
| `external_outcome_unknown` | Query the recorded destination/original operation through its broker reconciliation path | Independent resource outcome or native bounded unresolved disposition; no blind mutation retry. |
| `storage_commit_failed` | Free user-selected disposable data or repair storage; retain authority journals | Native store verifies consistency and durability before new admission. |

## Acceptance procedures

### AT-MAC-OPS-001: Distinct service custody

Inspect process identities, privileges, data directories, and actual service connections on a signed install. Submit an approval-like event from a provider and stop the UI/controller independently. Oracle: native writer history alone can contain approval/authority commits; provider messages cannot create them; component lifetime and data custody match roles. Artifact: `service-custody.json`.

### AT-MAC-OPS-002: Authenticated routing

From two users and two incarnations with reused PIDs, send valid requests and forged UID/session/run fields through actual IPC. Oracle: independent native records bind the connection's principal; wrong-session/cross-user requests fail before data access or effects. Artifact: `principal-routing.json` with audit/process observations collected outside the request payload.

### AT-MAC-OPS-003: Approval-aware registration

Install without enabling background operation, opt in, deny OS approval, reopen the app five times, then approve and revoke. Oracle: no background launch before authorized availability, no repeated prompt loop, and read-only diagnostics name the actual blocked layer. Artifact: `service-registration.json` from OS status and process census.

### AT-MAC-OPS-004: Bounded restart and singleton

Open five app instances, crash the controller repeatedly, and lose a mutation response during restart. Oracle: no more than three attempts in 60 seconds, one native writer for the scope, stable original operation identity, and external effect count at most one. Artifact: `restart-singleton.json` and server counter transcript.

### AT-MAC-OPS-005: Session fence race

Run a held operation, lock, fast-switch users, lose a lock notification, and log out in separate cases. Oracle: native fence order distinguishes precommitted intent from later intents; later release is rechecked; stale review fails; outside worker observer records actual termination separately. Artifact: `session-fence-matrix.json`.

### AT-MAC-OPS-006: Global provider without a user

Keep provider installed while all users log out, then log in as a different user. Probe policy/data access and attempted user-secret use. Oracle: host restriction may remain, but no user task resumes, no cross-user record appears, and no credential-backed effect occurs. Artifact: `no-user-provider.json`.

### AT-MAC-OPS-007: Sleep, wake, reboot, clock shift

Suspend before and after native intent/fence durability, reboot during broker return, and shift wall clock while preserving the test's monotonic observations. Oracle: fresh identities and native deadline evaluation precede new admission; unknown effects stay unknown; no reply loss repeats the effect. Artifact: `power-restart-reconciliation.json` with external counter and clock map.

### AT-MAC-OPS-008: Keychain state matrix

Exercise the selected broker item on unlocked, screen-locked, keychain-denied, logged-out, migrated, deleted-item, and missing-access-group fixtures. Oracle: OSStatus and actual broker dispatch agree with the declared policy; missing access never falls back to plaintext or another user's keychain. Artifact: `keychain-matrix.json`, excluding secret bytes.

### AT-MAC-OPS-009: Rotation with in-flight effect

Cache a synthetic provider token, dispatch one held request, rotate/remove the token, and attempt another request. Oracle: new uses cannot use the old cache, while the original's external completion/unknown result remains attached to its native identity. Artifact: `credential-rotation.json` with external token-version counters.

### AT-MAC-OPS-010: Consistent but non-authorizing backup

Back up idle and unknown-operation state; omit a native snapshot component and alter a schema digest in negatives. Oracle: independent manifest verification identifies complete versus incomplete backups, and even a valid backup grants no execution merely by extraction. Artifact: `backup-custody.json` with synthetic encrypted backup and separate key metadata.

### AT-MAC-OPS-011: Rollback and clone freshness

Snapshot before spending/revocation, advance native state, then restore database, keychain, full home, and VM snapshots, including a second-machine clone and offline freshness owner. Oracle: all restored authority remains fenced until current native freshness verification; unavailable freshness never passes; the outside effect counter cannot increment through stale authority. Artifact: `restore-rollback-clone.json`.

### AT-MAC-OPS-012: Multidimensional health

Independently break connectivity, authentication, permission, activation, policy convergence, sensor continuity, and storage. Oracle: health shows each dimension and observation age without reporting an overall protected state from partial success. A stale provider heartbeat cannot prove current policy. Artifact: `health-dimensions.json` with independent fault schedule.

### AT-MAC-OPS-013: Runbook reproduction

A tester other than the implementer induces each listed reason and follows only the runbook. Oracle: the specified recovery reaches a verified state or explicit unresolved diagnosis, without database reset, permission expansion, or effect replay. Artifact: `runbook-reproduction.json`, commands/actions, and exact before/after evidence.

### AT-MAC-OPS-014: Separate closure facts

Hold one child alive, one flow open, and one remote reply unavailable after stop. Then allow each to close in a different order. Oracle: the UI and evidence preserve all individual states and never derive remote completion from process disappearance. Artifact: `closure-dimensions.json` from process, network, and external-service observers.

### AT-MAC-OPS-015: Corruption and lost custody

Inject database corruption, missing key, truncated mapping journal, and EIO during a commit. Oracle: original bytes are quarantined for diagnosis, new effects are denied, unknown operations remain listed, and no automatic empty database is treated as recovered authority. Artifact: `operational-faults.json` with immutable copies and native refusal evidence.

### AT-MAC-OPS-016: Managed restriction attribution

Apply and remove independent managed restrictions during a user task and change management enrollment. Oracle: denials identify the external restrictive owner; removing it does not create a native grant or reopen a profile whose support tuple changed. Artifact: `managed-policy-attribution.json`.

### AT-MAC-OPS-017: Shared-Mac privacy

Give two users identical task labels, switch rapidly, export diagnostics, inspect temp directories, and recreate a fixture account with a reused numeric UID. Oracle: per-user payloads, notifications, native references, and exports never cross owner boundaries; old principal identity is not recovered from UID alone. Artifact: `shared-mac-privacy.json` with distinct canary scan.

### AT-MAC-OPS-018: Compromised-component exercise

Revoke a fixture helper/signing trust, seed a suspicious provider record, and execute the incident runbook. Oracle: affected scopes fence, minimal evidence survives with provenance, secret/trust rotation goes through the respective native owner, and resumption requires an exact passing profile manifest. Artifact: `incident-response.json` and independent release verifier result.
