# Chio desktop experience

Status: Proposed. Confidence: high in the source-grounded Omarchy interaction boundaries; moderate in the proposed UX until tested on actual Omarchy. Scope: the complete operator journey, not runtime implementation. Dependencies: [upstream research](research/omarchy-upstream.md), [plugin contract](03-omarchy-plugin.md), [operator protocol](05-operator-protocol.md), and [state/evidence contract](14-state-evidence-data.md). P0 establishes compatibility; P1 enables read-only status; P2 admits one confined project task. P3-P6 capabilities remain unavailable until their separate native gates close.

Chio should make a bounded piece of agent work feel like an ordinary desktop activity: choose the project and allowed work, see what is happening, review the result, and recover without guessing whether an external action occurred. The modern Rust kernel supplies the authority and evidence; the desktop gives that authority a comprehensible operator surface.

## Decisions and alternatives

Use one compact bar presence and one keyboard-capable panel with progressively expanded task details. Keep task results and approvals in that same navigation model. The existing Omarchy Agents panel continues to own subscription usage and account workflows; its figures do not become Chio task budget guarantees. Use the user's current theme and spacing rather than inventing a second desktop chrome. This follows the observed shell plugin and Agents surfaces, while adding the missing task/evidence journey. [Pinned upstream evidence](research/omarchy-upstream.md#pinned-primary-source-map)

A terminal-only flow is valuable for diagnostics and automation but does not satisfy a native desktop experience. A replacement bar unnecessarily expands integration and trust scope. A browser dashboard adds a second session/transport surface. A full-screen conversational assistant gives model text excessive visual authority and competes with the user's editor. These remain alternatives, not requirements of the initial profile.

The default threat profile trusts the operator and installed shell plugins and confines the agent guest. State this once in setup and make the current profile inspectable. Do not use a shield icon or the word "secure" to imply that same-UID desktop malware is contained.

## Surface and navigation contract

| Surface | Purpose and behavior |
|---|---|
| Bar | Chio glyph plus compact count/state. Always distinguish "No tasks", "Working", "Needs attention", and "Disconnected" with accessible text; a dot or color alone is insufficient. Click/keyboard activation opens the panel. Secondary-click offers navigation/settings only, never execution or approval. |
| Overview | Current task first, explicit status, last confirmed update, next available action. Initial P2 supports one active task. Empty state offers "Set up Chio" or "New project task" according to readiness. |
| New task | Project, task instruction, selected execution profile, provider/account reference, resource limits, fixed verification commands, review output location, and permitted network/publication behavior. A concise summary precedes "Start task". |
| Task detail | Task state and step, enforced versus measured limits, bounded activity, failures, cancellation, native operation identity on demand, and review entry. Model prose is displayed as untrusted task output. |
| Review | Immutable review identity, changed files/diff, required checks and their results, artifact/evidence status, exact origin and base revision. No publication control in P2. P3 publication is a distinct exact operation. |
| Attention | Pending native approval, compatibility issue, expired credential, resource exhaustion or unknown outcome. Each shows the reason, consequence, and supported next action. |
| Diagnostics | Current qualified profile, package/protocol identities, connectivity, redacted export, and repair directions. Diagnostics remain reachable on version mismatch. |

Opening, closing, or switching views never creates a task, approves, resumes, cancels, changes default agent, modifies a project, or grants desktop access. A notification or desktop deep link names an opaque task UUID and view only. The controller re-fetches the current task before acting on the link.

## Complete operator journey

### Install, first launch, and profile selection

1. Install a future qualified native package and reviewed QML plugin using the release contract. The proposed installer presents the exact owned files, native service and plugin versions, source/digest verification result, and removal behavior. No download or package exists merely because this spec names it.
2. Open Chio from the application launcher, a static Omarchy menu item, or the bar. Show detected compatibility and native health. P1 offers read-only status with "Task execution is not available on this installation" when native prerequisites are missing.
3. Select from available profiles. "Observe tasks" is P1. "Confined project task" is P2 and initially Pi only. "Reviewed publication" (P3), "Desktop tools" (P4), "Configuration repair" (P5), and "Delegated workers" (P6) appear only as explicit unavailable capabilities or installed qualified choices. Do not display every planned phase as an active feature. A profile's claimed protections must correspond to its recorded native evidence.
4. Credential setup opens the qualified native/provider setup flow. QML receives readiness, an account display label and opaque credential reference. It never collects a raw key, mirrors an OAuth code, reads another tool's auth directory, or logs credentials. A provider/account switch applies to a new task unless the native protocol explicitly defines a reauthorization transition.
5. Complete trusted operator enrollment through the qualified native setup route before enabling a first task. Its resulting record binds the operator principal, authority/trust root, permitted project resources and profile/policy identities. The desktop shows those nonsecret bindings and readiness, while signing keys and authority credentials stay outside QML. A desktop UID, an installed plugin, a provider login or a toggled setup-complete flag does not fabricate enrollment. If the native enrollment route or its proof is unavailable, the installation remains read-only with a specific prerequisite message.
6. Offer an optional shortcut. Preserve existing bindings and the user's default-agent choice. Detect collisions before saving; the proposed shortcut is selected by the operator rather than assumed free. Setup completion alone does not launch an agent.

Profile copy separates enforced constraints from estimates: for example, "Wall time: enforced by task supervisor" versus "Provider spend: estimated from reported usage". Unknown enforcement is shown as unknown and prevents a profile from claiming that bound. Account labels are not proof of which credential the task actually used; the task record binds the chosen native credential reference.

### Project selection and import

Use a native project picker or literal typed path, then ask the controller to resolve and validate it. The project summary shows the resolved directory, repository identity/base revision where applicable, clean/dirty state, and exactly what the task will access. The controller handles traversal, symlink, mount and resource identity validation; QML never shells out to inspect the tree.

The initial workflow prepares an isolated task workspace from the selected project according to the native host contract. Unrelated edits in the source tree are preserved. Untracked files, ignored files, secrets and nested repositories are not silently copied under a promise of "whole project". The import preview enumerates inclusion/exclusion policy and any unsupported path. A destination collision or changed source identity invalidates the preview and requires a fresh summary, not silent overwrite. An unsupported project can still be inspected in diagnostics but cannot start.

### Create and supervise a task

The start summary binds the task instruction, enrolled operator/authority identity, project identity, profile and policy, agent/provider reference, fixed verification plan, deadlines/limits, and review artifact destination. Before enabling Start, refresh all of those bindings and show an explicit reason if enrollment, project admission, provider readiness or native qualification is missing. "Start task" sends one mutation with its idempotency key and canonical argument binding. Repeated clicks are disabled while admission is pending. A lost response exposes "Checking whether task started" and reconciles the same operation. It never synthesizes a second task to hide uncertainty.

P2 performs one confined project task and produces a review artifact. It does not publish, push, send messages, grant desktop control, or inherit a broad host credential environment. The task panel may close, the shell may reload, and the user may open another application without killing or restarting admitted work.

Initial proposed presentation defaults, to be measured on the qualification host: open already-loaded panel within 200 ms at p95; show an admission acknowledgement or an explicit waiting state within 2 seconds; render at most 10 coalesced activity updates/second; retain at most 500 event rows and 1 MiB of in-memory activity. These are proposed budgets, not observed performance.

### Read state without manufacturing certainty

| Native task state | Operator meaning and permitted next action |
|---|---|
| `preparing` | Creating the confined workspace and verifying prerequisites. Show the specific preparation step and Cancel if admitted. |
| `ready` | Native preparation is complete and execution is eligible under its recorded contract. This is not a generic "all protections verified" badge. |
| `running` | Work is active. Show known step, elapsed time, enforced limits and bounded output. |
| `waiting_approval` | Native authority has a specific pending operation. Show the exact review if supported; otherwise explain that approval is unavailable and execution remains blocked. |
| `recovering` | Native recovery is reconciling a prior operation. Show what is being checked; prevent duplicate actions. |
| `blocked_unknown` | Outcome cannot be established. Show the affected operation and evidence gap; provide diagnostics and only the native-supported reconciliation route. No ordinary retry. |
| `cancelling` | Cancellation has been requested but completion is not confirmed. Show possible in-flight effects. |
| `cancelled` | Native cancellation is confirmed, with retained artifacts and any known effects. Cancellation does not imply rollback. |
| `succeeded` | Task contract succeeded; show required check results and review artifact. This does not mean changes were published. |
| `failed` | Native terminal failure. Show reason, completed effects, remaining artifacts, and whether a separately admitted new task is appropriate. |

Connectivity is a second axis: connected/fresh, stale, or offline. A missed event is not a task failure. Heartbeats occur every 5 seconds; after 15 seconds without confirmed liveness, status becomes stale and all mutation controls disable. A transport loss displays offline immediately. Preserve last known status with its timestamp and a prominent qualification that it may have changed. The UI never changes a task to succeeded because a child process exited or because a log says "done".

### Review, native approvals, and publication

Review is useful before approval support exists. P2 shows the result, checks and verification status, with "Open review" and "Export evidence" subject to native resource validation. The native receipt verifier is the only source for "Verified receipt". A projected status, JSON event, human-readable log or screenshot gets a different label.

P3 adds exact native decisions only after the native approval gate is qualified. A review shows resource identity, operation identity, immutable canonical arguments digest, human-readable exact effect, current revision, expiry, policy and authority bindings. If these cannot be rendered faithfully, the decision is unavailable. A grant cannot be inferred from "Continue", a toast click, a selected profile, a model instruction, or a remembered decision for different arguments. Submission binds the idempotency key and expected revision; conflicts/expiry re-fetch the review and require a new deliberate operator action. Closing or Escape neither approves nor denies unless the operator explicitly activates a supported denial action.

The current approval-decide path is an open native prerequisite. Product UI must say approval is unavailable and refuse submission until a qualified native decision exists. A simulated green check, writable local approval file, or controller-only decision is forbidden. No P2 acceptance case pretends to prove P3 approval.

Publication is separate from task completion. Its future review binds the exact artifact/diff, destination repository/account/reference, base version, policy and native operation. Changes to any binding invalidate the review. An uncertain publication remains the same native operation in reconciliation; a new operation cannot be created to "retry" it.

### Failures and recovery

| Trigger | Required presentation | Recovery contract |
|---|---|---|
| Missing native package or unsupported protocol | "Chio needs a compatible desktop service", with detected versions | Read-only diagnostics and reviewed installation/update route. Never fall back to unconfined `pi` or a raw shell command. |
| Credential missing/expired | Provider/account label and setup action, without secret details | Qualified native credential flow; no background account change or silently widened credentials. |
| Resource limit reached | Name the enforced bound and known effects | End or pause exactly as native policy specifies; increasing a limit creates a newly admitted contract if supported. |
| Source tree changed after preview | Explain which identity is stale | Rebuild preview and verify binding; do not mutate the changed tree. |
| Disconnected controller/shell restart | Last confirmed state plus timestamp; actions disabled | Reconnect, fetch snapshot and event watermark, then re-enable supported actions on fresh state. |
| Gap in event cursor | "Refreshing task state" | Replace with an atomic snapshot and resume from its cursor, not append incompatible old events. |
| Unknown effect after crash | `blocked_unknown`, affected operation, evidence gap | Native reconciliation only. No optimistic success, rollback claim or automatic new task. |
| Cancel during external effect | `cancelling`; effect may still complete | Continue observing native outcome, retain result if completion won the race. |
| Verification failed | Required check and result, inspectable evidence | Keep review artifacts; do not label the task complete merely because a diff exists. |

### Upgrade, disable and uninstall

An update rechecks the plugin/native protocol pair, admission capabilities and data schema before new mutations. It does not replay in-flight requests as new work. Display active-task state before an operator-requested service migration. Omarchy's post-update hook can trigger a recheck but is not the final gate; its subsequent package work can still change dependencies.

Disabling/removing the QML plugin only removes the desktop client. State clearly when tasks continue under the native supervisor. Uninstall offers distinct scopes: remove desktop integration; stop native service after native-confirmed task handling; remove selected retained local data. The default preserves project work, review artifacts, receipts and user configuration unrelated to Chio. Destructive data removal enumerates exact owned paths and is an explicit operator action. Failure to confirm task termination prevents claiming full removal.

Do not promise that an Omarchy system snapshot restores Chio's home-directory configuration, task state or project data. Native migrations need an independently restorable backup and documented version compatibility.

## Accessibility, focus, privacy and content safety

Every control has an accessible name, role, enabled/disabled state and action. Status changes announce a concise sentence; high-volume events do not repeatedly interrupt speech. Text, icon shape and focus indication supplement color. Proposed visual acceptance targets: normal text contrast at least 4.5:1, large text and nontext UI at least 3:1, a minimum 32 logical-pixel activation area, and usable layout at 200% text scale and 150% output scale. Where a user theme cannot satisfy contrast, offer a Chio high-contrast mode and report the unsatisfied requirement. Theme adoption does not override legibility.

Tab/Shift+Tab visit controls in reading order. Arrow keys navigate lists; optional h/j/k/l works only outside editors. Space/Enter activates the focused control once. Text entry, selection, IME composition and multiline prompts retain their expected keys. Escape closes the current view/dialog without an authority mutation. On open, focus the heading or primary navigation, never an approval button. On close restore the invoking focus where the compositor permits it, and test the fallback. Task updates and notifications never steal focus. Repeated open/close, another output, an unplugged monitor, and shell reload must not trap keys.

The service observes session lock through a separately qualified host signal; QML does not look up Omarchy's credential-bearing lock service. On lock or unknown lock state, close/redact task details, erase transient sensitive previews, suspend detail delivery, and disable all mutations. Unlock alone does not restore an approval decision surface: require fresh health/task/review bindings. A task can continue in its existing admitted scope while locked; no new operator grant, renewed session or extended deadline is inferred from locking or unlocking. Logout and reboot follow the native supervisor's qualified stop/recovery contract; the desktop must not promise continuation through logout merely because panel closure is safe. Capture/clipboard desktop capabilities require their own P4 lock policy.

Notifications use a normal-urgency Chio identity and generic text, such as "Chio needs attention" or "Chio task finished". They respect DND, coalesce bursts, and persist no task prompt/path/diff/secret. At most one attention notification per task per 60 seconds is an initial policy default. The sole action opens Chio after a fresh query. Persisted historical notifications cannot approve, cancel, retry or publish.

All model text, paths, log fragments and imported metadata render as plain text. Strip control characters in display labels, visibly isolate bidirectional text when necessary, cap displayed lengths, and provide an explicit full-value view for exact review fields. Truncation may not conceal the destination/effect being approved. No executable links, HTML, shell substitutions or automatic clipboard writes originate in task output.

## Requirements and proposed acceptance

| Requirement ID | Normative requirement | Acceptance ID |
|---|---|---|
| OM-UX-001 | First launch exposes only qualified profiles and distinguishes read-only readiness from execution readiness. | AT-UX-001 |
| OM-UX-002 | Project import binds resolved identity and preserves unrelated source-tree work. | AT-UX-002 |
| OM-UX-003 | Task start is deliberate, canonically bound and idempotent under lost responses. | AT-UX-003 |
| OM-UX-004 | Task state and connectivity remain distinct and mutations require fresh state. | AT-UX-004 |
| OM-UX-005 | Overview/detail remain responsive with bounded activity and no focus stealing. | AT-UX-005 |
| OM-UX-006 | Review distinguishes native outcome, artifact checks, publication and verified receipts. | AT-UX-006 |
| OM-UX-007 | Exact native approval is unavailable until qualified and rejects changed, expired or stale bindings. | AT-UX-007 |
| OM-UX-008 | Cancellation reports in-flight uncertainty and never implies rollback. | AT-UX-008 |
| OM-UX-009 | Unknown outcomes reconcile the same operation without blind retries. | AT-UX-009 |
| OM-UX-010 | Every journey is operable by keyboard with correct editor and multi-monitor focus behavior. | AT-UX-010 |
| OM-UX-011 | Controls, states, scaling, contrast and motion meet the stated accessibility contract. | AT-UX-011 |
| OM-UX-012 | Lock/unknown-lock states conceal sensitive content and refuse mutations until freshly reconciled. | AT-UX-012 |
| OM-UX-013 | Notifications are private, rate-limited navigation with no authority effects. | AT-UX-013 |
| OM-UX-014 | Credentials and provider budget claims reflect qualified native behavior. | AT-UX-014 |
| OM-UX-015 | Upgrade and reconnect invalidate stale decisions without duplicating work. | AT-UX-015 |
| OM-UX-016 | Disable/uninstall distinguish client removal, task handling and explicit data deletion. | AT-UX-016 |
| OM-UX-017 | Chio preserves upstream Agents/default-agent and existing menu/shortcut settings. | AT-UX-017 |
| OM-UX-018 | Untrusted content cannot alter navigation, commands or exact review presentation. | AT-UX-018 |

### AT-UX-001: Honest first launch

Trigger: launch clean installations with no native service, P1-only capabilities, missing/expired operator enrollment, and a separately qualified enrolled P2 profile. Observable outcome: correct setup/read-only/task choices and clear unavailable reasons; a first task requires fresh operator, authority, project and profile bindings. Negative: a mocked "available" UI flag, provider login or UID-only setup flag without native admission cannot start work. Independent oracle: package inventory, native enrollment record and capability/admission responses, not screenshots alone. Evidence artifact: `ux/first-launch-matrix.json` and screen recording for each installation.

### AT-UX-002: Project import identity and preservation

Trigger: select a clean repository, a dirty repository, an excluded secret fixture, and a path whose symlink target changes between preview and start. Outcome: correct inclusion preview, untouched unrelated edits, and stale-identity refusal. Negative: no silently broadened home access or original-tree overwrite. Oracle: independent before/after filesystem manifests, Git status/diffs and native resource binding. Artifact: `ux/project-import-report.json` with preserved fixture hashes.

### AT-UX-003: One task for one deliberate start

Trigger: double-click Start, press Enter repeatedly, and drop the admission reply after commit. Outcome: pending feedback within 2 seconds and reconciliation of one admitted task. Negative: reopening a view or notification admits zero tasks. Oracle: native durable admission/operation records and task count queried independently of QML. Artifact: `ux/admission-idempotency.json` plus input/network fault trace.

### AT-UX-004: Staleness is not an outcome

Trigger: stop event delivery, then disconnect and reconnect while a task completes. Outcome: stale within the 15-second bound, offline on transport close, controls disabled, and fresh snapshot replaces last known state. Negative: neither disconnection nor process exit manufactures failed/succeeded state. Oracle: controlled monotonic clock, independent native task query and mutation rejection log. Artifact: `ux/connectivity-timeline.json`.

### AT-UX-005: Responsive bounded supervision

Trigger: deliver 100,000 fixture events over ten minutes while opening/closing the panel and typing in another app. Outcome: at most 500 retained rows/1 MiB activity, at most 10 UI updates/second, p95 open latency at most 200 ms for a loaded panel, no stolen focus. Negative: output flood must not freeze the compositor or grow UI retention without bound. Oracle: external input/focus harness, process memory samples and model-retention counters. Artifact: `ux/supervision-performance.json` with host specification.

### AT-UX-006: Review without false evidence

Trigger: show a successful task with verified receipts, a failed required check, and a forged log saying "verified and published". Outcome: review reflects native checks and receipt verification; P2 has no publication control. Negative: log text cannot promote evidence or task success. Oracle: independent receipt verifier, fixed-test outputs and destination inspection. Artifact: `ux/review-evidence-matrix.json`.

### AT-UX-007: No simulated approval

Trigger: a pending operation on the current unsupported approval backend; later, separately qualified P3 fixtures with expired revision, changed digest and valid exact decision. Outcome: unsupported/changed/expired cases refuse and remain blocked; the qualified exact case can submit once. Negative: profile choice, toast click, Enter on opening or local UI state grants nothing. Oracle: native authority decision/receipt verification and protected executor effect count. Artifact: `ux/exact-approval-report.json`; P3 positive evidence cannot be replaced by UI mocks.

### AT-UX-008: Cancellation race

Trigger: cancel before execution, during cancellable execution, and while an effect is already committed. Outcome: cancelling persists until native confirmation; completed effects remain visible. Negative: closing the panel sends no cancellation, and cancellation never displays "rolled back" without native evidence. Oracle: supervisor state and independent resource effect inspection. Artifact: `ux/cancel-races.json`.

### AT-UX-009: Unknown operation recovery

Trigger: crash after dispatch before final outcome is durably known. Outcome: recovering/blocked_unknown with the original operation and supported diagnostic path. Negative: repeated Resume or reopening cannot create a new operation to bypass uncertainty. Oracle: durable native operation identity and destination effect audit. Artifact: `ux/unknown-recovery.json`.

### AT-UX-010: Keyboard and focus journey

Trigger: perform setup, import, task start, review, cancellation and diagnostics using only keyboard; include IME/text editing, rapid re-summon, monitor unplug and another-output click. Outcome: reachable actions, visible focus, one activation per key, no text intercepted as navigation, Escape has no mutation. Negative: pending approval never receives automatic activation focus. Oracle: external key/focus recording and controller request trace. Artifact: `ux/keyboard-focus.md` and session recording.

### AT-UX-011: Accessible native presentation

Trigger: run the journey with Orca/AT-SPI inspection, 200% text, 150% output scale, light/dark/high-contrast themes, animations disabled and user reduced-motion preference. Outcome: named roles/states/actions, usable uncut controls, stated contrast thresholds, no essential animation. Negative: icon-only unnamed controls and color-only state fail. Oracle: AT-SPI tree and spoken-output audit, contrast measurement and screenshots at recorded settings. Artifact: `ux/accessibility-report.json`; manual keyboard success alone does not pass screen-reader acceptance.

### AT-UX-012: Lock and unknown-lock privacy

Trigger: lock with detail/review open, lose lock-state observation, then unlock with a changed pending revision or expired grant. Outcome: immediate concealment on observed lock, no new sensitive projection while lock is unknown, disabled mutations and fresh reconciliation before display/actions. Negative: historical content/approval cannot reappear from cache on unlock, and original grant/session expiry never extends. Oracle: external session-state fixture, screenshots, native expiry records and socket-response capture with secret canaries. Artifact: `ux/lock-privacy-report.json`.

### AT-UX-013: Safe notifications and history

Trigger: many task events, DND, session lock, shell restart and clicks on old notifications. Outcome: generic content, at most one task attention notice per 60 seconds, no DND bypass, current task view opens. Negative: no approval/cancel/retry/publication from a click and no secret canary on disk. Oracle: notification bus capture, Omarchy history-file scan and native mutation log. Artifact: `ux/notifications-report.json`.

### AT-UX-014: Credentials and honest budgets

Trigger: missing/expired provider credentials, an account change, and providers with measured versus enforced limits. Outcome: native setup route, immutable admitted account binding, correct limit labels. Negative: QML process argv/env/log/cache contains no seeded credential and a spend estimate is never labeled enforced. Oracle: credential-provider reference, native admission record and independent process/log inspection. Artifact: `ux/credentials-and-budgets.json`.

### AT-UX-015: Upgrade and reconnection

Trigger: update QML during an active task, stop/restart shell, introduce native protocol mismatch, and restore compatibility. Outcome: read-only mismatch diagnostics, same task/operation identities, fresh snapshot before mutations. Negative: no retained approval draft can execute after the version/revision change. Oracle: native durable ledger, package identities and fault trace. Artifact: `ux/upgrade-reconnect.json`.

### AT-UX-016: Explicit removal scopes

Trigger: disable plugin with active work, remove integration, then request native/data removal on a fixture installation with unrelated edits. Outcome: truthful continuing/stopping state, preserved artifacts by default, exact deletion preview for selected Chio data. Negative: no full-removal success when native task termination remains unknown; no unrelated paths deleted. Oracle: process/service inventory and filesystem before/after manifest. Artifact: `ux/uninstall-report.json`.

### AT-UX-017: Desktop coexistence

Trigger: install with existing Agents widget, selected default agent, custom menu entries and conflicting shortcut. Outcome: Chio is independently launchable; existing settings and shortcuts remain intact; collision is reported. Negative: selecting Pi in Omarchy never gains a Chio confinement label. Oracle: config semantic diff, existing launcher execution trace and independent native task list. Artifact: `ux/desktop-coexistence.json`.

### AT-UX-018: Hostile presentation data

Trigger: inject HTML, shell substitutions, ANSI controls, bidirectional controls, overlong filenames and misleading "Approve" log text. Outcome: inert bounded text; exact review values remain inspectable and unambiguous. Negative: no generated command, executable URL or hidden approval destination. Oracle: process-exec capture, protected-resource canaries and accessibility/rendered-content audit. Artifact: `ux/untrusted-content.json`.

## Risks and prerequisite owners

The desktop integration maintainer owns installed-version compatibility and lifecycle tests. The accessibility reviewer owns AT-SPI/Orca qualification; source reuse does not close that gate. The native runtime maintainer owns approval availability, cancellation semantics and unknown-outcome reconciliation. The security maintainer owns the lock-state observer and protected host boundary. The release maintainer owns installer/uninstaller ownership manifests, paired-version migrations and retained-data backup.

The largest product risk is presenting planned authority as working UI. The release profile must omit unavailable mutation features and provide a useful read-only path. The largest UX unknowns are real layer-shell assistive technology support and multi-monitor focus behavior. Both require actual target-host evidence before a release can claim this contract is satisfied.
