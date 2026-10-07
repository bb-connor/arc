# Native Omarchy plugin contract

Status: Proposed. Confidence: high for the inspected Omarchy source contracts; moderate for the proposed plugin design pending Linux desktop qualification. Scope: native QML presentation, connection lifecycle, desktop entry points, packaging boundaries and compatibility. Dependencies: [desktop experience](02-desktop-experience.md), [operator protocol](05-operator-protocol.md), [state/evidence contract](14-state-evidence-data.md) and [pinned upstream research](research/omarchy-upstream.md). No executable, package, service or plugin described here is implemented by this specification.

## Selected design and rationale

Use one third-party plugin with `bar-widget`, `panel` and `service` kinds, a small compiled client shim, and the separate native desktop controller. The controller calls the existing Chio authority/kernel and protected adapters. The plugin owns no capability signing key, policy evaluator, independent approval decision, execution receipt signer, recovery journal or authority substitute.

The first candidate profile uses the built-in `omarchy.bar` on an actual x86_64 Omarchy machine. Test released v4.0.4 (`c668141e9c42b13c80c9ca4ea108e11708c5e8a5`) and observed development HEAD (`0f8af9be307d5d4f12cc0f6394892cac651ed5e6`) separately. Both are source baselines, not qualified Chio environments. Installed Qt, Quickshell, Hyprland, kernel, native package, provider and confinement versions belong in each P0/P7 evidence record.

Alternative A, direct QML access to the authority/guest socket, couples presentation to sensitive protocol details and cannot provide a robust stream/resource boundary. Alternative B, repeatedly invoking a CLI and parsing its human output, multiplies processes and destroys event/recovery identity. Alternative C, a generic shell command widget, cannot provide the task/review lifecycle. The selected shim has literal argv and bounded typed streams; it transports operator requests without becoming another authority.

Omarchy third-party facades are not QML sandboxes. The qualified threat profile trusts installed shell plugins and the desktop user. Same-UID file/socket modes reduce accidental exposure but do not confine a malicious desktop plugin. The untrusted agent guest receives neither the operator socket nor raw compositor, session-bus, SSH-agent or container-engine sockets.

## Proposed package layout and manifest

The following is a proposed manifest example, not an installable release:

```json
{
  "schemaVersion": 1,
  "id": "computer.chio.desktop",
  "name": "Chio",
  "version": "0.1.0",
  "description": "Confined agent tasks, review and native execution evidence.",
  "kinds": ["bar-widget", "panel", "service"],
  "keepLoaded": false,
  "entryPoints": {
    "barWidget": "BarWidget.qml",
    "panel": "Panel.qml",
    "service": "Service.qml"
  },
  "barWidget": {
    "displayName": "Chio",
    "category": "AI",
    "allowMultiple": false,
    "defaultSection": "right",
    "defaults": {
      "showCount": true,
      "reducedMotion": true
    },
    "schema": [
      { "key": "showCount", "type": "boolean", "label": "Show task count" },
      { "key": "reducedMotion", "type": "boolean", "label": "Reduce motion" }
    ]
  }
}
```

Validate the final package using the exact supported upstream `omarchy plugin validate` command plus the Chio package checks. Do not invent an Omarchy manifest `minVersion`, permission, dependency or sandbox field and assume it is enforced. Manifest version 1 validates structure and entry paths; it is not protocol compatibility negotiation. Do not claim `activation: "on-demand"` defers enabled service construction: the inspected `_syncServices` loads enabled service kinds without consulting that key. [Registry and validation sources](research/omarchy-upstream.md#pinned-primary-source-map)

Proposed installed plugin files:

| File | Responsibility |
|---|---|
| `manifest.json` | Upstream shape only. Runtime compatibility is negotiated separately. |
| `Service.qml` | One shell-wide connection owner, bounded projection model, health and lock-status handling. |
| `BarWidget.qml` | Per-monitor visual instance reading the shared service; no separate subscriptions or native processes. |
| `Panel.qml` | Lazy native surface with `open(payloadJson)`, `close()`, `opened`, navigation and task/review views. |
| `components/` | Accessible controls and plain-text bounded rendering. |
| `Model.js` | Pure projection/view transformations without process execution or native authorization. |
| `compatibility.json` | Chio-owned declared/tested version identities and feature requirements, consumed by Chio checks rather than assumed upstream behavior. |

The native package separately supplies the proposed `chio-desktop-client` and `chio-desktop-open` executables, native service/socket units where chosen by the controller contract, and the desktop entry. Packaging pins their identities. `omarchy plugin add` only clones and validates plugin files; it cannot install these prerequisites or certify them.

## QML host contracts

### Shared service

`Service.qml` is an `Item` that declares nullable `shell`, `manifest`, `pluginRegistry` and optional `omarchyPath` properties compatible with host injection. Upstream `ensureService` creates the object and then injects these properties. A readiness function runs after required properties become usable; unconditional process startup in `Component.onCompleted` is forbidden. Repeated property updates cannot start duplicate clients. [Pinned creation and lifecycle source](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/shell.qml#L893)

The service owns a generation ID, current client process, negotiated capabilities, health timestamps, current snapshot/cursor, bounded task summaries, selected task detail, pending request IDs and current lock-state projection. These are presentation/session data. Durable native operation identity and idempotency state remain with the controller. An unacknowledged mutation cannot disappear merely because this model was destroyed.

A new generation invalidates callbacks from older processes and subscriptions. Destruction closes stdin/socket, stops reconnect timers, clears transient detail buffers and terminates only its transport shim. It sends no `task.cancel`, `task.resume`, approval or publication request. Disabling/removing the plugin follows the same cleanup. The native supervisor and already admitted tasks are independently managed.

### Bar widget

Use the upstream `BarWidget` contract: injected `bar`, `moduleName` and inline `settings`. Resolve the plugin's own shell facade through `bar.shell`, then obtain only `serviceFor("computer.chio.desktop")`. Do not request first-party credentials/services or traverse the parent graph to recover a broader host object. Each monitor can render a widget, but all share the single service. [Pinned BarWidget contract](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Ui/BarWidget.qml), [bar facade](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Ui/PluginBarApi.qml)

The widget calls its own scoped `shell.summon`/`toggle` for navigation and does not call `bar.run` for task input. Under a third-party replacement bar, own-service lookup may be unavailable by design. Render a clear unsupported/degraded state; do not spawn a service per monitor or bypass the facade. Built-in-bar compatibility is the first release gate.

### Panel and navigation payload

The panel declares injectable `shell`, `manifest` and nullable `service`; the host assigns a matching service when loading a service-backed panel. `open(payloadJson)` parses a small allowlisted navigation object and sets `opened`; `close()` clears transient review state and hides without sending a native mutation. Declaring a separate panel kind is necessary because bar-widget-only summon paths discard payloads. [Pinned panel loader and summon implementation](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/shell.qml#L1120)

Proposed navigation payload: `{"view":"overview"}` or `{"view":"task","task_id":"<opaque UUID>"}`. Allow only overview, task, review and diagnostics routes, maximum 4 KiB UTF-8 total. Reject unsupported keys, malformed UUIDs and oversized data. No commands, path opens, credentials, URLs, approval arguments or executable configuration enter through summon. `open` is idempotent, performs a fresh query where possible, and may coalesce repeated navigation to the newest requested view; it never duplicates a task.

Upstream can queue multiple payloads before the panel is loaded. Do not depend on a single `open` call per UI instance. Opening a review by ID still requires fresh native task/review bindings and an unlocked known session.

## Shim and operator connection

The proposed QML `Process` command is an absolute package-resolved executable path with a fixed argv array, conceptually `["/qualified/path/chio-desktop-client", "--stdio"]`. Request values travel as bounded UTF-8 JSON through stdin. They never appear in a shell command, process title, environment variable, notification action or journal message. The path is package-owned configuration, not a task-provided override. The shim connects only to the configured versioned AF_UNIX operator endpoint from [the protocol contract](05-operator-protocol.md).

Quickshell `Process.command` preserves argument boundaries, and processes normally die with Quickshell. Its `startDetached` would break transport supervision and is prohibited for the shim. Enable stdin before launch, send requests only after process-start confirmation, and parse newline-delimited stdout incrementally. Do not use `StdioCollector` to retain an unbounded lifetime transcript. [Official Process reference](https://quickshell.org/docs/v0.2.0/types/Quickshell.Io/Process/), [SplitParser reference](https://quickshell.org/docs/v0.2.0/types/Quickshell.Io/SplitParser/)

Clear the subprocess environment, then pass only the native controller contract's necessary locale/runtime-location variables. Do not inherit provider secrets, application credential directories, signing material or arbitrary desktop environment variables. The shim writes protocol frames only to stdout and fixed redacted diagnostic codes to bounded stderr. An executable identity mismatch refuses startup; QML does not download or compile a replacement.

The selected controller starts with the graphical user session, without a linger requirement, as defined by the controller architecture. A health connection observes that service; it does not launch a task. QML never starts the long-lived controller as its child, runs `systemctl` with task input, or activates an agent merely by loading a widget. Native service activation and logout recovery are separate from upstream QML service activation. Socket activation is a possible later deployment variant requiring its own qualification, not part of the initial profile.

### Initial proposed resource defaults

These are design policy defaults, not measured upstream limits. The operator protocol owns the wire definitions; this plugin applies equal or stricter presentation limits.

| Bound | Proposed value and overflow behavior |
|---|---|
| Maximum frame | 64 KiB UTF-8 including delimiter. The shim rejects oversize/unterminated native input before forwarding; QML rejects invalid frames and reconnects with a fresh snapshot. |
| Navigation payload | 4 KiB, strict route schema; invalid input opens a harmless error/overview state. |
| Task list | At most 200 summaries per page; paging is explicit and stable against snapshot revision. |
| Visible activity | At most 500 event rows and 1 MiB retained text. Drop oldest presentation rows with a visible truncation marker; durable evidence is fetched/exported separately. |
| Per-client pending output | 256 KiB. If a slow consumer cannot catch up, invalidate the stream and require resynchronization; never silently lose an authority transition and pretend to be current. |
| Render rate | At most 10 coalesced UI updates/second. Preserve native state/revision ordering while collapsing display refreshes. |
| Heartbeat/stale | 5-second heartbeat; stale after 15 seconds without confirmed liveness. Transport close becomes offline immediately. |
| Reconnection | One attempt after 1, 2, 4, 8, 16, then 30 seconds, with bounded jitter; single-flight. Reset after established healthy negotiation. |
| Subscription count | One live event subscription per plugin service, independent of monitor/panel count. |
| Diagnostic buffers | At most 4 KiB of fixed/redacted shim diagnostics in memory; no full request or event echo. |

The shim must enforce pre-delimiter bounds: a `SplitParser` delimiter alone does not establish a bounded unfinished frame. The trusted shim validates native frame size before stdout, adds only validated complete frames, and closes on malformed input. QML validates again before model mutation. There is no unbounded file-tail fallback or continuous raw-log subscription.

### Negotiation and event state

On connection, negotiate protocol major/minor, plugin/native build identity, profile capabilities and lock-state availability via the root protocol. `health.get` cannot claim execution readiness based on executable presence alone. Unknown major version, incompatible required field/capability or unqualified profile disables mutations. Read-only diagnostics show detected versions without trying alternate mutation commands.

Subscribe using the protocol's snapshot/watermark contract. The cursor consists of an opaque epoch UUID and a safe integer sequence. Do not treat it as a timestamp or increment beyond safe integer semantics. Buffer bounded events during snapshot acquisition, then apply only events strictly after the returned watermark in the same epoch. An epoch change, sequence gap, reset-required response or queue overflow invalidates the old stream and triggers a fresh atomic snapshot. Duplicate frames are ignored by identity/revision, not re-executed.

Mutations use `idempotency_key`, immutable task/authority bindings and the exact canonical argument digest. Existing-entity mutations also bind `expected_revision`. QML never reconstructs a failed request with changed arguments under the old key. Reconnect resolves pending operation/task state using the controller contract before allowing a new deliberate action. Current unsupported approval calls refuse; absence of a native capability cannot be patched by writing a local UI decision.

Task outcomes come from native projections with explicit provenance. The plugin may display the latest projected state but cannot issue or validate its own execution receipt. `receipts.export` and native verification are separate actions. A daemon health check, exit status, log or screen capture does not become execution evidence.

## Cache, privacy and lock behavior

Store only visual preferences in Omarchy's inline widget settings: count visibility, density where supported, motion preference. Never put projects, prompts, account secrets, capabilities or approval state in `shell.json`. QML retains no sensitive persistent task cache. Current task details exist only within the bounded memory model and are cleared on lock/unknown-lock, disconnect where required by the data policy, generation replacement and close of sensitive review views.

The native state owner controls durable records, retention and redacted exports. The plugin does not follow arbitrary file paths from task output or create an independent local task database. `review.open` validates an opaque artifact binding and resolves any host opening through the qualified native adapter. QML may render a bounded structured/plain-text review returned by that interface; it does not execute `xdg-open` against untrusted returned URLs or files.

Lock state must be supplied through a separately qualified host observation path. A third-party plugin cannot assume access to Omarchy's trusted authentication service. Unknown lock state is privacy-closed: conceal details, stop detailed projections and refuse mutations. Unlock triggers fresh health, snapshot and review binding checks and never extends an operator session, approval expiry or capability lease. Tasks may continue only within the previously admitted native scope. Logout/reboot use the independently qualified native stop/recovery policy. No retention or privacy statement claims protection against a malicious same-UID shell plugin.

## Theme, input and native notification contract

Use `Color`, `Style`, `Border` and suitable upstream primitives while preserving the experience requirements. Theme changes must not restart a task/client or erase a pending operation binding. Probe `Style.duration` before using it: it is absent in the release baseline and present at HEAD. The fallback is static motion-safe presentation; the explicit Chio reduced-motion preference is always honored. No unconditional `ShellIpc` import or HEAD-only theme helper may prevent v4.0.4 parsing.

Custom QML controls supply Accessible names/roles/states/actions, keyboard focus and plain-text rendering. `PanelKeyCatcher` must be blocked while text editors/IME own input. Multi-monitor close/dismiss/focus handling requires rendered acceptance on each supported baseline. A successful component import is not sufficient accessibility evidence.

The native notification sender, if qualified, uses `app_name=Chio`, normal urgency and generic text. Its only action is a fixed Chio opener with a validated opaque task ID. A persisted historical action cannot embed a mutation request or approval payload. The upstream sender defaults to `omarchy-action`, so relying on defaults would bypass the intended DND policy. No arbitrary `--exec` command originates in model output. [Pinned notification contract](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/docs/notifications.md)

## Desktop entry, menu and default-agent compatibility

Provide a package-owned `.desktop` entry with a literal opener command and optional independently owned icon asset. A reviewed optional menu addition uses a unique `chio` key and a literal static `action` invoking the opener, with no dynamic prompt/path interpolation. Merge only that owned key into the user's extension file using a parser that preserves unrelated content; on unsupported JSONC syntax, produce a proposed edit for review rather than replacing the file. Do not add a custom menu provider, which upstream's extension schema cannot register.

A launcher/shortcut/menu invocation summons the plugin and checks live compatibility. It must distinguish missing shell, disabled plugin, unsupported protocol and native service unavailable. `omarchy-shell -q` deliberately suppresses failures and returns success; do not use it as a readiness test. The common `shell summon <id> <payload>` interface is sufficient. No Chio authority mutation is exposed as an Omarchy IPC method.

Upstream `omarchy-default-agent` and `omarchy-agent` use hardcoded cases. Installing Chio does not register a new default-agent type. Preserve the current selection, do not shadow `pi`, and do not alter upstream agent launch flags. An optional future default-agent contribution requires upstream support and a separately qualified interactive Chio agent contract. The initial controlled Pi task path cannot be advertised as an interactive CLI drop-in.

## Hot reload, upgrades, distribution and removal

`keepLoaded: false` deliberately allows service code to be replaced during upstream reload. On change, the new service performs fresh negotiation and snapshot recovery; native tasks keep their identities. Choosing `keepLoaded: true` would leave changed service code inactive until shell restart and is rejected for this plugin. A shell crash, reload, plugin disable or panel destructor must have the same nonmutating disconnect semantics.

Upstream plugin updates fetch and fast-forward their independent repository. A Chio release therefore publishes a qualified pair manifest and validates runtime version skew. Mixed plugin/native versions render diagnostics until compatible. The final native installer must coordinate package-owned activation and state migration, preserve backups, and expose rollback without assuming home-directory state rolls back with Omarchy's root snapshot. A post-update hook may invalidate compatibility but is not a final gate because later update stages can change agents and dependencies.

The plugin installer does not run a build/install hook or gain sudo. Distribution must not depend on a binary embedded in a mutable plugin checkout, an automatic network bootstrap from QML, or an executable fetched on first panel open. Publish native package signatures/digests and source provenance through the release contract; a GitHub plugin URL alone supplies none of those guarantees. No public plugin repository or native download endpoint is claimed to exist in this proposal.

Upstream remove disables then removes or backs up plugin files according to checkout type. Native package removal is separate. Its ownership manifest removes only Chio desktop entry/menu fragment/binding/plugin/service files it installed, preserving unrelated edits and retained evidence by default. If an owned file changed after install, keep it or produce a merge/removal review artifact. Removal cannot say "all tasks stopped" without native confirmation.

## Requirements and proposed acceptance

| Requirement ID | Normative requirement | Acceptance ID |
|---|---|---|
| OM-UI-001 | The manifest and package conform to the supported schema without invented security or activation guarantees. | AT-UI-001 |
| OM-UI-002 | Late injection, multiple monitors and repeated readiness produce exactly one shared service connection. | AT-UI-002 |
| OM-UI-003 | Open/close/summon payloads perform only bounded validated navigation. | AT-UI-003 |
| OM-UI-004 | QML communicates through the pinned literal-argv shim with stdin JSON and no credential inheritance. | AT-UI-004 |
| OM-UI-005 | Streams, queues, models and rendering obey the stated resource bounds. | AT-UI-005 |
| OM-UI-006 | Epoch/sequence snapshot resynchronization prevents stale or missing transitions being presented as current. | AT-UI-006 |
| OM-UI-007 | Mutations bind exact native identity, canonical arguments, idempotency and current revision. | AT-UI-007 |
| OM-UI-008 | Client destruction/reload never cancels, duplicates or supervises native tasks. | AT-UI-008 |
| OM-UI-009 | Protocol/profile incompatibility fails closed with useful read-only diagnostics. | AT-UI-009 |
| OM-UI-010 | The supported bar contract is explicit and replacement-bar degradation never bypasses facade boundaries. | AT-UI-010 |
| OM-UI-011 | Cache and lock handling prevent sensitive persistent UI state and stale decision replay. | AT-UI-011 |
| OM-UI-012 | Theme, scaling, accessibility and keyboard input work on both named baselines without HEAD-only dependencies. | AT-UI-012 |
| OM-UI-013 | Notifications preserve privacy/DND and contain navigation-only actions. | AT-UI-013 |
| OM-UI-014 | Menu/desktop/shortcut installation preserves user customization and never silently changes default agent. | AT-UI-014 |
| OM-UI-015 | Native package activation is independently installed/qualified and cannot be bootstrapped by plugin code. | AT-UI-015 |
| OM-UI-016 | Paired-version upgrades and rollback preserve native operation/evidence state. | AT-UI-016 |
| OM-UI-017 | Removal respects exact file ownership and distinguishes client removal from native task termination. | AT-UI-017 |
| OM-UI-018 | Guest exclusion of operator/desktop sockets and truthful receipt provenance are independently demonstrated. | AT-UI-018 |

### AT-UI-001: Manifest validation and load contract

Trigger: validate the proposed final package on both pinned baselines, then substitute wrong schema type, reserved ID, escaping path, missing entry, symlink and fake activation metadata. Outcome: valid package validates/loads; invalid structure is rejected; enabled service behavior does not depend on the fake activation claim. Oracle: upstream CLI result plus actual shell object/loader observations, not a local JSON schema alone. Artifact: `plugin/manifest-matrix.json` with upstream revision and package digest.

### AT-UI-002: Late injection and one connection

Trigger: instantiate with required properties initially null, inject them in varied order, update manifest, add three monitors and repeatedly open the panel. Outcome: no pre-ready crash; exactly one live shim/subscription and one shared model. Negative: no per-monitor native connection growth. Oracle: external process inventory and native accepted-connection counter. Artifact: `plugin/service-lifecycle.json`.

### AT-UI-003: Navigation payload isolation

Trigger: summon before load with repeated valid routes, malformed JSON, oversized payload, command-like fields, unrecognized UUID and expired review IDs. Outcome: bounded navigation or clear harmless refusal. Negative: zero native mutations and zero arbitrary process/file opens from every payload. Oracle: native request trace and host process/open audit. Artifact: `plugin/navigation-corpus.json`.

### AT-UI-004: Literal argv and secret-free transport

Trigger: submit fixture text with spaces, quotes, newlines, shell substitutions, option prefixes and seeded credential environment variables. Outcome: exact JSON reaches native input; argv remains the fixed shim invocation and environment remains allowlisted. Negative: no shell subprocess or canary disclosure. Oracle: external exec/environment capture, stdin frame digest comparison and log scan. Artifact: `plugin/transport-boundary.json`.

### AT-UI-005: Stream and queue bounds

Trigger: malformed UTF-8, 64-KiB-boundary frames, never-terminated oversized frame, slow reader, 100,000 events and oversized diagnostic output. Outcome: pre-forward rejection, 256-KiB queue maximum, resync on overflow, 500-row/1-MiB activity cap and at most 10 render updates/second. Negative: no whole-stream accumulation or silently current state after dropped events. Oracle: shim instrumentation plus independent RSS/pipe/model sampling. Artifact: `plugin/bounded-stream-report.json`.

### AT-UI-006: Watermark and epoch recovery

Trigger: change state during snapshot fetch, duplicate/reorder an event, insert a sequence gap, change epoch and exceed JavaScript-safe sequence input. Outcome: snapshot/watermark merge yields exact current revision or explicit resync; unsafe sequence refuses. Negative: no approval enabled against pre-gap state. Oracle: deterministic native event fixture and independently queried task revision. Artifact: `plugin/cursor-resynchronization.json`.

### AT-UI-007: Exact native mutation contract

Trigger: repeated task start, dropped mutation response, stale revision, changed arguments under one key, expired native decision and unsupported approval backend. Outcome: one exact operation, explicit conflict/refusal and same-operation reconciliation. Negative: QML/local files cannot authorize execution when native rejects. Oracle: durable native operation records, authority evidence and executor effect count. Artifact: `plugin/mutation-binding.json`.

### AT-UI-008: Reload and destruction isolation

Trigger: edit plugin files, force rescan, restart/kill shell, disable plugin and destroy an open panel while a confined task runs. Outcome: UI/shim resources stop and reconnect cleanly; native task/operation identity persists without duplicate or cancellation. Negative: no detached orphan shim or implicit task restart. Oracle: native ledger plus independent host process/socket inventory. Artifact: `plugin/reload-chaos.json`.

### AT-UI-009: Version and profile refusal

Trigger: incompatible protocol major, missing required capability, unqualified package combination, stale health and absent native package. Outcome: diagnostics names the mismatch; mutation controls disable and native requests refuse. Negative: no fallback to raw agent, previous protocol mutation, cached approval or human-output parsing. Oracle: native admission trace and process-exec audit. Artifact: `plugin/compatibility-negative-controls.json`.

### AT-UI-010: Built-in and replacement bar

Trigger: load under built-in bar, switch to a third-party replacement with service-less facade, then return. Outcome: first profile works; replacement shows degraded/unsupported status without exception or independent service; return restores fresh shared model. Negative: no parent traversal or first-party service lookup. Oracle: facade test hooks, source audit and native connection count. Artifact: `plugin/bar-compatibility.json`.

### AT-UI-011: Cache and lock handling

Trigger: display secret-canary task details, lock or lose lock-state signal, reload shell and unlock against changed task/review revision. Outcome: details clear/redact, sensitive projections stop, no persistent QML cache, fresh query precedes mutations. Negative: stale review or canary cannot be recovered from settings, notification history or plugin state files. Oracle: independent disk scan, session event capture and native mutation trace. Artifact: `plugin/cache-lock-privacy.json`.

### AT-UI-012: Cross-version native UI

Trigger: actual v4.0.4 and pinned HEAD with light/dark themes, text/output scaling, reduced motion, keyboard/IME and AT-SPI reader. Outcome: no missing `ShellIpc`/`Style.duration` load errors, legible accessible controls, correct focus behavior and no task/client restart on theme change. Negative: an unnamed mouse-only control fails even if QML loads. Oracle: shell logs, accessible tree, rendered journey audit and connection/task counters. Artifact: `plugin/rendered-compatibility.json`.

### AT-UI-013: Persistent notification safety

Trigger: emit attention notifications under DND, persist/restart shell and click an old notification after the task changes. Outcome: normal Chio notification policy, generic body, fresh navigation only. Negative: no default `omarchy-action` bypass, model-derived executable argv or native mutation on click. Oracle: D-Bus capture, history-file scan and native effect audit. Artifact: `plugin/notification-contract.json`.

### AT-UI-014: Reversible desktop registration

Trigger: install twice into custom menu/shortcuts/default-agent settings, including malformed unsupported JSONC and a shortcut collision. Outcome: one owned launcher entry, existing semantic content preserved, safe refusal/review artifact where merge cannot be trusted. Negative: no changed default agent, shadowed `pi` or edited shipped Omarchy files. Oracle: independent semantic/text diff and command-resolution inventory. Artifact: `plugin/desktop-registration.json`.

### AT-UI-015: Separate native prerequisites

Trigger: install only plugin files on a clean host, then install the independently verified native package, then tamper with shim identity. Outcome: missing-package diagnostics first, qualified health activation without task launch second, identity refusal third. Negative: no QML download/build/sudo or execution from the plugin checkout. Oracle: process/network audit and package/file provenance verification. Artifact: `plugin/native-prerequisites.json`.

### AT-UI-016: Paired upgrade and rollback

Trigger: update only plugin, update only native service, interrupt a state migration, roll back system root while leaving home state newer, and complete a supported paired upgrade. Outcome: incompatible pairs refuse mutations, recoverable backup/state policy is honored, original task/operation identity survives. Negative: successful post-update hook is not accepted as final compatibility proof. Oracle: independent package/digest record, durable native state comparison and migration fault injection. Artifact: `plugin/upgrade-matrix.json`.

### AT-UI-017: Ownership-aware removal

Trigger: remove a Git-installed plugin, remove native package with active work, and uninstall after manual edits to owned/menu files. Outcome: truthful client/service/task state, ownership-limited removal, modified files retained/reviewed and evidence preserved by default. Negative: no unrelated configuration deletion or claim of task termination without confirmation. Oracle: filesystem manifests, service/process inventory and native task records. Artifact: `plugin/removal-ownership.json`.

### AT-UI-018: Guest separation and provenance

Trigger: from the real confined guest try the operator socket, shell IPC socket, compositor/session-bus/SSH/container sockets and a forged "verified" event; then export a genuine receipt. Outcome: guest access fails under the qualified isolation profile; forged projection cannot acquire verified status; exported receipt is independently checked. Negative: same-UID shell-plugin resistance is not counted as passed isolation. Oracle: guest namespace/mount/network inspection, protected executor logs and independent receipt verifier. Artifact: `plugin/guest-and-provenance.json`.

## Risks and prerequisite owners

Desktop maintainers own QML parser/API compatibility, one-service lifecycle, focus and theme acceptance. The controller owner owns bounded native framing, durable request reconciliation and the protocol capability matrix. Native security owners qualify guest exclusion and lock-state observation; no QML behavior closes those gates. Release owners publish the paired artifacts and ownership/migration record. Accessibility reviewers qualify the AT-SPI/Orca journey on actual supported packages.

The first implementation should prove P1 on the named built-in-bar profile before enabling P2. Each later mutation surface waits for native evidence, especially approvals. A successful manifest check, mock screenshot, macOS source test, or privileged non-Omarchy container run cannot satisfy the rendered Linux or guest-isolation acceptance cases above.
