# Bounded desktop tools

Status: Proposed. Confidence: high in the inspected IPC and community-tool behavior; moderate in a native adapter until compositor/session qualification. Scope: P4 bounded desktop metadata and explicit workspace selection. Dependencies: P3 exact native approvals, operator/guest separation, native durable operation and recovery contracts, and P0's installed Omarchy/Hyprland version pins. Proposed tool names below are resource tools, not additional controller API methods.

Chio adds governed access to a desktop the operator already uses. A protected resource adapter owns session access; the guest sees typed results. The initial profile has four read tools and one workspace mutation. Window targeting, capture and input injection require distinct gates. The QML plugin displays review and native status; it does not own compositor authority or issue receipts.

## Decision and alternatives

OMCP already implements fixed verbs, allow/ask/off, a global pause, resolved approval targets and activity UI. Omarchy-MCP implements a broad tool catalog, window state observations, layout operations and generic route/dispatch surfaces. The [ecosystem research](research/desktop-ecosystem.md) records pinned implementations. Adopt narrow behavior and test cases after license/source review. Do not import an entire MCP server's ambient authority into the guest, wrap its generic executor as one Chio tool, or introduce a second approval panel with independent semantics.

Direct guest access to `hyprctl`, the Wayland socket, session D-Bus, PipeWire, clipboard helpers or raw compositor IPC is rejected. Executable allowlists do not restrict the arguments, runtime authority or data exposure of those interfaces. Broad `run_command`, `omarchy_exec`, `hypr_dispatch`, arbitrary Lua and shell strings remain absent from every default profile.

## Requirements

| ID | Normative requirement | Acceptance |
| --- | --- | --- |
| OM-DSK-001 | P4 MUST advertise exactly the enabled closed desktop inventory and refuse every unqualified action before dispatch. | AT-DSK-001 |
| OM-DSK-002 | The protected desktop resource MUST own all compositor access and keep raw session/operator transports unreachable from the guest. | AT-DSK-002 |
| OM-DSK-003 | Each request MUST bind one enrolled user/session/compositor epoch and refuse stale, locked or ambiguous session targets. | AT-DSK-003 |
| OM-DSK-004 | Input schemas MUST reject extra properties, raw selectors, commands, arbitrary paths and unknown enum values before native admission. | AT-DSK-004 |
| OM-DSK-005 | Desktop reads MUST expose only the selected metadata with explicit freshness, bounded pages and privacy labels. | AT-DSK-005 |
| OM-DSK-006 | Workspace selection MUST target an explicit enrolled numeric slot, bind exact native approval and preserve its original operation identity. | AT-DSK-006 |
| OM-DSK-007 | Address-targeted window mutations MUST remain disabled until compositor-side stable-target validation closes address-reuse races. | AT-DSK-007 |
| OM-DSK-008 | A mutation result MUST distinguish dispatch, observed post-state and independently verified native execution evidence. | AT-DSK-008 |
| OM-DSK-009 | Bounded socket lifecycle, serialization and event resynchronization MUST protect compositor responsiveness and stale-state handling. | AT-DSK-009 |
| OM-DSK-010 | Cancellation, expiry, revocation and stop MUST be enforced by native admission and the resource, with honest in-flight outcomes. | AT-DSK-010 |
| OM-DSK-011 | Lost responses and resource/controller restarts MUST reconcile the original operation without redispatching or treating current desktop state as original completion. | AT-DSK-011 |
| OM-DSK-012 | Screenshots, screen recording, clipboard and OCR MUST remain unavailable in the default profile pending explicit disclosure and target/capture gates. | AT-DSK-012 |
| OM-DSK-013 | Launch, URL opening, keystrokes, notifications with actions, audio/network/power and package operations MUST remain outside this first desktop profile. | AT-DSK-013 |
| OM-DSK-014 | Desktop observations and untrusted strings MUST not become instructions, executable markup, approval authority or unbounded logs. | AT-DSK-014 |
| OM-DSK-015 | Each enabled profile MUST retain source provenance, exact tool/schema/policy hashes and actual-machine independent acceptance evidence. | AT-DSK-015 |

## Exact initial inventory and schemas

All objects reject additional properties. UUIDs are opaque enrolled handles; digests are 64 lowercase hexadecimal characters; integer values must be finite integers. `session_id` cannot be used to derive an arbitrary socket pathname. The controller enrolls it from the selected operator session. Common read inputs are `{session_id: UUID, session_epoch: Digest}`. The fixed resource configuration supplies tool deadlines, output limits and capability scope; the guest cannot widen them.

| Proposed resource tool | Additional input fields | Exact returned projection and scope |
| --- | --- | --- |
| `desktop_session` | None | `session_id`, epoch, locked/available status, installed version identifiers, observed timestamp, snapshot digest. No environment dump or PID command line. |
| `desktop_windows` | `limit: integer 1..32`, optional opaque snapshot-bound `cursor` | Maximum 32 mapped-window records: opaque window handle, enrolled app class identifier when policy permits, numeric workspace, mapped/floating/fullscreen booleans. Titles, initial titles, executable paths and command lines excluded. |
| `desktop_workspaces` | None | Enrolled numeric workspace slots 1..10 with occupancy and active flag, maximum ten records. Special and named workspaces excluded. |
| `desktop_monitors` | None | Up to eight session-local opaque monitor handles, dimensions, scale and active flag. Serial numbers, descriptions and stable hardware identifiers excluded. |
| `desktop_workspace_select` | `workspace_id: integer 1..10`, `expected_snapshot_digest: Digest` | Attempted destination slot, pre/post snapshot references, one observed outcome and native operation reference. The action selects the numeric slot in the enrolled session; it promises no particular physical monitor or window focus. |

Pagination binds one immutable observation snapshot with a 5-second proposed lifetime. A changed/expired snapshot refuses the cursor rather than mixing pages; returning fewer records with `truncated: true` is allowed and explicit. Empty, unavailable and truncated are distinct. A snapshot digest covers canonical relevant state and session epoch; observation timestamps are separate, so an unchanged state can be freshly confirmed without changing its digest. Proposed read result cap is 16 KiB, including JSON escapes. The controller's 64 KiB protocol frame carries metadata or a private artifact reference, never an arbitrary raw compositor response. These are proposed limits, not measured capacities.

`desktop_window_focus` and window move/close/resize are reserved concepts and are not advertised tools. Raw `address:0x...`, PID, title regular expression or app-name arguments are forbidden. If a later profile enables a window operation, the resource creates a handle binding session epoch, compositor-provided stable generation, observed client identity and allowed operation. The compositor must compare that generation and perform the operation in the same serialized handler. A resource-side lookup immediately before sending an address is insufficient. The inspected Hyprland documentation does not establish such a primitive; no enabled feature may assume it exists.

## Custody, session identity and effects

The proposed protected desktop participant receives only the enrolled user's permitted compositor request/event endpoints. It is launched by trusted native configuration and serves the kernel on its protected transport. The guest receives no session socket, runtime-directory mount, service bus, `DISPLAY`, `WAYLAND_DISPLAY` route, SSH agent, container socket, clipboard helper or operator control socket. Only native resource calls cross that boundary. Same-UID files and modes protect against other users, not malicious installed shell plugins; the selected threat profile trusts the operator and plugins.

Enrollment records OS boot identity, UID, logind session identifier when available, compositor PID plus start identity, instance signature, socket identity and binary/version inventory. The adapter derives allowed socket paths from trusted enrollment and validates ownership/type and peer credentials; it does not accept guest `XDG_RUNTIME_DIR` or `HYPRLAND_INSTANCE_SIGNATURE`. Pin the connected peer for the request. A compositor restart produces a new epoch and requires re-enrollment/explicit task binding update, not transparent retargeting. Missing lock-state support, multiple plausible sessions, unavailable peer identity or a locked session makes writes unavailable. Read access while locked returns only availability, never a cached window inventory.

Workspace selection uses a fixed serialization of the integer slot into the installed compositor's qualified dispatcher grammar. There is no model-provided Lua. Before admission, native review binds task/authority, tool/schema version, canonical arguments, session epoch, exact slot, snapshot digest and approval expiry. Proposed approval lifetime is 60 seconds; final pre-dispatch observation must be at most 2 seconds old and match the reviewed state digest. Unchanged state can be freshly confirmed; changed relevant state requires a new review. Native approval is mandatory for the first profile. A native decision gate that refuses `approval.submit` leaves the request waiting and dispatch count zero.

The resource rereads session lock/identity and the relevant snapshot just before dispatch. This does not lock the user's input; a human may change workspace concurrently. The action's scope is the numbered slot in this compositor session, not the mutable previously active window or output. No mouse-relative, `+1`, next, special workspace or broad batch action is used. Exactly one compositor dispatch is attempted per native operation. Post-observation records whether the requested slot became active within 2 seconds. If it immediately changes due to human input, report the actual sequence; do not continually force it back.

An IPC acknowledgement such as `ok` means the request was accepted, not that the desired state occurred. Resource results distinguish `not_dispatched`, `dispatched_observed`, `dispatched_postcondition_failed`, and `dispatch_outcome_unknown` as effect details; these are not additional task states. `succeeded` requires retained native completion plus the required post-state observation. A read-only status projection never replaces either. Timeouts after a possible dispatch retain unresolved native intent and lead to `blocked_unknown` until reconciliation.

## Responsiveness, cancellation and recovery

Hyprland's [IPC specification](https://github.com/hyprwm/hyprland-wiki/blob/ede823b521d8bade91894cf1b3ff25b5ab7ee64b/content/ipc/_index.md) describes synchronous request handling and separate events. Initial policy: one request in flight per session, maximum eight queued resource calls, one-second IPC read/write deadline, immediate connection close on completion/error, 64 KiB raw response ceiling, 8 KiB event line ceiling, 256 queued events and at most two full metadata polls per second. Event overflow or disconnect invalidates the snapshot and requires one bounded full resync; dropped events cannot leave a snapshot marked fresh. Resource deadlines are below the native gateway deadline. Unsupported command grammar or malformed JSON disables the affected tool without invoking a fallback shell command.

A native stop prevents future admissions and cancels queued calls, including reads. It cannot retract already sent compositor bytes. In-flight work retains original identity, dispatch phase and receipt delivery state. A user switching workspace after stop is not an adapter effect. A restart never replays an unrecorded desktop mutation to obtain evidence. Current active workspace alone cannot distinguish this operation from a human or another tool; unresolved histories remain unknown unless native original-operation evidence is sufficient. Exact completed replay returns the retained result without refocusing the desktop.

The kernel owns capability checks, approval, revocation and signing. The resource's durable effect record retains intent, exact request, connection/session epoch, dispatch boundary and observations. The controller has no alternate allowlist or retry engine that can bypass a native denial. OMCP's own permission files and activity logs can be displayed as separate external information if later integrated, but they are never imported as Chio decisions or receipts.

## Privacy and deliberately deferred interfaces

Default desktop metadata is still private context: app classes and workspace use can reveal activity. Enroll reads per task, label them `desktop-private`, never inject them automatically into every conversation and strip terminal control sequences/markup before UI rendering. Model output, titles and compositor events cannot request more tools by embedding instructions. Raw diagnostics remain private bounded artifacts and must not be embedded into activity notifications.

Capture and clipboard are disabled, including convenience access through OMCP, portals, `grim`, `wl-paste`, OCR or thumbnail tools. Any later capture profile needs exact window/region/monitor identity, per-capture native consent, exclusion of other windows/overlays, a local image review before provider egress, recipient/retention labels, bounded pixels/bytes and independent evidence for focus/geometry changes during capture. A window rectangle is not proof the pixels belong exclusively to that window. Clipboard read/write needs exact selection ownership/content digest and approval without exposing raw contents in logs. If capture cannot satisfy those conditions, refuse it.

Launchers, URLs, keyboard/pointer input, actionable notifications, theme hooks, session locks, audio, network, power, packages and arbitrary Omarchy routes are not incremental additions to a generic executor. Each would require a separately specified narrow destination, effect and recovery profile. They remain absent in P4 even when a community server implements them.

## Acceptance cases

Run against the pinned actual Omarchy x86-64 compositor with a separate observer connected only for evidence. The observer does not trust adapter success strings. Retain machine/profile/version/schema digests and a sanitized timing log for each case.

### AT-DSK-001: Exact advertised inventory

Trigger: enumerate tools under P4 and request reserved/unknown tools. Observable outcome: exactly four reads and workspace selection when its native gates are ready; otherwise selection is unavailable; every other action refuses. Independent oracle: native registered manifest plus compositor dispatch observer. Evidence artifact: `dsk-001-inventory.json`.

### AT-DSK-002: Raw desktop bypass denial

Trigger: guest probes compositor/Wayland/D-Bus/PipeWire/SSH/container/operator sockets and attempts `hyprctl` directly. Observable outcome: no session access; an admitted read succeeds. Independent oracle: OS socket/mount/process observer and compositor request counter. Evidence artifact: `dsk-002-custody.json`.

### AT-DSK-003: Session substitution and lock

Trigger: forge environment paths, reuse an epoch after compositor restart, introduce a second session and lock during pending approval. Observable outcome: no retargeted dispatch or cached private reads; explicit unavailable/stale result. Independent oracle: separate session/peer identity and compositor request capture. Evidence artifact: `dsk-003-session-races.json`.

### AT-DSK-004: Schema injection

Trigger: submit strings in numeric slots, unknown fields, relative selectors, socket paths, raw Lua, NUL and oversized cursors. Observable outcome: refusal before admission/effect; valid fixed integer succeeds. Independent oracle: native canonical argument digest plus zero compositor dispatch for rejected cases. Evidence artifact: `dsk-004-schema.json`.

### AT-DSK-005: Private bounded metadata

Trigger: create windows with credential-like titles, more than 32 windows, cursor expiry, event staleness and locked state. Observable outcome: omitted titles, bounded pages, explicit truncation/staleness and no private inventory while locked. Independent oracle: known fixture windows and encoded response scan/byte count. Evidence artifact: `dsk-005-metadata.json`.

### AT-DSK-006: Exact slot approval

Trigger: review slot 3 then substitute slot 4, snapshot, epoch, task revision, approval expiry or native gate availability. Observable outcome: only the exact current approval dispatches one slot selection; unavailable native approval dispatches zero. Independent oracle: native decision evidence and compositor event/request capture. Evidence artifact: `dsk-006-approval.json`.

### AT-DSK-007: Address reuse gate

Trigger: request focus/move/close and replace a window at the same address during a target race fixture. Observable outcome: base profile refuses all such operations. Any future enabled profile must prove atomic generation comparison and zero effect on replacement. Independent oracle: compositor-side instrumented handle lifecycle and operation counters, not pre/post address equality. Evidence artifact: `dsk-007-target-gate.json`.

### AT-DSK-008: Real postcondition

Trigger: compositor accepts a request but post-state differs, then a real slot selection succeeds while the user changes it again. Observable outcome: dispatch acknowledgement alone never yields success; retained observations accurately show ordering and limits. Independent oracle: separately collected compositor state/events and native receipt verifier. Evidence artifact: `dsk-008-outcome.jsonl`.

### AT-DSK-009: IPC responsiveness

Trigger: issue a burst, malformed/oversized responses, delayed request completion and an event overflow/disconnect. Observable outcome: bounds enforced, connections closed, queue capped, snapshots invalidated and one resync performed. Independent oracle: compositor frame/input latency observer, socket lifetime trace and actual request count. Evidence artifact: `dsk-009-ipc-bounds.json`; proposed gate is no adapter-held request socket beyond one second plus measured scheduler tolerance of 100 ms.

### AT-DSK-010: Stop and admission races

Trigger: stop/revoke/expire while queued, after approval and during dispatch. Observable outcome: zero dispatch for pre-dispatch denial; possible dispatched effect remains recorded and cannot become false cancellation success. Independent oracle: native admission timings and socket write observer. Evidence artifact: `dsk-010-stop-races.json`.

### AT-DSK-011: Lost desktop response

Trigger: kill the resource after socket write and before result commit; separately lose a completed reply and restart controller. Observable outcome: unknown stays fenced; completed replay returns original evidence with no second focus; current matching desktop alone never clears the unknown. Independent oracle: original native-operation verifier and dispatch counter. Evidence artifact: `dsk-011-recovery.json`.

### AT-DSK-012: Capture and clipboard exclusion

Trigger: request screenshot, OCR, clipboard, raw capture helper and indirect capture via a community route. Observable outcome: unavailable under the default manifest; no capture or selection request occurs. Independent oracle: compositor capture/clipboard observer and no image/clipboard canary bytes in provider/log/artifact channels. Evidence artifact: `dsk-012-disclosure.json`.

### AT-DSK-013: Unsupported effect classes

Trigger: request app launch, URL, keypress, notification action, network/power change and generic Omarchy routing. Observable outcome: all absent/refused without command launch. Independent oracle: process and relevant external state observers with positive controls. Evidence artifact: `dsk-013-exclusions.json`.

### AT-DSK-014: Untrusted desktop text

Trigger: emit event strings containing prompt injection, terminal escapes, HTML and huge Unicode sequences. Observable outcome: treated as bounded data, UI literal rendering, no extra admission or log growth. Independent oracle: rendered UI inspection, native operation inventory and file byte counts. Evidence artifact: `dsk-014-untrusted-text.json`.

### AT-DSK-015: Installed profile qualification

Trigger: install the exact candidate on a clean supported machine, run the above cases, then change compositor/schema/package identity. Observable outcome: a named profile report only for the tested combination; changed identity invalidates mutation qualification until rechecked. Independent oracle: package/binary hash inventory and a separately signed acceptance report. Evidence artifact: `dsk-015-profile-manifest.json`.

## Risks and owners

Desktop adapter ownership includes bounded IPC, epoch enrollment and observer integration. Native authority ownership includes exact approval and original-outcome recovery. Compositor integration owns the unresolved stable-target primitive; no root task should assume it is available. Release engineering must measure responsiveness and locked-session behavior on actual hardware. The first useful outcome is reliable metadata plus an explicitly selected workspace, not unrestricted desktop autonomy.
