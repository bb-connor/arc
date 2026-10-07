# Native Mac operator and exact-review experience

Status: proposed normative design, 2026-10-07. No native app or platform runtime is qualified by this document. Confidence: high in the retrieved Apple API behavior, moderate in the proposed interaction design, unknown in final per-OS interaction qualification.

Read [product scope](01-product-scope.md), [authority and integrity](04-authority-integrity.md), [operator protocol](06-operator-protocol.md), [resources](10-project-resources.md), and [workflow API research](research/macos-workflow.md). Wire types, method parameters, opaque authority references, bounds, and retry semantics are owned solely by the operator protocol. The view models below are presentation concepts and never alternate wire definitions.

## Native composition

Use a SwiftUI application with an ordinary window and Dock presence, plus `MenuBarExtra` for quick status and stop access. AppKit supplies Services, file selection, window lifecycle, and desktop-specific accessibility behavior. Closing the main window or removing the menu-bar item does not imply stopping a task or terminating the per-user service. The app explicitly distinguishes **Close Window**, **Quit Chio**, and **Stop Work**; quitting disconnects a presentation client, while service lifetime follows the host/recovery contracts.

The main window uses a compact sidebar with **Work**, **Review**, **Resources**, and **Evidence & Recovery**. Work shows task outcome and worker state; Review groups concrete pending operations by task; Resources shows OS access separately from run grants; Evidence & Recovery shows original operation outcomes, gaps and safe recovery actions. The task detail leads with result, next action, and execution location, then input generation, authority and evidence. There is no global green “protected” badge.

The menu bar shows a neutral icon with accessible text and bounded counts for active work, awaiting review, and attention needed. It exposes Open Chio and Stop Work. It does not expose one-click approval, resource contents, filenames, recipient addresses, prompts, or a stream of sensor events. A stop request presents its progress immediately and remains queryable after disconnection.

## Entry points

**Finder Services.** Register `Run with Chio` through `NSServices` and `NSApplication.servicesProvider`, accepting a bounded list of file URLs and supporting exactly one directory in the first release. A service invocation is an input proposal. The UI resolves access and shows the selected repository/revision before starting. Reject non-file URLs, file promises, aliases not explicitly resolved by selection, multiple selections, device roots and unsupported projects with an actionable message. An app Open Project command is always available when Services is hidden or disabled. Services registration is tested in a signed installed app; development invocation is not installation evidence.

**Finder extensions.** A Finder Sync extension is not required for the pilot. Apple's Finder Sync API addresses synchronization status and control; any later badge/context extension must justify that role and follow the same bounded handoff. A Shortcuts-based Finder Quick Action can open the same configured intent; installing a workflow is a separate distribution action. No broad filesystem watcher is introduced just to obtain a menu item.

**App Intents.** A closed vocabulary can open the task composer for `project-change-v1`, obtain redacted status, open task evidence, or request a stop. Any start still requires a valid native task grant and preflight. There is no generic shell intent, argument-to-command interpolation, grant creation intent, or approve/publish intent. The authentication policy for resource-bearing intents requires local device authentication; this establishes device interaction only, not exact endorsement. SDK-specific foreground APIs are selected with availability checks; the current docs deprecate `openAppWhenRun` in favor of `supportedModes`, so source compilation pins the chosen SDK rather than copying an obsolete pattern.

**Notifications and deep links.** A notification says “A Chio task needs review” or “A Chio task needs attention” and opens the authenticated review location. The notification payload contains only an opaque routing identifier. A URL, notification action, restored window, clipboard item, or shortcut cannot submit endorsement. Cross-user or stale routing identifiers resolve to unavailable, with no task-title disclosure.

## Preflight and review

Preflight has a fixed order: source revision and dirty-state exclusion; bounded user objective and its sealed task-input resource; intended change and edit allowlist; execution profile and location; permitted resources and model data export; fixed tests; budget/time/resource limits; expected deliverable and publication boundary. A missing qualification or OS permission disables start with a specific recovery action. Task configuration text is captured as a distinct task-input resource before `task.create`; its reference cannot substitute for the workspace reference. Bootstrap influence joins before worker readiness, and authentic operator assertions require the native integrity contract. Text cannot change the selected template's effect surface.

The exact review window displays native-verified operation content: effect kind, full meaningful destination/recipient, account identity, exact artifact/diff commitment, released data, costs, expiry, original operation state, policy/binding freshness, and changed relevant influence. Human-readable summaries supplement the exact material and never replace it. Long destinations have selectable wrapped text; the action button is named for the effect, such as **Export this patch**. Approve is not the default Return action; Cancel/Dismiss is safe. The person can inspect bounded full content without executing it, decline, or request a new proposal.

Opaque kernel-owned proposal and endorsement references travel through the protocol. Swift does not sign, serialize an alternate authority payload, choose a policy digest, mint a native operation identity, or cache approval for future unrelated effects. When native binding changes, the window shows **Review changed** and disables submission until a fresh review opens. A timeout or lost reply shows **Checking original outcome**, never an optimistic success. A duplicate click carries the same stable client intent and reconciles the same native operation.

Review renders repository strings as text. Strip terminal control effects from logs while keeping a separately downloadable raw evidence payload under explicit export. Show bidirectional controls, confusable destination names and invisible path characters in an inspectable escaped representation. Render Unicode labels for people but bind raw source identities, not a normalized display string. Web/HTML previews are inert and have no network, scripts, auto-loading remote images, or command links. Dangerous file types default to plain-text or metadata inspection.

## Privacy, accessibility, and interruption

Private content is hidden in menu-bar, notification, app-switcher/restoration previews, and presenter mode. The app starts sensitive review windows redacted; foreground local interaction plus a fresh native review enables deliberate reveal. Loss of app activity, user-session change, system sleep or screen sleep re-redacts and clears presentation-only review readiness. These notifications are UI hints, not an authoritative lock-state API. Native authority must independently reject endorsement when the required session/authentication conditions cannot be established.

Do not promise capture prevention. Apple's current documentation describes `NSWindow.SharingType.none` as a legacy constant macOS no longer uses. `privacySensitive` marks views for redaction when the privacy redaction reason is applied; it is not a universal screen-recording detector. Presenter mode hides the data before rendering, removes it from accessibility labels and copy affordances, and disables endorsement until exact content is deliberately revealed again. A person can still screen-share visible content; the product must not claim otherwise. Secret credentials never enter view state at all.

Keyboard navigation, VoiceOver reading order, Voice Control labels, clear focus movement, increased contrast, reduced motion, text resizing and a non-color state vocabulary are release requirements. Review controls remain accessible without TCC Accessibility permission; requesting that permission for the app's own accessible UI would confuse product accessibility with automation of other apps. App strings use a string catalog with pluralization, locale-aware numbers/costs and time-zone-aware timestamps. Technical identities remain byte-exact and left-to-right isolated where appropriate, with copyable full values. Pseudolocalization and right-to-left layout are qualification inputs, not promises that every language is translated.

| Condition | User-visible truth | Available action |
| --- | --- | --- |
| App disconnected; service health unknown | “Reconnecting; latest state unavailable.” Previous data is explicitly stale. | Reconnect, open last verified evidence, request stop with pending state. |
| Missing folder permission | “Choose access to this project.” | Select the exact folder or cancel; no automatic home-directory access. |
| Resource grant expired/revoked | “This task no longer has access.” | Inspect grant, request a new bounded task action. |
| Profile unqualified or degraded | Exact unavailable capability and last observed health. | Select a separately qualified profile after fresh preflight or view evidence. |
| Task awaiting exact review | Concrete effect and destination. | Inspect, endorse exactly, decline. |
| Source/destination changed | Conflict or stale review with changed input highlighted. | Create a fresh generation/proposal; no overwrite. |
| Stop requested | Admission fence, worker closure, broker outcome and cleanup as distinct rows. | Inspect progress, reconcile original operations. |
| Outcome unresolved | “Outcome unknown; do not repeat this action.” | Reconcile, export redacted evidence; no fresh retry shortcut. |
| Disk full/evidence unavailable | “Result not yet durable” or exact evidence gap. | Recover storage, reconcile original state, inspect retained evidence. |

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-UX-001 | The native operator MUST provide Work, Review, Resources, and Evidence & Recovery views with authoritative-state freshness. | AT-MAC-UX-001 |
| MAC-UX-002 | Menu-bar presence and window/app closure MUST be independent of authority-service task lifetime and MUST expose a distinct stop action. | AT-MAC-UX-002 |
| MAC-UX-003 | Finder Services and Open Project MUST validate bounded selection and open preflight without granting resource or effect authority. | AT-MAC-UX-003 |
| MAC-UX-004 | App Intents MUST use a closed task/status/evidence/stop vocabulary and MUST NOT expose generic shell, approve, or publish actions. | AT-MAC-UX-004 |
| MAC-UX-005 | Permission onboarding MUST distinguish OS access, run grant, and exact endorsement and present refusal-specific recovery. | AT-MAC-UX-005 |
| MAC-UX-006 | Preflight MUST make source generation, profile/location, fixed tests, exports and limits inspectable before admission. | AT-MAC-UX-006 |
| MAC-UX-007 | Exact review MUST display native-verified effect, destination, artifact, meaningful release, cost and binding freshness before the effect-specific submission. | AT-MAC-UX-007 |
| MAC-UX-008 | Changed bindings, duplicate submission and lost replies MUST use native invalidation and original-operation reconciliation without optimistic success. | AT-MAC-UX-008 |
| MAC-UX-009 | Notifications, deep links, restored windows and event hints MUST only route or refresh UI and MUST NOT authorize or disclose another user's data. | AT-MAC-UX-009 |
| MAC-UX-010 | Stop UI MUST separately display admission fence, worker termination, network/resource cleanup and known or unresolved broker outcomes. | AT-MAC-UX-010 |
| MAC-UX-011 | Sensitive review MUST default to redacted presentation and re-redact on inactivity, session/sleep signals and presenter mode; native endorsement MUST independently validate required current conditions. | AT-MAC-UX-011 |
| MAC-UX-012 | Presenter mode MUST remove sensitive rendered text, accessibility content, previews and copy actions without claiming screen-capture prevention. | AT-MAC-UX-012 |
| MAC-UX-013 | All primary flows MUST be operable with keyboard and VoiceOver and support non-color state, increased contrast, reduced motion and larger text. | AT-MAC-UX-013 |
| MAC-UX-014 | Localized UI MUST preserve exact technical identities, full destinations, plural meaning and readable layout under pseudolocalization and right-to-left presentation. | AT-MAC-UX-014 |
| MAC-UX-015 | Logs, paths, diffs and previews MUST render adversarial content inertly, expose ambiguous characters and preserve byte-exact evidence identity. | AT-MAC-UX-015 |
| MAC-UX-016 | Error states MUST preserve recoverable work and name the failed boundary and safe next action without inventing successful closure. | AT-MAC-UX-016 |
| MAC-UX-017 | App UI and diagnostics MUST omit service secrets, minimize resource contents, and require explicit redacted evidence export. | AT-MAC-UX-017 |
| MAC-UX-018 | Endorsement UI MUST be kernel-owned in authority, with no Swift approval key/store and no assumption that local authentication alone endorses an effect. | AT-MAC-UX-018 |

## Acceptance procedures

| Acceptance | Setup/action | Expected independent evidence |
| --- | --- | --- |
| AT-MAC-UX-001 | Replay fresh, stale and disconnected protocol fixtures into all four views. | Screenshot/accessibility tree and controller records agree; stale timestamps are visible and consequential controls are disabled where freshness is required. |
| AT-MAC-UX-002 | Start a task; close its window, remove menu extra, quit/relaunch app; then request Stop Work. | Service/task identity survives presentation changes under the declared lifetime contract; explicit stop records its own transition and truthful closure. |
| AT-MAC-UX-003 | Invoke Services with one folder, two folders, HTTP URL, file promise, alias and inaccessible directory. | Only the supported exact folder reaches preflight; rejected inputs have bounded localized errors and zero task admissions. |
| AT-MAC-UX-004 | Inspect generated intent metadata; invoke start while locked and inject shell metacharacters/template substitutions. | Only the declared vocabulary exists; locked resource invocation requires unlock; no arbitrary executable, grant creation or publication operation appears in controller logs. |
| AT-MAC-UX-005 | Independently deny folder access, revoke run grant and expire endorsement. | Three distinct explanations and recoveries; approving an OS dialog does not unblock missing native authority. |
| AT-MAC-UX-006 | Compare preflight screen and accessible text with native records for local and remote tasks. | Exact source/profile/location and bounded tests/export/spend values match; no collapsed field hides the remote destination or requested release. |
| AT-MAC-UX-007 | Open a long, costly, sensitive publication proposal and navigate only by keyboard/VoiceOver. | Full meaningful destination, content and cost are inspectable before enabled effect-specific submission; Return from initial focus does not approve. |
| AT-MAC-UX-008 | Change policy/influence/destination after opening review; double-click; drop the successful response. | Native rejects old binding; stable intent maps duplicates to one operation; UI queries original outcome and never invents a new approval. |
| AT-MAC-UX-009 | Replay notification and URL for expired, unknown and another-user task; restore an old window. | No endorsement is sent; other-user titles and paths remain absent from UI/logs; fresh authenticated lookup controls routing. |
| AT-MAC-UX-010 | Stop after one intent committed while worker dies but broker reply is missing. | UI shows fence and worker closure separately from unresolved broker; receipt/effect count matches recovery evidence. |
| AT-MAC-UX-011 | Show sensitive review, deactivate app, switch users, lock screen without sleep, sleep/wake and restart. Attempt queued approval on each transition. | Presentation redacts and loses review readiness; current native session gate refuses stale/unknown conditions even if a UI notification is delayed; exact OS lock behavior is recorded per matrix. |
| AT-MAC-UX-012 | Enable presenter mode while screen sharing through the qualification capture app; inspect accessibility tree, window restoration and Copy commands. | No sensitive field remains rendered, spoken, restored or copied. Revealing data is explicit and the test does not claim that visible content cannot be captured. |
| AT-MAC-UX-013 | Complete configure, inspect, decline, stop and reconcile using keyboard, VoiceOver and larger text with contrast/reduced-motion settings. | Recorded completion without pointer, no focus trap/truncation of required action, labeled status and no essential motion/color dependency. |
| AT-MAC-UX-014 | Run UI tests with doubled-length strings, Arabic-style RTL layout, German number formatting and mixed-script destinations. | Buttons remain visible; costs parse correctly in locale; displayed and copied technical bytes match exact input; accessible reading order preserves effect meaning. |
| AT-MAC-UX-015 | Render ANSI cursor controls, bidi override paths, HTML scripts, remote image URLs and a 10 MiB log. | No execution/network callback; bounded viewer remains responsive; ambiguous characters are disclosed and raw evidence hash remains unchanged. |
| AT-MAC-UX-016 | Inject revoked access, service exit, disk full, evidence loss, destination conflict and unresolved publication. | Each state has one safe action or explicit no-safe-retry message, retained operation identity, and no successful closure without evidence. |
| AT-MAC-UX-017 | Place credential canaries in broker memory and resource content; export diagnostics with normal settings. | UI state dump, logs and export contain no credentials; sensitive paths/content follow redaction policy and export requires an explicit action. |
| AT-MAC-UX-018 | Present locally authenticated but forged/stale opaque review reference from the app and a second client. | Native authority rejects invalid provenance/binding; no UI key or second approval database exists; genuine exact review maps to the kernel-owned record. |
