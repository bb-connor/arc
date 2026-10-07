# Omarchy upstream research

Status: Proposed research baseline, verified 2026-10-07. Confidence: high for the pinned source behavior below; unknown for Chio running on an actual Omarchy desktop. No runtime qualification is claimed.

Scope: release versus development compatibility, shell plugin API, launch/menu paths, lifecycle, theme, input, notification privacy, and distribution. This research supports the desktop experience and plugin specifications. Native authority, isolation, and provider qualification remain separate prerequisites.

## Evidence baseline

The current public repository redirects the old `basecamp/omarchy` URL to `omacom/omarchy`. Live `git ls-remote` returned the following exact revisions. GitHub's latest-release URL resolved to v4.0.4 on the research date. A checkout of HEAD is not equivalent to the released ISO or to the user's installed rolling package set.

| Baseline | Public revision | Use in this package |
|---|---|---|
| Released Omarchy v4.0.4 | `c668141e9c42b13c80c9ca4ea108e11708c5e8a5` | Initial release compatibility candidate, still requiring P0 and P7 execution evidence. |
| Development HEAD observed 2026-10-07 | `0f8af9be307d5d4f12cc0f6394892cac651ed5e6` | Separate development compatibility candidate. Do not silently substitute for v4.0.4. |
| Installed Quickshell, Qt, Hyprland, kernel | Not measured on an Omarchy host | P0 must record package versions, architecture, shell source/package identity, and compositor/session behavior. The repository package list supplies package names, not these installed versions. |

The [v4.0.4 release page](https://github.com/omacom/omarchy/releases/tag/v4.0.4) identifies the release and downloadable ISO. The source commit timestamp is distinct from the release publication timestamp. No ISO boot, install, package update, hardware behavior, or binary execution was performed for this research.

## Pinned primary source map

All GitHub source links below were inspected from the corresponding local public checkout; the release page, shell manual/reference, and upstream Qt/Quickshell references were also checked through the web. A URL's presence is not proof that a Chio package exists.

| Source ID | Pinned public source | Evidence used |
|---|---|---|
| O-01 | [Release plugin registry](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/shell/services/PluginRegistry.qml) | Manifest validation, enabled state, trusted metadata, file discovery. |
| O-02 | [HEAD plugin registry](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/services/PluginRegistry.qml) | Compared with release; no change in this file between the two pins. |
| O-03 | [HEAD shell lifecycle](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/shell.qml) | Service instantiation, injection order, self-scoped APIs, panel queues, reload. |
| O-04 | [Release shell lifecycle](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/shell/shell.qml) | Release baseline for the shared shell integration. |
| O-05 | [Plugin facade](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/services/PluginShellApi.qml) | Own-service lookup, summon/hide/toggle, settings access; not a sandbox. |
| O-06 | [HEAD shell reference](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/docs/omarchy-shell.md) | Documented manifest kinds, shell configuration, bar and component contracts. |
| O-07 | [Release shell reference](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/shell/README.md) | Reference lived in shell/README.md before the HEAD documentation move. |
| O-08 | [Plugin install](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-add) and [validation](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-validate) | Git staging, confirmation, reserved IDs, entry-point and symlink checks. |
| O-09 | [Plugin update](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-update) and [remove](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-plugin-remove) | Fast-forward update, validation rollback, removal semantics. |
| O-10 | [Release IPC wrapper](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/bin/omarchy-shell) and [HEAD IPC wrapper](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-shell) | Release uses qs IPC; HEAD adds socket fast path and uncertainty handling. |
| O-11 | [HEAD ShellIpc](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Commons/ShellIpc.qml) and [IpcRegistry](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Commons/IpcRegistry.qml) | New handler registry absent at the release pin. |
| O-12 | [Default-agent setter](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-default-agent) and [agent launcher](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-agent) | Hardcoded supported agents, package/account selection, launch modes. |
| O-13 | [Menu schema and behavior](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/docs/menu.md) and [menu implementation](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/plugins/menu/MenuModel.js) | JSONC extension merge, action strings, guards, fixed provider set. |
| O-14 | [Default shortcuts](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/default/hypr/bindings/utilities.lua) | Existing menu, agent, audio, notification and task-adjacent shortcut collisions. |
| O-15 | [Agents plugin](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/plugins/agents/README.md) and [manifest](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/plugins/agents/manifest.json) | Existing usage/subscription UI, local projections, refresh and account flows. |
| O-16 | [Release Style](https://github.com/omacom/omarchy/blob/c668141e9c42b13c80c9ca4ea108e11708c5e8a5/shell/Commons/Style.qml) and [HEAD Style](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Commons/Style.qml) | Shared scale and typography; HEAD-only reduceMotion/duration helper. |
| O-17 | [KeyboardPanel](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Ui/KeyboardPanel.qml), [PanelKeyCatcher](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Ui/PanelKeyCatcher.qml), [WidgetButton](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/Ui/WidgetButton.qml) | Focus priming, multiple monitors, editor key interception, custom controls. |
| O-18 | [Notifications](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/docs/notifications.md), [sender](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-notification-send), [service](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/shell/plugins/notifications/Service.qml) | Disk persistence, DND behavior and persistent click commands. |
| O-19 | [Update implementation](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-update) and [hook runner](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/bin/omarchy-hook) | Hook ordering and nonfatal hook failures. |
| O-20 | [Snapshot manual](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/47-system-snapshots.md) | Root restoration excludes home and user configuration. |
| O-21 | [Quickshell Process 0.2.0](https://quickshell.org/docs/v0.2.0/types/Quickshell.Io/Process/) and [SplitParser 0.2.0](https://quickshell.org/docs/v0.2.0/types/Quickshell.Io/SplitParser/) | Literal argv, stdin, lifetime coupling and delimited stream behavior. API reference version, not a measured installed package. |
| O-22 | [Qt Quick Accessible](https://doc.qt.io/qt-6/qml-qtquick-accessible.html) | Accessibility roles, names, states and actions must be supplied for custom items. Rolling documentation; installed Qt version must be checked. |

## Findings and compatibility decisions

### Plugins are native UI code with desktop-user privileges

Manifest schema version 1 supports `bar-widget`, `panel`, `overlay`, `menu`, `service`, and full `bar` entry points. User plugins live under `~/.config/omarchy/plugins/<id>/`; shipped plugins live under the Omarchy shell tree. A third-party ID cannot use the reserved `omarchy.` namespace. The third-party facades narrow ordinary calls to the plugin's own service and lifecycle. Visual QML still shares an object scene, and plugin code retains the desktop user's file and process access. Authentication services receive separate upstream treatment, which does not establish a general third-party sandbox. [O-01, O-03, O-05, O-08]

Decision: trust the installed Chio plugin and desktop user. Place the untrusted agent in a separately qualified guest. A 0600 socket or same-UID daemon is not a security boundary against a malicious installed plugin. Never market facade restrictions as agent confinement.

### Lifecycle must tolerate destruction and late property injection

`ensureService` creates a QML object, then assigns `shell`, `manifest`, and supported registry properties. Startup cannot assume these exist during `Component.onCompleted`. `_syncServices` mounts enabled service kinds; the observed implementation does not use an `activation` manifest key to defer that work. `keepLoaded` has concrete lifecycle semantics: retained service instances survive plugin reload, and their changed service code does not take effect until replacement or shell restart. Ordinary reload unloads panels, nonretained services, and registered widgets before rescan. A `bar-widget` without panel/menu/overlay kinds takes the bar's own summon path and drops the payload; a plugin declaring `panel` takes the panel-loader path and receives queued `open(payloadJson)` deliveries. [O-03, O-04]

Decision: one service, one bar widget, one explicit panel, `keepLoaded: false`. Treat destruction as disconnect only. Late injection starts one connection after capability checks; repeated ready events are idempotent. The native task supervisor must outlive QML, its client shim, and shell restart. A Chio deep link opens a view and never authorizes work.

### Release and HEAD are separate support candidates

| Surface | v4.0.4 | Observed HEAD | Chio consequence |
|---|---|---|---|
| Schema and registry | Version 1 | Same registry file | Manifest validation is necessary, insufficient for runtime compatibility. |
| Shell IPC transport | `qs ipc` through `omarchy-shell` | Socket fast path, then safe fallback to qs where no call ran | Call the public wrapper for navigation; never use its private socket as the Chio protocol. |
| `ShellIpc` QML type | Absent | Adds own-socket registration | No unconditional import/use in a release-compatible plugin. Chio needs no custom Omarchy mutation IPC target. |
| Motion helper | No `Style.duration`/`reduceMotion` | Helper follows compositor animation preference | Feature probe and explicit Chio reduced-motion setting; static fallback on unrecognized shell. |
| Menu guards | `when`/`checked` | Adds `disabled` handling | Installation entry must use common fields; task capability gating occurs in Chio UI and native admission. |
| Default agent choices | Hardcoded list includes Pi and Gemini | Adds Ori, maps Gemini aliases to Antigravity (`agy`), other launcher changes | Do not infer supported agent interface from an executable being on PATH. |
| Agents panel | Existing usage panel | Expands account/sign-in/autoswitch and Grok handling | Retain the upstream panel; Chio owns task and authority state, not subscription-account administration. |
| Documentation location | Detailed shell/README.md | Reference moved to docs/omarchy-shell.md | Source links must use the correct revision and path. |

An upstream version string does not freeze Arch dependencies. P0 needs a compatibility record naming all installed versions plus each expected feature. Unknown combinations may open a read-only diagnostics screen but cannot expose execution as qualified. [O-01 through O-17]

### Third-party replacement bars degrade service-backed widgets

Under the trusted built-in bar, a Chio widget can retrieve its own service through the scoped facade. A replacement bar is not allowed to manufacture live service access for arbitrary widgets; its widget entry facade is service-less. [O-03, O-05, O-06]

Decision: first qualified profile requires `omarchy.bar`. Detect missing own-service access and show a useful unavailable status rather than dereference null, poll a parallel service, or reach through parent objects. A separately summoned Chio panel is a possible later compatibility route, but must be tested before inclusion in a support claim.

### Native launch paths do not provide a Chio provider registration point

The agent setter and launcher dispatch through explicit cases. Pi is recognized, but launching upstream `pi` is not equivalent to launching a confined Chio Pi task. Several other agents are deliberately launched with unattended or permission-skipping flags; those flags do not establish Chio authorization. `SUPER+SHIFT+CTRL+A` already launches the selected agent. `SUPER+A` and related A shortcuts have existing meanings. [O-12, O-14]

Decision: install a distinct Chio desktop/menu opener. Do not overwrite the user's default-agent selection, shadow `pi`, or rewrite `omarchy-agent`. An upstream default-agent entry is an optional contribution after interactive adapter and lifecycle qualification. The initial Pi candidate is a controlled task runner, not a promise of interactive drop-in parity.

### Menu customization is possible, but not a dynamic authorization API

User menu JSONC overlays named keys and is watched live. Actions and guards are shell command strings. The parser removes whole-line comments and trailing commas; malformed user content can remove all custom entries from the live menu. Providers are a fixed implementation map, not plugin-defined callbacks. [O-13]

Decision: add at most one owned static action with a literal installed opener command, no project path/prompt/token interpolation, no guard that contacts the authority. Preserve the user's other extension fields and formatting or refuse an unsafe parse with a repair artifact. Use a desktop entry as the primary independently removable launcher. A menu action opens Chio and obtains fresh state; menu guard visibility is never an authorization check.

### Theme reuse requires explicit accessibility work

The shell offers `Color`, `Style`, and `Border` roles; font and spacing scales can change at runtime. `KeyboardPanel` handles layer-shell focus and outside-click dismissal across screens. `PanelKeyCatcher` consumes navigation and activation keys before child handling unless blocked for active editors. The inspected custom `WidgetButton` does not establish a complete keyboard or assistive-technology contract by itself. Source inspection did not establish end-to-end Orca/AT-SPI behavior. [O-16, O-17, O-22]

Decision: reuse visual roles, add names/roles/states/actions to Chio controls, use text plus shape for status, and test keyboard, text entry, screen reader, large text, multi-monitor focus and reduced motion independently. An importable `Accessible` type is not evidence of a usable screen reader experience.

### Notification content becomes persistent desktop state

Omarchy writes displayed notifications to disk and moves dismissed/expired entries into history. Click commands survive shell restarts. Its default notification sender uses the `omarchy-action` application name, which can bypass DND. [O-18]

Decision: emit `app_name=Chio`, normal urgency, generic bodies, and a fixed opener action only. Do not include task prompts, project paths, approval arguments, credentials, diffs or output excerpts. DND is respected. The notification opens the current pending item after reconnect; it never grants, retries, cancels or publishes. Lock privacy is enforced through minimized content and a separately qualified lock-state observation path, not by requesting the shell's authentication service object.

### Update and rollback are not Chio recovery

The observed HEAD updater runs the `post-update` hook before mise updates and later AUR work. Hook failures are printed while the hook runner continues. Omarchy system snapshots restore the root filesystem, leaving `/home` and `~/.config` unchanged. [O-19, O-20]

Decision: a post-update hook can invalidate cached compatibility but cannot certify final compatibility. Recheck before each task admission and after reconnect. Versioned controller state, plugin configuration backups, review artifacts, and native reconciliation need their own upgrade/rollback policy. A root snapshot is not a task checkpoint or a home-directory restore.

### Distribution installs QML files, not a qualified native stack

Plugin add clones a repository, validates manifest/files, then can enable it. It has no package installation hook and does not install a Rust daemon, native authority, confinement backend, Qt module, or credential store. Update fetches origin HEAD, shows a diff in the ordinary interactive path, fast-forwards and validates. Validation rollback is a repository rollback, not transactional coordination with a running controller. [O-08, O-09]

Decision: publish pinned public qualification candidates for the native package and plugin repository before the P7 clean-host retrieval gate, explicitly marked unqualified. Promote a supported release only after P7 passes for the selected pair. P1 prepares the generated plugin source/export handoff; P7 publishes, pins and installs the candidate through the real plugin lifecycle. Pin the qualified pair in a release manifest. Treat upstream plugin update as an independently occurring version change and fail closed on protocol mismatch. Provide no invented public install URL in this proposal.

## Existing adjacent work and differentiation

The built-in Agents panel already solves usage and subscription visibility. Its JSON usage files are useful display inputs, not execution attestations or enforceable task budgets. Chio should coexist with it. [O-15]

The community [Omarchy OMCP project](https://github.com/btsouth/omarchy-omcp) already supplies desktop MCP tools, per-tool allow/ask/off controls, queued requests, a visible panel, and stop controls. The inspected Python source uses `allow`, `ask`, and `deny` internally. These are meaningful existing capabilities. Chio's proposed distinction must be demonstrated at the protected executor and native authority boundaries: confined guests, exact resource and operation identity, durable uncertainty handling, independently verified receipts, and controlled publication. A prettier panel or another stop button is not sufficient differentiation. Pin the community revision in the community comparison artifact before making detailed implementation comparisons; this section is not a full OMCP security assessment.

## Open qualification work and owners

| Prerequisite artifact | Owner | Closure evidence |
|---|---|---|
| Omarchy compatibility record for each supported profile | Desktop integration maintainer | Exact package and source identities, actual x86_64 Omarchy shell boot, IPC and lifecycle tests, theme/input evidence. |
| Native controller/authority capability matrix | Native runtime maintainer | Read-only versus mutation gates, exact approval support, isolation and recovery qualification. |
| Accessibility report | Desktop accessibility reviewer | Keyboard trace, AT-SPI tree, spoken output, zoom/scaling/theme contrast measurements and exceptions. |
| Lock/privacy integration record | Desktop and security maintainers | Session lock observation proven on target, fail-closed unknown state, notification history scan, reconnect races. |
| Paired-package upgrade record | Release maintainer | Native/plugin version skew, state backup and forward/backward migration, package rollback and resumed task reconciliation. |
| Community comparison revision record | Research maintainer | Public OMCP commit pinned with source-level capability comparison. |

Research completion does not close any P0-P7 runtime gate. Release claims require the independently collected evidence named by the implementation roadmap.
