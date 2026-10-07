# Reviewed configuration repair

Status: Proposed. Confidence: high that user-configuration backup, restricted validation and exact approval are required by the inspected source; moderate in the proposed transactional host adapter until fault qualification. Scope: P5 one bounded user configuration domain, Hyprland appearance scalars in `~/.config/hypr/looknfeel.lua`. Dependencies: P4 desktop identity/observer, P3 exact native approvals, P0 version pins, project-style immutable artifacts, and a qualified native host-file mutation participant. When writer exclusion or reload safety cannot be established, this profile produces preview and diagnosis only.

The product outcome is a small, reviewable repair whose exact file changes, validation evidence, backup and live result are visible. A diagnosis does not authorize arbitrary configuration changes. The controller presents the plan; a protected native resource owns mutation and recovery, and Chio owns authorization, receipts and original-operation identity.

## Decision and bounded domain

Choose appearance scalars because their value space can be closed and their intended effects observed. Initial allowed keys are `general.gaps_in` and `general.gaps_out` integers 0..32, `general.border_size` integer 0..8, `decoration.rounding` integer 0..32 and `animations.enabled` boolean. These are proposed policy bounds, not all values Hyprland permits. The installed compositor's pinned option schema must confirm each key/type before use. A wrong type or changed schema disables repair.

Only the enrolled `looknfeel.lua` regular file may be changed. The entire input must parse as single-line comments, whitespace and literal `hl.config({ ... })` declarations over that allowed scalar subset. Preserve unrelated allowed declarations and comments; unsupported functions, loops, variables, dynamic expressions, strings that select programs, `require`, `dofile`, `load`, `os`, `io`, keybindings, monitors, plugins and other option keys refuse automated apply. The shipped comments-only template can qualify. An existing customized Lua file outside this subset receives diagnosis and a manual patch artifact, with no host mutation.

Do not replace all Hyprland files using `omarchy refresh hyprland`, reinstall configs, run an agent-produced Lua interpreter on the host, or use root filesystem rollback for home configuration. Omarchy already has a [crash diagnosis workflow](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/default/agents/skills/diagnose-crash/SKILL.md). Reuse its evidence categories and keep the task's diagnosis separate from the proposed repair.

## Requirements

| ID | Normative requirement | Acceptance |
| --- | --- | --- |
| OM-FIX-001 | The first repair profile MUST restrict changes to the declared single-file scalar domain and reject broad or privileged repair requests. | AT-FIX-001 |
| OM-FIX-002 | Diagnosis MUST retain bounded selected evidence with source/version/time provenance and distinguish observations from causal hypotheses. | AT-FIX-002 |
| OM-FIX-003 | Proposed bytes MUST be generated and reviewed from one immutable config snapshot with exact before/after hashes and a closed semantic diff. | AT-FIX-003 |
| OM-FIX-004 | Preflight MUST parse and validate only private copied inputs under confinement; proposed or existing Lua must never execute on the host merely to validate. | AT-FIX-004 |
| OM-FIX-005 | Apply MUST require native approval binding the exact file set, patch, validation, backup, reload effect plan, session/version and expiry. | AT-FIX-005 |
| OM-FIX-006 | Independent home-configuration backups MUST be durably verified before mutation; system snapshots are not accepted as those backups. | AT-FIX-006 |
| OM-FIX-007 | File mutation MUST use a qualified writer-exclusion and compare-and-swap protocol with no-follow identity checks; ordinary hash-then-rename is insufficient. | AT-FIX-007 |
| OM-FIX-008 | Original intent, individual file stages, reload boundary and terminal outcome MUST be durable; multi-file requests are refused in the first profile and never described as atomic without proof. | AT-FIX-008 |
| OM-FIX-009 | Reload MUST be explicitly included in the effect plan, bounded to the enrolled session and refused when dependent Lua/hooks have unbounded or changed effects. | AT-FIX-009 |
| OM-FIX-010 | Success MUST require exact installed bytes, empty relevant config errors and independently observed live scalar values; a successful command alone is insufficient. | AT-FIX-010 |
| OM-FIX-011 | Rollback MUST compare the current state, preserve newer user changes and retain the original failure; failed or uncertain rollback cannot be called restored. | AT-FIX-011 |
| OM-FIX-012 | Crash, lost reply, cancellation and timeout MUST reconcile the original operation and preserve unknown effects instead of automatically retrying apply or reload. | AT-FIX-012 |
| OM-FIX-013 | Config, logs, backups and diagnostic outputs MUST remain private, bounded and excluded from provider/export channels unless explicitly selected. | AT-FIX-013 |
| OM-FIX-014 | The default repair profile MUST have no sudo/polkit, package/update, bootloader, system snapshot, service-management or arbitrary command authority. | AT-FIX-014 |
| OM-FIX-015 | P5 enablement MUST require an actual-machine fault matrix, independent restoration evidence and a version-bound profile gate. | AT-FIX-015 |

## Diagnosis, snapshot and preview

The proposed diagnostic intake uses fixed resource queries: installed Omarchy/Hyprland identities, selected session availability, bounded `configerrors`, current allowed option values and a no-follow copy of the single target file. An optional crash reference is an operator-selected immutable tuple of boot/session identity, executable build identity, timestamp and PID/start identity. A PID alone can refer to a later process. The default collects structured coredump metadata and selected bounded journal ranges, not core memory or an unrestricted journal. Match evidence to the selected incident; absent/rotated logs are recorded as unavailable. A timestamp correlation is a hypothesis, not proof that configuration caused a crash.

The target file must be owned by the enrolled user, a regular single-link file under its registered canonical root, at most 64 KiB. Default profile refuses symlinked dotfiles, aliases and files with ACL/xattr/flags that its backup/restore implementation cannot preserve. It never rewrites a symlink target or normalizes an original in place. The resource snapshots exact bytes, mode, permitted metadata, inode identity, source digest and dependency inventory into private immutable storage. Any input change invalidates the snapshot and requires a new preview.

The patch artifact contains task and native authority references, enrolled target handle, original hash, proposed hash, bounded textual diff, parsed scalar before/after values, reason/evidence references, grammar version and validator digest. It explicitly lists unchanged meaning that the parser could establish; it never claims arbitrary Lua semantics are unchanged. The review states that replacing a config file can trigger automatic reload and lists the concrete reload plan. No model-supplied path, shell command, executable, validator flag or Lua expression becomes an operator parameter.

Proposed limits: one file, 64 KiB original/proposed bytes, 16 KiB diff, five scalar keys, 10-second validator deadline, 32 MiB scratch space and 16 KiB validator output. Large diagnostics remain selected private artifacts; the controller returns references in its bounded protocol frame. These limits are policy defaults and require measurement.

## Validation without host execution

Phase one is a real syntax parser for the closed literal subset, not regular-expression removal of suspicious words. It rejects any node outside the grammar, duplicate/conflicting keys, nonfinite/fractional/out-of-range numbers, unsupported Unicode/path aliases and additional statements. The generator emits only that grammar. This validates the proposed file's allowed meaning without evaluating Lua.

Phase two runs the pinned validator against the proposed copy and the sealed configuration dependency graph in a private sandbox. It has no host home, Wayland/compositor/D-Bus/SSH/container/operator sockets, network or provider credentials; copied inputs are read-only, scratch is bounded and descendants are governed. If installed Hyprland supports a useful offline parser, qualify that exact binary/mode. Otherwise use a qualified isolated headless test compositor with no live session devices and a pinned minimal test configuration. Do not invent a `hyprctl` dry-run flag: `hyprctl configerrors` reads the running compositor, and a live `reload` evaluates configuration. `luac` syntax success alone proves neither option validity nor effect safety.

Validation reports exact source/dependency/validator/runtime hashes, parsed values, parser errors, duration and any attempted external effects. A green confined run is evidence for those inputs, not a guarantee that arbitrary surrounding live Lua is harmless. The whole live reload graph, including `hyprland.lua`, packaged defaults, autostart, user required modules and relevant environment-derived includes, must match an operator-enrolled effect profile. Dynamic/unresolvable includes or hooks whose reload behavior cannot be bounded make apply unavailable. A new Chio import of that graph cannot become an agent grant to execute it on the host.

## Approval, backup and file custody

Native approval binds the canonical effect-plan digest: original native operation, task revision and authority, enrolled file identity, complete before/after hashes, grammar/validator/runtime/dependency hashes, validation result, backup manifest, exact reload target/behavior, any explicitly authorized compensating restore, and approval expiry. The decision is one use, proposed expiry 60 seconds. Changing bytes, schema, file set, dependent config, compositor epoch or backup invalidates it. If the native decision gate is unavailable, the UI can preview but cannot apply.

Before requesting apply approval, prepare the backup under a proposed private repair store, using operator-selected paths that the guest never receives. Backup includes original content, hash and supported metadata, and an independently reloadable manifest. Write/fsync file and containing directory, read back, rehash and verify restore representability. Keep backup and recovery records separate from mutable live configuration. Proposed retention is the latest ten completed repairs for 30 days, whichever retains more, plus every unresolved or unacknowledged repair indefinitely. Quota exhaustion refuses a new repair; it never removes the only recoverable original.

Omarchy's [snapshot guide](https://github.com/omacom/omarchy/blob/0f8af9be307d5d4f12cc0f6394892cac651ed5e6/manual/47-system-snapshots.md) says root snapshots omit `/home` and leave `~/.config` unchanged. A Snapper ID is therefore contextual evidence, never a substitute for this backup. Restoring a root snapshot can additionally change software while retaining a newer user config; compatibility must be rechecked afterward.

The native host-file resource must own a qualified write exclusion protocol for the entire replacement interval. Requirements include no-follow directory-relative opens, stable root/ancestor identities, current-file type/link/metadata and full-content preconditions, safe same-directory staging, durable rename, and rechecking the complete dependency/approval binding. A cooperating editor lock or qualified exclusive maintenance mode may satisfy writer exclusion; a lock ignored by active editors does not. Linux rename atomicity prevents a torn individual replacement but does not implement content CAS against arbitrary concurrent writers. If the prerequisite cannot prevent/detect a stale overwrite with a safe outcome under its stated writer model, automated apply is unavailable. Same-UID malicious user defense is outside the chosen threat profile, but ordinary concurrent editors remain a required race case.

## Durable effect stages and reload

The resource retains one original operation with stages `prepared`, `backup_verified`, `intent_durable`, `file_installed`, `reload_sent`, `postcheck_observed` and a terminal or unresolved outcome. These are resource stages, not task states. Each stage records exact hashes and observations, with durable intent before the first live effect. The kernel alone determines signed completion/delivery. A controller restart does not infer completion from this unsigned journal.

First-profile multi-file plans refuse before live writes. This is intentional: filesystem renames across several paths are not one atomic operation, and Hyprland may observe intermediate states. Any future domain expansion must record per-file planned/original/installed/restored hashes, stage all files and verify all preconditions before effect, control automatic reload, and fault-test every replacement boundary. If a second replacement fails after the first, the result is `partial` or `unknown` effect detail with exact known installed files, never an ordinary no-effect failure. It must preserve backup and original identity, block further repair and use a reviewed conditional compensation. A successful database commit is not proof of a multi-file atomic host effect.

Even a scalar-only candidate lives within executable Lua configuration. Before replacement, the qualified adapter must suppress/coordinate automatic reload using only its enrolled native mechanism and record the previous setting, or prove the installed compositor supports an equivalent safe one-file apply sequence. Existing privileged Omarchy package reload guards are not the repair participant. Failure to establish/restore the selected reload mode is a retained failure, not an ignored best effort. When reload is sent, its dependency graph and potential hooks must still match the approved plan. Host execution of those already enrolled config effects happens only as the explicitly approved apply step; it never happens during preview validation.

Issue one normal reload against the exact session; `full-reset`, compositor restart, service restart or reboot is excluded. Observe reload completion, bounded config errors and the allowed live option values using the protected desktop participant. A `configreloaded` event alone is insufficient: it may belong to another edit and says nothing about errors. Bind observation timestamps and installed digests, retain conflicting events, and compare the expected option values. Proposed postcheck deadline is 3 seconds. If the compositor disappears or response is lost after possible reload, retain unknown; never automatically replay Lua to find out what happened.

## Failure, restoration and privacy

Failure before live mutation can become a proven no-effect refusal. After a possible live effect, retain the exact stage and evidence. Safe automatic compensation is allowed only if the original approval explicitly included restoring the exact backup under declared conditions, the currently installed file equals the proposed hash and the dependency/session state remains compatible. Otherwise create a fresh reviewed restore proposal. Never overwrite a newer user edit. Restoration is a new conditional effect linked to the original, not erasure of the failed attempt.

Restoring bytes does not undo external effects that a reload hook already performed. A recovery report separately records file restoration, reload restoration, live option recovery and any unverified external effects. Missing backup, changed current file, failed fsync, failed reload or uncertain descendant state prevents a `restored` claim. Preserve broken/proposed bytes as private forensic material. Cancelling before dispatch prevents effect; cancelling after installation stops later unapproved work and reconciles the original, without pretending the old configuration returned.

Diagnostic logs, config text and backups may contain secrets. The default model context contains only selected error excerpts, allowed scalar values and necessary relative file labels. Core dumps, complete environment, command lines, arbitrary journal ranges, screenshots and clipboard are excluded. Sensitive content screening plus labels and explicit selection gate the provider-bound excerpts; unrecognized secrets cannot be assumed absent. No backup is attached automatically to a bug report or remote artifact. Proposed default diagnostic read budget is 64 KiB per incident, with per-field truncation flags and original-byte counts where known. Artifact names and logs must not contain raw secret values.

## Acceptance cases

These are proposed gates, not completed checks. Every mutation case uses a disposable actual Omarchy x86-64 user session with a separate filesystem/compositor observer, independent of the controller and repair participant.

### AT-FIX-001: Domain restriction

Trigger: repair an allowed scalar, then attempt keybindings, monitor layout, arbitrary Lua and a second file. Observable outcome: only the closed scalar plan validates; others remain preview/refusal with no live write. Independent oracle: target/neighbor hashes and compositor dispatch/process observer. Evidence artifact: `fix-001-domain.json`.

### AT-FIX-002: Diagnosis provenance

Trigger: supply a real incident, reused PID, rotated log and an unrelated package timestamp. Observable outcome: exact incident matching and explicit unavailable/inferred fields; no fabricated cause. Independent oracle: independent journal/coredump metadata capture and incident fixture timeline. Evidence artifact: `fix-002-diagnosis.json`.

### AT-FIX-003: Exact preview

Trigger: propose two scalar changes with preserved comments, then alter source bytes during review. Observable outcome: original/proposed hashes and semantic diff match; altered source invalidates apply. Independent oracle: parse and hash proposed bytes with a separate parser/harness. Evidence artifact: `fix-003-preview.json` and private diff artifact.

### AT-FIX-004: Host-free validation

Trigger: candidate and dependent Lua attempt process launch, network, host-file reads, socket access, infinite loop and output flood. Observable outcome: grammar refusal or confined bounded failure; zero host execution as validation. Independent oracle: host syscall/process/network observation, canary hashes and sandbox output/timing counters. Evidence artifact: `fix-004-validator-isolation.json`.

### AT-FIX-005: Exact approval

Trigger: approve one plan, then substitute hash, backup, validator, dependency, session, expiry or native decision availability. Observable outcome: invalid/unsupported approval cannot produce a write or reload. Independent oracle: native approval verifier and live inode/hash/IPC observations. Evidence artifact: `fix-005-approval.json`.

### AT-FIX-006: Real home backup

Trigger: create verified backup, inject disk-full/fsync/readback corruption and present only a Snapper ID. Observable outcome: original backup restores exact bytes and supported metadata; incomplete backup or root-only snapshot blocks apply. Independent oracle: restore into a separate private directory and independently compare bytes/metadata. Evidence artifact: `fix-006-backup.json`.

### AT-FIX-007: Writer exclusion and CAS

Trigger: edit the file between hash and replace; rename a parent; substitute symlink/hardlink; leave an editor holding a writable descriptor. Observable outcome: the qualified protocol preserves newer user changes or refuses before live effect; unsupported exclusion leaves apply unavailable. Independent oracle: adversarial writer trace, independent inode/byte history and no-follow syscall trace. Evidence artifact: `fix-007-cas-races.json`.

### AT-FIX-008: Stage and multi-file truth

Trigger: send a two-file plan to the first profile and fault the single-file journal at every durable stage. For any future expanded profile, inject failure immediately after first replacement. Observable outcome: default multi-file has zero effects; crash truth remains exact; extension reports partial/unknown rather than atomic success or no-effect failure. Independent oracle: external file-history observer and reopened native/resource journals. Evidence artifact: `fix-008-stage-matrix.json`; extension results cannot close first-profile runtime gaps by simulation alone.

### AT-FIX-009: Reload effect containment

Trigger: add dynamic include or command-executing reload hook, change a dependency after validation, fail reload suppression and replace compositor epoch. Observable outcome: apply/reload is unavailable before exposure; approved bounded graph receives one normal reload only. Independent oracle: host process/write/network observer, compositor request log and dependency hashes. Evidence artifact: `fix-009-reload-effects.json`.

### AT-FIX-010: Observed repair success

Trigger: emit accepted reload with config error, valid parse with wrong live value, unrelated reload event and successful actual repair. Observable outcome: only exact bytes plus clean relevant errors plus expected live values produces success. Independent oracle: separate `getoption`/error observer and on-disk hashes. Evidence artifact: `fix-010-postconditions.json`.

### AT-FIX-011: Conditional restoration

Trigger: fail postcheck with unchanged proposed file, then repeat after a user edit and with a corrupted backup/failed restore reload. Observable outcome: only preauthorized compatible restoration proceeds; new user bytes survive; incomplete restoration remains failed/unknown with the original failure retained. Independent oracle: independent before/proposed/current/restored hashes and live-value observations. Evidence artifact: `fix-011-restoration.json`.

### AT-FIX-012: Unknown and cancellation

Trigger: crash after replacement, lose reload reply, cancel before dispatch and after installation, restart the controller. Observable outcome: original identity retained, zero undispatched effects, no blind reload/reapply, and unresolved effects shown `blocked_unknown`. Independent oracle: native original-operation verifier plus exact write/reload counters. Evidence artifact: `fix-012-recovery.json`.

### AT-FIX-013: Diagnostic disclosure bounds

Trigger: insert token canaries in config comments, environment, core-like bytes and logs; generate oversized/malicious error text. Observable outcome: only selected bounded excerpts leave the private resource; no raw secrets/core/environment in prompts, logs or exports; UI treats text literally. Independent oracle: trusted provider-relay capture, canary scan and encoded frame measurements. Evidence artifact: `fix-013-privacy.json`.

### AT-FIX-014: No privileged repair

Trigger: request package refresh, sudo, polkit action, root snapshot, bootloader edit, system service restart and generic shell fallback. Observable outcome: unavailable with no elevation prompt or privileged process. Independent oracle: process/audit observer, package state and protected-file hashes. Evidence artifact: `fix-014-privilege-exclusion.json`.

### AT-FIX-015: Actual-machine release gate

Trigger: execute the full repair and restoration matrix on a clean named profile, then update Omarchy, compositor, parser or validator. Observable outcome: enabled only for accepted identities and bounded writer/reload models; drift disables apply while preserving diagnosis/review. Independent oracle: independent acceptance runner and complete version/hash manifest. Evidence artifact: `fix-015-profile-qualification.json`.

## Prerequisites and unresolved risks

The repair adapter owner must deliver the restricted parser, generator, safe snapshotter, backup store, host write-exclusion contract and stage journal. Native integration owns exact approvals and original-operation reconciliation. Desktop integration owns session-safe reload/observation and automatic-reload coordination. Release engineering owns actual-machine fault and restoration evidence. The harder unresolved issue is not generating a plausible Lua edit; it is proving the surrounding live reload and concurrent-writer behavior fit the approved effect. Until those prerequisites exist, P5 is preview/diagnosis only.
