# Project resource contract

Status: Proposed. Confidence: high in the inspected coding-resource primitives; moderate in the proposed desktop importer until P2 qualification. Scope: one recoverable, confined project task with an immutable local review artifact. Dependencies: P0 compatibility and native resource prerequisites, P1 status integration, P2 protected Pi execution; P3 adds reviewed publication decisions. No Git push, pull-request creation, deployment or host-checkout writeback is supported by this profile.

Chio should turn a selected project into a bounded resource whose original inputs, edits, test results and review output can be independently checked. The controller requests work; the protected resource owns repository effects. Kernel admission, exact approval, signatures, original operation identity and recovery remain native responsibilities.

## Decision and existing candidate

Adopt the public [coding-resource candidate](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/CODING-RESOURCE.md) rather than exposing the developer's working directory to Pi or implementing another effect ledger in the controller. Its [schemas](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/coding-resource/schemas.ts), [repository](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/coding-resource/repository.ts), and [ledger](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/coding-resource/ledger.ts) support exact-source reads, compare-and-swap patches, immutable generations, fixed recipes and retained outcomes. That source is a candidate, not an Omarchy-qualified package.

Direct use of its `init` against a normal checkout is unsuitable: it requires private modes and rejects links. A proposed trusted importer prepares a private copy without chmod, moving, cleaning or resetting the source. An unrestricted Git worktree plus shell is rejected because build configuration, hooks, filters and credentials become ambient authority.

## Requirements

| ID | Normative requirement | Acceptance |
| --- | --- | --- |
| OM-RES-001 | Only an operator-selected registered project and explicit import selection may enter a task; task text cannot choose host paths or discover repositories. | AT-RES-001 |
| OM-RES-002 | Intake MUST preserve dirty originals and retain reviewed provenance for tracked, staged, unstaged and selected untracked inputs. | AT-RES-002 |
| OM-RES-003 | Intake MUST inventory links, gitlinks, ignored and sensitive paths without following or silently admitting them; unsupported selections refuse. | AT-RES-003 |
| OM-RES-004 | The importer MUST publish one race-checked immutable selected generation or refuse; mixed-time copies are not an accepted snapshot. | AT-RES-004 |
| OM-RES-005 | The resource owner MUST be reachable only through the kernel-owned participant connection; guest host filesystem, operator state and original checkout access are absent. | AT-RES-005 |
| OM-RES-006 | The tool inventory MUST stay closed and bounded to the nine candidate tools; no shell, Git, network, arbitrary path or arbitrary recipe tool is added. | AT-RES-006 |
| OM-RES-007 | Patches MUST bind the current source digest and every full-file precondition and commit all changed resource files together. | AT-RES-007 |
| OM-RES-008 | Native original-operation binding, durable intent, generation publication and retained result MUST preserve uncertainty and exact replay across crashes. | AT-RES-008 |
| OM-RES-009 | Tests MUST execute only operator-pinned recipes against the exact immutable generation under qualified OS confinement and bounded lifetime/output. | AT-RES-009 |
| OM-RES-010 | Test success MUST retain exact source, recipe, runtime, result and operation lineage; command exit alone is insufficient to authorize a review artifact. | AT-RES-010 |
| OM-RES-011 | Publication MUST bind exact retained successful test lineage and destination; the only supported destination is the private local `review` artifact store. | AT-RES-011 |
| OM-RES-012 | Every returned context/output MUST carry source and sensitivity provenance, enforce serialized byte bounds and preserve explicit partial or truncated results. | AT-RES-012 |
| OM-RES-013 | Review MUST distinguish resource changes from original dirty changes and require an exact native approval wherever the task's publication policy requires one. | AT-RES-013 |
| OM-RES-014 | Cancellation, expiry and revocation MUST stop future admission and reconcile in-flight effects using their original identities before reporting completion. | AT-RES-014 |
| OM-RES-015 | Export, retention and recovery MUST preserve authoritative native evidence separately from unsigned resource bundles and never invent supported destinations. | AT-RES-015 |

## Intake and immutable source

The proposed project registration is operator-owned: an opaque `project_id` UUID, canonical root identity, owner UID, allowed relative selections, sensitivity policy, approved recipe IDs and current registration revision. `task.create` accepts enrolled `profile_id` and `project_id` handles, never raw host paths. Opaque task UUIDs are distinct from resource operation SHA256 identifiers. A task binds the project registration revision, import manifest digest and immutable native authority. No agent-controlled environment variable selects a host root.

The importer prepares an explicit selection preview. For each candidate it records relative name, filesystem type, bytes, tracked/index/worktree status, content digest only if selected and permitted, and disposition (`included`, `excluded`, `unsupported`). Repository identity, HEAD and index digest are provenance, not permission to reset the checkout. Staged and working bytes may differ; the selected working bytes are the resource input and the staged digest is retained separately. A clean HEAD is never substituted for dirty contents. The initial manifest identifies the actual selected bytes, not a claim that the whole repository was imported.

Metadata inspection uses a qualified non-executing Git reader. Any future Git subprocess alternative needs fixed read-only argv, sanitized environment, disabled hooks/fsmonitor/external diff/textconv and proof that no filters execute. The first importer invokes no repository-provided code, automatic checkout, submodule update or package install. Credentials embedded in remote URLs and `.git/config` never enter guest context.

Symbolic links are inventoried by `lstat`, preserving originals and recording that they were excluded; targets are not read. Selecting a symlink or hardlinked/special file refuses with its bounded relative name. Submodules appear as gitlinks with recorded revision and dirty-status availability; they are excluded by default and not recursively initialized. A separately registered, explicitly selected submodule may be imported as its own resource, never flattened implicitly. A project that requires excluded inputs is reported incomplete and cannot run its recipe until the operator changes the selection/profile. Ignored files are excluded without reading their contents; the operator can select a nonsensitive ignored file explicitly. Credential stores, `.env` and configured secret paths remain denied even when tracked or explicitly requested in the default profile. Screening selected bytes is additional defense, not proof that all unknown secrets are recognizable.

The importer requires a qualified immutable source snapshot or enforceable writer-exclusion mechanism for the selected set before claiming a coherent import. A read-only bind, advisory editor lock, user pause or matching pre/post hashes alone does not establish that mechanism: ABA edits can evade endpoint checks. If no qualified stable-capture mechanism is available, inspection/preview remains available but project admission refuses. The initial controlled fixture can use a resource-owned immutable source generation; arbitrary dirty checkout import remains gated. Within the admitted snapshot/exclusion interval, use directory-relative no-follow traversal; check directory/file identity, ownership, links and bytes; repeat selected inventory and repository metadata validation before sealing. Changes cause `source_changed` and discard the candidate without exporting it to Pi. Snapshot/exclusion scope and lifetime are included in the import manifest. No whole-repository snapshot claim follows from importing a selected subset. Original modes and contents remain unchanged; required private modes apply only to newly created staging inodes.

Initial proposed P2 limits deliberately fit the candidate's small-workflow defaults: 128 files, 1 MiB total source, 256 KiB per file, 64 KiB read and patch payloads, 50 search matches, eight read-many entries, eight queued calls, 128 KiB resource MCP input/output frames. The controller protocol has its own smaller 64 KiB frame limit; it returns bounded summaries and enrolled artifact references rather than forwarding oversized resource frames. These are policy defaults, not measured desktop throughput. The preview refuses oversize selections before init; a smaller explicit selection is a new reviewed import. It never silently drops files to meet a limit. Portable namespace rules are those of the pinned candidate, including normalized Unicode and collision refusal.

## Tools and task recipe

| Candidate tool | Model-controlled fields | Protected checks |
| --- | --- | --- |
| `repo_status` | Empty object | Current and original manifest comparison; no Git execution. |
| `read_range`, `read_many` | Exact `sourceDigest`, canonical relative paths, bounded line intervals | Full-file hashes, immutable source; ordered individual errors in `read_many`. |
| `search` | Exact digest, literal text, optional selected paths and match count | No regex interpreter, traversal or external search program. |
| `repo_diff`, `repo_context` | Exact digest | Bounded unsigned content and generation provenance. |
| `apply_patch` | Exact digest, distinct paths, each `expectedFileSha256`, replacement or unique literal edits | All preconditions checked first; absent file explicit; no deletion/rename support inferred from replacement. |
| `test_recipe` | Exact digest and registered recipe name | Executable/runtime hashes, fixed argv, sanitized environment, no model-provided dependencies. |
| `publish_artifact` | Digest, original test operation, result and recipe digests, `destination: "review"` | Successful retained test under the same resource/caller/config binding; immutable local artifact only. |

Recipes initially run one pinned Node program with explicitly listed runtime dependencies, a read-only generation and a private scratch job. The default recipe permits no network, sockets, shell, process spawning, user namespace escape or access to host credentials. A typical test runner that forks or downloads is unsupported unless separately qualified under a new recipe profile. Proposed initial deadline: 2 seconds plus 100 ms termination grace, 16 KiB captured output; total recipe and admission duration must fit below the candidate native 30-second execution deadline. The source contract's 600-second schema maximum is not the desktop default. Runtime pins, actual binary architecture, seccomp/bubblewrap behavior and ordinary Omarchy user namespaces require native Linux acceptance.

A deterministic recipe is fixed by the operator, not asserted by the model. Its test program and expected assertions are included in the initial source or an independently pinned harness. If the task may edit tests, review shows those edits and publication additionally requires an unchanged independent acceptance harness. Successful self-edited tests alone are insufficient for acceptance.

## Outcomes, publication and context

Use the candidate's native dispatch ID and immutable binding to owner, workspace, caller capability digest, config, tool, canonical arguments and source. An exact completed replay returns the original outcome even after a later generation exists. Reusing an identity with different arguments refuses. Materialize/fsync/verify a new generation, then commit the current head and terminal result in one resource database transaction. An orphan generation is not success. A post-intent failure without conclusive outcome retains the fence; controller state becomes `blocked_unknown` until native reconciliation establishes the original result. Neither deleting the ledger nor issuing a new operation ID is recovery.

P2 may produce a task-local review bundle under the pre-admitted fixed local review capability. P3 introduces exact interactive approvals where required by policy, bound to current task revision, source/diff/test/recipe digests, artifact destination identity and expiry. If the native decision gate is unavailable, a task requiring that decision stays `waiting_approval` and no effect is dispatched. A UI button or an OMCP approval file cannot substitute for native approval.

The bundle contains exact selected files, manifest, internal diff and test lineage and declares `unsigned: true`, `authority: false`. The destination is a pinned private artifact root; the agent cannot provide a path, URL, Git ref or remote. `review.open` opens a controller-selected immutable artifact; it does not write the project checkout. P3's publication surface for this profile means reviewed delivery to this local destination. Supporting a checkout export, Git branch, pull request or deployment requires a separate effect adapter, native destination contract, approvals and recovery acceptance. A patch text shown to the user is not an applied checkout change.

Repository text, comments, diagnostics and test output are untrusted data. Returned context carries `project_id`, generation, file/range digest, origin kind and confidentiality label. Proposed labels `public`, `project-private`, `secret-denied` are policy vocabulary pending native classifier binding; they do not establish confidentiality enforcement by themselves. The default allows only operator-selected project context to the selected model provider. Strict governed-egress mode refuses when native label enforcement is unavailable. No credential bytes, raw remote credentials or host-path inventory enter prompts, logs or receipt projections. Serialization bounds include JSON escaping and envelope overhead; truncation includes exact emitted byte count and `truncated: true` and cannot become a successful full test transcript claim.

Cancellation prevents undispatched work and terminates active recipe descendants through the qualified native owner. It does not undo a committed generation or artifact. Completed-but-unacknowledged and unknown effects retain their original IDs; UI cancellation is not proof of absence. Unsigned inspection/export is forensic only. Native signed outcome, delivery/acknowledgement evidence and manifest hashes remain separately inspectable. Proposed default retention is seven days for ordinary completed private artifacts, with explicit operator deletion; unresolved intent, unacknowledged outcomes and required recovery material are pinned regardless of age. No automatic collection makes a pending outcome unrecoverable.

## Acceptance cases

Each case is a proposed runtime gate. The independent observer runs outside the agent, adapter and controller, reads actual filesystem/process/native evidence and stores a redacted manifest with exact component versions. A mock callback alone cannot pass these gates.

### AT-RES-001: Registered project boundary

Trigger: request a selected project, then substitute a root path, another registration revision and `../` in task data. Observable outcome: only the selected registration is admitted; substitutions create no resource. Independent oracle: separate observer inventories resource roots and original host paths. Evidence artifact: `res-001-registration.json` with admitted binding and zero-effect observations.

### AT-RES-002: Dirty checkout preservation

Trigger: import a fixture with different HEAD/index/worktree bytes, staged deletion and selected untracked text. Observable outcome: exact selected working bytes and original status are shown; HEAD, index, originals, ownership and modes are unchanged. Independent oracle: pre/post raw hashes and an independent Git status/index reader. Evidence artifact: `res-002-originals.json` and selected manifest.

### AT-RES-003: Excluded and unsafe inputs

Trigger: include internal/external symlinks, hardlinks, FIFO, dirty submodule, ignored credential canaries and a tracked `.env`; explicitly select each denied type. Observable outcome: bounded exclusions or explicit refusal, no target reads and no credential bytes in staging or output. Independent oracle: filesystem access tracing plus canary search across guest/context/artifacts; original symlink strings and submodule bytes unchanged. Evidence artifact: `res-003-intake-exclusions.json`.

### AT-RES-004: Intake race

Trigger: rename a parent, replace a selected file with a symlink and edit the index/content during copy, including ABA writes that restore endpoint hashes. Remove the stable-capture mechanism in a separate negative case. Observable outcome: candidate discarded as changed; no mixed generation is visible to the guest. Independent oracle: external race driver and full emitted manifest verification against one stable fixture generation. Evidence artifact: `res-004-import-races.jsonl`.

### AT-RES-005: Resource custody

Trigger: hostile Pi guest attempts direct owner stdio access, original checkout reads/writes, artifact modification and operator/socket access. Observable outcome: denial while an admitted resource read succeeds. Independent oracle: protected-path canary hashes, syscall/process observations and native dispatch count. Evidence artifact: `res-005-custody.json`.

### AT-RES-006: Closed inventory and limits

Trigger: inspect tools, submit unknown fields/tools, shell text, path escapes, one-byte-over-limit inputs and oversized selections. Observable outcome: exactly the nine tools; refusal before effect or explicit documented read truncation. Independent oracle: registry schema digest and filesystem/recipe-launch counters outside the resource. Evidence artifact: `res-006-schema-boundaries.json`.

### AT-RES-007: Whole-patch CAS

Trigger: patch two files with one stale precondition, then ambiguous/overlapping edits, then a valid pair. Observable outcome: failed batches change neither head nor file; valid pair exposes one new verified generation. Independent oracle: independently recomputed old/new manifests and direct database transaction observation. Evidence artifact: `res-007-cas.json`.

### AT-RES-008: Original outcome through crash

Trigger: kill the resource after intent, after generation rename, inside final commit and after commit before reply; replay exact and changed arguments. Observable outcome: old head plus unresolved fence or new head plus exact original result; never mixed terminal state or second patch. Independent oracle: crash supervisor, durable database reopen, full-tree hashes and dispatch count. Evidence artifact: `res-008-crash-matrix.json` with native recovery receipts; unsigned export alone fails.

### AT-RES-009: Recipe confinement

Trigger: selected recipe attempts host reads, socket/network use, shell/fork, descendant escape and output/time floods; then replace a runtime pin. Observable outcome: forbidden probes fail, bounded termination is observed, changed runtime refuses before launch, positive unit recipe runs. Independent oracle: OS process/network observer and host-file canaries. Evidence artifact: `res-009-linux-recipe.json` naming actual x86-64 Omarchy package versions.

### AT-RES-010: Test provenance

Trigger: pass recipe A at source S, modify source/tests, then present stale or forged success for publication. Observable outcome: exact retained lineage is required; changed acceptance harness prevents completion. Independent oracle: separately execute the pinned independent test harness over exported S and compare source/runtime/result digests. Evidence artifact: `res-010-test-lineage.json`.

### AT-RES-011: Local publication only

Trigger: publish exact tested source to `review`, replay after response loss, then request path, Git, PR or URL destinations. Observable outcome: one immutable local artifact and original replay; unsupported destinations refuse. Independent oracle: artifact directory inode/hash inventory, network observer and unchanged original checkout. Evidence artifact: `res-011-publication.json`.

### AT-RES-012: Context and output disclosure

Trigger: request private context, injected instruction text, NUL-heavy recipe output and a response near wire capacity; require governed egress without its native prerequisite. Observable outcome: labels/provenance remain data, bounds cover full encoding, partial truth is explicit, unsupported required governance refuses before provider bytes. Independent oracle: captured provider request at the trusted relay and encoded-wire byte counter with secret canaries. Evidence artifact: `res-012-context-output.json`.

### AT-RES-013: Exact review approval

Trigger: approve a reviewed artifact then change source, recipe, task revision, destination or expiry; repeat with native decision unavailable. Observable outcome: stale approvals refuse, unavailable approval stays pending, no artifact delivery occurs under substituted binding. Independent oracle: native admission record plus destination observer, independent of panel state. Evidence artifact: `res-013-approval-bindings.json`.

### AT-RES-014: Cancellation and in-flight truth

Trigger: cancel/revoke before dispatch, during recipe and after artifact commit before reply. Observable outcome: no pre-dispatch effect; process termination evidence for running work; committed effect retained and reconciled under original ID. Independent oracle: process-group observer, artifact hashes, dispatch counts and native original-operation records. Evidence artifact: `res-014-cancel-races.json`.

### AT-RES-015: Export and retention

Trigger: export a completed resource record, remove ordinary expired artifacts, and attempt collection while an original is unknown/unacknowledged. Observable outcome: unsigned exports are labeled, protected recovery evidence remains, no exported record clears native uncertainty. Independent oracle: native receipt verifier and independent pre/post evidence inventory. Evidence artifact: `res-015-retention-recovery.json`.

## Risks and prerequisite owners

The project adapter owner must deliver the importer, selection manifest and race protocol; these do not exist in the candidate. Native integration must qualify caller binding, the exact decision path and original-outcome reconciliation on Linux. Release engineering owns the real x86-64 recipe evidence. Product/authority owners must decide whether any future checkout or remote publication is worth its additional recovery contract. Until then, visible local review is the complete supported destination story.
