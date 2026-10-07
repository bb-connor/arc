# 13. Privacy, diagnostics, performance, and battery

Status: proposed normative design. Confidence: high in data-boundary requirements, moderate in the proposed numerical targets, unknown for actual Mac measurements. Dependencies: [native experience](02-native-experience.md), [authority](04-authority-integrity.md), [resource custody](10-project-resources.md), [recovery](11-state-recovery.md), and [qualification](17-qualification.md). None of the budgets below is a measured performance claim.

## Data inventory and defaults

Collection is justified by the selected task and execution profile. No default whole-home scan, clipboard polling, screenshot capture, host-wide network payload retention, usage analytics, remote crash upload, or background code indexing is proposed. Model release is a separately authorized crossing: project read access does not imply release to a model provider or support service.

| Data class | Proposed custodian and local retention | Disclosure and deletion boundary |
| --- | --- | --- |
| Provider credentials and signing material | Per-user credential/native authority owners; retain until rotation or explicit removal | Never UI projection, worker environment, argv, telemetry, or support export; native signer remains native-owned. |
| Prompt, captured document, source snapshot, model response, and tool content | Task-scoped protected payload store; default seven days after resolved completion, explicit retain option | Authorized task/provider only; unknown operations retain only the minimum payload needed to reconcile. User source files are not subject to Chio retention. |
| Signed receipts and operation custody | Native owner; no automatic deletion of unresolved custody or required revocation/freshness state; proposed 90-day local receipt view for resolved tasks | A receipt body may disclose sensitive fields. Export verified subsets under an explicit disclosure profile; pruning must preserve native proof dependencies or truthfully lose that verification claim. |
| Sensor diagnostic ring | Profile-scoped local store; maximum 24 hours and 50 MiB per user, whichever bound is reached first | Content omitted, paths replaced with scoped opaque references, explicit gap counters on drop; this ring never replaces authority history. |
| Bounded application diagnostics | Local store; seven days and 20 MiB per user, whichever first | Fixed reason codes, component digests, counts and durations; no raw request/response/stderr or bearer references. |
| Aggregate performance samples | Local store; 30 days and 10 MiB per user | No task names, raw URLs, paths, prompt text, or stable cross-export user identifiers; no remote transmission by default. |
| Support archive | Created only on explicit export; proposed 10 MiB bound and 15-minute selected default window | Preview inventory, explicit destination, safe archive members, redaction summary, verification limitations. Exported copies become the user's custody. |
| OS-managed logs and crash reports | macOS controls retention | Minimize at emission; do not promise application purge erases OS logs, Time Machine snapshots, or external provider copies. |

All values are initial proposed product policy. Policy changes require visible documentation and retention tests. Expiration cleans protected payloads and metadata indexes, queued exports, thumbnails, and caches, but cannot undo external effects. Keep an explicit retained-obligation entry when reconciliation or verification requires preservation. Disk pressure must not silently evict the authority state needed to prevent replay.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-PRV-001 | Collection and disclosure MUST follow a versioned inventory scoped to the task/profile, with model, app, and support release separately authorized; ambient host collection MUST be off by default. | AT-MAC-PRV-001 |
| MAC-PRV-002 | Sensitive content, secrets, raw paths, destinations, decision handles, and stable user identifiers MUST be omitted or explicitly protected before any diagnostic persistence, not merely hidden in the UI. | AT-MAC-PRV-002 |
| MAC-PRV-003 | Native signed evidence MUST remain byte-preserving; redacted presentations and exports MUST identify omissions and distinguish verified commitments from omitted or unverifiable payloads. | AT-MAC-PRV-003 |
| MAC-PRV-004 | All Chio-owned diagnostic and payload stores MUST enforce the declared retention and size bounds, with explicit custody exceptions and no automatic loss of unresolved authority. | AT-MAC-PRV-004 |
| MAC-PRV-005 | Support export MUST preview exact scope, use a bounded safe archive, scan for secrets, require explicit local export, and transmit nothing automatically. | AT-MAC-PRV-005 |
| MAC-PRV-006 | Lock or uncertain session ownership MUST clear sensitive views, protect notification content, invalidate review handles, and apply the authority lifecycle fence from the operations contract. | AT-MAC-PRV-006 |
| MAC-PRV-007 | Metrics MUST use bounded-cardinality fixed labels and explicit loss/queue/callback counters; metric collection MUST NOT block authority or turn dropped observations into evidence of no effects. | AT-MAC-PRV-007 |
| MAC-PRV-008 | Performance evidence MUST bind exact source, installed profile, OS, architecture, hardware, power mode, thermal conditions, workload, measurement tools, sample distribution, and baseline identity. | AT-MAC-PRV-008 |
| MAC-PRV-009 | Admission, broker, VM start, user-visible result, stop fencing, process termination, and network closure MUST be measured separately with independent timing and outcome oracles. | AT-MAC-PRV-009 |
| MAC-PRV-010 | The implementation MUST meet or explicitly fail the proposed UI, idle-resource, and benchmark budgets; security deadline or coverage failures MUST close the affected profile rather than be waived as performance issues. | AT-MAC-PRV-010 |
| MAC-PRV-011 | Battery claims MUST use paired repeatable energy measurements against the same useful workload, account for collection overhead and uncertainty, and remain scoped to the tested machine/profile. | AT-MAC-PRV-011 |
| MAC-PRV-012 | Background observation MUST coalesce subscriptions, bound queues, stop unnecessary polling, and respect power/thermal changes without suspending safety-critical fencing or delaying required native callbacks. | AT-MAC-PRV-012 |
| MAC-PRV-013 | Overload and disk pressure MUST produce explicit gaps and bounded diagnostic shedding while preserving authority correctness; inability to durably authorize MUST deny new crossing. | AT-MAC-PRV-013 |
| MAC-PRV-014 | Deletion and purge MUST enumerate retained authority obligations, protected payloads, caches, exports, and known external copies without claiming universal secure erasure. | AT-MAC-PRV-014 |
| MAC-PRV-015 | Public evidence, screenshots, fixtures, and bug reports MUST use synthetic task data and host pseudonyms; public witnessing, if added, MUST have a separately approved metadata-disclosure contract. | AT-MAC-PRV-015 |
| MAC-PRV-016 | Dependency telemetry, updater requests, crash handling, and provider SDK behavior MUST be inventoried and observed under normal and failure paths; an unreviewed dependency MUST NOT silently expand collection. | AT-MAC-PRV-016 |

## Diagnostic and evidence boundaries

The permitted structured record fields are timestamp, boot/session pseudonym scoped to the local diagnostic window, component/build digest, phase, stable reason code, queue depth, duration, bounded counters, and native operation reference only where the export policy explicitly permits it. Do not log bearer-like native references, review handles, XPC request bodies, raw errors from an untrusted provider, or machine usernames. Publicly safe codes are fixed constants, not strings interpolated from a task. Untrusted diagnostic text is capped at 1,024 UTF-8 bytes, control characters escaped, and stored only in the protected task payload class when necessary.

Use OSLog privacy annotations as additional defense, not as the primary data-selection mechanism. Unified logging is OS-managed persistence; dynamic numeric values can disclose as much as strings. [Apple logging](https://developer.apple.com/documentation/os/logging), [privacy options](https://developer.apple.com/documentation/os/oslogprivacy), [message-generation guidance](https://developer.apple.com/documentation/os/generating-log-messages-from-your-code).

A native receipt cannot be edited and still presented as the original signed object. A support export either includes permitted original bytes, provides a verified reference/commitment with payload omitted, or emits a clearly marked redacted derivative that does not claim the original signature covers the edited body. Hashes of low-entropy personal data are not anonymization. Use per-export opaque labels where cross-export correlation is unnecessary, and keep the mapping local. Evidence verification reports `payload_omitted` rather than fabricating inspection of absent content.

## Proposed workload suite and budgets

Benchmark fixtures are immutable synthetic projects and deterministic local model/provider stubs, with a separate end-to-end real provider run. Report network/model latency in full user latency; report local service overhead as an explicitly separate measure. Five warm-ups then 30 measured runs supply p50, p95, maximum, failures, and raw samples for latency. Ten-minute idle runs begin after five minutes settling. Contention runs use 1, 8, and 32 submitted tasks with admission limits recorded, plus hostile event rates ramped until bounded overload activates.

| Measurement | Proposed budget | Independent boundary |
| --- | --- | --- |
| Cached 200-task native window | p95 <= 200 ms | User action to first usable rendered frame, independent UI timing |
| Healthy read-only IPC query | p95 <= 100 ms | Client send to parsed response on same-host monotonic clock |
| Durable task acknowledgment | p95 <= 500 ms | Client intent to persisted native operation identity; staging/model time excluded and reported separately |
| Projection update visibility | p95 <= 250 ms | Native committed event observation to rendered state |
| Healthy idle app plus per-user controller, no VM | Mean <= 1% of one CPU core; combined RSS <= 200 MiB | External process sampler; report child processes, peaks, and provider cost separately |
| Idle diagnostic writes | <= 1 MiB per hour after settling | External filesystem write accounting; authority writes counted separately |
| Local deterministic broker overhead | p95 <= 10 ms above direct stub baseline | Same payload, authority durability mode, and concurrent workload; no provider/network time hidden |
| Stop fence acknowledgment | p95 <= 500 ms when host schedulable | Input to native durable-fence proof; not process or remote-effect closure |
| Owned local worker termination | <= 10 seconds when host schedulable | Fence action to outside observation of all owned incarnations gone; otherwise escalation and unresolved closure |
| Idle energy delta | <= 5% over paired baseline when measurement resolution supports the comparison | Whole-machine energy over at least 60 minutes; report absolute energy and uncertainty; do not substitute battery-percentage change |
| Useful-work energy overhead | <= 15% over paired equivalent local workload baseline | Total energy to the same declared artifact, both runs completing the same work |

These are proposed initial release targets. A product owner may revise a target prospectively with measured rationale and a new manifest before a fresh run. Moving thresholds after seeing a candidate to make it pass is prohibited. A provider deadline, bounded queue invariant, or required enforcement behavior remains a safety gate, independent of these experience targets. An ES callback cannot wait for telemetry flush, remote logging, a UI frame, or a Swift review prompt.

For energy trials, fix hardware, OS build, display brightness, refresh rate, network fixture, power mode, battery health/charge band, background workload, and thermal starting range. Randomize baseline/candidate order across at least five paired runs. Prefer external energy measurement or a supported instrument with units and calibration; record privileged instrumentation separately from ordinary product permissions. Report the paired relative delta and confidence interval, absolute watt-hours, workload completion, CPU time, wakeups, storage I/O, and tool overhead. If the instrument lacks enough resolution or temperature drifts beyond the declared range, the energy result is inconclusive, not passing. Apple recommends doing less unnecessary work; it does not supply these Chio numerical budgets. [Apple energy guidance](https://developer.apple.com/documentation/xcode/reducing-your-app-s-battery-use).

## Acceptance procedures

### AT-MAC-PRV-001: Read does not imply release

Grant synthetic project read and deny model/support release. Open the app, enumerate tasks, execute permitted local work, and try model export. Oracle: an independent destination server and network observer receive no project canary; host clipboard/screen/home sensors remain inactive. Artifact: `data-inventory-disclosure.json` with enabled collectors and external counters.

### AT-MAC-PRV-002: Persistence canaries

Seed unique canaries in secret, prompt, source, path, URL query, task title, untrusted error, review handle, and numeric identifier. Exercise success, denial, crash, queue overflow, and reconnect. Oracle: independent scans of Chio logs, OS logs available to the tester, crash artifacts, argv/env captures, filenames, and default archives find no forbidden canary. Artifact: `diagnostic-canaries.json` with classes, scan coverage, and omitted OS surfaces identified.

### AT-MAC-PRV-003: Redaction retains evidence honesty

Export a receipt with permitted metadata and secret-bearing payload, then edit an included signed body and strip a referenced commitment. Oracle: independent native verifier rejects tampered originals and reports omitted payloads explicitly; redacted derivatives never appear as signature-valid originals. Artifact: `evidence-redaction.json` plus original and exported synthetic fixtures.

### AT-MAC-PRV-004: Retention with unresolved custody

Advance a controlled clock over each retention horizon and fill each bounded store beyond its cap with resolved and unknown operations. Oracle: eligible data expires, queue/ring drops are counted, required custody survives, and affected admission stops if authority storage cannot persist. Artifact: `retention-boundaries.json` with before/after inventories and external effect count.

### AT-MAC-PRV-005: Archive preview and secret rejection

Request an export with oversized records, path traversal, symlink members, raw database/WAL files, credentials, and secret-bearing receipt payloads. Oracle: preview and produced archive match exactly, exceedance is explicit, archive members stay inside extraction root, secrets are excluded, and an outside network counter stays zero. Artifact: `support-archive.json` and independent archive audit.

### AT-MAC-PRV-006: Locked-screen disclosure race

Open detailed review, lock during rendering, drop a lock-state event, switch users, and deliver task notifications. Oracle: external synthetic screen/notification capture contains only generic attention text while native authority rejects the stale review and closes new sensitive release. Artifact: `lock-disclosure.json` with timestamped native rejection and UI observations.

### AT-MAC-PRV-007: Cardinality and metric loss

Send one million unique untrusted task strings and flood sensor events. Oracle: exported metric label cardinality remains bounded by the fixed enum set; queue/drop counters agree with independent producer counts; no path/prompt appears in labels; authority continues correctly or denies explicitly. Artifact: `metric-bounds.json` with observer counts and process samples.

### AT-MAC-PRV-008: Reproducible benchmark identity

Run the pinned workload twice; remove baseline digest, thermal range, installed provider identity, or raw samples in mutated reports. Oracle: semantic verification rejects each incomplete report; complete reports identify all compared dimensions and uncertainty. Artifact: `benchmark-provenance.json` and raw sample files with digests.

### AT-MAC-PRV-009: Distinct timing facts

Delay worker death, hold an existing network flow, and delay a remote operation after stop-fence acknowledgment. Oracle: independent observer records separate fence, termination, flow, and external-outcome timestamps; UI and reports do not reuse the first as proof of the others. Artifact: `lifecycle-latency.json` with clock-domain mapping and uncertainties.

### AT-MAC-PRV-010: Declared threshold enforcement

Run all latency/idle workloads at declared loads and inject a slow callback plus one failed safety probe. Oracle: raw percentile calculations independently reproduce pass/fail; unmet experience budgets fail their gate; safety failure closes the profile regardless of fast median results. Artifact: `performance-gates.json` with unchanged pre-run threshold-manifest digest.

### AT-MAC-PRV-011: Paired energy measurement

Run five randomized paired 60-minute idle trials and equivalent useful-work trials using the declared instrument. Include a synthetic high-wakeup regression and a low-resolution measurement fixture. Oracle: high-wakeup regression fails, low-resolution fixture is inconclusive, and valid comparisons include absolute energy, paired uncertainty, and instrument overhead. Artifact: `energy-baselines.json` with raw traces and calibration record.

### AT-MAC-PRV-012: Idle and low-power behavior

Compare hidden app, visible app, 20 subscribers, low-power mode, and thermal pressure; then issue a revocation during reduced collection. Oracle: observation coalesces and needless wakeups fall while native fence/callback bounds still hold. Artifact: `power-mode-behavior.json` from external process sampler and authority observer.

### AT-MAC-PRV-013: Saturation and storage pressure

Fill diagnostic queues and disk while producing known sensor counts and submitting an operation. Oracle: bounded diagnostic shedding produces exact gap records; no queue silently grants access; a failed authoritative commit cannot dispatch an effect. Artifact: `overload-privacy-authority.json` with native journal and external effect counter.

### AT-MAC-PRV-014: Honest deletion inventory

Create cache, payload, export, receipt, unresolved-operation, and backup fixtures; expire and purge eligible data. Oracle: independent filesystem inventory matches declared deletion; retained obligations and outside backups remain explicit; no proof claims deleted payloads were inspected. Artifact: `deletion-inventory.json`.

### AT-MAC-PRV-015: Public artifact scan

Generate screenshots, demo evidence, and a bug bundle using synthetic identities; seed a real-looking home path, account identifier, and low-entropy unsalted commitment in reject fixtures. Oracle: public-artifact review rejects disclosed fields and requires explicit metadata policy for witnessing. Artifact: `public-artifact-privacy.json` with scan rules and reviewer result.

### AT-MAC-PRV-016: Dependency telemetry observation

Capture outgoing destinations during fresh launch, update check, provider call, SDK error, crash, and idle. Compare with the disclosure inventory and repeat with collection opted out. Oracle: every destination and payload class has a declared purpose; undeclared analytics/crash upload fails. Artifact: `dependency-telemetry.json` from an independent capture with synthetic payloads.
