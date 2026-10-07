# Privacy, diagnostics and performance

Status: Proposed. Confidence: high in data minimization requirements; moderate
in proposed performance budgets until measured on the named Omarchy machine.
Dependencies: [UX](02-desktop-experience.md), [protocol](05-operator-protocol.md),
[state and retention](14-state-evidence-data.md).

## Data inventory and disclosure

| Data | Custodian and allowed use | Default exposure |
| --- | --- | --- |
| Provider/operator credentials | Native trusted custody and fixed-route provider relay | Never QML, argv, guest, logs or support bundle |
| Prompt, source content, tool arguments/results | Enrolled resource, confined host and authorized provider route | Explicit task scope; no analytics collection |
| Project path, branch, window title, diff | Trusted enrollment/resource and unlocked review view | Opaque ID or safe label in status; no notification body |
| Task IDs, state, bounded reason codes, counters | Controller projection | Local unlocked shell with retained disclosure policy |
| Signed receipts | Native owner and verified inspector | References first; filtered export requires enrolled profile |
| Crash dump and core | May contain every item above | Disable automatic core upload; exclude by default |

Model disclosure is a capability decision separate from filesystem read. Before
the first task, show exact provider route, governance mode, enrolled source scope,
available enforced limits and declared retention dependencies. Never promise that
provider data is not retained without a verified provider-specific contract.
No automatic code indexing, screenshot capture, clipboard capture or scanning of
all home directories. No usage analytics or remote crash reporting by default.

Use synthetic data for public screenshots, test recordings and review artifacts.
Default notifications contain only “Chio needs attention” and a fixed opener;
they cannot contain task titles, prompts, paths, receipts or approval arguments.
The unlocked panel can reveal detail on explicit selection. A lock transition
clears sensitive rendered strings and review payloads, invalidates open review
handles, and uses the native lifecycle rule to stop admission. Lock state unknown
has the same refusal policy. The logged-in user and installed QML plugins remain
trusted; UI redaction does not claim protection from another same-user process.

## Structured diagnostics

Write local structured records with timestamp, boot ID, component/build digest,
task/operation reference, phase, stable reason code, duration and bounded counts.
Do not log request bodies, decision handles, bearer material, provider responses,
raw stderr or file content. Untrusted diagnostics are capped at 1,024 UTF-8 bytes,
control characters escaped, and marked untrusted. Sanitize before persistence,
not only at display. Native receipt storage follows its own exact disclosure rules.

Count admissions, denials, unknown outcomes, reconnects, queue pressure, orphan
worker detections, prerequisite failures, reconciliation age and refused upgrades.
Counters describe observations, not proof of enforcement. The most actionable
signals are unknown operations, loss of native custody and surviving descendants.
Any of these stops new admission for the affected scope. A controller log cannot
clear the fence; native reconciliation can.

Support export first produces a preview inventory: selected time window, paths
represented as opaque IDs, included source identities, counters and redaction
summary. Export through the retained `receipts.export` contract; do not post it
anywhere automatically. Include no raw database, WAL, prompt, provider credential,
home config or unrestricted receipt body. Treat archive names and metadata as
data and disallow traversal/symlink members. A user-selected broader disclosure
requires a separately enrolled and qualified export profile.

## Proposed performance and availability budgets

Measure on a recorded non-root x86_64 Omarchy machine with CPU/RAM/storage/kernel,
display scale, compositor and shell builds stated. Numbers below are targets,
not observations. The benchmark contains 30 runs after five warmups; report p50,
p95, maximum and failures. Model latency is reported separately, never excluded
from end-to-end user latency without labeling.

| Measurement | Initial target | Measurement boundary |
| --- | --- | --- |
| Panel open with cached 200-task view | p95 <= 150 ms | invocation to rendered usable frame |
| Local health/task query | p95 <= 100 ms | shim write to parsed response, idle qualified machine |
| Task reservation acknowledgment | p95 <= 500 ms | request to durable reservation, excludes resource staging |
| Known status change visibility | p95 <= 250 ms | committed projection event to rendered state |
| Healthy idle controller | <= 1% one CPU core, <= 64 MiB RSS | 10 minutes, no guest; report peak too |
| Plugin incremental memory | <= 32 MiB | same shell before/after with 500 bounded rows |
| Guest stop after cancel | <= 10 seconds when schedulable | stop request to independent cgroup-empty observation |
| Reconnection loss detection | <= 15 seconds | last valid heartbeat to stale display |

Source staging, model requests, native qualification and test execution have
profile-specific deadlines. A timeout is an observation and stop trigger, not
proof of no effect. Failure to meet a UX target blocks a performance claim and
requires tuning or a consciously revised measured target. Failure to meet a
security bound blocks the execution profile. QML render work cannot delay native
revocation or process teardown.

## Normative requirements

| ID | Requirement | Proposed acceptance |
| --- | --- | --- |
| OM-OBS-001 | Disclosures MUST follow the inventory and distinguish source read from provider release. | AT-OBS-001 |
| OM-OBS-002 | Sensitive data MUST be excluded from notifications, process metadata and default diagnostics. | AT-OBS-002 |
| OM-OBS-003 | Lock or unknown session ownership MUST redact views and invalidate review handles. | AT-OBS-003 |
| OM-OBS-004 | Support export MUST preview and enforce an enrolled bounded disclosure profile. | AT-OBS-004 |
| OM-OBS-005 | Performance claims MUST include reproducible machine, workload and percentile evidence. | AT-OBS-005 |
| OM-OBS-006 | Unknown outcomes and surviving descendants MUST remain actionable until native reconciliation. | AT-OBS-006 |

## Proposed acceptance

### AT-OBS-001: Disclosure scope
Trigger: grant project read but deny model release, then start the actual provider
route. Expected: no source reaches provider. Oracle: external provider request
capture with synthetic canary. Artifact: `model-disclosure-scope.json`.

### AT-OBS-002: Sensitive canary scan
Trigger: place distinct synthetic secrets in prompt, source, provider credential
and native denial; exercise success, failure and crash. Expected: no canary in
argv/env, shell notification history or default diagnostics. Oracle: outside
process observer and byte scanner. Artifact: `privacy-canary-scan.json`.

### AT-OBS-003: Lock race
Trigger: lock during detail rendering and an open review; lose lock-state events.
Expected: cleared sensitive view and refused stale decision handle. Oracle:
synthetic screenshot capture and native decision counter. Artifact: `lock-race.json`.

### AT-OBS-004: Diagnostic archive
Trigger: export with path traversal, symlink, secret-bearing log and overlarge
receipt candidates. Expected: bounded safe preview and exact filtered archive,
no automatic network transfer. Oracle: archive parser and network observer.
Artifact: `support-export-disclosure.json`.

### AT-OBS-005: Measured budgets
Trigger: named workload and hostile event flood on the recorded machine.
Expected: measured targets or explicit failed gate; no event correctness loss.
Oracle: external frame clock, process sampler and monotonic timestamps.
Artifact: `desktop-performance.json` with raw samples.

### AT-OBS-006: Actionable uncertainty
Trigger: orphan a guest and lose an effect response, then dismiss all notifications.
Expected: persistent affected-scope fence and recoverable details until native
settlement. Oracle: guest observer and native ledger. Artifact: `uncertainty-alerts.json`.
