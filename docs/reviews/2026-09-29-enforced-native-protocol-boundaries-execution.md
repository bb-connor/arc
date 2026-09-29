# Enforced native and protocol boundaries execution

Base: `150f7bea8e`. Implementation candidate: `93fbf2eb4d`.
Review repairs: `cbd78cd8b1`. Gate/fixture repairs: `f2889ea83c`.
Final native consumer migration: `9cb2ac5679`.
Checkout: `/tmp/arc-security-launch`, `packet/3-retention-accounting`.
Plan: [approved owner batch](../superpowers/plans/2026-09-29-enforced-native-protocol-boundaries.md).

## Delivered scope

| Task | Implementation |
| --- | --- |
| Enforced native API and consumers | Removed `NativeMcpLaunch` and `LegacyNativeLaunchAuthorization`. CLI, doctor, broker and remote Rust consumers require `CageRequiredLaunch`, with migration revalidation, enforcement evidence and persisted launch receipt. |
| Remove remaining native/A2A bypasses | Disabled provisioning accepts reviewed fixtures only; Shadow live discovery rejects before target launch. Removed uncaged discovery child/backend and A2A compatibility feature/wrapper. |
| Original-byte ingress and rejection custody | MCP remote/hosted and A2A reject duplicate keys and oversized inputs before value projection. Retain native envelope integer IDs. Preserve typed parser/encoding causes locally and redacted outward codes; A2A notifications retain their local failure sidecar. |
| Fallible clocks and task retention | Policy evaluation samples shared clock before condition composition; audited receipts reject failure, regression and overflow. No serialized time override. A2A uses fenced wall/monotonic deadlines, counts terminal results toward capacity and checks ID exhaustion. |
| Structural caps and fixtures | Extracted active-response tests, budget-store test support and policy evaluation tests. Active-response allowance removed; policy allowance reduced from 3,170 lines/five fragments to 1,909/four. No cap increases. |
| Source contracts and review | Added 15 reviewed owner dispositions; updated documentation, clock/negative-assertion paths, typed reader census and native bypass gate. One independent review followed by author repairs and focused verification. |

## Decisions and review

Implementation was inline with one final reviewer. Hosted HTTP/auth/session/
receipt tests moved to the remote implementation owner so test-only transports
can replace native processes while production factory APIs remain sealed.
Inactive migration stages prepare offline signed artifacts only. A final consumer
scan also migrated the shared shell helper, Docker entrypoint, Python process
SDK provisioner and native conformance runner to Enforced reference-runtime
provisioning. All require explicit helper, anchor and read-grant configuration.
The shell/Docker paths preserve existing authority on restart, and Docker keeps
its session keyring. Runnable guides and the optional Docker profile now expose
these requirements. Historical Disabled-stage qualification remains historical.
 The scaffold
builds a musl target and requires an enforcing Linux host, helper and independent
receipt anchor; its real execution scenario is behind `real-linux-enforcement`.
The HMAC keyring keeps strict typed decoding rather than a secret-bearing JSON
value copy. Remote OAuth/session/rate clock migration is the next owner batch.

The independent review of `93fbf2eb4d` requested changes for uncaged provisioning
discovery and A2A dispatch source loss. Both are repaired, with negative controls
for target execution and public byte-API source custody. A suggested same-kernel
clock rollback attack was withdrawn after checking the kernel's global fence;
the repair also retains the task's final clock observation in place and removes
it at final-check expiry. Review fixes receive author verification, not a second
independent review. No minor findings were deferred.

## Verification

All selected implementation tasks and review repairs are complete locally.
[Terminal evidence and earlier failures](artifacts/2026-09-29-enforced-native-protocol-boundaries/README.md)
retain the exact commands, logs and source boundary.

| Boundary | Terminal result |
| --- | --- |
| Policy, MCP adapter/remote, hosted facade, A2A edge | Initial owning campaign: 602 tests across 20 binaries, no ignored cases. After review repairs, A2A passes 104 tests, replacing its earlier 102. This represents 604 distinct owning scenarios. |
| Active response and SQLite budget | 53 active-response and 113 budget-store tests pass after the module extraction. |
| CLI consumers | 16 cage-policy, eight init, nine demo-provision and three preflight tests pass. Reference-runtime provisioning has 12 passing cases from the full run plus a passing focused rerun of the repaired Shadow-discovery case. Its original full-run failure is retained. |
| Native consumer follow-through | Three Rust conformance configuration cases, nine Docker entrypoint cases, three Python SDK cases and three shell helper cases pass. The hosted admin credential gate and shell/Python syntax checks also pass. These mocks do not qualify a native host. |
| No-bypass gate | Workspace gate and 27 calibration tests pass. The final expanded launch-phase mutation case also passes its focused rerun. |
| Source contracts | Trust-boundary, clock, negative-assertion and file-hygiene gates pass; 18 trust, three clock and all 30 hygiene calibrations pass. |
| Compiler and formatting | Strict all-target Clippy passes for the eight owning/consumer packages and separately for xtask and conformance. Formatting passes for 83 changed `.rs` files and two include fragments; diff whitespace check passes. |

The gate now inventories `new_*` constructors and function pointers, retires
nine physical production entries that had moved into test directories, removes
the obsolete uncaged supervision exception and checks enforced launch phases
in order. The source-shape checks supplement runtime tests; they do not prove
arbitrary control flow.

Intermediate failures exposed obsolete inactive-stage fixtures, a missing CLI
argument, a missing A2A fixture skill, an independent anchor directory mode,
nested test-module paths and stale gate inventory. Their repairs and terminal
successors are retained. No full-workspace or privileged native campaign was
run for this bounded batch. CLI provisioning scenarios used the built executable
with debug sections stripped; the small size reduction is recorded, with no
performance improvement claimed.

## Inventory and remaining scope

Reviewed authority owners: 99 to 114; registered reader files: 264 to 279.
The decoder census has 433 files, including 281 still classified as raw-input
baseline. These are source-review counts, not vulnerability totals.
Clock inventory: 156 occurrences at 151 keys. Expansion adds five existing
remote production reads and eight fixture reads; two policy reads are removed.
The negative assertion ratchet retains 1,260 assertions at 1,177 sites, including
relocated active-response tests. Tenant-table and SQL principal counts remain
85 and 170.

The [remaining queue](2026-09-28-remaining-security-work.md) specifies remote MCP
clock/lifecycle completion and ACP edge/proxy authority boundaries next. This
batch makes no hosted, native x86_64, release, publication, M5 or M11 acceptance
claim. It does not close broader semantic errors, remaining reader owners,
structural/declaration work, original-scale retention or candidate qualification.

Native process-host, SDK/example and conformance deployment jobs still need
qualified enforcing-host inputs before rerunning their actual tool scenarios.
The ordinary process-worker workflow does not install that native profile;
its native recovery scenarios are not claimed passing by this local batch.
The next queue includes that fixture/workflow integration without restoring
a Disabled fallback.
