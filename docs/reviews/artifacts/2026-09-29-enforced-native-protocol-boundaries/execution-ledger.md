# Execution ledger

Base: 150f7bea8e. User approved all five tasks in the plan.

- Ruling: implement inline, one final independent reviewer, no implementation subagents. The user prioritizes efficient substantial implementation and minimal delegation.
- Ruling: use CageRequiredLaunch directly rather than retain a one-variant compatibility enum. Removes the uncaged production branch and redundant adapters.
- Ruling: move hosted integration scenarios to the remote implementation owner if necessary to inject test-only transports. Preserve HTTP/auth/session/receipt coverage; do not expose a production feature that bypasses launch authority.
- Ruling: remove A2A edge compatibility passthrough discovered in the selected owner. The user's no-legacy directive applies; verified kernel ingress remains the production path.
- Ruling: policy clock faults must reject the whole evaluation before NOT or conditioned-rule filtering, not become a false subcondition that can broaden permission.
- Ruling: Disabled and Shadow stages may prepare signed offline artifacts; both refuse runtime launch before operator resources are opened. Enforced and LegacyRemoved stages alone may produce CageRequiredLaunch.
- Ruling: the scaffold builds a static musl server and requires an enforcing Linux host, helper and separate receipt anchor. Its real execution scenario is part of the existing real-linux-enforcement feature; default init scenarios verify generated files and authority arguments.
- Ruling: remote OAuth/session/rate ambient clocks are explicitly remaining owner work. This batch migrates policy evaluation and A2A deferred tasks, and extends the clock scan to both remote and A2A owners.
- Task 1 implementation: launch enum and legacy authorization removed; CLI/doctor/broker consumers migrated; hosted integration scenarios moved to test-only remote transports with signed discovery checks; A2A passthrough removed.
- Task 2 implementation: bounded original-byte readers and typed causes installed; native u64 envelope IDs retained, argument canonicalization enforced; secret keyring keeps strict typed zeroizing decoding.
- Task 3 implementation: explicit fallible policy clock and audited results; A2A wall/monotonic expiry, custody on faults, bounded retained terminal results and checked identifiers.
- Task 4 implementation: active-response and budget test support extracted. Policy test module also extracted after new signatures crossed its old cap. No cap increases.
- Verification: initial A2A contract-assertion and hosted fixture wiring failures are retained. The final owning campaign passes 602 tests including 89 remote tests; the post-review A2A rerun passes 104. Active response passes 53, SQLite budget 113, and all selected CLI cases reach terminal passing results. Exact split evidence for reference provisioning is documented. No hosted or native enforcement qualification claimed.

- Review R1 (P1): removed uncaged provisioning discovery and Disabled discovery option. Shadow discovery rejects before executable launch in shared input resolution, with a second check at the discovery launcher. Native discovery directory is now scanned by adapter-no-bypass.
- Review R2 (P2): A2aJsonRpcResponse retains typed local dispatch causes, including notifications; added public byte-entry regression for malformed DTOs, unsafe canonical arguments and clock outages.
- Review clarification: kernel ClockFence already defeats the suggested same-kernel rollback sequence. Retained task deadline now also records its final observation and exact final-check expiry removes the task; this is bounded hardening, not closure of a demonstrated replay vulnerability.
- Fixture repairs: explicit private mode for the independent receipt-anchor directory, and explicit paths for nested active-response test modules after extraction.
- Deferred minors: none. Native privileged execution, hosted qualification and next-owner remote clocks remain explicit acceptance/work boundaries.

- Gate reconciliation: retired stale test-owned C28/C29 and D047-D052/D088 physical production entries; C16 now names new_with_clock, and new_* constructor/function-pointer calibration catches injected-clock factories. Removed the uncaged reaper exception and replaced legacy gate calibration with ordered enforced migration, release, evidence, receipt and transport obligations.
- Consumer fixture repair: preflight uses reviewed tools fixtures; Shadow discovery supplies the required server identity so the negative case reaches stage validation. The other twelve reference-runtime scenarios passed in the full run; only the repaired fast negative case was rerun.

- Completion: all five approved tasks, both independent review repairs and final gate/fixture reconciliation are complete locally; the final native consumer source is 9cb2ac5679b74d28a6b4814a72cb2bcc909b9ccd. Strict Clippy, changed-source formatting and selected source gates pass. Full-workspace, privileged native and hosted/release gates remain outside this batch.

- Final consumer follow-through: removed Disabled provisioning from the shared shell helper, Docker entrypoint, Python SDK helper and native conformance runner. Require explicit cage helper, independent anchor and reviewed read grants; preserve shell/Docker authority and the Docker session keyring on restart. The Docker edge is an explicit enforcing-host profile. Historical results are not reclassified as current host qualification.
- Consumer verification: three Rust configuration tests, fifteen Python/shell cases, the hosted-admin credential gate and syntax checks pass. Source trust, negative and file-hygiene gates pass after this extension.
- Final consumer Clippy passes for conformance with all targets; formatting covers 83 Rust files plus two include fragments. Native consumer CI fixture/host integration is explicitly queued, not represented by these local mock/configuration checks.
