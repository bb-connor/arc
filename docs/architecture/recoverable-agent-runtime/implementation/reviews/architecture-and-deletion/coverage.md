# Review coverage and limits

Status: the bounded architecture report is delivered. A complete inventory is
not a complete code review. This is not approval of all changed source, a
security certification, an independent second reviewer or runtime acceptance.

## Subject accounting

[subject.json](subject.json) preserves the pinned commit, base, timestamp and
nineteen tracked overlay hashes. Its SHA256 is
`21969aa7116b114ce1a269a2ac1e3045b98b8d1a5ebd7e8d5edc1dc4f709dec3`.
The captured overlay bytes remain in
`target/recovery-architecture-review/source-overlay/`; do not clean that directory
if reproducing this review is required. The manifest alone does not reconstruct
uncommitted overlay bytes. Concurrent later edits are outside this subject.

[inspected-paths.csv](inspected-paths.csv) records 96 paths accessed through the
snapshot reader: 70 full-text architecture readings, 25 selected-excerpt
readings and one access-only excluded tool. These include code, tests and
packaging documents. Full-text reading is not a claim that every behavior was
proved correct. Requested ranges can exceed the text actually reviewed when a
tool display was truncated; such files are not promoted to full coverage.

The complete committed-diff inventory has 7,655 paths in
`target/recovery-architecture-review/changed-paths.csv`. Of those, the explicit
ledger marks 69 full-text readings, 23 excerpt readings and one excluded access.
The remaining 7,562 are conservatively `not_read`, including the large historical,
generated and vendor bodies. Filename inventory, Git diff statistics, caller
searches and examining a generator do not turn those bodies into individually
reviewed source. Baseline comparisons and several earlier spec/header/diff reads
are described in the report but are not inflated into this ledger's counts.

## Examined responsibility boundaries

| Area | What was read or traced | What this does not establish |
|---|---|---|
| Support and compatibility | Baseline/current schema declarations, Process version gates and ABI documentation, four full admission predecessor guards, V2 grant implementation, selected normative migration text | Deployed-version census, every pre-existing migration, or an old-binary/current-binary upgrade run |
| Questioned legacy regression | Captured `command_quotas.rs:997-1150`, its modeled predecessor setup and genuine terminal assertions; selected active-account initialization | Passing quota/retirement acceptance or validation of the entire test helper |
| ControlPlane recovery | Runtime, transport, command executor, owned-work handoff, settlement and setup in full; materialization excerpts and exact call-site searches | A successful native capture, interruption/restart sequence, or every HTTP/error helper |
| Kernel integration | Recovery runtime/selection and native-finishing hook in full; admission Store trait defaults, entry points and first-purpose path excerpts | Complete Kernel evaluation, resource bank, output-retention or capture security review |
| Process integration | Recovery facade/origin snapshot and participant capsule interface in full; invoke and reservation writer excerpts; knowledge mode writer in full | Full Process storage/accounting implementation or cross-store failure acceptance |
| Store command lifecycle | Full command engine and original resolver; selected read ports, resource admission, active-workflow/reservation accounting, native settlement and full private-settlement helper | Complete physical-liability, quota, retirement and historical configuration correctness |
| Pure planning and semantic verification | Every production `src/` file in the two new crates; explanation service through report preparation; selected native semantic facade | Full native semantic materialization, authorization, status, output and policy integration review |
| Durable knowledge | Checkpoint save and head reader, restore codec, old label reader, reference/readiness interfaces, collection lifecycle and participant journal codec in full; activation/label/publication excerpts | Every reference producer, current codec internals, restore/retirement workflow and physical capacity acceptance |
| Frameworks | LangGraph and CrewAI recovery adapters, shared Python session and client in full; portability fixture inspected | The remaining SDKs/CLI, framework-version compatibility or live two-host trials |
| Confined host | Host facade, execution/channel readers, acknowledgment and Process broker entry points in full | Store confinement internals, the pre-existing cage, any excluded controller, or actual Linux execution |
| Packaging/generation | Schema catalog and generated quarantine-policy test in full; generated consumers; manifest-builder and auditor selector excerpts; historical package wrapper/record/imports in full | All generated types, the complete 5,331-line auditor, every historical script or all release packaging |
| Vendor additions | Both patch records; demangler patch; production portion of the SQLite patch | Full vendored dependencies, all patch tests or confirmation of a qualified upstream replacement |

## Deliberate exclusions

The previously parked Capture workflow-identity/cumulative-roster implementation
and rejected review remain excluded. The repository syntax/naming review also
remains parked. Reading a required public interface to identify an integration
gap does not approve or reopen the excluded implementation behind it.

No credentials, live provider calls, cloud/OCI/SSH operations, native-controller
or isolation execution campaign was performed. No Rust build, test suite, formal
tool, Linux binary, performance campaign, hosted CI or independent review ran
for this report. No production source, historical evidence, remediation register
or PR state was changed by this review.

## How to use the result

Use the deletion decisions to reduce unnecessary maintenance obligations before
resuming blanket remediation. Do not translate this report into a zero-P1/P2
verdict. In particular, an unsupported Store hook with no production caller is
an unresolved integration contract, not a passed test or a safe blanket deletion.

Before implementing a proposal, reconcile its cited pinned source with the
executing session, decide its stated support/API conditions, and keep the named
public-interface checks. Broader review and qualification must cover the final
integrated source. Later evidence cannot be attributed retroactively to this pin.
