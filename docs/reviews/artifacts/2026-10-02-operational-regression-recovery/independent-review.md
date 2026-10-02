# Independent review record

Reviewer: `operational_recovery_review`, fresh context, read-only.
Range: `df9f1791b32b3bd18fd83bb5758587607a20e753..83d5e8a47a31d01150034ee9a3c4fc8627adbfd4`.
All five tasks were reviewed. The reviewer ran no Cargo and inspected retained
terminal logs and matching SHA-256 digests. Final Clippy was in progress at the
review boundary. This record summarizes the review and preserves its finding,
assessment and exclusions; root's fix disposition appears in the execution report.

## Findings

- Critical: none found.
- Important: none found.
- Minor: `crates/products/chio-cli/src/cert/session_receipts.rs:100-107`
  converts bounded SQLite TEXT to `Option<String>` inside `query_map`. Invalid
  UTF-8, for example `CAST(X'FF' AS TEXT)`, fails before `RowError` receives the
  row ID. Certification denies safely and the native cause survives, but the
  operator loses the row identifier required by Task 3 and the docs. Preserve
  the row ID before converting text and wrap the conversion failure. Test
  denial, row context, retained native cause and no payload disclosure.

## Source assessment

PB3 contains background clock faults without disconnecting; observation precedes
queue removal and idle ticks need no read. PR3 retains fractional elapsed time,
forward steps and error anchors, and shares the service clock with actual
production owners. PR5 preserves one snapshot, limits, exact metadata and sequence
numbers, with a real 4,097-receipt CLI round trip. NC2 preserves repeated value
order, signed replay, request uniqueness and framing, with one provider execution.
TR2 has explicit Deny-default unseen policy and a bounded documented 404 shape.

The reviewer recommended pinning the late-clock boundary: pre-evaluation failure
preserves pending work, while an execution-stage error may become a retained
terminal result. Automatically retrying generic clock errors could repeat effects
or reuse consumed authority.

Original assessment: **With fixes**. The five repairs match the plan, with no
Critical or Important defect found. Correct the Minor row-context gap and finish
qualification before treating the candidate as accepted. This is not a merge,
hosted, release or operator approval.

## Declined to judge

- Historical certificate truth, global sequence semantics and archival/deletion
  completeness: unchanged and separately queued; the review assessed collection.
- Authentication of excluded receipt bodies: outside the explicit selection
  contract; exact metadata selects, and selected signatures are checked.
- Cross-process/cross-host recovery and broader AC2/AC3 clock owners: projection
  is process-local and retained durable rollback obligations remain separate.
- Broader SF1/CA2 gate completeness: source coverage is not closure of those findings.
- Hosted, merge, release and operational acceptance: not established by this review.

Root retains these as explicit boundaries and outstanding work, without treating
any exclusion as roadmap completion.

## Root fix disposition

Source commit `be925005f6e4a37b6a6f6588fb907b7e55a9b5f2` fixes the Minor
conversion-context gap. The invalid UTF-8 control failed before the fix, then
passed with both the receipt row ID and native cause retained. All 12 certificate
owner tests, including UTF-16le/be compatibility, and the actual CLI round trip
passed. Both background processors now have a passing late-clock boundary
control. All 383 combined clock-owner tests and warnings-denied all-target
Clippy for the six changed owners passed after the fix. This is root verification
of the fix pass, not a second independent review or hosted qualification.
