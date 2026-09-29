# Protocol authority boundary execution

Date: September 29, 2026. Checkout: `/tmp/arc-security-launch`, branch
`packet/3-retention-accounting`. Base: `1d4f3b4ad3`.
This implements the four tasks in the
[protocol authority plan](../superpowers/plans/2026-09-29-protocol-authority-boundaries.md).
Qualification is local and limited to the owners listed below.

## Delivered boundaries

1. **Original peer bytes and rejection causes.** MCP edge and adapter frames,
   A2A HTTP/SSE and registry bytes, OpenAI provider responses and argument text,
   and the shared provider SSE reader now use bounded original-input contracts.
   Nested duplicate keys reject before conversion. Native envelopes retain
   lossless integer values; tool arguments require I-JSON objects and reject
   unsafe integers, duplicates and non-object shapes. The MCP frame limit is
   1 MiB. A2A/provider documents and streams are capped at 16 MiB; tool argument
   text and shared SSE frames at 1 MiB. Shared SSE permits at most 16,384 frames,
   preserving the existing 4,096-frame per-tool positive case. Oversized MCP edge
   input terminates without draining an unbounded line or accepting its suffix
   as another request. Typed JSON causes survive the migrated conversion and
   kernel-error paths; their Display/Debug surfaces use registered redacted codes.
   Raw MCP payload logging is removed.
2. **A2A OAuth and lifecycle clocks.** Discovery, OAuth custody, message IDs and
   registry observations share a configured fallible clock. Cache deadlines
   begin before token acquisition and combine checked wall and monotonic bounds.
   Unknown expiry and lifetimes consumed by the 30-second skew never enter the
   cache. Full advertised expiry is checked before returning an acquired token;
   cache lookup refuses faults, regressions and exact expiry. Registry reads are
   bounded, duplicate-aware and validate schema, task identity and timestamp
   ordering. OAuth custody and clock ownership have separate small modules.
3. **MCP task and writer deadlines.** Edge task deadlines use the kernel's fenced
   clock, and both background dispatch paths recheck immediately before effects.
   Nested tasks have finite deadlines, a 128-task bound and a one-day maximum
   TTL. Clock faults preserve pending work without dispatching it. Task/request
   counters and pagination cannot wrap. Stdio writer admission uses a checked
   deadline; the supervisor rejects queued commands that expire before writing.
   Outcome recording uses the pre-effect observation so a later clock failure
   cannot discard an effect's result. The writer is now a responsibility-named
   module.
4. **Authority census and assurance.** Twenty-two reader-file owners have named
   contracts; the raw-input baseline falls from 298 to 289 files. Parsed values
   remain untrusted and the kernel or verified registry supplies authority at
   consumption. `CageRequiredLaunch` joins the sealed-proof gate, bringing the
   registered set to 13. The clock gate now includes all four adapters and UTC
   aliases. It records 145 occurrences at 140 keys, including three newly scoped
   fixture sites and two previously missed policy UTC reads. Those policy reads
   are explicitly queued. A2A test fragments became named modules with narrow
   shared fixtures so the new regressions do not grow its root include tree.

## Local qualification

The terminal owning/consumer campaign passed all 883 tests across 58 targets
in 13 packages, with no failures or ignored cases. It covers the four adapters,
shared provider core/fabric and seven provider consumers of the changed SSE/error
contract. The original failing OAuth-cache and duplicate-input regressions and
intermediate consumer taxonomy failures are retained with the
[terminal evidence](artifacts/2026-09-29-protocol-authority-boundaries/README.md).

Trust-boundary, clock and negative-assertion gates passed. The clock scanner's
three calibration cases passed. The trust gate records 364 constructors,
85 tenant tables and 170 explicit SQL principal contracts. This batch does not
change those tenant counts or add tenant-runtime coverage.

Repository-wide file hygiene currently reports two failures that are byte-for-byte
unchanged from the base: `chio-control-plane/src/security/active_response.rs`
(2,003 lines against a 2,002 cap), and
`chio-store-sqlite/src/budget_store/tests.rs` (2,482 against 2,479). The changed
protocol owners satisfy their existing caps. No allowance was raised.

## Explicit remaining boundaries

This is not a complete workspace rejection-source migration. Existing semantic
string errors and other protocol/product ingress remain in the U1 queue. A2A's
task registry is local correlation state, not authenticated custody or crash-safe
durable admission. A writer deadline cannot cancel an OS write already in
progress. Provider provenance records attribution; it does not authenticate a
remote identity or mint kernel authority.

The preexisting `LegacyNativeLaunchAuthorization` and
`NativeMcpLaunch::LegacyAuthorized` path remains queued for removal with its CLI,
hosted and remote factories and fixtures. No new compatibility path or alias is
introduced here. The next substantial batch removes that path, hardens raw
ingress and rejection contracts in `chio-mcp-remote`, `chio-hosted-mcp` and
`chio-a2a-edge`, and migrates `chio-policy::resolve_current_time` and
`evaluate_audited` to the shared clock.

The broader [remaining-work queue](2026-09-28-remaining-security-work.md),
retention stall #1045, model correspondence, native enforcement, supply-chain and
candidate/release/operator acceptance gates remain open. No hosted, release or
M5 qualification is claimed. Preexisting `output/` is preserved.
