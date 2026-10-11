# Protocol authority boundary completion

Approved continuation of remaining security queue item 2, base `1d4f3b4ad3`,
branch `packet/3-retention-accounting`. Implement inline in the existing isolated
worktree. Preserve `output/`; no hosted or release claims.

## Contracts and task queue

1. **Peer decoders and local rejection causes.** Review every raw reader and
   typed conversion in MCP edge/adapter, A2A and OpenAI. Retain original bytes
   until duplicate-key and numeric contracts are checked, bound inputs before
   allocation, preserve source errors with redacted registered codes. Provider
   arguments must be I-JSON objects; signed native envelopes retain u64 values.
   Test nested duplicates, malformed shapes, limits and secret redaction.
2. **A2A OAuth and lifecycle ownership.** Shared injected fallible clock,
   finite checked cache deadlines sampled before token acquisition, no cache
   entry for absent or short expiry, no effects on clock failure. Bound and
   validate registry reads. Test expiry, overflow, faults and record substitution.
3. **MCP task and dispatch time.** Use the kernel clock for deferred work;
   check expiry immediately before background effects, checked IDs/deadlines
   and safe pagination. Enforce nested task expiry and capacity. Refuse writer
   work after its deadline. Test both active dispatch and failure boundaries.
4. **Authority results and assurance.** Census proof owners and require live
   verification at actual consumers. Classify all scoped reader sites, extend
   clock gates to these owners, tighten negative tests, update roadmap and
   execution evidence. Run the four owning crate suites (OpenAI provider feature),
   changed-owner lint/format and relevant source gates, then one fresh final
   review and one fixes pass. Commit reviewable changes locally.

Use existing shared UntrustedJsonText, clock ports and manifest authority APIs.
No compatibility aliases or permissive decoder fallbacks. Peripheral source
changes must support the four owners and be verified at their consumer boundary.
Record any material deviation and its cost in the execution ledger.

## Execution review (October 1, 2026)

Reviewed at `a2630c20a1` in the [protocol boundaries review](../../reviews/2026-10-01-execution-review-protocol-boundaries.md). The cross-cutting verdict is in the [pass 9 execution review](../../reviews/2026-10-01-execution-review.md).

**Verdict:** All four tasks are done, three of them with a defect. The A2A OAuth cache custody is verified clean, and the record's 889-test count matches its logs.

Open findings against this plan:

- **PB2, Medium.** Unsigned documents (provider SSE, OpenAI responses and tool results, MCP and remote frames) are parsed with signed-record number rules, rejecting valid `10.00` and `1e-05`.
- **PB3, Medium.** Any clock fault, including a backward wall-clock step, ends every live MCP edge session at its next 25 ms idle poll.
- **PB4, Medium.** The per-session remote input queue is unbounded, and nested-flow waits on the client have no deadline.
- **PB5, Medium.** The A2A task registry bounds reads at 16 MiB but not writes, so once the file passes that size the adapter cannot start.
- **PB12, Low.** Six test names use `review_regression_*`, and a module is named `oauth_cache_review`.

**Next:** Decide the numeric contract by producer (PB2) and make clock faults degrade rather than terminate sessions (PB3).

## Compliance and product-truth review (October 1, 2026)

The [compliance and product-truth review](../../reviews/2026-10-01-compliance-product-truth-review.md) re-verified at `122414b48e` the product defects behind the repository's compliance, security and supply-chain claims: 69 findings, 3 High. Open findings at the protocol edges:

- **EV3, Medium.** `mcp serve` and `serve-http` reject uncovered calls, including constraint and
  model-metadata mismatches, before the kernel with no receipt; the `tool_denied` notification goes
  only to the client, which can suppress it; this plan's own batch added more receiptless rejections
  (`3d3e4b4d9d`, `348b7ae4c2`).
- **EV4, Medium.** Session-credential `serve-http` answers out-of-allowlist tools with a bare 403.
- **AP5, Medium.** A `cnf` carrying only RFC 9449 `jkt` is accepted as a plain bearer.
- **AP6, Medium.** Certificate and attestation sender binding is satisfied by caller-set headers.
- **AP8, Medium.** `POST /admin/sessions/{id}/trust` reports `revoked: true` when revocation fails.
