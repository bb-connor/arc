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
