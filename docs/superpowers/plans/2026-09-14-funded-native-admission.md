# Verified funding bound to native admission

This executes the next admission step of Task 4 in the claim escrow plan, from
qualified integration `412866ccbd4c6ad2654b648570161fd0d51f3559`. Execution is
inline in the existing isolated worktree. The original checkout and optional
process worktree remain independent.

The receiver owns the observer, deployment pins, native authority and original
request. A signed experimental agreement commits to those identities before
funding. The funding event alone is insufficient: decode exact contract state,
check code, token transfer, chain ancestry and local confirmation depth. This
development-chain profile does not claim public settlement finality.

- [x] Establish strict allocation ABI parity and negative admission tests using
  real native SQLite authority, budget holds and W0 execution.
- [x] Verify receiver-owned funding observations and commit the exact agreement
  and request before entering the kernel. Deny changed identity, fresh authority,
  unavailable observer, expired authority and exhausted retention before reserve.
- [x] Bind the native payment operation and original budget hold atomically in
  the example journal; reconcile the same IDs across crash gaps and replay.
  Preserve pending payment until independently observed financial settlement.
- [x] Run the real private-chain/native smoke, adversarial and recovery tests,
  standalone regressions, formatting and strict Clippy. Review the final diff
  and retain source-specific public evidence and explicit remaining gates.

The admission step leaves the allocation funded and the native payment pending.
Positive Finding facets, verifier-authorized claim submission, ERC20 withdrawal,
refund successors and the killed native parent/earned-child trial remain the
following Task 4 work. Local kernel capture is never reported as ERC20 payment.

Selected local gates passed. See [results and remaining work](../../market/open-agent-work/execution/17-native-funding-admission.md) and the [source-specific evidence](../../market/open-agent-work/execution/18-native-funding-evidence.json). This closes the native admission step, not the complete Task 4 settlement lifecycle.
