//! Human-in-the-loop (HITL) primitives.
//!
//! This module houses the approval-request data model, the persistent
//! approval-store contract, the approval guard that decides when a call
//! needs human sign-off, and the async resume entry points used by the
//! HTTP surface after a human responds. The design follows
//! `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md`.
//!
//! `crate::runtime::Verdict` is `Copy`. This module exposes a richer
//! [`HitlVerdict`] that carries the pending approval request when one is
//! needed, keeping `Verdict` itself `Copy`. The public `Verdict` enum carries a
//! `PendingApproval` marker variant so external callers can pattern-match on
//! the three-way decision; the payload is returned separately via
//! [`ApprovalGuard::evaluate`] and
//! [`ChioKernel::evaluate_tool_call_with_hitl`](crate::ChioKernel).

include!("approval.part1.inc");
include!("approval.part2.inc");
include!("approval.part3.inc");
