//! Portable ARC kernel core.
//!
//! Phase 14.1 extracts the pure-compute subset of ARC evaluation into its
//! own `no_std + alloc` crate so the same verdict-producing code can run
//! inside a browser (wasm32-unknown-unknown), a Cloudflare Worker
//! (wasm32-wasip1), a mobile app (UniFFI static lib), or the current
//! desktop sidecar (`arc-kernel`). The contract is described in
//! `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md`.
//!
//! # What lives here
//!
//! - [`Verdict`] -- the three-valued outcome of an evaluation.
//! - [`Guard`] -- the sync guard trait (identical signature to the legacy
//!   `arc_kernel::Guard`, modulo `Error` surface mapped onto [`KernelCoreError`]).
//! - [`GuardContext`] -- the inputs a guard sees.
//! - [`evaluate`] -- pure compute that walks a capability + request through
//!   the sync checks (signature, time, subject binding, scope, guard pipeline)
//!   and returns `Ok(Verdict::Allow)` or `Ok(Verdict::Deny { reason })`. No
//!   I/O, no budget mutation, no revocation lookup.
//! - [`verify_capability`] -- offline capability verification used by tools
//!   that only need to inspect a token (no scope, no revocation).
//! - [`sign_receipt`] -- sign an `ArcReceiptBody` with a `SigningBackend`.
//! - [`Clock`] / [`Rng`] -- abstract trait boundaries for time/entropy so
//!   adapters on wasm/mobile can inject platform clocks and CSPRNGs.
//!
//! # What stays in `arc-kernel`
//!
//! The full `arc-kernel` crate keeps every piece that actually touches I/O
//! or async: `tokio` tasks, `rusqlite` receipt/revocation/budget stores,
//! `ureq` price-oracle client, `lru` DPoP nonce cache, async session ops,
//! HTTP/stdio transport, nested-flow bridges, tool-server dispatch. Those
//! modules depend on `arc-kernel-core` for the pure-compute kernels but
//! add the IO glue around them.
//!
//! # `no_std` status
//!
//! The crate is `#![no_std]` with `extern crate alloc;`. At the source level
//! we never name `std::*`, and the portable proof for this phase is now
//! scripted in `scripts/check-portable-kernel.sh`.
//!
//! That proof runs both:
//! - `cargo build -p arc-kernel-core --no-default-features`
//! - `cargo build -p arc-kernel-core --target wasm32-unknown-unknown --no-default-features`
//!
//! Later portability work still has to qualify the browser and mobile adapter
//! crates end to end, but `arc-kernel-core` itself now cross-builds cleanly
//! for the host and `wasm32-unknown-unknown` targets with `--no-default-features`.

#![no_std]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
#![deny(unsafe_code)]

extern crate alloc;

pub mod capability_verify;
pub mod clock;
pub mod evaluate;
pub mod guard;
pub mod normalized;
pub mod passport_verify;
pub mod receipts;
pub mod rng;
pub mod scope;

pub use capability_verify::{verify_capability, CapabilityError, VerifiedCapability};
pub use clock::{Clock, FixedClock};
pub use evaluate::{evaluate, EvaluateInput, EvaluationVerdict, KernelCoreError};
pub use guard::{Guard, GuardContext, PortableToolCallRequest};
pub use normalized::{
    NormalizationError, NormalizedCapability, NormalizedConstraint, NormalizedEvaluationVerdict,
    NormalizedMonetaryAmount, NormalizedOperation, NormalizedPromptGrant, NormalizedRequest,
    NormalizedResourceGrant, NormalizedRuntimeAssuranceTier, NormalizedScope, NormalizedToolGrant,
    NormalizedVerdict, NormalizedVerifiedCapability,
};
pub use passport_verify::{
    verify_parsed_passport, verify_passport, PortablePassportBody, PortablePassportEnvelope,
    VerifiedPassport, VerifyError, PORTABLE_PASSPORT_SCHEMA,
};
pub use receipts::{sign_receipt, ReceiptSigningError};
pub use rng::{NullRng, Rng};
pub use scope::{MatchedGrant, ScopeMatchError};

/// Three-valued outcome of a kernel evaluation step.
///
/// This mirrors the legacy `arc_kernel::runtime::Verdict` exactly. The
/// kernel core never emits `PendingApproval` itself; the full `arc-kernel`
/// orchestration shell wraps the core verdict with the human-in-the-loop
/// approval path where needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny,
    /// The action is suspended pending a human decision. Only produced by
    /// the full `arc-kernel` shell, never by `arc-kernel-core` directly.
    PendingApproval,
}
