#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
#![forbid(unsafe_code)]
//! Browser (wasm-bindgen) bindings over the portable Chio kernel core.
//!
//! This crate exposes portable entry points to browser JavaScript /
//! TypeScript through `wasm-bindgen`. Each entry point accepts and
//! returns serde-serialized JSON so the same canonical `ToolCallRequest`
//! / `Verdict` / `CapabilityToken` / `ChioReceipt` shapes flow across
//! the wasm boundary unchanged.
//!
//! # Platform adapters
//!
//! - [`BrowserClock`] routes `chio_kernel_core::Clock` through
//!   `js_sys::Date::now()`.
//! - [`WebCryptoRng`] routes `chio_kernel_core::Rng` through
//!   `window.crypto.getRandomValues(...)`.
//!
//! Both adapters are cheap to construct; each wasm entry point
//! instantiates fresh copies rather than carrying mutable state across
//! calls.
//!
//! # no_std posture
//!
//! The pure surface uses `no_std + alloc`. The browser clock uses `std`
//! for its thread-local regression fence; the JavaScript binding dependencies
//! also link `std` on wasm. Those dependencies and entry points are gated on
//! `cfg(target_arch = "wasm32")`, so native tests compile the pure helpers
//! without JavaScript bindings. The underlying portable kernel and shared
//! clock types remain `no_std + alloc`.
//!
//! # Fail-closed design
//!
//! Every entry point maps a malformed JSON input, a missing Web Crypto
//! global, a signing-key mismatch, or a verification failure into a
//! structured `Err(JsValue)`. The browser never sees a silent deny or a
//! signed receipt with a zeroed seed: the JS caller receives a rich
//! error message describing which step failed.

#![no_std]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "Test and proof fixtures deliberately fail on violated setup invariants."
    )
)]

extern crate alloc;

extern crate std;

pub mod clock;
pub mod rng;

mod pure;
mod wire;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use clock::BrowserClock;
pub use pure::{
    decode_seed_hex, evaluate_pure, hex_encode_lower, parse_authority_input, sign_receipt_pure,
    sign_receipt_relaying_trusted_body_pure, verify_capability_pure, verify_receipt_pure,
};
pub use rng::{WebCryptoRng, WebCryptoRngError};
pub use wire::{
    AdmittedChildBudgetJson, BindingError, CapabilityVerificationJson, EvaluateRequestJson,
    EvaluationVerdictJson, ParentBudgetSnapshotJson, SignReceiptRequestJson, ToolCallRequestJson,
    VerifyCapabilityRequestJson, VerifyReceiptResultJson,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
