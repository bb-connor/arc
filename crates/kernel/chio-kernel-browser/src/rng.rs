//! Web Crypto RNG adapter.
//!
//! Wraps `crypto.getRandomValues()` so the portable
//! [`chio_kernel_core::Rng`] trait can source CSPRNG-quality entropy
//! inside a browser. Used by the signing path to build a fresh Ed25519
//! seed per `sign_receipt` call when the caller does not already have a
//! long-lived kernel key, and to mint receipt identifiers.
//!
//! The adapter fails closed: if the runtime has no `globalThis.crypto`
//! global (e.g. a wasm32 host that does not provide the Web Crypto API), the [`WebCryptoRng::try_new`] constructor returns
//! [`WebCryptoRngError::Unavailable`]. The kernel-core `Rng` trait's
//! `fill_bytes` has no error channel, so once the adapter is constructed
//! a later `fill_bytes` call that fails for any reason falls back to
//! zeroing the destination buffer; callers that depend on entropy (such
//! as the receipt-signing path in this crate) detect a zero-filled
//! seed up-front and refuse to sign with structured error.

#[cfg(target_arch = "wasm32")]
use alloc::string::{String, ToString};

#[cfg(not(target_arch = "wasm32"))]
use std::string::{String, ToString};

use chio_kernel_core::Rng;

/// Errors that can occur while probing for the browser's Web Crypto
/// subsystem. These are surfaced at adapter construction time so the
/// wasm entry points can reject work early rather than signing with a
/// silently-zeroed seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebCryptoRngError {
    /// The host environment does not expose `globalThis.crypto` with a
    /// `getRandomValues` function. Fail-closed: the wasm
    /// binding refuses to mint receipts without CSPRNG-grade entropy.
    Unavailable(String),
}

impl core::fmt::Display for WebCryptoRngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WebCryptoRngError::Unavailable(reason) => {
                write!(f, "Web Crypto API unavailable: {reason}")
            }
        }
    }
}

/// CSPRNG adapter backed by `globalThis.crypto.getRandomValues(...)`.
///
/// Constructing the adapter caches a handle to the browser `Crypto`
/// object so `fill_bytes` is a straight FFI call. The adapter is
/// cheap to construct -- two global property lookups -- but the caller should still hold one per wasm entry-point call
/// instead of per-receipt to avoid redundant globals lookups.
#[cfg(target_arch = "wasm32")]
pub struct WebCryptoRng {
    crypto: web_sys::Crypto,
}

#[cfg(target_arch = "wasm32")]
impl WebCryptoRng {
    /// Probe for `globalThis.crypto` and cache the handle.
    ///
    /// Returns [`WebCryptoRngError::Unavailable`] if `globalThis.crypto`
    /// is missing or has no `getRandomValues` function. Works in
    /// browsers, Workers, Durable Objects, Deno and Node 20+.
    pub fn try_new() -> Result<Self, WebCryptoRngError> {
        use wasm_bindgen::JsCast;
        let unavailable = |reason: &str| WebCryptoRngError::Unavailable(reason.to_string());
        let global = js_sys::global();
        let value = js_sys::Reflect::get(&global, &"crypto".into())
            .map_err(|_| unavailable("globalThis.crypto threw"))?;
        if !value.is_object() {
            return Err(unavailable("globalThis.crypto is not defined"));
        }
        let method = js_sys::Reflect::get(&value, &"getRandomValues".into())
            .map_err(|_| unavailable("crypto.getRandomValues threw"))?;
        if !method.is_function() {
            return Err(unavailable("crypto.getRandomValues is not a function"));
        }
        let crypto: web_sys::Crypto = value.unchecked_into();
        Ok(Self { crypto })
    }
}

#[cfg(target_arch = "wasm32")]
impl Rng for WebCryptoRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        // `get_random_values_with_u8_array` populates the slice in place
        // using the browser CSPRNG. If it throws (e.g. the slice is
        // oversized past the 65 536-byte quota in older browsers), fall
        // back to zeros and trust the upstream caller to refuse a
        // zero-seed signing attempt. We explicitly ignore the Result:
        // the Rng trait has no error channel, and signing-path callers
        // in `lib.rs` detect the all-zero seed fallback before they
        // would sign anything with it.
        if self.crypto.get_random_values_with_u8_array(dest).is_err() {
            for byte in dest.iter_mut() {
                *byte = 0;
            }
        }
    }
}

/// Host-target stub so the crate still compiles on native targets and
/// `cargo test -p chio-kernel-browser` can run without the wasm
/// toolchain. Native callers should not rely on this for entropy: the
/// adapter always errors out at construction, and the wasm bindings
/// that reach for it are themselves gated on `cfg(target_arch =
/// "wasm32")`.
#[cfg(not(target_arch = "wasm32"))]
pub struct WebCryptoRng;

#[cfg(not(target_arch = "wasm32"))]
impl WebCryptoRng {
    /// Native stub that always fails -- the browser adapter is not
    /// available outside of a browser wasm host.
    pub fn try_new() -> Result<Self, WebCryptoRngError> {
        Err(WebCryptoRngError::Unavailable(
            "native builds do not implement WebCryptoRng".to_string(),
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Rng for WebCryptoRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = 0;
        }
    }
}
