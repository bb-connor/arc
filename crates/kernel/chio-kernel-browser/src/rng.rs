//! Web Crypto RNG adapter.
//!
//! Wraps `crypto.getRandomValues()` so the portable
//! [`chio_core_types::rng::Rng`] trait can source CSPRNG-quality entropy
//! inside a browser. Used to mint receipt signing seeds.
//!
//! The adapter fails closed: [`WebCryptoRng::try_new`] returns
//! [`WebCryptoRngError::Unavailable`] when the runtime has no
//! `globalThis.crypto.getRandomValues`, and a failed `getRandomValues` call
//! returns [`RngError`] from `fill_bytes`.

#[cfg(target_arch = "wasm32")]
use alloc::string::{String, ToString};

#[cfg(not(target_arch = "wasm32"))]
use std::string::{String, ToString};

use chio_core_types::rng::{Rng, RngError};

/// Errors that can occur while probing for the browser's Web Crypto
/// subsystem. These are surfaced at adapter construction time so the
/// wasm entry points can reject work early.
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

/// Web Crypto `getRandomValues` quota per call, in bytes.
#[cfg(any(target_arch = "wasm32", test))]
const MAX_GET_RANDOM_VALUES_BYTES: usize = 65_536;

/// Fills `dest` in quota-sized chunks; the first failing chunk fails the whole fill.
#[cfg(any(target_arch = "wasm32", test))]
fn fill_in_quota_chunks<E>(
    dest: &mut [u8],
    mut fill_chunk: impl FnMut(&mut [u8]) -> Result<(), E>,
) -> Result<(), RngError> {
    for chunk in dest.chunks_mut(MAX_GET_RANDOM_VALUES_BYTES) {
        fill_chunk(chunk).map_err(|_| RngError("Web Crypto getRandomValues failed"))?;
    }
    Ok(())
}

/// CSPRNG adapter backed by `globalThis.crypto.getRandomValues(...)`.
///
/// Constructing the adapter caches a handle to the browser `Crypto`
/// object so `fill_bytes` is a straight FFI call. The adapter is
/// cheap to construct -- two global property lookups -- but the caller should
/// still hold one per wasm entry-point call instead of per-receipt to avoid
/// redundant globals lookups.
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
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        fill_in_quota_chunks(dest, |chunk| {
            self.crypto
                .get_random_values_with_u8_array(chunk)
                .map(|_| ())
        })
    }
}

/// Host-target stub so the crate still compiles on native targets and
/// `cargo test -p chio-kernel-browser` can run without the wasm
/// toolchain. The adapter always errors out at construction, and the
/// wasm bindings that reach for it are themselves gated on
/// `cfg(target_arch = "wasm32")`.
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
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("Web Crypto is unavailable on native targets"))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{fill_in_quota_chunks, MAX_GET_RANDOM_VALUES_BYTES};
    use chio_core_types::rng::RngError;

    #[test]
    fn fill_failure_returns_error() {
        let mut dest = std::vec![0xaa_u8; MAX_GET_RANDOM_VALUES_BYTES * 2 + 1];
        let mut calls = 0usize;
        let result = fill_in_quota_chunks(&mut dest, |chunk| {
            calls += 1;
            if calls == 2 {
                return Err(());
            }
            chunk.fill(0x11);
            Ok(())
        });
        assert_eq!(result, Err(RngError("Web Crypto getRandomValues failed")));
        assert_eq!(calls, 2, "the fill stops at the first failing chunk");
    }

    #[test]
    fn fill_splits_at_the_web_crypto_quota() {
        let mut dest = std::vec![0u8; MAX_GET_RANDOM_VALUES_BYTES * 2 + 1];
        let mut lengths = std::vec::Vec::new();
        let result = fill_in_quota_chunks(&mut dest, |chunk| {
            lengths.push(chunk.len());
            chunk.fill(0x11);
            Ok::<(), ()>(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(
            lengths,
            [MAX_GET_RANDOM_VALUES_BYTES, MAX_GET_RANDOM_VALUES_BYTES, 1]
        );
        assert!(dest.iter().all(|byte| *byte == 0x11));
    }

    #[test]
    fn native_stub_refuses_to_fill() {
        use chio_core_types::rng::Rng;
        let mut dest = [0u8; 8];
        assert_eq!(
            super::WebCryptoRng.fill_bytes(&mut dest),
            Err(RngError("Web Crypto is unavailable on native targets"))
        );
    }
}
