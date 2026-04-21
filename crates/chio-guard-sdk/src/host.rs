//! Typed host function bindings for the Chio WASM guard runtime.
//!
//! The host runtime registers three functions under the `arc` import module:
//!
//! - `chio.log(level, ptr, len)` -- structured logging
//! - `chio.get_config(key_ptr, key_len, val_out_ptr, val_out_len) -> i32` -- config lookup
//! - `chio.get_time_unix_secs() -> i64` -- wall clock
//!
//! This module provides safe Rust wrappers for each. On `wasm32` targets the
//! wrappers call into the host via the FFI declarations. On non-wasm targets
//! (used for native `cargo test`) the wrappers are no-ops or return sensible
//! defaults so the crate compiles and tests run without a WASM runtime.

// ---------------------------------------------------------------------------
// Raw FFI declarations (wasm32 only)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "chio")]
extern "C" {
    #[link_name = "log"]
    fn chio_log_raw(level: i32, ptr: i32, len: i32);

    #[link_name = "get_config"]
    fn chio_get_config_raw(key_ptr: i32, key_len: i32, val_out_ptr: i32, val_out_len: i32) -> i32;

    #[link_name = "get_time_unix_secs"]
    fn chio_get_time_raw() -> i64;
}

// ---------------------------------------------------------------------------
// Log level constants
// ---------------------------------------------------------------------------

/// Numeric log-level constants matching the host runtime's level encoding.
///
/// Pass these to [`log`] as the `level` argument.
pub mod log_level {
    /// Trace level (0).
    pub const TRACE: i32 = 0;
    /// Debug level (1).
    pub const DEBUG: i32 = 1;
    /// Info level (2).
    pub const INFO: i32 = 2;
    /// Warn level (3).
    pub const WARN: i32 = 3;
    /// Error level (4).
    pub const ERROR: i32 = 4;
}

// ---------------------------------------------------------------------------
// Safe wrappers
// ---------------------------------------------------------------------------

/// Emit a log message at the given level via the host runtime.
///
/// On `wasm32` this calls the `chio.log` host import. On native targets it is
/// a no-op (the host runtime is not available).
///
/// # Levels
///
/// Use the constants in [`log_level`]: `TRACE` (0), `DEBUG` (1), `INFO` (2),
/// `WARN` (3), `ERROR` (4).
#[inline]
pub fn log(level: i32, msg: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: msg.as_ptr() and msg.len() describe a valid UTF-8 slice
        // in guest linear memory. The host reads but never writes this region.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        unsafe {
            chio_log_raw(level, msg.as_ptr() as i32, msg.len() as i32);
        }
    }

    // On non-wasm32 targets: silent no-op.
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = level;
        let _ = msg;
    }
}

/// Look up a configuration value by key from the host runtime.
///
/// On `wasm32` this calls the `chio.get_config` host import with a 4096-byte
/// output buffer. Returns `None` if the key is missing or the value is not
/// valid UTF-8.
///
/// On native targets this always returns `None`.
#[inline]
pub fn get_config(key: &str) -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        const BUF_SIZE: usize = 4096;
        let mut buf = vec![0u8; BUF_SIZE];

        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let result = unsafe {
            chio_get_config_raw(
                key.as_ptr() as i32,
                key.len() as i32,
                buf.as_mut_ptr() as i32,
                BUF_SIZE as i32,
            )
        };

        if result < 0 {
            return None;
        }

        let actual_len = (result as usize).min(BUF_SIZE);
        buf.truncate(actual_len);
        String::from_utf8(buf).ok()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = key;
        None
    }
}

/// Return the current wall-clock time as a Unix timestamp in seconds.
///
/// On `wasm32` this calls the `chio.get_time_unix_secs` host import. On native
/// targets it returns 0.
#[inline]
pub fn get_time() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: the host function has no preconditions.
        unsafe { chio_get_time_raw() }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_constants_have_correct_values() {
        assert_eq!(log_level::TRACE, 0);
        assert_eq!(log_level::DEBUG, 1);
        assert_eq!(log_level::INFO, 2);
        assert_eq!(log_level::WARN, 3);
        assert_eq!(log_level::ERROR, 4);
    }

    #[test]
    fn get_config_returns_none_on_native() {
        // On non-wasm32 targets the host import is not available, so the
        // fallback implementation always returns None.
        assert!(get_config("any_key").is_none());
        assert!(get_config("").is_none());
    }

    #[test]
    fn get_time_returns_zero_on_native() {
        // On non-wasm32 targets the host import is not available, so the
        // fallback implementation returns 0.
        assert_eq!(get_time(), 0);
    }

    #[test]
    fn log_does_not_panic_on_native() {
        // On non-wasm32 targets log is a no-op. Verify it does not panic.
        log(log_level::INFO, "hello from native test");
        log(log_level::ERROR, "");
        log(-1, "invalid level should not panic");
    }
}
