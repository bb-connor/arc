//! C ABI for deterministic Chio SDK invariant helpers.
//!
//! The ABI intentionally stays narrow: UTF-8 strings and byte buffers in,
//! UTF-8 buffers out, explicit Rust-side deallocation, and no async/session
//! state crossing the boundary.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use chio_binding_helpers::{Error, ErrorCode};

pub const CHIO_FFI_NO_MAX_DELEGATION_DEPTH: u32 = u32::MAX;

const STATUS_OK: i32 = 0;
const STATUS_ERROR: i32 = 1;
const STATUS_PANIC: i32 = 2;
const STATUS_NULL_ARGUMENT: i32 = 3;

const ERROR_NONE: i32 = 0;
const ERROR_INTERNAL: i32 = 255;

#[repr(C)]
pub struct ChioFfiBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct ChioFfiResult {
    pub status: i32,
    pub error_code: i32,
    pub data: ChioFfiBuffer,
}

impl ChioFfiBuffer {
    fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::empty();
        }
        let mut boxed = bytes.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        Self { ptr, len }
    }

    fn from_string(value: String) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

#[no_mangle]
pub extern "C" fn chio_buffer_free(buffer: ChioFfiBuffer) {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return;
    }
    // SAFETY: all non-empty buffers returned by this crate come from
    // `Vec::into_boxed_slice` with exactly this pointer and length.
    unsafe {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len));
    }
}

fn ok_string(value: String) -> ChioFfiResult {
    ChioFfiResult {
        status: STATUS_OK,
        error_code: ERROR_NONE,
        data: ChioFfiBuffer::from_string(value),
    }
}

fn err_string(status: i32, error_code: i32, message: String) -> ChioFfiResult {
    ChioFfiResult {
        status,
        error_code,
        data: ChioFfiBuffer::from_string(message),
    }
}

fn helper_error_code(error: &Error) -> i32 {
    match error.code() {
        ErrorCode::InvalidPublicKey => 1,
        ErrorCode::InvalidHex => 2,
        ErrorCode::InvalidSignature => 3,
        ErrorCode::Json => 4,
        ErrorCode::CanonicalJson => 5,
        ErrorCode::CapabilityExpired => 6,
        ErrorCode::CapabilityNotYetValid => 7,
        ErrorCode::CapabilityRevoked => 8,
        ErrorCode::DelegationChainBroken => 9,
        ErrorCode::AttenuationViolation => 10,
        ErrorCode::ScopeMismatch => 11,
        ErrorCode::SignatureVerificationFailed => 12,
        ErrorCode::DelegationDepthExceeded => 13,
        ErrorCode::InvalidHashLength => 14,
        ErrorCode::MerkleProofFailed => 15,
        ErrorCode::EmptyTree => 16,
        ErrorCode::InvalidProofIndex => 17,
        ErrorCode::EmptyManifest => 18,
        ErrorCode::DuplicateToolName => 19,
        ErrorCode::UnsupportedSchema => 20,
        ErrorCode::ManifestVerificationFailed => 21,
    }
}

fn run_ffi<F>(f: F) -> ChioFfiResult
where
    F: FnOnce() -> Result<String, Error>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => ok_string(value),
        Ok(Err(error)) => err_string(STATUS_ERROR, helper_error_code(&error), error.to_string()),
        Err(_) => err_string(
            STATUS_PANIC,
            ERROR_INTERNAL,
            "panic while executing Chio FFI helper".to_string(),
        ),
    }
}

fn read_c_str(ptr: *const c_char, name: &str) -> Result<&str, ChioFfiResult> {
    if ptr.is_null() {
        return Err(err_string(
            STATUS_NULL_ARGUMENT,
            ERROR_INTERNAL,
            format!("{name} must not be null"),
        ));
    }
    // SAFETY: caller promises a valid NUL-terminated C string.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str().map_err(|error| {
        err_string(
            STATUS_ERROR,
            ERROR_INTERNAL,
            format!("{name} must be valid UTF-8: {error}"),
        )
    })
}

fn read_bytes(ptr: *const u8, len: usize, name: &str) -> Result<Vec<u8>, ChioFfiResult> {
    if ptr.is_null() && len != 0 {
        return Err(err_string(
            STATUS_NULL_ARGUMENT,
            ERROR_INTERNAL,
            format!("{name} pointer must not be null when length is non-zero"),
        ));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: caller promises `ptr` references `len` readable bytes.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_string(value).map_err(Into::into)
}

#[no_mangle]
pub extern "C" fn chio_canonicalize_json(input_json: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| chio_binding_helpers::canonicalize_json_str(input))
}

#[no_mangle]
pub extern "C" fn chio_sha256_hex_utf8(input_utf8: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_utf8, "input_utf8") {
        Ok(value) => value,
        Err(result) => return result,
    };
    ok_string(chio_binding_helpers::sha256_hex_utf8(input))
}

#[no_mangle]
pub extern "C" fn chio_sha256_hex_bytes(input: *const u8, input_len: usize) -> ChioFfiResult {
    let bytes = match read_bytes(input, input_len, "input") {
        Ok(value) => value,
        Err(result) => return result,
    };
    ok_string(chio_binding_helpers::sha256_hex_bytes(&bytes))
}

#[no_mangle]
pub extern "C" fn chio_sign_utf8_message_ed25519(
    input_utf8: *const c_char,
    seed_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_utf8, "input_utf8") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let seed = match read_c_str(seed_hex, "seed_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| {
        json(&chio_binding_helpers::sign_utf8_message_ed25519(
            input, seed,
        )?)
    })
}

#[no_mangle]
pub extern "C" fn chio_verify_utf8_message_ed25519(
    input_utf8: *const c_char,
    public_key_hex: *const c_char,
    signature_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_utf8, "input_utf8") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let public_key = match read_c_str(public_key_hex, "public_key_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let signature = match read_c_str(signature_hex, "signature_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| {
        Ok(
            chio_binding_helpers::verify_utf8_message_ed25519(input, public_key, signature)?
                .to_string(),
        )
    })
}

#[no_mangle]
pub extern "C" fn chio_sign_json_ed25519(
    input_json: *const c_char,
    seed_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let seed = match read_c_str(seed_hex, "seed_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| json(&chio_binding_helpers::sign_json_str_ed25519(input, seed)?))
}

#[no_mangle]
pub extern "C" fn chio_verify_json_signature_ed25519(
    input_json: *const c_char,
    public_key_hex: *const c_char,
    signature_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let public_key = match read_c_str(public_key_hex, "public_key_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let signature = match read_c_str(signature_hex, "signature_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| {
        Ok(
            chio_binding_helpers::verify_json_str_signature_ed25519(input, public_key, signature)?
                .to_string(),
        )
    })
}

#[no_mangle]
pub extern "C" fn chio_verify_capability_json(
    input_json: *const c_char,
    now_secs: u64,
    max_delegation_depth: u32,
) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let max_depth = if max_delegation_depth == CHIO_FFI_NO_MAX_DELEGATION_DEPTH {
        None
    } else {
        Some(max_delegation_depth)
    };
    run_ffi(|| {
        json(&chio_binding_helpers::verify_capability_json(
            input, now_secs, max_depth,
        )?)
    })
}

#[no_mangle]
pub extern "C" fn chio_verify_receipt_json(input_json: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| json(&chio_binding_helpers::verify_receipt_json(input)?))
}

#[no_mangle]
pub extern "C" fn chio_verify_manifest_json(input_json: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| json(&chio_binding_helpers::verify_signed_manifest_json(input)?))
}

#[cfg(test)]
mod tests {
    use super::{
        chio_buffer_free, chio_canonicalize_json, chio_sha256_hex_utf8,
        chio_sign_utf8_message_ed25519, ChioFfiBuffer, STATUS_OK,
    };
    use std::ffi::CString;

    fn result_to_string(buffer: ChioFfiBuffer) -> String {
        let bytes = if buffer.len == 0 {
            Vec::new()
        } else {
            // SAFETY: test consumes a buffer returned by this crate exactly once.
            unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len).to_vec() }
        };
        chio_buffer_free(buffer);
        String::from_utf8(bytes).expect("ffi output must be utf8")
    }

    #[test]
    fn canonicalize_roundtrips_over_c_abi() {
        let input = CString::new(r#"{"z":1,"a":2}"#).expect("CString");
        let result = chio_canonicalize_json(input.as_ptr());
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result_to_string(result.data), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn hashing_roundtrips_over_c_abi() {
        let input = CString::new("hello").expect("CString");
        let result = chio_sha256_hex_utf8(input.as_ptr());
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(
            result_to_string(result.data),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn signing_roundtrips_over_c_abi() {
        let input = CString::new("hello chio").expect("CString");
        let seed = CString::new("09".repeat(32)).expect("CString");
        let result = chio_sign_utf8_message_ed25519(input.as_ptr(), seed.as_ptr());
        assert_eq!(result.status, STATUS_OK);
        let output = result_to_string(result.data);
        assert!(output.contains("public_key_hex"));
        assert!(output.contains("signature_hex"));
    }
}
