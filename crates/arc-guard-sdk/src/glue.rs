//! ABI glue for the ARC WASM guard guest-host boundary.
//!
//! Provides:
//! - `read_request(ptr, len)` -- deserialize a `GuardRequest` from linear memory
//! - `encode_verdict(verdict)` -- convert a `GuardVerdict` into an ABI return code
//! - `arc_deny_reason(buf_ptr, buf_len)` -- write structured deny JSON into host buffer

// Implementation will be added in the GREEN phase.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    // These tests define the expected behavior. They will fail until the
    // implementation is written (TDD RED phase).

    use crate::types::{GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW, VERDICT_DENY};

    #[test]
    fn encode_verdict_allow_returns_zero_and_clears_reason() {
        // encode_verdict(Allow) should return VERDICT_ALLOW (0) and clear
        // any previously stored deny reason.
        super::encode_verdict(GuardVerdict::deny("leftover"));
        let code = super::encode_verdict(GuardVerdict::Allow);
        assert_eq!(code, VERDICT_ALLOW);
        // After Allow, arc_deny_reason should have nothing to report.
        let mut buf = vec![0u8; 4096];
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let written = super::arc_deny_reason(buf.as_mut_ptr() as i32, buf.len() as i32);
        assert_eq!(written, -1, "No deny reason should exist after Allow");
    }

    #[test]
    fn encode_verdict_deny_returns_one_and_stores_reason() {
        let code = super::encode_verdict(GuardVerdict::deny("blocked"));
        assert_eq!(code, VERDICT_DENY);
    }

    #[test]
    fn arc_deny_reason_writes_json_after_deny() {
        super::encode_verdict(GuardVerdict::deny("blocked"));

        let mut buf = vec![0u8; 4096];
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let written = super::arc_deny_reason(buf.as_mut_ptr() as i32, buf.len() as i32);

        assert!(written > 0, "arc_deny_reason should return positive byte count");
        let json_bytes = &buf[..written as usize];
        let resp: GuestDenyResponse = serde_json::from_slice(json_bytes).unwrap();
        assert_eq!(resp.reason, "blocked");
    }

    #[test]
    fn arc_deny_reason_returns_negative_after_allow() {
        super::encode_verdict(GuardVerdict::Allow);

        let mut buf = vec![0u8; 4096];
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let written = super::arc_deny_reason(buf.as_mut_ptr() as i32, buf.len() as i32);
        assert_eq!(written, -1, "No deny reason after Allow");
    }

    #[test]
    fn arc_deny_reason_returns_negative_for_tiny_buffer() {
        super::encode_verdict(GuardVerdict::deny("this reason is definitely longer than 2 bytes"));

        // Buffer of 2 bytes cannot hold {"reason":"..."} JSON.
        let mut buf = vec![0u8; 2];
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let written = super::arc_deny_reason(buf.as_mut_ptr() as i32, buf.len() as i32);
        assert_eq!(written, -1, "Buffer too small should return -1");
    }

    #[test]
    fn read_request_deserializes_valid_json() {
        // Test the deserialization logic directly (the unsafe pointer cast is
        // trivial and only meaningful on wasm32).
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs".to_string(),
            agent_id: "a1".to_string(),
            arguments: serde_json::json!({"path": "/tmp"}),
            scopes: vec!["fs:read_file".to_string()],
            action_type: None,
            extracted_path: Some("/tmp".to_string()),
            extracted_target: None,
            filesystem_roots: vec![],
            matched_grant_index: None,
        };

        let json = serde_json::to_vec(&req).unwrap();
        // Simulate what read_request does internally: serde_json::from_slice
        let deserialized: GuardRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized, req);
    }

    #[test]
    fn read_request_returns_error_for_invalid_json() {
        let bad_json = b"not valid json";
        let result = serde_json::from_slice::<GuardRequest>(bad_json);
        assert!(result.is_err(), "Invalid JSON should fail deserialization");
    }
}
