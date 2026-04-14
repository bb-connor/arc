// Stub -- types will be implemented after tests are written.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_constants_match_host() {
        assert_eq!(VERDICT_ALLOW, 0);
        assert_eq!(VERDICT_DENY, 1);
    }

    #[test]
    fn guard_request_round_trip_all_fields() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs-server".to_string(),
            agent_id: "agent-42".to_string(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            scopes: vec!["fs-server:read_file".to_string()],
            action_type: Some("file_access".to_string()),
            extracted_path: Some("/etc/passwd".to_string()),
            extracted_target: Some("example.com".to_string()),
            filesystem_roots: vec!["/home".to_string(), "/tmp".to_string()],
            matched_grant_index: Some(0),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: GuardRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tool_name, req.tool_name);
        assert_eq!(deserialized.server_id, req.server_id);
        assert_eq!(deserialized.agent_id, req.agent_id);
        assert_eq!(deserialized.arguments, req.arguments);
        assert_eq!(deserialized.scopes, req.scopes);
        assert_eq!(deserialized.action_type, req.action_type);
        assert_eq!(deserialized.extracted_path, req.extracted_path);
        assert_eq!(deserialized.extracted_target, req.extracted_target);
        assert_eq!(deserialized.filesystem_roots, req.filesystem_roots);
        assert_eq!(deserialized.matched_grant_index, req.matched_grant_index);
    }

    #[test]
    fn guard_request_defaults_for_optional_fields() {
        let json = serde_json::json!({
            "tool_name": "test_tool",
            "server_id": "test_server",
            "agent_id": "agent-1",
            "arguments": {"key": "value"}
        });

        let req: GuardRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.tool_name, "test_tool");
        assert!(req.scopes.is_empty(), "scopes should default to empty Vec");
        assert!(req.action_type.is_none(), "action_type should default to None");
        assert!(req.extracted_path.is_none(), "extracted_path should default to None");
        assert!(req.extracted_target.is_none(), "extracted_target should default to None");
        assert!(req.filesystem_roots.is_empty(), "filesystem_roots should default to empty Vec");
        assert!(req.matched_grant_index.is_none(), "matched_grant_index should default to None");
    }

    #[test]
    fn guard_request_omits_none_and_empty_fields() {
        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };

        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("action_type").is_none(), "None fields should be omitted");
        assert!(json.get("extracted_path").is_none(), "None fields should be omitted");
        assert!(json.get("extracted_target").is_none(), "None fields should be omitted");
        assert!(json.get("matched_grant_index").is_none(), "None fields should be omitted");
        assert!(json.get("filesystem_roots").is_none(), "Empty Vec should be omitted");
    }

    #[test]
    fn guard_verdict_allow_constructor() {
        let v = GuardVerdict::allow();
        assert!(matches!(v, GuardVerdict::Allow));
    }

    #[test]
    fn guard_verdict_deny_constructor() {
        let v = GuardVerdict::deny("not permitted");
        match v {
            GuardVerdict::Deny { reason } => assert_eq!(reason, "not permitted"),
            GuardVerdict::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn guest_deny_response_serializes() {
        let resp = GuestDenyResponse {
            reason: "blocked by policy".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json, serde_json::json!({"reason": "blocked by policy"}));
    }
}
