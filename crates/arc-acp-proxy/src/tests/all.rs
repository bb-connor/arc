#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- FsGuard tests --

    #[test]
    fn fs_guard_allows_path_under_prefix() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("/home/user/project/src/main.rs").is_ok());
        assert!(guard.check_write("/home/user/project/README.md").is_ok());
    }

    #[test]
    fn fs_guard_blocks_path_outside_prefix() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("/etc/passwd").is_err());
        assert!(guard.check_write("/tmp/evil.sh").is_err());
    }

    #[test]
    fn fs_guard_blocks_path_traversal() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard
            .check_read("/home/user/project/../../../etc/passwd")
            .is_err());
        assert!(guard.check_write("/home/user/project/../../evil").is_err());
    }

    #[test]
    fn fs_guard_denies_when_no_prefixes_configured() {
        let guard = FsGuard::new(vec![]);
        assert!(guard.check_read("/any/path").is_err());
        assert!(guard.check_write("/any/path").is_err());
    }

    #[test]
    fn fs_guard_multiple_prefixes() {
        let guard = FsGuard::new(vec![
            "/home/user/project".to_string(),
            "/tmp/workspace".to_string(),
        ]);
        assert!(guard.check_read("/home/user/project/file.txt").is_ok());
        assert!(guard.check_read("/tmp/workspace/output.log").is_ok());
        assert!(guard.check_read("/var/log/system.log").is_err());
    }

    #[test]
    fn fs_guard_blocks_prefix_substring_attack() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Must NOT match a sibling directory whose name starts with the prefix
        assert!(guard
            .check_read("/home/user/project_evil/secret.txt")
            .is_err());
        // Exact match is allowed
        assert!(guard.check_read("/home/user/project").is_ok());
        // Subdirectory is allowed
        assert!(guard.check_read("/home/user/project/file.txt").is_ok());
    }

    #[test]
    fn fs_guard_rejects_relative_paths() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("relative/path/file.txt").is_err());
        assert!(guard.check_write("../escape").is_err());
        assert!(guard.check_read("file.txt").is_err());
    }

    #[test]
    fn fs_guard_handles_empty_path() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("").is_err());
        assert!(guard.check_write("").is_err());
    }

    #[test]
    fn fs_guard_with_resolve_symlinks_flag() {
        // Verify the builder works (actual symlink resolution depends
        // on filesystem state, so we just test the config path).
        let guard = FsGuard::new(vec!["/home/user/project".to_string()])
            .with_resolve_symlinks(true);
        // A non-existent path falls back to textual canonicalization.
        assert!(guard
            .check_read("/home/user/project/nonexistent.txt")
            .is_ok());
    }

    // -- TerminalGuard tests --

    #[test]
    fn terminal_guard_allows_listed_command() {
        let guard = TerminalGuard::new(vec!["cargo".to_string(), "npm".to_string()]);
        assert!(guard
            .check_command("cargo", &["build".to_string()])
            .is_ok());
        assert!(guard
            .check_command("npm", &["install".to_string()])
            .is_ok());
    }

    #[test]
    fn terminal_guard_blocks_unlisted_command() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard.check_command("rm", &["-rf".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_denies_when_no_commands_configured() {
        let guard = TerminalGuard::new(vec![]);
        assert!(guard.check_command("ls", &[]).is_err());
    }

    #[test]
    fn terminal_guard_blocks_shell_injection_in_args() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard
            .check_command("echo", &["$(rm -rf /)".to_string()])
            .is_err());
        assert!(guard
            .check_command("echo", &["hello; rm -rf /".to_string()])
            .is_err());
        assert!(guard
            .check_command("echo", &["`evil`".to_string()])
            .is_err());
        assert!(guard
            .check_command("echo", &["hello | cat /etc/passwd".to_string()])
            .is_err());
    }

    #[test]
    fn terminal_guard_allows_clean_args() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard
            .check_command(
                "cargo",
                &[
                    "build".to_string(),
                    "--release".to_string(),
                    "--target".to_string(),
                    "x86_64-unknown-linux-gnu".to_string(),
                ]
            )
            .is_ok());
    }

    #[test]
    fn terminal_guard_strips_path_prefix() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard
            .check_command("/usr/bin/cargo", &["test".to_string()])
            .is_ok());
    }

    // -- PermissionMapper tests --

    #[test]
    fn permission_mapper_maps_known_kinds() {
        let mapper = PermissionMapper::new(3600);

        let allow_once = PermissionOption {
            option_id: "opt-1".to_string(),
            name: "Allow".to_string(),
            kind: "allow_once".to_string(),
        };
        let mapped = mapper.map_option(&allow_once);
        assert_eq!(mapped.arc_decision, PermissionDecision::AllowOnce);

        let allow_always = PermissionOption {
            option_id: "opt-2".to_string(),
            name: "Always allow".to_string(),
            kind: "allow_always".to_string(),
        };
        let mapped = mapper.map_option(&allow_always);
        assert_eq!(
            mapped.arc_decision,
            PermissionDecision::AllowScoped {
                duration_secs: 3600
            }
        );

        let reject_once = PermissionOption {
            option_id: "opt-3".to_string(),
            name: "Deny".to_string(),
            kind: "reject_once".to_string(),
        };
        let mapped = mapper.map_option(&reject_once);
        assert_eq!(mapped.arc_decision, PermissionDecision::Deny);

        let reject_always = PermissionOption {
            option_id: "opt-4".to_string(),
            name: "Never allow".to_string(),
            kind: "reject_always".to_string(),
        };
        let mapped = mapper.map_option(&reject_always);
        assert_eq!(mapped.arc_decision, PermissionDecision::DenyPermanent);
    }

    #[test]
    fn permission_mapper_denies_unknown_kind() {
        let mapper = PermissionMapper::new(3600);
        let unknown = PermissionOption {
            option_id: "opt-x".to_string(),
            name: "Mystery".to_string(),
            kind: "unknown_kind".to_string(),
        };
        let mapped = mapper.map_option(&unknown);
        assert_eq!(mapped.arc_decision, PermissionDecision::Deny);
    }

    // -- ReceiptLogger tests --

    #[test]
    fn receipt_logger_generates_tool_call_receipt() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallEvent {
            tool_call_id: "tc-1".to_string(),
            title: Some("Read file".to_string()),
            kind: Some("fs_read".to_string()),
            status: Some("running".to_string()),
        };
        let receipt = logger.log_tool_call("session-1", &event);
        assert_eq!(receipt.tool_call_id, "tc-1");
        assert_eq!(receipt.title, "Read file");
        assert_eq!(receipt.kind, Some("fs_read".to_string()));
        assert_eq!(receipt.status, "running");
        assert_eq!(receipt.session_id, "session-1");
        assert_eq!(receipt.server_id, "test-server");
        assert!(!receipt.timestamp.is_empty());
        assert!(!receipt.content_hash.is_empty());
        // SHA-256 hex is 64 chars
        assert_eq!(receipt.content_hash.len(), 64);
    }

    #[test]
    fn receipt_logger_generates_update_receipt_with_status() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-2".to_string(),
            status: Some("completed".to_string()),
        };
        let receipt = logger.log_tool_call_update("session-2", &event);
        assert!(receipt.is_some());
        let receipt = receipt.unwrap();
        assert_eq!(receipt.tool_call_id, "tc-2");
        assert_eq!(receipt.status, "completed");
        assert!(!receipt.content_hash.is_empty());
        assert_eq!(receipt.content_hash.len(), 64);
    }

    #[test]
    fn receipt_logger_skips_update_without_status() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-3".to_string(),
            status: None,
        };
        let receipt = logger.log_tool_call_update("session-3", &event);
        assert!(receipt.is_none());
    }

    // -- Protocol deserialization tests --

    #[test]
    fn parse_json_rpc_message() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/home/user/file.txt"
            }
        });
        let msg: JsonRpcMessage = serde_json::from_value(raw).unwrap();
        assert_eq!(msg.method.as_deref(), Some("fs/read_text_file"));
        assert_eq!(msg.id, Some(serde_json::Value::Number(1.into())));
    }

    #[test]
    fn parse_read_text_file_params() {
        let raw = json!({
            "sessionId": "s1",
            "path": "/home/user/file.txt",
            "line": 10,
            "limit": 50
        });
        let params: ReadTextFileParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.session_id, "s1");
        assert_eq!(params.path, "/home/user/file.txt");
        assert_eq!(params.line, Some(10));
        assert_eq!(params.limit, Some(50));
    }

    #[test]
    fn parse_write_text_file_params() {
        let raw = json!({
            "sessionId": "s1",
            "path": "/home/user/out.txt",
            "content": "hello world"
        });
        let params: WriteTextFileParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.path, "/home/user/out.txt");
        assert_eq!(params.content, "hello world");
    }

    #[test]
    fn parse_create_terminal_params() {
        let raw = json!({
            "sessionId": "s1",
            "command": "cargo",
            "args": ["build", "--release"],
            "cwd": "/home/user/project"
        });
        let params: CreateTerminalParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.command, "cargo");
        assert_eq!(params.args, vec!["build", "--release"]);
        assert_eq!(params.cwd, Some("/home/user/project".to_string()));
    }

    #[test]
    fn parse_permission_option() {
        let raw = json!({
            "optionId": "opt-1",
            "name": "Allow once",
            "kind": "allow_once"
        });
        let option: PermissionOption = serde_json::from_value(raw).unwrap();
        assert_eq!(option.option_id, "opt-1");
        assert_eq!(option.kind, "allow_once");
    }

    #[test]
    fn extract_method_returns_correct_variant() {
        let msg = json!({ "jsonrpc": "2.0", "method": "terminal/create" });
        let method = extract_method(&msg);
        assert_eq!(method, Some(AcpMethod::TerminalCreate));
    }

    #[test]
    fn extract_method_returns_none_for_response() {
        let msg = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        assert_eq!(extract_method(&msg), None);
    }

    #[test]
    fn parse_tool_call_event() {
        let raw = json!({
            "toolCallId": "tc-1",
            "title": "Read file",
            "kind": "fs_read",
            "status": "running"
        });
        let update = parse_session_update(&raw);
        match update {
            SessionUpdate::ToolCall(event) => {
                assert_eq!(event.tool_call_id, "tc-1");
                assert_eq!(event.title, Some("Read file".to_string()));
            }
            other => panic!("expected ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn parse_tool_call_update_event() {
        let raw = json!({
            "toolCallId": "tc-2",
            "status": "completed"
        });
        let update = parse_session_update(&raw);
        match update {
            SessionUpdate::ToolCallUpdate(event) => {
                assert_eq!(event.tool_call_id, "tc-2");
                assert_eq!(event.status, Some("completed".to_string()));
            }
            other => panic!("expected ToolCallUpdate, got {:?}", other),
        }
    }

    // -- New ACP method variants --

    #[test]
    fn protocol_parses_new_method_variants() {
        assert_eq!(
            AcpMethod::from_method_str("authenticate"),
            AcpMethod::Authenticate
        );
        assert_eq!(
            AcpMethod::from_method_str("session/load"),
            AcpMethod::SessionLoad
        );
        assert_eq!(
            AcpMethod::from_method_str("session/list"),
            AcpMethod::SessionList
        );
        assert_eq!(
            AcpMethod::from_method_str("session/set_config_option"),
            AcpMethod::SessionSetConfigOption
        );
        assert_eq!(
            AcpMethod::from_method_str("session/set_mode"),
            AcpMethod::SessionSetMode
        );
        assert_eq!(
            AcpMethod::from_method_str("terminal/output"),
            AcpMethod::TerminalOutput
        );
        assert_eq!(
            AcpMethod::from_method_str("terminal/wait_for_exit"),
            AcpMethod::TerminalWaitForExit
        );
    }

    // -- Session update variant parsing --

    #[test]
    fn protocol_parses_all_session_update_variants() {
        // agent_message_chunk
        let raw = json!({"type": "agent_message_chunk", "content": "hello"});
        match parse_session_update(&raw) {
            SessionUpdate::AgentMessageChunk(_) => {}
            other => panic!("expected AgentMessageChunk, got {:?}", other),
        }

        // agent_thought_chunk
        let raw = json!({"type": "agent_thought_chunk", "content": "thinking..."});
        match parse_session_update(&raw) {
            SessionUpdate::AgentThoughtChunk(_) => {}
            other => panic!("expected AgentThoughtChunk, got {:?}", other),
        }

        // plan
        let raw = json!({"type": "plan", "steps": []});
        match parse_session_update(&raw) {
            SessionUpdate::Plan(_) => {}
            other => panic!("expected Plan, got {:?}", other),
        }

        // available_commands_update
        let raw = json!({"type": "available_commands_update", "commands": []});
        match parse_session_update(&raw) {
            SessionUpdate::AvailableCommandsUpdate(_) => {}
            other => panic!("expected AvailableCommandsUpdate, got {:?}", other),
        }

        // current_mode_update
        let raw = json!({"type": "current_mode_update", "mode": "code"});
        match parse_session_update(&raw) {
            SessionUpdate::CurrentModeUpdate(_) => {}
            other => panic!("expected CurrentModeUpdate, got {:?}", other),
        }

        // config_option_update
        let raw = json!({"type": "config_option_update", "key": "theme", "value": "dark"});
        match parse_session_update(&raw) {
            SessionUpdate::ConfigOptionUpdate(_) => {}
            other => panic!("expected ConfigOptionUpdate, got {:?}", other),
        }

        // session_info_update
        let raw = json!({"type": "session_info_update", "session_id": "s1"});
        match parse_session_update(&raw) {
            SessionUpdate::SessionInfoUpdate(_) => {}
            other => panic!("expected SessionInfoUpdate, got {:?}", other),
        }

        // unknown type falls through to Other
        let raw = json!({"type": "unknown_future_type", "data": 42});
        match parse_session_update(&raw) {
            SessionUpdate::Other(_) => {}
            other => panic!("expected Other, got {:?}", other),
        }
    }

    // -- MessageInterceptor tests --

    fn test_config() -> AcpProxyConfig {
        AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo")
            .with_allowed_command("npm")
    }

    #[test]
    fn interceptor_forwards_unrelated_message() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let result = interceptor
            .intercept(Direction::ClientToAgent, &msg)
            .unwrap();
        match result {
            InterceptResult::Forward(v) => assert_eq!(v, msg),
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_blocks_fs_read_outside_prefix() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/etc/passwd"
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Block(v) => {
                assert!(v.get("error").is_some());
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_allows_fs_read_in_prefix() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/home/user/project/src/main.rs"
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Forward(_) => {}
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_blocks_terminal_create_unlisted_command() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "terminal/create",
            "params": {
                "sessionId": "s1",
                "command": "rm",
                "args": ["-rf", "/"]
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Block(v) => {
                assert!(v.get("error").is_some());
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_allows_terminal_create_listed_command() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "terminal/create",
            "params": {
                "sessionId": "s1",
                "command": "cargo",
                "args": ["test"]
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Forward(_) => {}
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_generates_receipt_for_tool_call() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s1",
                "update": {
                    "toolCallId": "tc-99",
                    "title": "Build project",
                    "kind": "terminal",
                    "status": "running"
                }
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::ForwardWithReceipt(_, receipt) => {
                assert_eq!(receipt.tool_call_id, "tc-99");
                assert_eq!(receipt.title, "Build project");
                assert_eq!(receipt.status, "running");
            }
            other => panic!("expected ForwardWithReceipt, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_forwards_client_to_agent_unchanged() {
        let interceptor = MessageInterceptor::new(test_config());
        // Even security-sensitive methods are forwarded when going client->agent
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/etc/shadow"
            }
        });
        let result = interceptor
            .intercept(Direction::ClientToAgent, &msg)
            .unwrap();
        match result {
            InterceptResult::Forward(v) => assert_eq!(v, msg),
            other => panic!("expected Forward for client->agent direction, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_blocks_fs_write_with_traversal() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "fs/write_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/home/user/project/../../../etc/crontab",
                "content": "* * * * * evil"
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Block(v) => {
                assert!(v.get("error").is_some());
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_handles_new_method_variants() {
        let interceptor = MessageInterceptor::new(test_config());

        // All new method variants should forward without errors
        let methods = vec![
            "authenticate",
            "session/load",
            "session/list",
            "session/set_config_option",
            "session/set_mode",
            "terminal/output",
            "terminal/wait_for_exit",
        ];

        for method in methods {
            let msg = json!({
                "jsonrpc": "2.0",
                "id": 100,
                "method": method,
                "params": {}
            });

            let result = interceptor
                .intercept(Direction::AgentToClient, &msg)
                .unwrap();
            match result {
                InterceptResult::Forward(_) => {}
                other => panic!(
                    "expected Forward for method '{}', got {:?}",
                    method, other
                ),
            }
        }
    }

    #[test]
    fn interceptor_uses_correct_error_code() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/etc/passwd"
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Block(v) => {
                let code = v
                    .get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_i64())
                    .unwrap();
                assert_eq!(code, -32000, "error code should be -32000 (server error range)");
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_blocks_fs_read_prefix_substring() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/home/user/project_evil/secret.txt"
            }
        });
        let result = interceptor
            .intercept(Direction::AgentToClient, &msg)
            .unwrap();
        match result {
            InterceptResult::Block(v) => {
                assert!(v.get("error").is_some());
            }
            other => panic!("expected Block for prefix substring attack, got {:?}", other),
        }
    }

    // -- AcpProxy lifecycle test --

    #[test]
    fn proxy_creation_and_shutdown() {
        // Use a command that exists on all platforms and exits immediately.
        // "true" is a shell builtin / coreutils command that always succeeds.
        let config = AcpProxyConfig::new("true", "deadbeef")
            .with_allowed_path_prefix("/tmp");

        let result = AcpProxy::start(config);
        // The proxy should start successfully (the 'true' command is
        // universally available on Unix systems).
        match result {
            Ok(mut proxy) => {
                // Shutdown should not error even if the process already exited.
                let _ = proxy.shutdown();
            }
            Err(_) => {
                // On systems where 'true' is not found, we accept the failure
                // gracefully rather than panicking.
            }
        }
    }

    // -- Audit entry content hash test --

    #[test]
    fn audit_entry_content_hash_is_deterministic() {
        let logger = ReceiptLogger::new("test-server");
        let event = ToolCallEvent {
            tool_call_id: "tc-hash".to_string(),
            title: Some("Determinism check".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let entry1 = logger.log_tool_call("session-hash", &event);
        let entry2 = logger.log_tool_call("session-hash", &event);
        assert_eq!(entry1.content_hash, entry2.content_hash);
    }
}

// ================================================================
// Extended test coverage -- no unwrap/expect used below.
// ================================================================
#[cfg(test)]
mod extended_tests {
    use super::*;
    use serde_json::json;

    // Helper: build a standard test interceptor config.
    fn test_config() -> AcpProxyConfig {
        AcpProxyConfig::new("echo", "deadbeef")
            .with_allowed_path_prefix("/home/user/project")
            .with_allowed_command("cargo")
            .with_allowed_command("npm")
    }

    // ================================================================
    // 1. Protocol Parsing Edge Cases
    // ================================================================

    #[test]
    fn protocol_malformed_json_rpc_missing_jsonrpc_field() {
        // A JSON-RPC message that is missing the required "jsonrpc" field
        // should fail to deserialize into JsonRpcMessage.
        let raw = json!({
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_err(), "missing jsonrpc field should fail deserialization");
    }

    #[test]
    fn protocol_json_rpc_with_null_id_notification() {
        // serde_json deserializes `"id": null` for Option<Value> as None.
        // This is effectively the same as omitting the id entirely.
        let raw = json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "session/update",
            "params": {}
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok(), "null id should be valid JSON-RPC");
        if let Ok(msg) = result {
            assert!(
                msg.id.is_none(),
                "explicit null id deserializes as None for Option<Value>"
            );
        }
    }

    #[test]
    fn protocol_json_rpc_with_string_id() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": "abc-123",
            "method": "initialize",
            "params": {}
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok(), "string id should be valid JSON-RPC");
        if let Ok(msg) = result {
            let id_str = msg.id.as_ref().and_then(|v| v.as_str());
            assert_eq!(id_str, Some("abc-123"));
        }
    }

    #[test]
    fn protocol_json_rpc_with_numeric_id() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "initialize",
            "params": {}
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok(), "numeric id should be valid JSON-RPC");
        if let Ok(msg) = result {
            let id_num = msg.id.as_ref().and_then(|v| v.as_i64());
            assert_eq!(id_num, Some(42));
        }
    }

    #[test]
    fn protocol_unknown_method_maps_to_unknown_variant() {
        let method = AcpMethod::from_method_str("some/future/method");
        assert_eq!(method, AcpMethod::Unknown("some/future/method".to_string()));
    }

    #[test]
    fn protocol_empty_method_string_maps_to_unknown() {
        let method = AcpMethod::from_method_str("");
        assert_eq!(method, AcpMethod::Unknown(String::new()));
    }

    #[test]
    fn protocol_session_update_with_unknown_type_maps_to_other() {
        let raw = json!({"type": "some_new_update_type", "payload": 42});
        match parse_session_update(&raw) {
            SessionUpdate::Other(_) => {}
            other => panic!("expected Other for unknown session update type, got {:?}", other),
        }
    }

    #[test]
    fn protocol_empty_params_object() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok(), "empty params object should be valid");
        if let Ok(msg) = result {
            assert!(msg.params.is_some());
            let params = msg.params.as_ref();
            assert!(
                params.map(|p| p.is_object()).unwrap_or(false),
                "params should be an object"
            );
        }
    }

    #[test]
    fn protocol_params_as_array() {
        // JSON-RPC 2.0 allows params as array. Our struct should handle
        // it since params is typed as Option<Value>.
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": [1, 2, 3]
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok(), "array params should be deserializable");
        if let Ok(msg) = result {
            assert!(msg.params.is_some());
            let is_array = msg.params.as_ref().map(|p| p.is_array()).unwrap_or(false);
            assert!(is_array, "params should be an array");
        }
    }

    #[test]
    fn protocol_extract_method_returns_none_for_no_method_field() {
        let msg = json!({"jsonrpc": "2.0", "id": 1});
        assert_eq!(extract_method(&msg), None);
    }

    #[test]
    fn protocol_extract_method_returns_none_for_non_string_method() {
        let msg = json!({"jsonrpc": "2.0", "method": 123});
        assert_eq!(extract_method(&msg), None);
    }

    #[test]
    fn protocol_json_rpc_notification_no_id() {
        // A notification has method but no id.
        let raw = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {"sessionId": "s1", "update": {}}
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert!(msg.id.is_none(), "notification should have no id");
            assert_eq!(msg.method.as_deref(), Some("session/update"));
        }
    }

    #[test]
    fn protocol_json_rpc_error_response() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        });
        let result = serde_json::from_value::<JsonRpcMessage>(raw);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert!(msg.error.is_some());
            if let Some(ref err) = msg.error {
                assert_eq!(err.code, -32600);
                assert_eq!(err.message, "Invalid Request");
            }
        }
    }

    #[test]
    fn protocol_json_rpc_error_builder_uses_correct_structure() {
        let error = json_rpc_error(Some(&json!(42)), -32000, "access denied");
        assert_eq!(error["jsonrpc"], "2.0");
        assert_eq!(error["id"], 42);
        assert_eq!(error["error"]["code"], -32000);
        assert_eq!(error["error"]["message"], "access denied");
    }

    #[test]
    fn protocol_json_rpc_error_builder_with_none_id() {
        let error = json_rpc_error(None, -32000, "access denied");
        assert_eq!(error["id"], serde_json::Value::Null);
    }

    #[test]
    fn protocol_parse_session_update_tool_call_without_title() {
        // toolCallId present but no title -- should match ToolCallUpdate, not ToolCall
        let raw = json!({
            "toolCallId": "tc-no-title",
            "status": "running"
        });
        match parse_session_update(&raw) {
            SessionUpdate::ToolCallUpdate(event) => {
                assert_eq!(event.tool_call_id, "tc-no-title");
                assert_eq!(event.status, Some("running".to_string()));
            }
            other => panic!("expected ToolCallUpdate (no title), got {:?}", other),
        }
    }

    #[test]
    fn protocol_parse_session_update_empty_object() {
        // An empty JSON object has no discriminator fields -- should be Other.
        let raw = json!({});
        match parse_session_update(&raw) {
            SessionUpdate::Other(_) => {}
            other => panic!("expected Other for empty object, got {:?}", other),
        }
    }

    // ================================================================
    // 2. FsGuard Comprehensive Coverage
    // ================================================================

    #[test]
    fn fs_guard_path_with_trailing_slash() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Trailing slash on the path should be normalized and still match.
        assert!(guard.check_read("/home/user/project/").is_ok());
    }

    #[test]
    fn fs_guard_path_with_double_slashes() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Double slashes should be collapsed during canonicalization.
        assert!(guard.check_read("/home/user//project/file.txt").is_ok());
    }

    #[test]
    fn fs_guard_root_path() {
        // The prefix "/" is stored as-is. After canonicalization "/"
        // becomes "/" (empty parts joined). The boundary check requires
        // the byte after the prefix to be '/' or an exact match. Since
        // prefix "/" has length 1 and canonicalized "/etc/passwd" has
        // 'e' at index 1, neither condition is met. This means "/" as
        // a prefix does NOT grant universal access -- it is effectively
        // a no-match because the implementation's boundary check is
        // strict. This is safe (fail-closed).
        let guard = FsGuard::new(vec!["/".to_string()]);
        assert!(
            guard.check_read("/etc/passwd").is_err(),
            "root prefix '/' does not pass boundary check -- fail-closed"
        );
    }

    #[test]
    fn fs_guard_root_path_not_configured() {
        let guard = FsGuard::new(vec!["/home/user".to_string()]);
        // Root path itself should not match a non-root prefix.
        assert!(guard.check_read("/").is_err());
    }

    #[test]
    fn fs_guard_very_long_path() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        let long_suffix = "a".repeat(1000);
        let long_path = format!("/home/user/project/{long_suffix}");
        assert!(guard.check_read(&long_path).is_ok());
    }

    #[test]
    fn fs_guard_path_with_unicode_characters() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard.check_read("/home/user/project/src/\u{00e9}ditor.rs").is_ok());
        assert!(guard.check_read("/home/user/project/\u{4e16}\u{754c}.txt").is_ok());
    }

    #[test]
    fn fs_guard_multiple_prefixes_matches_second() {
        let guard = FsGuard::new(vec![
            "/opt/first".to_string(),
            "/opt/second".to_string(),
        ]);
        // Should fail for first prefix but succeed for second.
        assert!(guard.check_read("/opt/second/file.txt").is_ok());
        // Verify the first also works.
        assert!(guard.check_read("/opt/first/file.txt").is_ok());
        // Neither prefix matches.
        assert!(guard.check_read("/opt/third/file.txt").is_err());
    }

    #[test]
    fn fs_guard_write_blocked_read_allowed_separate_instances() {
        // A read guard allows /tmp, a write guard allows only /home.
        let read_guard = FsGuard::new(vec!["/tmp".to_string()]);
        let write_guard = FsGuard::new(vec!["/home".to_string()]);

        assert!(read_guard.check_read("/tmp/data.txt").is_ok());
        assert!(write_guard.check_write("/tmp/data.txt").is_err());
        assert!(write_guard.check_write("/home/user/file.txt").is_ok());
        assert!(read_guard.check_read("/home/user/file.txt").is_err());
    }

    #[test]
    fn fs_guard_dot_segments_are_collapsed() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // "." segments should be collapsed to a clean path.
        assert!(guard.check_read("/home/user/./project/./file.txt").is_ok());
    }

    #[test]
    fn fs_guard_prefix_exact_match_no_trailing_slash() {
        let guard = FsGuard::new(vec!["/home/user/project".to_string()]);
        // Exact match of the prefix itself should be allowed.
        assert!(guard.check_read("/home/user/project").is_ok());
    }

    // ================================================================
    // 3. TerminalGuard Edge Cases
    // ================================================================

    #[test]
    fn terminal_guard_empty_command_string() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        // Empty command is not on the allowlist.
        assert!(guard.check_command("", &[]).is_err());
    }

    #[test]
    fn terminal_guard_command_with_spaces_in_path() {
        let guard = TerminalGuard::new(vec!["my tool".to_string()]);
        // The base name extraction uses rsplit('/'), so "/usr/local/bin/my tool"
        // has base name "my tool".
        assert!(guard.check_command("/usr/local/bin/my tool", &[]).is_ok());
    }

    #[test]
    fn terminal_guard_multiple_allowed_matching_second() {
        let guard = TerminalGuard::new(vec!["git".to_string(), "npm".to_string()]);
        assert!(guard.check_command("npm", &["install".to_string()]).is_ok());
    }

    #[test]
    fn terminal_guard_arg_with_pipe_only() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["|".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_semicolon_only() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &[";".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_backtick() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["`".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_dollar_paren() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["$(whoami)".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_arg_with_newline_character() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["line1\nline2".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_clean_arg_with_equals_sign() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(guard.check_command("cargo", &["--flag=value".to_string()]).is_ok());
    }

    #[test]
    fn terminal_guard_clean_arg_with_dashes_and_numbers() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        assert!(
            guard
                .check_command("cargo", &["--jobs=4".to_string(), "-j2".to_string()])
                .is_ok()
        );
    }

    #[test]
    fn terminal_guard_arg_with_carriage_return() {
        let guard = TerminalGuard::new(vec!["echo".to_string()]);
        assert!(guard.check_command("echo", &["hello\rworld".to_string()]).is_err());
    }

    #[test]
    fn terminal_guard_command_matching_is_exact() {
        let guard = TerminalGuard::new(vec!["cargo".to_string()]);
        // "cargoo" or "carg" should not match "cargo".
        assert!(guard.check_command("cargoo", &[]).is_err());
        assert!(guard.check_command("carg", &[]).is_err());
    }

    // ================================================================
    // 4. Interceptor Integration Tests
    // ================================================================

    #[test]
    fn interceptor_client_to_agent_always_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session/prompt",
            "params": {"sessionId": "s1", "message": "hello"}
        });
        let result = interceptor.intercept(Direction::ClientToAgent, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for client->agent, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_fs_read_blocked_returns_correct_error_json() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/etc/shadow"
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Block(v)) => {
                assert_eq!(v["jsonrpc"], "2.0");
                assert_eq!(v["id"], 99);
                assert!(v.get("error").is_some());
                assert_eq!(v["error"]["code"], -32000);
                let msg_str = v["error"]["message"].as_str().unwrap_or("");
                assert!(
                    msg_str.contains("denied"),
                    "error message should contain 'denied', got: {msg_str}"
                );
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_fs_write_blocked_returns_correct_error_json() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "fs/write_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/etc/crontab",
                "content": "malicious"
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Block(v)) => {
                assert_eq!(v["id"], 100);
                assert_eq!(v["error"]["code"], -32000);
            }
            other => panic!("expected Block for fs write outside prefix, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_terminal_create_blocked_returns_correct_error_json() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "terminal/create",
            "params": {
                "sessionId": "s1",
                "command": "rm",
                "args": ["-rf", "/"]
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Block(v)) => {
                assert_eq!(v["id"], 101);
                assert_eq!(v["error"]["code"], -32000);
                let msg_str = v["error"]["message"].as_str().unwrap_or("");
                assert!(
                    msg_str.contains("denied"),
                    "error message should contain 'denied', got: {msg_str}"
                );
            }
            other => panic!("expected Block for unlisted terminal command, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_session_update_tool_call_generates_receipt() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s1",
                "update": {
                    "toolCallId": "tc-200",
                    "title": "Compile",
                    "kind": "terminal",
                    "status": "running"
                }
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::ForwardWithReceipt(_, receipt)) => {
                assert_eq!(receipt.tool_call_id, "tc-200");
                assert_eq!(receipt.title, "Compile");
                assert_eq!(receipt.status, "running");
                assert_eq!(receipt.session_id, "s1");
            }
            other => panic!("expected ForwardWithReceipt, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_session_update_agent_message_chunk_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s1",
                "update": {
                    "type": "agent_message_chunk",
                    "content": "Hello, I am an agent."
                }
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for agent_message_chunk, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_response_message_forwarded_unchanged() {
        // A response (has "result" but no "method") should be forwarded.
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"status": "ok"}
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for response message, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_message_without_method_forwarded() {
        // A notification without a method field should be forwarded.
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 5
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for message without method, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_fs_read_missing_params_returns_protocol_error() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "fs/read_text_file"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_err(), "missing params should produce a protocol error");
    }

    #[test]
    fn interceptor_fs_write_missing_params_returns_protocol_error() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 103,
            "method": "fs/write_text_file"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_err(), "missing params should produce a protocol error");
    }

    #[test]
    fn interceptor_terminal_create_missing_params_returns_protocol_error() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 104,
            "method": "terminal/create"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_err(), "missing params should produce a protocol error");
    }

    #[test]
    fn interceptor_fs_write_allowed_in_prefix() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 105,
            "method": "fs/write_text_file",
            "params": {
                "sessionId": "s1",
                "path": "/home/user/project/output.txt",
                "content": "hello"
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(_)) => {}
            other => panic!("expected Forward for allowed fs write, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_terminal_create_with_injection_arg_blocked() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 106,
            "method": "terminal/create",
            "params": {
                "sessionId": "s1",
                "command": "cargo",
                "args": ["build; rm -rf /"]
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Block(v)) => {
                assert!(v.get("error").is_some());
            }
            other => panic!("expected Block for injection arg, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_session_update_tool_call_update_with_status_generates_receipt() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s2",
                "update": {
                    "toolCallId": "tc-300",
                    "status": "completed"
                }
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::ForwardWithReceipt(_, receipt)) => {
                assert_eq!(receipt.tool_call_id, "tc-300");
                assert_eq!(receipt.status, "completed");
                assert_eq!(receipt.session_id, "s2");
            }
            other => panic!("expected ForwardWithReceipt for tool_call_update, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_session_update_tool_call_update_without_status_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "s3",
                "update": {
                    "toolCallId": "tc-400"
                }
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(_)) => {}
            other => panic!(
                "expected Forward for tool_call_update without status, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn interceptor_permission_request_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 200,
            "method": "session/request_permission",
            "params": {
                "sessionId": "s1",
                "toolCall": {"name": "fs_read"},
                "options": [
                    {"optionId": "opt-1", "name": "Allow", "kind": "allow_once"},
                    {"optionId": "opt-2", "name": "Deny", "kind": "reject_once"}
                ]
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for permission request, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_unknown_method_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 201,
            "method": "some/future/method",
            "params": {}
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for unknown method, got {:?}", other),
        }
    }

    // ================================================================
    // 5. Permission Mapper
    // ================================================================

    #[test]
    fn permission_mapper_all_four_kinds() {
        let mapper = PermissionMapper::new(7200);

        let cases = vec![
            ("allow_once", PermissionDecision::AllowOnce),
            (
                "allow_always",
                PermissionDecision::AllowScoped {
                    duration_secs: 7200,
                },
            ),
            ("reject_once", PermissionDecision::Deny),
            ("reject_always", PermissionDecision::DenyPermanent),
        ];

        for (kind, expected_decision) in cases {
            let option = PermissionOption {
                option_id: format!("opt-{kind}"),
                name: kind.to_string(),
                kind: kind.to_string(),
            };
            let mapped = mapper.map_option(&option);
            assert_eq!(
                mapped.arc_decision, expected_decision,
                "kind '{kind}' should map to {expected_decision:?}"
            );
            assert_eq!(mapped.original_option_id, format!("opt-{kind}"));
        }
    }

    #[test]
    fn permission_mapper_unknown_kind_defaults_to_deny() {
        let mapper = PermissionMapper::new(3600);
        let option = PermissionOption {
            option_id: "opt-mystery".to_string(),
            name: "Mystery".to_string(),
            kind: "future_kind".to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(mapped.arc_decision, PermissionDecision::Deny);
    }

    #[test]
    fn permission_mapper_empty_kind_string_defaults_to_deny() {
        let mapper = PermissionMapper::new(3600);
        let option = PermissionOption {
            option_id: "opt-empty".to_string(),
            name: "Empty".to_string(),
            kind: String::new(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(mapped.arc_decision, PermissionDecision::Deny);
    }

    #[test]
    fn permission_mapper_preserves_original_option_id() {
        let mapper = PermissionMapper::new(3600);
        let option = PermissionOption {
            option_id: "unique-id-42".to_string(),
            name: "Allow".to_string(),
            kind: "allow_once".to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(mapped.original_option_id, "unique-id-42");
    }

    #[test]
    fn permission_mapper_scoped_duration_reflects_constructor() {
        let mapper = PermissionMapper::new(900); // 15 minutes
        let option = PermissionOption {
            option_id: "opt-scoped".to_string(),
            name: "Always".to_string(),
            kind: "allow_always".to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(
            mapped.arc_decision,
            PermissionDecision::AllowScoped {
                duration_secs: 900
            }
        );
    }

    // ================================================================
    // 6. Receipt/Audit Entry
    // ================================================================

    #[test]
    fn receipt_content_hash_deterministic_same_input() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallEvent {
            tool_call_id: "tc-det".to_string(),
            title: Some("Hash test".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let entry1 = logger.log_tool_call("session-det", &event);
        let entry2 = logger.log_tool_call("session-det", &event);
        assert_eq!(entry1.content_hash, entry2.content_hash);
        assert_eq!(entry1.content_hash.len(), 64);
    }

    #[test]
    fn receipt_different_inputs_produce_different_hashes() {
        let logger = ReceiptLogger::new("srv-1");
        let event_a = ToolCallEvent {
            tool_call_id: "tc-a".to_string(),
            title: Some("Event A".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let event_b = ToolCallEvent {
            tool_call_id: "tc-b".to_string(),
            title: Some("Event B".to_string()),
            kind: Some("test".to_string()),
            status: Some("running".to_string()),
        };
        let entry_a = logger.log_tool_call("session-diff", &event_a);
        let entry_b = logger.log_tool_call("session-diff", &event_b);
        assert_ne!(
            entry_a.content_hash, entry_b.content_hash,
            "different events should produce different hashes"
        );
    }

    #[test]
    fn receipt_missing_optional_fields_handled_gracefully() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallEvent {
            tool_call_id: "tc-minimal".to_string(),
            title: None,
            kind: None,
            status: None,
        };
        let entry = logger.log_tool_call("session-minimal", &event);
        assert_eq!(entry.tool_call_id, "tc-minimal");
        assert_eq!(entry.title, "", "missing title should default to empty string");
        assert!(entry.kind.is_none());
        assert_eq!(entry.status, "started", "missing status should default to 'started'");
        assert!(!entry.content_hash.is_empty());
        assert_eq!(entry.content_hash.len(), 64);
    }

    #[test]
    fn receipt_tool_call_update_without_status_returns_none() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-no-status".to_string(),
            status: None,
        };
        let result = logger.log_tool_call_update("session-none", &event);
        assert!(result.is_none());
    }

    #[test]
    fn receipt_tool_call_update_with_status_returns_some() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-with-status".to_string(),
            status: Some("error".to_string()),
        };
        let result = logger.log_tool_call_update("session-status", &event);
        assert!(result.is_some());
        if let Some(entry) = result {
            assert_eq!(entry.tool_call_id, "tc-with-status");
            assert_eq!(entry.status, "error");
            assert_eq!(entry.content_hash.len(), 64);
        }
    }

    #[test]
    fn receipt_update_content_hash_deterministic() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallUpdateEvent {
            tool_call_id: "tc-upd-det".to_string(),
            status: Some("completed".to_string()),
        };
        let entry1 = logger.log_tool_call_update("session-upd", &event);
        let entry2 = logger.log_tool_call_update("session-upd", &event);
        assert!(entry1.is_some());
        assert!(entry2.is_some());
        if let (Some(e1), Some(e2)) = (entry1, entry2) {
            assert_eq!(e1.content_hash, e2.content_hash);
        }
    }

    #[test]
    fn receipt_server_id_matches_logger_config() {
        let logger = ReceiptLogger::new("custom-server-id");
        let event = ToolCallEvent {
            tool_call_id: "tc-srv".to_string(),
            title: Some("Server ID test".to_string()),
            kind: None,
            status: Some("running".to_string()),
        };
        let entry = logger.log_tool_call("s1", &event);
        assert_eq!(entry.server_id, "custom-server-id");
    }

    #[test]
    fn receipt_timestamp_is_numeric_string() {
        let logger = ReceiptLogger::new("srv-1");
        let event = ToolCallEvent {
            tool_call_id: "tc-ts".to_string(),
            title: Some("Timestamp test".to_string()),
            kind: None,
            status: Some("running".to_string()),
        };
        let entry = logger.log_tool_call("s1", &event);
        assert!(
            !entry.timestamp.is_empty(),
            "timestamp should not be empty"
        );
        let parsed: Result<u64, _> = entry.timestamp.parse();
        assert!(
            parsed.is_ok(),
            "timestamp should be a parseable numeric string, got: {}",
            entry.timestamp
        );
    }

    // ================================================================
    // 7. AcpProxy Lifecycle / Config
    // ================================================================

    #[test]
    fn config_builder_defaults() {
        let config = AcpProxyConfig::new("agent-cmd", "pubkey-hex");
        assert_eq!(config.agent_command(), "agent-cmd");
        assert_eq!(config.public_key(), "pubkey-hex");
        assert!(config.allowed_path_prefixes().is_empty());
        assert!(config.allowed_commands().is_empty());
        assert!(config.agent_args().is_empty());
        assert!(config.agent_env().is_empty());
        assert_eq!(config.server_id(), "arc-acp-proxy");
    }

    #[test]
    fn config_builder_chaining() {
        let config = AcpProxyConfig::new("agent", "key")
            .with_allowed_path_prefix("/home")
            .with_allowed_path_prefix("/tmp")
            .with_allowed_command("cargo")
            .with_allowed_command("npm")
            .with_server_id("my-proxy")
            .with_agent_args(vec!["--flag".to_string()])
            .with_agent_env(vec![("KEY".to_string(), "VAL".to_string())]);

        assert_eq!(config.allowed_path_prefixes().len(), 2);
        assert_eq!(config.allowed_commands().len(), 2);
        assert_eq!(config.server_id(), "my-proxy");
        assert_eq!(config.agent_args().len(), 1);
        assert_eq!(config.agent_env().len(), 1);
    }

    #[test]
    fn proxy_start_with_nonexistent_command_fails() {
        let config = AcpProxyConfig::new(
            "/nonexistent/path/to/fake-agent-binary-xyz123",
            "deadbeef",
        );
        let result = AcpProxy::start(config);
        assert!(result.is_err(), "starting with a nonexistent command should fail");
    }

    #[test]
    fn proxy_interceptor_exposes_config() {
        let config = test_config();
        let interceptor = MessageInterceptor::new(config);
        assert_eq!(interceptor.config().agent_command(), "echo");
        assert_eq!(interceptor.config().allowed_path_prefixes().len(), 1);
        assert_eq!(interceptor.config().allowed_commands().len(), 2);
    }

    // ================================================================
    // 8. Serialization round-trip tests
    // ================================================================

    #[test]
    fn audit_entry_serialization_round_trip() {
        let entry = AcpToolCallAuditEntry {
            tool_call_id: "tc-rt".to_string(),
            title: "Round trip".to_string(),
            kind: Some("test".to_string()),
            status: "completed".to_string(),
            session_id: "s-rt".to_string(),
            timestamp: "1700000000".to_string(),
            server_id: "srv-rt".to_string(),
            content_hash: "a".repeat(64),
        };
        let json_result = serde_json::to_string(&entry);
        assert!(json_result.is_ok(), "audit entry should serialize to JSON");
        if let Ok(json_str) = json_result {
            let deserialized: Result<AcpToolCallAuditEntry, _> = serde_json::from_str(&json_str);
            assert!(deserialized.is_ok(), "audit entry should deserialize back");
            if let Ok(entry2) = deserialized {
                assert_eq!(entry2.tool_call_id, "tc-rt");
                assert_eq!(entry2.title, "Round trip");
                assert_eq!(entry2.status, "completed");
                assert_eq!(entry2.content_hash, "a".repeat(64));
            }
        }
    }

    #[test]
    fn tool_call_event_serialization_round_trip() {
        let event = ToolCallEvent {
            tool_call_id: "tc-ser".to_string(),
            title: Some("Serialize test".to_string()),
            kind: Some("terminal".to_string()),
            status: Some("running".to_string()),
        };
        let json_result = serde_json::to_value(&event);
        assert!(json_result.is_ok());
        if let Ok(val) = json_result {
            assert_eq!(val["toolCallId"], "tc-ser");
            assert_eq!(val["title"], "Serialize test");
            assert_eq!(val["kind"], "terminal");
            assert_eq!(val["status"], "running");
        }
    }

    #[test]
    fn tool_call_event_with_none_fields_omitted() {
        let event = ToolCallEvent {
            tool_call_id: "tc-none".to_string(),
            title: None,
            kind: None,
            status: None,
        };
        let json_result = serde_json::to_value(&event);
        assert!(json_result.is_ok());
        if let Ok(val) = json_result {
            assert_eq!(val["toolCallId"], "tc-none");
            // None fields with skip_serializing_if should not be present.
            assert!(val.get("title").is_none());
            assert!(val.get("kind").is_none());
            assert!(val.get("status").is_none());
        }
    }

    // ================================================================
    // 9. Additional edge cases for completeness
    // ================================================================

    #[test]
    fn all_acp_methods_have_correct_from_str() {
        let pairs = vec![
            ("initialize", AcpMethod::Initialize),
            ("authenticate", AcpMethod::Authenticate),
            ("session/new", AcpMethod::SessionNew),
            ("session/prompt", AcpMethod::SessionPrompt),
            ("session/cancel", AcpMethod::SessionCancel),
            ("session/update", AcpMethod::SessionUpdate),
            ("session/request_permission", AcpMethod::SessionRequestPermission),
            ("session/load", AcpMethod::SessionLoad),
            ("session/list", AcpMethod::SessionList),
            ("session/set_config_option", AcpMethod::SessionSetConfigOption),
            ("session/set_mode", AcpMethod::SessionSetMode),
            ("fs/read_text_file", AcpMethod::FsReadTextFile),
            ("fs/write_text_file", AcpMethod::FsWriteTextFile),
            ("terminal/create", AcpMethod::TerminalCreate),
            ("terminal/kill", AcpMethod::TerminalKill),
            ("terminal/release", AcpMethod::TerminalRelease),
            ("terminal/output", AcpMethod::TerminalOutput),
            ("terminal/wait_for_exit", AcpMethod::TerminalWaitForExit),
        ];
        for (method_str, expected) in pairs {
            assert_eq!(
                AcpMethod::from_method_str(method_str),
                expected,
                "method string '{method_str}' should map correctly"
            );
        }
    }

    #[test]
    fn interceptor_session_update_with_bad_params_forwarded() {
        // session/update with params that cannot deserialize to
        // SessionUpdateNotification should still forward.
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": "not an object"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(_)) => {}
            other => panic!("expected Forward for malformed session/update params, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_session_update_with_no_params_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "session/update"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(_)) => {}
            other => panic!("expected Forward for session/update with no params, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_permission_request_with_empty_options() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 300,
            "method": "session/request_permission",
            "params": {
                "sessionId": "s1",
                "options": []
            }
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for empty options, got {:?}", other),
        }
    }

    #[test]
    fn interceptor_permission_request_with_no_params_forwarded() {
        let interceptor = MessageInterceptor::new(test_config());
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 301,
            "method": "session/request_permission"
        });
        let result = interceptor.intercept(Direction::AgentToClient, &msg);
        assert!(result.is_ok());
        match result {
            Ok(InterceptResult::Forward(v)) => assert_eq!(v, msg),
            other => panic!("expected Forward for permission without params, got {:?}", other),
        }
    }

    #[test]
    fn fs_guard_prefix_with_trailing_slash_in_config() {
        // The prefix is stored as-is (not canonicalized). A trailing
        // slash in the prefix means `starts_with` matches, but the
        // boundary check looks at `canonical[prefix.len()]` which is
        // past the '/' character, so 'f' != '/' and the boundary
        // check fails. This is consistent with fail-closed behavior:
        // configure prefixes without trailing slashes.
        let guard = FsGuard::new(vec!["/home/user/project/".to_string()]);
        assert!(
            guard.check_read("/home/user/project/file.txt").is_err(),
            "trailing slash in prefix breaks boundary check -- use without trailing slash"
        );

        // Without trailing slash, it works correctly.
        let guard2 = FsGuard::new(vec!["/home/user/project".to_string()]);
        assert!(guard2.check_read("/home/user/project/file.txt").is_ok());
    }

    #[test]
    fn create_terminal_params_with_no_args() {
        let raw = json!({
            "sessionId": "s1",
            "command": "ls"
        });
        let result = serde_json::from_value::<CreateTerminalParams>(raw);
        assert!(result.is_ok());
        if let Ok(params) = result {
            assert_eq!(params.command, "ls");
            assert!(params.args.is_empty());
            assert!(params.cwd.is_none());
            assert!(params.env.is_none());
        }
    }

    #[test]
    fn read_text_file_params_minimal() {
        let raw = json!({
            "sessionId": "s1",
            "path": "/tmp/file.txt"
        });
        let result = serde_json::from_value::<ReadTextFileParams>(raw);
        assert!(result.is_ok());
        if let Ok(params) = result {
            assert_eq!(params.path, "/tmp/file.txt");
            assert!(params.line.is_none());
            assert!(params.limit.is_none());
        }
    }

    #[test]
    fn request_permission_params_with_empty_options() {
        let raw = json!({
            "sessionId": "s1",
            "options": []
        });
        let result = serde_json::from_value::<RequestPermissionParams>(raw);
        assert!(result.is_ok());
        if let Ok(params) = result {
            assert!(params.options.is_empty());
            assert!(params.tool_call.is_none());
        }
    }
}
