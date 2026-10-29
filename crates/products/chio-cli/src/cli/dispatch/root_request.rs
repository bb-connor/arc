#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use chio_core::crypto::{Keypair, PublicKey};
    use chio_mcp_remote::root_exchange::kinds::operator_key::SignedOperatorRootRequest;
    use chio_mcp_remote::root_exchange::RootExchangeError;

    use super::*;

    const REQUEST: &str = r#"{
        "request_id": "req-1",
        "principal": "ops:carol",
        "tenant_value": "acme",
        "scope": {"grants": [{"server_id": "crm", "tool_name": "search", "operations": ["invoke"]}]},
        "holder": "edge_session",
        "expires_at": 1792234920
    }"#;

    fn seed_file(dir: &tempfile::TempDir, mode: u32) -> (PathBuf, PublicKey) {
        let operator = Keypair::from_seed(&[0x31; 32]);
        let path = dir.path().join("operator.seed");
        std::fs::write(&path, format!("{}\n", operator.seed_hex())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        (path, operator.public_key())
    }

    #[test]
    fn root_request_sign_output_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let (path, operator_key) = seed_file(&dir, 0o600);
        let signed = sign_root_request(&path, REQUEST.as_bytes()).unwrap();

        let verified = SignedOperatorRootRequest::parse(&signed)
            .unwrap()
            .verify(&operator_key)
            .unwrap();
        let request = verified.request();
        assert_eq!(request.request_id.as_str(), "req-1");
        assert_eq!(request.principal.as_str(), "ops:carol");
        assert_eq!(
            request.tenant_value.as_ref().map(|tenant| tenant.as_str()),
            Some("acme")
        );
        assert_eq!(request.expires_at, 1_792_234_920);

        let unpinned = Keypair::from_seed(&[0x32; 32]).public_key();
        assert_eq!(
            SignedOperatorRootRequest::parse(&signed)
                .unwrap()
                .verify(&unpinned)
                .unwrap_err(),
            RootExchangeError::OperatorRootRequestSignatureInvalid
        );
    }

    #[test]
    fn root_request_sign_without_tenant_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = seed_file(&dir, 0o600);
        let mut request: serde_json::Value = serde_json::from_str(REQUEST).unwrap();
        request.as_object_mut().unwrap().remove("tenant_value");
        let error =
            sign_root_request(&path, serde_json::to_vec(&request).unwrap().as_slice()).unwrap_err();
        assert_eq!(
            error.to_string(),
            CliError::cli_json_error(
                RootExchangeError::OperatorRootRequestMissingTenant.to_string()
            )
            .to_string()
        );
    }

    #[test]
    fn root_request_sign_refuses_an_unknown_member() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = seed_file(&dir, 0o600);
        let mut request: serde_json::Value = serde_json::from_str(REQUEST).unwrap();
        request["operator_key"] = serde_json::json!("00");
        let error =
            sign_root_request(&path, serde_json::to_vec(&request).unwrap().as_slice()).unwrap_err();
        assert_eq!(
            error.to_string(),
            CliError::cli_json_error(
                RootExchangeError::OperatorRootRequestMalformed(
                    "body does not have the request shape"
                )
                .to_string()
            )
            .to_string()
        );
    }

    #[test]
    fn root_request_sign_refuses_a_group_readable_seed_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = seed_file(&dir, 0o640);
        let error = sign_root_request(&path, REQUEST.as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            CliError::cli_io_error(
                "authority seed must be singly linked with mode 0600 or stricter"
            )
            .to_string()
        );
    }
}
