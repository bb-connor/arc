//! `chio mcp root-request`: the operator side of `chio_operator_key` roots.

use std::io::{Read, Write as _};
use std::path::Path;

use chio_core::crypto::Ed25519Backend;
use chio_mcp_remote::root_exchange::kinds::operator_key::{
    OperatorRootRequest, OperatorRootRequestError, SignedOperatorRootRequest,
    MAX_OPERATOR_ROOT_REQUEST_BYTES,
};

use super::*;

pub(super) fn dispatch_root_request(command: McpRootRequestCommands) -> Result<(), CliError> {
    match command {
        McpRootRequestCommands::Sign { operator_seed_file } => {
            let signed = sign_root_request(&operator_seed_file, std::io::stdin().lock())?;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&signed)?;
            stdout.write_all(b"\n")?;
            Ok(())
        }
    }
}

/// Sign the operator root request JSON read from `input` with the seed at
/// `operator_seed_file`, returning the canonical JSON of the signed request.
/// The seed file must already exist with private custody; a request without
/// `tenant_value` refuses at parse, before any signing call.
fn sign_root_request(operator_seed_file: &Path, input: impl Read) -> Result<Vec<u8>, CliError> {
    let operator = Ed25519Backend::new(crate::load_existing_authority_keypair(operator_seed_file)?);
    let body = crate::input::read_stream(input, MAX_OPERATOR_ROOT_REQUEST_BYTES)?;
    let request = OperatorRootRequest::parse(&body).map_err(refused)?;
    SignedOperatorRootRequest::sign(request, &operator)
        .and_then(|signed| signed.to_canonical_json())
        .map_err(refused)
}

/// A request refusal under the registered cli-json code, with a fixed public
/// message and the typed refusal kept as the inspectable source.
fn refused(error: OperatorRootRequestError) -> CliError {
    let message = match &error {
        OperatorRootRequestError::Malformed(reason) => *reason,
        OperatorRootRequestError::MissingTenant => "operator root request names no tenant_value",
        OperatorRootRequestError::SignatureInvalid => {
            "operator root request signature does not verify"
        }
        OperatorRootRequestError::Canonicalization(_) => {
            "operator root request could not be canonicalized"
        }
    };
    CliError::with_public_source(
        &chio_errors::_generated::error_codes::CLI_JSON,
        message,
        error,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::error::Error as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use super::*;
    use chio_core::crypto::{Keypair, PublicKey};
    use chio_errors::_generated::error_codes::{CLI_IO, CLI_JSON};

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
        assert_eq!(request.tenant_value.as_str(), "acme");
        assert_eq!(request.expires_at, 1_792_234_920);
    }

    #[test]
    fn root_request_sign_without_tenant_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = seed_file(&dir, 0o600);
        let mut request: serde_json::Value = serde_json::from_str(REQUEST).unwrap();
        request.as_object_mut().unwrap().remove("tenant_value");
        let error =
            sign_root_request(&path, serde_json::to_vec(&request).unwrap().as_slice()).unwrap_err();
        let refusal = error
            .source()
            .and_then(|registered| registered.source())
            .and_then(|source| source.downcast_ref::<OperatorRootRequestError>());
        assert_eq!(refusal, Some(&OperatorRootRequestError::MissingTenant));
        assert_eq!(error.report().code, CLI_JSON.urn);
    }

    #[test]
    fn seed_file_group_readable_refuses() {
        for mode in [0o640, 0o604] {
            let dir = tempfile::tempdir().unwrap();
            let (path, _) = seed_file(&dir, mode);
            let error = sign_root_request(&path, REQUEST.as_bytes()).unwrap_err();
            assert_eq!(error.report().code, CLI_IO.urn, "mode {mode:o}");
        }
    }
}
