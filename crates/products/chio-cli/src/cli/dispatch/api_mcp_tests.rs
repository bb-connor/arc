use super::*;
use crate::cli_entrypoint_support::parse_cli;

fn authority_key() -> String {
    chio_core::crypto::Keypair::generate().public_key().to_hex()
}

fn serve_http_start(global: &[&str]) -> Result<(), CliError> {
    let mut argv = vec!["chio"];
    argv.extend_from_slice(global);
    argv.extend([
        "mcp",
        "serve-http",
        "--policy",
        "/nonexistent/policy.yaml",
        "--server-id",
        "edge",
        "--cage-policy",
        "/nonexistent/cage.json",
        "--cage-policy-signer",
        "signer",
        "--allow-plaintext",
        "--",
        "/bin/true",
    ]);
    let cli = parse_cli(argv).expect("serve-http argv parses");
    let Commands::Mcp { command } = cli.command else {
        panic!("expected chio mcp");
    };
    dispatch_mcp(
        command,
        cli.receipt_db,
        cli.revocation_db,
        cli.authority_seed_file,
        cli.authority_db,
        cli.budget_db,
        cli.session_db,
        cli.control_url,
        cli.control_internal_url,
        cli.control_token,
        cli.control_authority_public_key,
        cli.control_authority_trusted_public_keys,
    )
}

fn refusal(global: &[&str]) -> String {
    match serve_http_start(global) {
        Ok(()) => panic!("serve-http started with {global:?}"),
        Err(CliError::Chio(error)) => error.message().to_string(),
        Err(error) => panic!("serve-http refused {global:?} outside the registry: {error}"),
    }
}

#[test]
fn control_url_refuses_serve_http_start() {
    assert_eq!(
        refusal(&["--control-url", "https://control.example"]),
        "serve-http keeps every store in --state-dir; --control-url is not accepted"
    );
}

#[test]
fn control_token_refuses_serve_http_start() {
    assert_eq!(
        refusal(&["--control-token", "control-secret"]),
        "serve-http keeps every store in --state-dir; --control-token is not accepted"
    );
}

#[test]
fn control_internal_url_refuses_serve_http_start() {
    assert_eq!(
        refusal(&["--control-internal-url", "https://control-internal.example"]),
        "serve-http keeps every store in --state-dir; --control-internal-url is not accepted"
    );
}

#[test]
fn control_authority_key_pins_refuse_serve_http_start() {
    let key = authority_key();
    assert_eq!(
        refusal(&["--control-authority-public-key", &key]),
        "serve-http keeps every store in --state-dir; --control-authority-public-key is not accepted"
    );
    assert_eq!(
        refusal(&["--control-authority-trusted-public-keys", &key]),
        "serve-http keeps every store in --state-dir; --control-authority-trusted-public-keys is not accepted"
    );
}

#[test]
fn control_url_refusal_names_the_first_remote_flag() {
    assert_eq!(
        refusal(&[
            "--control-token",
            "control-secret",
            "--control-url",
            "https://control.example",
        ]),
        "serve-http keeps every store in --state-dir; --control-url is not accepted"
    );
}

#[test]
fn serve_http_has_no_remote_authority_workload_token_flag() {
    let error = match parse_cli([
        "chio",
        "mcp",
        "serve-http",
        "--policy",
        "policy.yaml",
        "--server-id",
        "edge",
        "--cage-policy",
        "cage.json",
        "--cage-policy-signer",
        "signer",
        "--remote-authority-workload-token",
        "workload-secret",
        "--",
        "/bin/true",
    ]) {
        Ok(_) => panic!("serve-http accepted --remote-authority-workload-token"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}
