//! The operator egress allowance file named by `--egress-allowance-file`.

use std::path::Path;
use std::sync::Arc;

use chio_egress_contract::EgressAllowanceSet;

use crate::{
    ApiCommands, CliError, Commands, FindingCommands, FindingOperatorCommands, McpCommands,
    TrustCommands, TrustConfigCommands,
};

const CONSUMING_COMMANDS: &str =
    "trust serve, trust config check, start, api protect, mcp wrap and finding operator serve";

/// `--egress-allowance-file` named on a command that does not thread the
/// allowance set into the egress contracts it dials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "--egress-allowance-file is refused: this command does not consume the egress allowance \
     set; it is accepted only by {}",
    CONSUMING_COMMANDS
)]
pub(crate) struct EgressAllowanceFlagRefused;

/// The commands that consume the allowance set.
fn consumes_egress_allowances(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Trust {
            command: TrustCommands::Serve { .. }
                | TrustCommands::Config {
                    command: TrustConfigCommands::Check { .. },
                },
        } | Commands::Start { .. }
            | Commands::Api {
                command: ApiCommands::Protect { .. },
            }
            | Commands::Mcp {
                command: McpCommands::Wrap(_),
            }
            | Commands::Finding {
                command: FindingCommands::Operator {
                    command: FindingOperatorCommands::Serve { .. },
                },
            }
    )
}

/// Refuse the flag on every command outside the consuming set.
pub(crate) fn refuse_unconsumed(
    command: &Commands,
    path: Option<&Path>,
) -> Result<(), EgressAllowanceFlagRefused> {
    if path.is_some() && !consumes_egress_allowances(command) {
        return Err(EgressAllowanceFlagRefused);
    }
    Ok(())
}

/// Load the allowance file once. No file means no allowance.
pub(crate) fn load(path: Option<&Path>) -> Result<Arc<EgressAllowanceSet>, CliError> {
    match path {
        None => Ok(Arc::new(EgressAllowanceSet::default())),
        Some(path) => EgressAllowanceSet::load_file(path)
            .map(Arc::new)
            .map_err(|error| CliError::cli_other_error(error.to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::error::Error;

    use chio_egress_contract::HttpEgressError;

    use super::*;

    const TOKEN: &str = "egress-allowance-token";

    fn egress_refusal(error: &CliError) -> Option<HttpEgressError> {
        let mut current: Option<&(dyn Error + 'static)> = Some(error);
        while let Some(cause) = current {
            if let Some(refusal) = cause.downcast_ref::<HttpEgressError>() {
                return Some(refusal.clone());
            }
            current = cause.source();
        }
        None
    }

    /// A loopback port with no listener, so a dial is refused at once.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("address").port()
    }

    fn revoke_and_status(control_url: &str, egress: &EgressAllowanceSet) -> [CliError; 2] {
        [
            crate::cmd_trust_revoke("cap-1", false, None, Some(control_url), Some(TOKEN), egress)
                .expect_err("no control plane answers"),
            crate::cmd_trust_status("cap-1", false, None, Some(control_url), Some(TOKEN), egress)
                .expect_err("no control plane answers"),
        ]
    }

    #[test]
    fn trust_commands_dial_under_the_loaded_allowance_file() {
        let directory = tempfile::tempdir().expect("dir");
        let port = closed_port();
        let path = directory.path().join("egress.toml");
        std::fs::write(
            &path,
            format!("[[allow]]\nhost = \"localhost\"\nport = {port}\ncidr = \"10.20.0.0/24\"\n"),
        )
        .expect("write");
        let control_url = format!("https://localhost:{port}");

        let listed = load(Some(&path)).expect("valid allowance file");
        for error in revoke_and_status(&control_url, &listed) {
            assert!(
                matches!(
                    egress_refusal(&error),
                    Some(HttpEgressError::PrivateNetworkAllowanceMismatch { ref host, port: pinned, address })
                        if host == "localhost" && pinned == port && address.is_loopback()
                ),
                "{error}"
            );
        }

        let unlisted = load(None).expect("no file");
        for error in revoke_and_status(&control_url, &unlisted) {
            assert_eq!(egress_refusal(&error), None, "{error}");
        }
    }

    #[test]
    fn a_private_control_url_outside_the_file_is_refused_before_dialing() {
        let unlisted = load(None).expect("no file");
        for error in revoke_and_status("https://10.20.0.5:8443", &unlisted) {
            assert_eq!(
                egress_refusal(&error),
                Some(HttpEgressError::PrivateNetworkDenied {
                    host: "10.20.0.5".to_string()
                }),
                "{error}"
            );
        }
    }

    #[test]
    fn absent_file_means_no_allowance() {
        assert!(load(None).expect("no file").entries().is_empty());
    }

    #[test]
    fn refused_file_stops_the_cli_with_the_loader_reason() {
        let directory = tempfile::tempdir().expect("dir");
        let path = directory.path().join("egress.toml");
        std::fs::write(
            &path,
            "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"169.254.0.0/16\"\n",
        )
        .expect("write");
        let error = load(Some(&path)).expect_err("reserved CIDR is refused");
        let refusal =
            chio_egress_contract::PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
                cidr: "169.254.0.0/16".to_string(),
                reserved: "169.254.0.0/16".to_string(),
            };
        assert_eq!(
            error.to_string(),
            CliError::cli_other_error(refusal.to_string()).to_string()
        );
    }
}
