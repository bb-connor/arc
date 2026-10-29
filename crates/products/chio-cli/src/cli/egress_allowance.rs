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
    use super::*;
    use crate::cli_entrypoint_support::parse_cli;

    fn refusal(args: &[&str]) -> Result<(), EgressAllowanceFlagRefused> {
        let argv = ["chio", "--egress-allowance-file", "egress.toml"]
            .into_iter()
            .chain(args.iter().copied());
        let cli = parse_cli(argv).expect("argv parses");
        refuse_unconsumed(&cli.command, cli.egress_allowance_file.as_deref())
    }

    #[test]
    fn consuming_commands_accept_the_flag() {
        for args in [
            &["trust", "serve", "--access-config", "access.toml"][..],
            &["trust", "config", "check", "--access-config", "access.toml"],
            &["start"],
            &["api", "protect", "--upstream", "http://127.0.0.1:9"],
            &["mcp", "wrap", "--server-id", "fs", "--", "true"],
            &["finding", "operator", "serve", "--profile", "profile.json"],
        ] {
            assert_eq!(refusal(args), Ok(()), "{args:?}");
        }
    }

    #[test]
    fn other_commands_refuse_the_flag() {
        for args in [
            &["run", "--policy", "policy.yaml", "--", "true"][..],
            &["trust", "revoke", "--capability-id", "cap-1"],
            &["trust", "status", "--capability-id", "cap-1"],
            &["finding", "operator", "tick", "--profile", "profile.json"],
            &[
                "mcp",
                "serve",
                "--policy",
                "policy.yaml",
                "--server-id",
                "fs",
                "--cage-policy",
                "cage.json",
                "--cage-policy-signer",
                "signer.pub",
                "--",
                "true",
            ],
            &[
                "trust",
                "config",
                "credential",
                "--deployment",
                "dep-a",
                "--secret-env",
                "CHIO_SECRET",
                "--id",
                "entry",
                "--role",
                "operator",
            ],
            &["init", "scaffold"],
        ] {
            assert_eq!(refusal(args), Err(EgressAllowanceFlagRefused), "{args:?}");
        }
    }

    #[test]
    fn without_the_flag_no_command_is_refused() {
        let cli = parse_cli(["chio", "trust", "status", "--capability-id", "cap-1"])
            .expect("argv parses");
        assert_eq!(refuse_unconsumed(&cli.command, None), Ok(()));
    }

    #[test]
    fn absent_file_means_no_allowance() {
        assert_eq!(*load(None).expect("no file"), EgressAllowanceSet::default());
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
