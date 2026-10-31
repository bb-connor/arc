//! `chio trust emergency`: the operator stop on a trust-control node.

use chio_kernel::stop::{
    ResumeRequestBody, StopEpochId, StopReadiness, StopRequestBody, StopStatus,
};
use zeroize::Zeroizing;

use super::*;

const CONTROL_TOKEN_ENV: &str = "CHIO_CONTROL_TOKEN";
const MAX_TOKEN_FILE_BYTES: usize = 4096;

pub(crate) fn cmd_trust_emergency(
    command: TrustEmergencyCommands,
    token_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let url = control_url.ok_or_else(|| {
        CliError::cli_other_error("chio trust emergency requires --control-url".to_string())
    })?;
    let token = admin_token(token_file, control_token)?;
    let client = trust_control::service_runtime::client::build_client(url, &token)?;
    let status = match command {
        TrustEmergencyCommands::Stop {
            reason,
            no_containment,
        } => client.emergency_stop(&StopRequestBody {
            reason,
            allow_containment: !no_containment,
        })?,
        TrustEmergencyCommands::Resume {
            expected_generation,
            expected_epoch,
        } => client.emergency_resume(&ResumeRequestBody {
            expected_epoch: StopEpochId {
                chain_generation: expected_generation,
                epoch: expected_epoch,
            },
        })?,
        TrustEmergencyCommands::Status => client.emergency_status()?,
    };
    print_status(&status, json_output)
}

/// The admin token from exactly one of `--token-file` or `CHIO_CONTROL_TOKEN`.
/// A token on the command line is visible to every local user, so a
/// `--control-token` value that did not come from the environment refuses.
fn admin_token(
    token_file: Option<&Path>,
    control_token: Option<&str>,
) -> Result<Zeroizing<String>, CliError> {
    let from_env = std::env::var(CONTROL_TOKEN_ENV).ok().map(Zeroizing::new);
    if let Some(token) = control_token {
        if from_env.as_deref().map(String::as_str) != Some(token) {
            return Err(CliError::cli_other_error(format!(
                "chio trust emergency reads the admin token from {CONTROL_TOKEN_ENV} or --token-file, never --control-token"
            )));
        }
    }
    match (token_file, from_env) {
        (Some(_), Some(_)) => Err(CliError::cli_other_error(format!(
            "chio trust emergency takes the admin token from one of {CONTROL_TOKEN_ENV} or --token-file, not both"
        ))),
        (Some(path), None) => read_token_file(path),
        (None, Some(token)) if !token.is_empty() => Ok(token),
        (None, _) => Err(CliError::cli_other_error(format!(
            "chio trust emergency requires an admin token in {CONTROL_TOKEN_ENV} or --token-file"
        ))),
    }
}

/// The token file is custody: a singly linked regular file owned by this user
/// with mode 0600 or stricter, opened without following links.
fn read_token_file(path: &Path) -> Result<Zeroizing<String>, CliError> {
    let bytes = chio_secure_ipc::seed_custody::read_private_file(path, MAX_TOKEN_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::cli_other_error("admin token file is not UTF-8".to_string()))?;
    let token = text.trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.contains(char::is_whitespace) {
        return Err(CliError::cli_other_error(
            "admin token file must hold one token without whitespace".to_string(),
        ));
    }
    Ok(Zeroizing::new(token.to_string()))
}

fn print_status(status: &StopStatus, json_output: bool) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(status)?);
        return Ok(());
    }
    println!("stopped:     {}", status.stopped);
    println!("durability:  {}", status.durability);
    match &status.readiness {
        StopReadiness::Ready => println!("readiness:   ready"),
        StopReadiness::ReadyStopped => println!("readiness:   ready_stopped"),
        StopReadiness::NotReady { reason } => println!("readiness:   not_ready ({reason})"),
    }
    if let Some(head) = &status.head {
        println!(
            "head:        generation {} epoch {}",
            head.chain_generation, head.epoch
        );
    }
    if let Some(withheld) = status.withheld_operations {
        println!("withheld:    {withheld}");
    }
    Ok(())
}
