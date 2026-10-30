//! The operator egress allowance file named by `--egress-allowance-file`.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use chio_egress_contract::{EgressAllowanceSet, MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES};

use crate::CliError;

/// The empty allowance set: every private-network egress target is denied.
/// The single production source of an empty set.
pub(crate) fn none() -> Arc<EgressAllowanceSet> {
    Arc::new(EgressAllowanceSet::default())
}

/// Load the allowance file once. No file means no allowance.
pub(crate) fn load(path: Option<&Path>) -> Result<Arc<EgressAllowanceSet>, CliError> {
    match path {
        None => Ok(none()),
        Some(path) => {
            let text = read(path)?;
            EgressAllowanceSet::from_toml_str(&text)
                .map(Arc::new)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "egress allowance file {} is refused: {error}",
                        path.display()
                    ))
                })
        }
    }
}

fn read(path: &Path) -> Result<String, CliError> {
    let unreadable = |reason: String| {
        CliError::cli_other_error(format!(
            "egress allowance file {} cannot be read: {reason}",
            path.display()
        ))
    };
    let file = File::open(path).map_err(|error| unreadable(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| unreadable(error.to_string()))?;
    if !metadata.is_file() {
        return Err(unreadable("not a regular file".to_string()));
    }
    let ceiling = u64::try_from(MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(ceiling.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(error.to_string()))?;
    if bytes.len() > MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES {
        return Err(unreadable(format!(
            "file exceeds {MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES} bytes"
        )));
    }
    String::from_utf8(bytes).map_err(|_| unreadable("file is not UTF-8".to_string()))
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
            CliError::cli_other_error(format!(
                "egress allowance file {} is refused: {refusal}",
                path.display()
            ))
            .to_string()
        );
    }

    #[test]
    fn a_directory_a_missing_file_and_non_utf8_text_are_unreadable() {
        let directory = tempfile::tempdir().expect("dir");
        for (path, reason) in [
            (directory.path().to_path_buf(), "not a regular file"),
            (directory.path().join("absent.toml"), "No such file"),
        ] {
            let error = load(Some(&path)).expect_err("unreadable").to_string();
            assert!(error.contains("cannot be read"), "{error}");
            assert!(error.contains(reason), "{error}");
        }
        let binary = directory.path().join("binary.toml");
        std::fs::write(&binary, [0xff, 0xfe, b'\n']).expect("write");
        let error = load(Some(&binary)).expect_err("not UTF-8").to_string();
        assert!(error.contains("file is not UTF-8"), "{error}");
    }

    #[test]
    fn a_file_over_the_ceiling_is_unreadable() {
        let directory = tempfile::tempdir().expect("dir");
        let path = directory.path().join("big.toml");
        std::fs::write(&path, vec![b'\n'; MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES + 1]).expect("write");
        let error = load(Some(&path)).expect_err("too large").to_string();
        assert!(error.contains("exceeds"), "{error}");
    }
}
