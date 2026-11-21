//! The operator egress allowance file named by `--egress-allowance-file`.

use std::path::Path;
use std::sync::Arc;

use chio_egress_contract::{EgressAllowanceSet, MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES};
use chio_secure_ipc::regular_file::{read_regular_file, OpenPolicy, RegularFileError};

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
            let bytes = read(path).map_err(|error| {
                CliError::cli_other_error(format!(
                    "egress allowance file {} cannot be read: {error}",
                    path.display()
                ))
            })?;
            EgressAllowanceSet::from_toml_bytes(&bytes)
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

fn read(path: &Path) -> Result<Vec<u8>, RegularFileError> {
    read_regular_file(
        path,
        MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES,
        OpenPolicy::Trusted,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::error::Error;

    use chio_egress_contract::HttpEgressError;
    use chio_test_support::write_file_with_mode;

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
        write_file_with_mode(
            &path,
            format!("[[allow]]\nhost = \"localhost\"\nport = {port}\ncidr = \"10.20.0.0/24\"\n"),
            0o600,
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
        write_file_with_mode(
            &path,
            "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"169.254.0.0/16\"\n",
            0o600,
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
    fn an_unreadable_path_is_refused_with_its_reader_variant() {
        let directory = tempfile::tempdir().expect("dir");
        assert_eq!(read(directory.path()), Err(RegularFileError::NotRegular));
        assert_eq!(
            read(&directory.path().join("absent.toml")),
            Err(RegularFileError::Missing)
        );
        let path = directory.path().join("absent.toml");
        assert!(load(Some(&path))
            .expect_err("missing")
            .to_string()
            .contains("cannot be read"));
    }

    #[test]
    fn a_symlinked_or_group_writable_file_is_refused_before_parsing() {
        let directory = tempfile::tempdir().expect("dir");
        let target = directory.path().join("egress.toml");
        write_file_with_mode(&target, "allow = []\n", 0o600).expect("write");
        let link = directory.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(read(&link), Err(RegularFileError::SymbolicLink));

        write_file_with_mode(&target, "allow = []\n", 0o664).expect("write");
        assert!(matches!(
            read(&target),
            Err(RegularFileError::Writable { mode }) if mode & 0o777 == 0o664
        ));
    }

    #[test]
    fn a_file_over_the_ceiling_is_refused_as_too_large() {
        let directory = tempfile::tempdir().expect("dir");
        let path = directory.path().join("big.toml");
        write_file_with_mode(
            &path,
            vec![b'\n'; MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES + 1],
            0o600,
        )
        .expect("write");
        assert_eq!(
            read(&path),
            Err(RegularFileError::TooLarge {
                max_bytes: MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES
            })
        );
    }
}
