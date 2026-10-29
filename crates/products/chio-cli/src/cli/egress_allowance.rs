//! The operator egress allowance file named by `--egress-allowance-file`.

use std::path::Path;
use std::sync::Arc;

use chio_egress_contract::EgressAllowanceSet;

use crate::CliError;

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
        let refusal = chio_egress_contract::PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
            cidr: "169.254.0.0/16".to_string(),
            reserved: "169.254.0.0/16".to_string(),
        };
        assert_eq!(
            error.to_string(),
            CliError::cli_other_error(refusal.to_string()).to_string()
        );
    }
}
