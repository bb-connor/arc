use std::str::FromStr;

use arc_core::PublicKey;
use arc_did::{DidArc, DidService, ResolveOptions};

use crate::CliError;

fn resolve_identifier(did: Option<&str>, public_key: Option<&str>) -> Result<DidArc, CliError> {
    match (did, public_key) {
        (Some(value), None) => {
            DidArc::from_str(value).map_err(|error| CliError::Other(error.to_string()))
        }
        (None, Some(value)) => PublicKey::from_hex(value)
            .map(DidArc::from_public_key)
            .map_err(CliError::from),
        (Some(_), Some(_)) => Err(CliError::Other(
            "provide either --did or --public-key, not both".to_string(),
        )),
        (None, None) => Err(CliError::Other(
            "provide either --did or --public-key".to_string(),
        )),
    }
}

pub(crate) fn cmd_did_resolve(
    did: Option<&str>,
    public_key: Option<&str>,
    receipt_log_urls: &[String],
    passport_status_urls: &[String],
    _json_output: bool,
) -> Result<(), CliError> {
    let did = resolve_identifier(did, public_key)?;
    let mut options = ResolveOptions::default();
    for (index, url) in receipt_log_urls.iter().enumerate() {
        options = options.with_service(
            DidService::receipt_log(&did, index, url)
                .map_err(|error| CliError::Other(error.to_string()))?,
        );
    }
    for (index, url) in passport_status_urls.iter().enumerate() {
        options = options.with_service(
            DidService::passport_status(&did, index, url)
                .map_err(|error| CliError::Other(error.to_string()))?,
        );
    }
    let document = did.resolve_with_options(&options);
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_identifier_requires_exactly_one_source() {
        assert!(resolve_identifier(None, None).is_err());
        assert!(resolve_identifier(
            Some("did:arc:d04ab232742bb4ab3a1368bd4615fa0ee602dfd08f52a2408e8dc3f92f2aee72"),
            Some("d04ab232742bb4ab3a1368bd4615fa0ee602dfd08f52a2408e8dc3f92f2aee72")
        )
        .is_err());
    }
}
