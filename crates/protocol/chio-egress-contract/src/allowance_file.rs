//! The operator egress allowance file.
//!
//! The file is TOML with one `[[allow]]` table per allowance, each naming
//! `host`, `port` and `cidr`. Unknown keys are refused, and every entry passes
//! the same validation as [`EgressAllowanceSet::new`].

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::allowance::{EgressAllowanceSet, PrivateNetworkAllowance, PrivateNetworkAllowanceError};

/// Largest allowance file [`EgressAllowanceSet::load_file`] reads.
pub const MAX_EGRESS_ALLOWANCE_FILE_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowanceDocument {
    allow: Vec<AllowanceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowanceEntry {
    host: String,
    port: u16,
    cidr: String,
}

impl EgressAllowanceSet {
    /// Read and validate the allowance file at `path`. The file must be a
    /// regular file of at most [`MAX_EGRESS_ALLOWANCE_FILE_BYTES`] bytes.
    pub fn load_file(path: &Path) -> Result<Self, PrivateNetworkAllowanceError> {
        let unreadable = |reason: String| PrivateNetworkAllowanceError::FileUnreadable {
            path: path.display().to_string(),
            reason,
        };
        let file = File::open(path).map_err(|error| unreadable(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| unreadable(error.to_string()))?;
        if !metadata.is_file() {
            return Err(unreadable("not a regular file".to_string()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_EGRESS_ALLOWANCE_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| unreadable(error.to_string()))?;
        if u64::try_from(bytes.len())
            .map_or(true, |length| length > MAX_EGRESS_ALLOWANCE_FILE_BYTES)
        {
            return Err(PrivateNetworkAllowanceError::FileTooLarge {
                path: path.display().to_string(),
                max_bytes: MAX_EGRESS_ALLOWANCE_FILE_BYTES,
            });
        }
        let text =
            String::from_utf8(bytes).map_err(|_| unreadable("file is not UTF-8".to_string()))?;
        parse(&text, path)
    }
}

fn parse(text: &str, path: &Path) -> Result<EgressAllowanceSet, PrivateNetworkAllowanceError> {
    let document: AllowanceDocument = toml::from_str(text).map_err(|error: toml::de::Error| {
        PrivateNetworkAllowanceError::FileInvalid {
            path: path.display().to_string(),
            reason: error.message().to_string(),
        }
    })?;
    let entries = document
        .allow
        .into_iter()
        .map(|entry| {
            Ok(PrivateNetworkAllowance {
                host: entry.host,
                port: entry.port,
                cidr: entry.cidr.parse()?,
            })
        })
        .collect::<Result<Vec<_>, PrivateNetworkAllowanceError>>()?;
    EgressAllowanceSet::new(entries)
}
