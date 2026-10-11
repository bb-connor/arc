//! Bounds apply before projection or signature verification. Hashes use original bytes.
use crate::ProofRoomError;
use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;
use std::{io::Read, path::Path};

pub(crate) const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_BUNDLE_FILES: usize = 4096;
pub(crate) const MAX_BUNDLE_DEPTH: usize = 64;
pub(crate) const MAX_BUNDLE_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProofRoomError> {
    Ok(UntrustedJsonText::from_wire(bytes, MAX_ARTIFACT_BYTES)?.decode_signed()?)
}

pub(crate) fn text<T: DeserializeOwned>(text: &str) -> Result<T, ProofRoomError> {
    decode(text.as_bytes())
}

pub(crate) fn project<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, ProofRoomError> {
    serde_json::from_value(value).map_err(|error| UntrustedJsonError::Decode(error).into())
}

pub(crate) fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, ProofRoomError> {
    read_inner(path.as_ref(), MAX_ARTIFACT_BYTES).map_err(|source| ProofRoomError::Io {
        context: "proof-room.input.read",
        source,
    })
}
fn read_inner(path: &Path, bound: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("artifact must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(std::io::Error::other(UntrustedJsonError::TooLarge {
            bytes: bytes.len(),
            bound,
        }));
    }
    Ok(bytes)
}

pub(crate) async fn read_async(path: impl AsRef<Path>) -> Result<Vec<u8>, ProofRoomError> {
    let path = path.as_ref().to_owned();
    tokio::task::spawn_blocking(move || read(path)).await?
}

/// Bind the single outstanding JSON-RPC response before using its result as evidence.
pub(crate) fn rpc_result(bytes: &[u8]) -> Result<serde_json::Value, ProofRoomError> {
    let body: serde_json::Value = decode(bytes)?;
    if body.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0")
        || body.get("id").and_then(serde_json::Value::as_u64) != Some(1)
        || body.get("error").is_some()
    {
        return Err("proof-room.rpc.response-binding-mismatch".into());
    }
    body.get("result")
        .cloned()
        .ok_or_else(|| "proof-room.rpc.result-missing".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn original_proof_json_keeps_typed_private_cause() {
        let error =
            decode::<serde_json::Value>(br#"{"proof":{"private-marker":1,"private-marker":2}}"#)
                .unwrap_err();
        assert!(matches!(error, ProofRoomError::Input(_)));
        assert!(error.source().unwrap().source().is_some());
        assert!(!format!("{error} {error:?}").contains("private-marker"));
    }

    #[test]
    fn artifact_read_is_bounded_before_json_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("huge.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES as u64 + 1)
            .unwrap();
        let error = read(&path).unwrap_err();
        let ProofRoomError::Io { source, .. } = error else {
            panic!("expected retained IO source")
        };
        assert!(matches!(
            source
                .get_ref()
                .unwrap()
                .downcast_ref::<UntrustedJsonError>(),
            Some(UntrustedJsonError::TooLarge { .. })
        ));
        assert!(read(directory.path()).is_err());
    }

    #[test]
    fn settlement_rpc_result_requires_protocol_id_and_unique_fields() {
        assert_eq!(
            rpc_result(br#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#).unwrap(),
            "0x1"
        );
        for bytes in [
            br#"{"jsonrpc":"2.0","id":2,"result":"0x1"}"#.as_slice(),
            br#"{"id":1,"result":"0x1"}"#,
            br#"{"jsonrpc":"2.0","id":1,"error":null,"result":"0x1"}"#,
            br#"{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0x2"}"#,
        ] {
            assert!(rpc_result(bytes).is_err());
        }
    }
}

/// A collector charges every visited entry before work and actual bytes before retention.
pub(crate) struct ArtifactBudget {
    entries: usize,
    bytes: usize,
}
impl Default for ArtifactBudget {
    fn default() -> Self {
        Self {
            entries: MAX_BUNDLE_FILES,
            bytes: MAX_BUNDLE_BYTES as usize,
        }
    }
}
impl ArtifactBudget {
    pub(crate) fn entry(&mut self, depth: usize) -> Result<(), ProofRoomError> {
        if depth > MAX_BUNDLE_DEPTH {
            return Err("proof-room.bundle.depth-limit".into());
        }
        self.entries = self
            .entries
            .checked_sub(1)
            .ok_or("proof-room.bundle.file-limit")?;
        Ok(())
    }
    pub(crate) fn charge(&mut self, count: usize) -> Result<(), ProofRoomError> {
        self.bytes = self
            .bytes
            .checked_sub(count)
            .ok_or("proof-room.bundle.byte-limit")?;
        Ok(())
    }
    pub(crate) fn read(&mut self, path: &Path) -> Result<Vec<u8>, ProofRoomError> {
        let bytes = read_inner(path, self.bytes.min(MAX_ARTIFACT_BYTES)).map_err(|source| {
            ProofRoomError::Io {
                context: "proof-room.input.read",
                source,
            }
        })?;
        self.charge(bytes.len())?;
        Ok(bytes)
    }
}

pub(crate) fn validate_upload_paths(parts: &[(String, Vec<u8>)]) -> Result<(), ProofRoomError> {
    use std::collections::BTreeSet;
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for (relative, bytes) in parts {
        crate::validate_bundle_relative_path(relative)?;
        if relative.len() > 4096 || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err("proof-room.upload.artifact-limit".into());
        }
        let path = Path::new(relative);
        if path.components().count() > MAX_BUNDLE_DEPTH + 1 {
            return Err("proof-room.bundle.depth-limit".into());
        }
        if directories.contains(path) || !files.insert(path.to_owned()) {
            return Err("proof-room.upload.path-conflict".into());
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            if files.contains(parent) {
                return Err("proof-room.upload.path-conflict".into());
            }
            directories.insert(parent.to_owned());
            if files.len() + directories.len() > MAX_BUNDLE_FILES {
                return Err("proof-room.bundle.file-limit".into());
            }
        }
        if files.len() + directories.len() > MAX_BUNDLE_FILES {
            return Err("proof-room.bundle.file-limit".into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod budget_tests {
    use super::*;
    #[test]
    fn upload_tree_amplification_is_rejected_before_any_path_is_created() {
        let deep = format!("{}x.json", "x/".repeat(MAX_BUNDLE_DEPTH + 1));
        assert!(
            matches!(validate_upload_paths(&[(deep, vec![])]), Err(ProofRoomError::Validation(code)) if code == "proof-room.bundle.depth-limit")
        );
        let paths: Vec<_> = (0..100)
            .map(|i| (format!("{i}/{}x.json", "x/".repeat(50)), vec![]))
            .collect();
        assert!(
            matches!(validate_upload_paths(&paths), Err(ProofRoomError::Validation(code)) if code == "proof-room.bundle.file-limit")
        );
        assert!(
            matches!(validate_upload_paths(&[("a".into(), vec![]), ("a/b".into(), vec![])]), Err(ProofRoomError::Validation(code)) if code == "proof-room.upload.path-conflict")
        );
    }
    #[test]
    fn collectors_charge_actual_bytes_and_cumulative_entries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("growing.json");
        std::fs::write(&path, b"123").unwrap();
        let mut budget = ArtifactBudget {
            entries: 1,
            bytes: 2,
        };
        assert!(matches!(budget.read(&path), Err(ProofRoomError::Io { .. })));
        assert_eq!(budget.bytes, 2);
        budget.entry(0).unwrap();
        assert!(
            matches!(budget.entry(0), Err(ProofRoomError::Validation(code)) if code == "proof-room.bundle.file-limit")
        );
    }
}
