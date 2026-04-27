//! Peer-binary discovery and lockfile parsing.
//!
//! External implementers cannot rely on having Python, Node.js, Go, or C++
//! toolchains available locally to build the conformance peer adapters. The
//! `chio conformance fetch-peers` subcommand downloads pre-built binaries
//! whose URLs and integrity digests are pinned in
//! `crates/chio-conformance/peers.lock.toml`.
//!
//! This module owns the parsing and validation of that lockfile. Actual
//! download / extraction lives in the CLI handler so that this crate stays
//! free of network code paths during unit tests.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Schema identifier for the v1 peers lockfile.
pub const PEERS_LOCK_SCHEMA: &str = "chio.conformance.peers/v1";

/// Recognised peer-language identifiers. New languages must be added here
/// and to the conformance harness in lock-step.
pub const SUPPORTED_LANGUAGES: &[&str] = &["python", "js", "go", "cpp"];

/// Parsed representation of `peers.lock.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct PeersLock {
    /// Schema discriminator. MUST equal `chio.conformance.peers/v1`.
    pub schema: String,
    /// Pinned peer-binary entries.
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerEntry>,
}

/// A single pinned peer-binary release artifact.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerEntry {
    /// Language adapter identifier (one of `SUPPORTED_LANGUAGES`).
    pub language: String,
    /// Fully-qualified https URL of the release artifact.
    pub url: String,
    /// 64-character lowercase hex sha256 of the artifact bytes.
    pub sha256: String,
    /// Rust target triple the binary was built for.
    pub target: String,
    /// Executable name inside the archive.
    pub binary: String,
}

/// Errors surfaced when loading or validating `peers.lock.toml`.
#[derive(Debug, thiserror::Error)]
pub enum PeersLockError {
    /// Filesystem failure reading the lockfile.
    #[error("i/o error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Lockfile bytes are not valid TOML matching the v1 schema.
    #[error("toml parse error in {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// Lockfile parsed but failed schema validation (see `PeersLock::validate`).
    #[error("invalid peers.lock.toml: {0}")]
    Validation(String),
}

impl PeersLock {
    /// Parse `peers.lock.toml` from disk. Does NOT validate; call
    /// `PeersLock::validate` after loading to enforce schema invariants.
    pub fn load(path: &Path) -> Result<Self, PeersLockError> {
        let bytes = fs::read_to_string(path).map_err(|source| PeersLockError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_str(&bytes).map_err(|source| match source {
            PeersLockError::Toml { source, .. } => PeersLockError::Toml {
                path: path.to_path_buf(),
                source,
            },
            other => other,
        })
    }

    /// Parse `peers.lock.toml` from an in-memory string. Named `parse_str`
    /// rather than `from_str` to avoid colliding with `std::str::FromStr`.
    pub fn parse_str(content: &str) -> Result<Self, PeersLockError> {
        toml::from_str::<PeersLock>(content).map_err(|source| PeersLockError::Toml {
            path: PathBuf::from("<memory>"),
            source,
        })
    }

    /// Validate the parsed lockfile:
    /// - schema MUST equal `chio.conformance.peers/v1`,
    /// - every `url` MUST be https,
    /// - every `sha256` MUST be 64 chars of lowercase hex,
    /// - every `language` MUST appear in `SUPPORTED_LANGUAGES`,
    /// - `target` and `binary` MUST be non-empty.
    pub fn validate(&self) -> Result<(), PeersLockError> {
        if self.schema != PEERS_LOCK_SCHEMA {
            return Err(PeersLockError::Validation(format!(
                "unexpected schema `{}`, expected `{}`",
                self.schema, PEERS_LOCK_SCHEMA
            )));
        }
        if self.peers.is_empty() {
            return Err(PeersLockError::Validation(
                "lockfile has no [[peer]] entries".to_string(),
            ));
        }
        for (idx, entry) in self.peers.iter().enumerate() {
            entry
                .validate()
                .map_err(|message| PeersLockError::Validation(format!("peer[{idx}]: {message}")))?;
        }
        Ok(())
    }

    /// Filter entries by language and target triple. Both filters are
    /// case-sensitive; pass an empty string to skip a filter.
    pub fn entries_for(&self, language: &str, target: &str) -> Vec<&PeerEntry> {
        self.peers
            .iter()
            .filter(|entry| language.is_empty() || entry.language == language)
            .filter(|entry| target.is_empty() || entry.target == target)
            .collect()
    }

    /// Filter entries by language only.
    pub fn entries_for_language(&self, language: &str) -> Vec<&PeerEntry> {
        self.entries_for(language, "")
    }
}

impl PeerEntry {
    fn validate(&self) -> Result<(), String> {
        if !SUPPORTED_LANGUAGES.contains(&self.language.as_str()) {
            return Err(format!(
                "unsupported language `{}`; expected one of {:?}",
                self.language, SUPPORTED_LANGUAGES,
            ));
        }
        if !self.url.starts_with("https://") {
            return Err(format!("url `{}` is not https", self.url));
        }
        if !is_lowercase_hex_64(&self.sha256) {
            return Err(format!(
                "sha256 `{}` is not 64 lowercase hex chars",
                self.sha256
            ));
        }
        if self.target.trim().is_empty() {
            return Err("target must be non-empty".to_string());
        }
        if self.binary.trim().is_empty() {
            return Err("binary must be non-empty".to_string());
        }
        Ok(())
    }
}

fn is_lowercase_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
}

/// Compute the lowercase hex sha256 digest of `bytes`. Used by the CLI
/// download path to verify integrity after fetching a release artifact.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest.iter() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema = "chio.conformance.peers/v1"

[[peer]]
language = "python"
url = "https://example.com/py.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
target = "x86_64-unknown-linux-gnu"
binary = "chio-py-peer"

[[peer]]
language = "js"
url = "https://example.com/js.tar.gz"
sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
target = "aarch64-apple-darwin"
binary = "chio-js-peer"
"#;

    #[test]
    fn parses_valid_lockfile() {
        let lock = PeersLock::parse_str(VALID).expect("parse valid lockfile");
        assert_eq!(lock.schema, PEERS_LOCK_SCHEMA);
        assert_eq!(lock.peers.len(), 2);
        lock.validate().expect("valid lockfile passes validation");
    }

    #[test]
    fn rejects_wrong_schema() {
        let bad = VALID.replace("chio.conformance.peers/v1", "chio.conformance.peers/v2");
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("wrong schema rejected");
        assert!(format!("{err}").contains("unexpected schema"));
    }

    #[test]
    fn rejects_non_https_url() {
        let bad = VALID.replace(
            "https://example.com/py.tar.gz",
            "http://example.com/py.tar.gz",
        );
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("http rejected");
        assert!(format!("{err}").contains("not https"));
    }

    #[test]
    fn rejects_short_sha256() {
        let bad = VALID.replace(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "deadbeef",
        );
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("short sha256 rejected");
        assert!(format!("{err}").contains("64 lowercase hex"));
    }

    #[test]
    fn rejects_uppercase_sha256() {
        let bad = VALID.replace(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("uppercase sha256 rejected");
        assert!(format!("{err}").contains("64 lowercase hex"));
    }

    #[test]
    fn rejects_unsupported_language() {
        let bad = VALID.replace(r#"language = "python""#, r#"language = "ruby""#);
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("ruby rejected");
        assert!(format!("{err}").contains("unsupported language"));
    }

    #[test]
    fn rejects_empty_peer_list() {
        let bad = "schema = \"chio.conformance.peers/v1\"\n";
        let lock = PeersLock::parse_str(bad).expect("still parses");
        let err = lock.validate().expect_err("empty list rejected");
        assert!(format!("{err}").contains("no [[peer]] entries"));
    }

    #[test]
    fn entries_for_filters_by_language_and_target() {
        let lock = PeersLock::parse_str(VALID).expect("parse");
        let py_only = lock.entries_for_language("python");
        assert_eq!(py_only.len(), 1);
        assert_eq!(py_only[0].language, "python");

        let py_linux = lock.entries_for("python", "x86_64-unknown-linux-gnu");
        assert_eq!(py_linux.len(), 1);

        let py_darwin = lock.entries_for("python", "aarch64-apple-darwin");
        assert!(py_darwin.is_empty());

        let all = lock.entries_for("", "");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn shipped_lockfile_validates() {
        // The lockfile shipped at crates/chio-conformance/peers.lock.toml is
        // the source of truth. This test prevents accidental schema drift.
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set during cargo test");
        let path = Path::new(&manifest_dir).join("peers.lock.toml");
        let lock = PeersLock::load(&path).expect("load shipped peers.lock.toml");
        lock.validate().expect("shipped lockfile validates");
        assert!(!lock.peers.is_empty());
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }
}
