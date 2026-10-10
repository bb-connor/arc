//! Entry points for the fuzz targets, compiled only with the `fuzz` feature.

use crate::peers::{PeersLock, SUPPORTED_LANGUAGES};

/// Decode a `peers.lock.toml` image, validate it and run every read-only
/// query over it. Any input must return rather than panic; the lockfile
/// gates which release artifacts `fetch-peers` downloads.
pub fn peers_lock_decode(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(lock) = PeersLock::parse_str(text) else {
        return;
    };
    let _ = lock.validate();
    for language in SUPPORTED_LANGUAGES {
        let entries = lock.entries_for_language(language);
        let _ = PeersLock::partition_by_published(&entries);
        for entry in &entries {
            let _ = lock.entries_for(language, &entry.target);
        }
    }
}
