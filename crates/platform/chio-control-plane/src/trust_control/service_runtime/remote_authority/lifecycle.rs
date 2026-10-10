//! Admission never treats a stale status cache as live issuer authority.
use super::*;
use chio_kernel::authority::lifecycle::issuer_is_live;
use chio_kernel::KernelError;

pub(super) fn validate_status_lifecycle(status: &TrustAuthorityStatus) -> Result<(), CliError> {
    let Some(state) = &status.issuer_state else {
        return Ok(());
    };
    chio_kernel::authority::replication::validate_state(state)?;
    if status.public_key.as_deref() != Some(state.public_key_hex.as_str())
        || status.generation != Some(state.generation)
        || status.rotated_at != Some(state.rotated_at)
        || status.trusted_public_keys.iter().any(|public| {
            !state
                .trusted_keys
                .iter()
                .any(|key| &key.public_key_hex == public)
        })
    {
        return Err(CliError::cli_other_error(
            "authority status disagrees with its lifecycle state",
        ));
    }
    Ok(())
}

impl AuthorityKeyCache {
    pub(super) fn live_keys(&self, now: u64) -> Vec<PublicKey> {
        self.trusted
            .iter()
            .filter(|key| self.permits(key, None, now))
            .cloned()
            .collect()
    }

    fn permits(&self, issuer: &PublicKey, issued_at: Option<u64>, now: u64) -> bool {
        if !self.trusted.contains(issuer) {
            return false;
        }
        let Some(state) = &self.issuer_state else {
            // Older status protocols carry no historical-key deadlines. They
            // can establish the current issuer, never indefinite old-key trust.
            return self.current.as_ref() == Some(issuer);
        };
        state
            .trusted_keys
            .iter()
            .position(|key| key.public_key_hex == issuer.to_hex())
            .is_some_and(|index| matches!(issuer_is_live(state, index, issued_at, now), Ok(true)))
    }
}

impl RemoteCapabilityAuthority {
    pub(super) fn verify_live_issuer(
        &self,
        issuer: &PublicKey,
        issued_at: u64,
        now: u64,
    ) -> Result<(), KernelError> {
        let observed = self.clock.unix_millis()?.as_secs();
        // Retirement must be observed at fresh admission, including when a
        // diagnostic cache entry has not reached its refresh interval yet.
        self.refresh_status().map_err(|error| {
            KernelError::CapabilityIssuanceFailed(format!(
                "failed to refresh remote issuer lifecycle: {error}"
            ))
        })?;
        let cache = self.cache.lock().map_err(|_| {
            KernelError::CapabilityIssuanceFailed(
                "remote issuer lifecycle cache is unavailable".into(),
            )
        })?;
        // Refresh and cache contention can cross a retirement deadline. Sample
        // under the final cache lock, retaining every earlier time floor.
        let after_refresh = self.clock.unix_millis()?.as_secs();
        if cache.permits(
            issuer,
            Some(issued_at),
            now.max(observed).max(after_refresh),
        ) {
            Ok(())
        } else {
            Err(KernelError::UntrustedIssuer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::CapabilityAuthority;
    use chio_security_types::clock::FixedClock;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn kg2_remote_projection_enforces_issuance_cutoff_and_exact_deadline() -> TestResult {
        let root = chio_test_support::private_tempdir()?;
        let source = SqliteCapabilityAuthority::open_with_clock(
            root.path().join("issuer.db"),
            Arc::new(FixedClock::new(100)),
        )?;
        let old = source.authority_public_key();
        let new = source.rotate_with_verification_deadline(110)?.public_key;
        let status = crate::trust_control::report_validation::authority_status_response(
            "sqlite".into(),
            source.status()?,
        );
        let cache = AuthorityKeyCache::from_status(&status)?;
        assert!(cache.permits(&old, Some(100), 109));
        assert!(!cache.permits(&old, Some(101), 109));
        assert!(!cache.permits(&old, Some(100), 110));
        assert_eq!(cache.live_keys(110), vec![new]);
        let mut missing = status.clone();
        missing.trusted_public_keys.clear();
        assert!(
            matches!(AuthorityKeyCache::from_status(&missing), Err(error) if error.to_string().contains("omits its current key"))
        );
        let mut inconsistent = status;
        inconsistent.generation = Some(9);
        assert!(
            matches!(AuthorityKeyCache::from_status(&inconsistent), Err(error) if error.to_string().contains("disagrees with its lifecycle state"))
        );
        Ok(())
    }

    #[test]
    fn kg2_remote_admission_refreshes_even_with_fresh_diagnostic_cache() -> TestResult {
        use std::io::{Read, Write};
        let root = chio_test_support::private_tempdir()?;
        let source = SqliteCapabilityAuthority::open_with_clock(
            root.path().join("issuer.db"),
            Arc::new(FixedClock::new(100)),
        )?;
        source.initialize_replication("remote-lifecycle")?;
        let old = source.authority_public_key();
        source.rotate_with_verification_deadline(110)?;
        let before = crate::trust_control::report_validation::authority_status_response(
            "sqlite".into(),
            source.status()?,
        );
        source.revoke_issuer(&old)?;
        let after = crate::trust_control::report_validation::authority_status_response(
            "sqlite".into(),
            source.status()?,
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let bodies = [serde_json::to_vec(&before)?, serde_json::to_vec(&after)?];
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            for body in bodies {
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                let mut request = [0; 4096];
                let _ = stream.read(&mut request)?;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
                stream.write_all(&body)?;
            }
            Ok(())
        });
        let remote = RemoteCapabilityAuthority {
            clock: Arc::new(FixedClock::new(100)),
            client: build_client(&endpoint, "test-only-control")?,
            cache: Mutex::new(AuthorityKeyCache::from_status(&before)?),
            refresh_lock: Mutex::new(()),
            pinned_current: None,
            pinned_trusted: Vec::new(),
        };
        remote.check_issuer_lifecycle(&old, 100, 100)?;
        assert!(matches!(
            remote.check_issuer_lifecycle(&old, 100, 100),
            Err(KernelError::UntrustedIssuer)
        ));
        assert!(!remote.trusted_public_keys().contains(&old));
        server.join().map_err(|_| "status fixture panicked")??;
        Ok(())
    }
}
