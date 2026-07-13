use super::client::build_client;
use super::*;

pub fn build_remote_capability_authority(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let client = build_client(control_url, control_token)?;
    let status = client.authority_status()?;
    let cache = AuthorityKeyCache::from_status(&status)?;
    Ok(Box::new(RemoteCapabilityAuthority {
        client,
        cache: Mutex::new(cache),
    }))
}

impl RemoteCapabilityAuthority {
    pub fn refresh_status(&self) -> Result<(), CliError> {
        let cache = self.fetch_status_cache()?;
        self.install_status_cache(cache);
        Ok(())
    }

    fn fetch_status_cache(&self) -> Result<AuthorityKeyCache, CliError> {
        let status = self.client.authority_status()?;
        AuthorityKeyCache::from_status(&status)
    }

    fn install_status_cache(&self, cache: AuthorityKeyCache) {
        match self.cache.lock() {
            Ok(mut guard) => *guard = cache,
            Err(poisoned) => *poisoned.into_inner() = cache,
        }
    }

    fn refresh_status_if_stale(&self) {
        let should_refresh = match self.cache.lock() {
            Ok(guard) => guard.refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
            Err(poisoned) => poisoned.into_inner().refreshed_at.elapsed() >= AUTHORITY_CACHE_TTL,
        };
        if should_refresh {
            let _ = self.refresh_status();
        }
    }

    fn trusted_keys_snapshot(&self) -> Vec<PublicKey> {
        match self.cache.lock() {
            Ok(guard) => guard.trusted.clone(),
            Err(poisoned) => poisoned.into_inner().trusted.clone(),
        }
    }

    fn verify_issuance_response(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), chio_kernel::KernelError> {
        let trusted = self.trusted_keys_snapshot();
        if trusted.contains(&capability.issuer) {
            return verify_issued_capability(capability, &trusted);
        }

        let refreshed = self.fetch_status_cache().map_err(|error| {
            chio_kernel::KernelError::CapabilityIssuanceFailed(format!(
                "failed to refresh remote capability-authority trust: {error}"
            ))
        })?;
        self.install_verified_status_cache(capability, refreshed)
    }

    fn install_verified_status_cache(
        &self,
        capability: &CapabilityToken,
        refreshed: AuthorityKeyCache,
    ) -> Result<(), chio_kernel::KernelError> {
        verify_issued_capability(capability, &refreshed.trusted)?;
        self.install_status_cache(refreshed);
        Ok(())
    }
}

fn verify_issued_capability(
    capability: &CapabilityToken,
    trusted: &[PublicKey],
) -> Result<(), chio_kernel::KernelError> {
    if !trusted.contains(&capability.issuer) {
        return Err(chio_kernel::KernelError::UntrustedIssuer);
    }
    match capability.verify_signature() {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(chio_kernel::KernelError::InvalidSignature),
    }
}

impl RemoteCapabilityAuthority {
    /// Fail-closed substitute for a missing current authority key.
    ///
    /// `AuthorityKeyCache::from_status` rejects any status without a current
    /// key, so a primed cache always carries one. If that invariant is ever
    /// violated we must NOT abort the process and must NOT return a key an
    /// attacker could control. We return a freshly
    /// generated ephemeral public key whose private half is discarded
    /// immediately: it can never validate a real capability, so callers that
    /// fold this value into a trust set gain no usable issuer. The effect is a
    /// denial (zero trust granted) rather than a panic.
    fn deny_sentinel_public_key() -> PublicKey {
        tracing::error!(
            "remote capability authority cache missing current key; \
             returning a non-trusting sentinel so admission fails closed"
        );
        Keypair::generate().public_key()
    }
}

impl CapabilityAuthority for RemoteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.refresh_status_if_stale();
        match self.cache.lock() {
            Ok(guard) => match &guard.current {
                Some(public_key) => public_key.clone(),
                None => Self::deny_sentinel_public_key(),
            },
            Err(poisoned) => match &poisoned.into_inner().current {
                Some(public_key) => public_key.clone(),
                None => Self::deny_sentinel_public_key(),
            },
        }
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.refresh_status_if_stale();
        self.trusted_keys_snapshot()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        let capability = self
            .client
            .issue_capability_with_attestation(subject, scope, ttl_seconds, runtime_attestation)
            .map_err(|error| {
                chio_kernel::KernelError::CapabilityIssuanceFailed(error.to_string())
            })?;
        self.verify_issuance_response(&capability)?;
        Ok(capability)
    }
}

impl AuthorityKeyCache {
    pub(crate) fn from_status(status: &TrustAuthorityStatus) -> Result<Self, CliError> {
        if !status.configured {
            return Err(CliError::cli_other_error(
                "trust control service does not have an authority configured".to_string(),
            ));
        }
        let current = status
            .public_key
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()?;
        if current.is_none() {
            return Err(CliError::cli_other_error(
                "trust control service returned no current authority public key".to_string(),
            ));
        }
        let trusted = status
            .trusted_public_keys
            .iter()
            .map(|value| PublicKey::from_hex(value))
            .collect::<Result<Vec<_>, _>>()?;
        let mut trusted = trusted;
        if let Some(current) = current.as_ref() {
            if !trusted.iter().any(|public_key| public_key == current) {
                trusted.push(current.clone());
            }
        }
        Ok(Self {
            current,
            trusted,
            refreshed_at: Instant::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::LocalCapabilityAuthority;

    fn issue_test_capability(
        authority: &LocalCapabilityAuthority,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        authority.issue_capability(&Keypair::generate().public_key(), ChioScope::default(), 300)
    }

    fn remote_with_trusted_key(
        public_key: PublicKey,
    ) -> Result<RemoteCapabilityAuthority, CliError> {
        Ok(RemoteCapabilityAuthority {
            client: build_client("http://127.0.0.1:1", "test-token")?,
            cache: Mutex::new(AuthorityKeyCache {
                current: Some(public_key.clone()),
                trusted: vec![public_key],
                refreshed_at: Instant::now(),
            }),
        })
    }

    #[test]
    fn issuance_response_accepts_trusted_valid_signature() -> Result<(), Box<dyn std::error::Error>>
    {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let capability = issue_test_capability(&authority)?;

        verify_issued_capability(&capability, &[authority.authority_public_key()])?;
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_unknown_issuer_without_changing_trust(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let trusted_authority = LocalCapabilityAuthority::new(Keypair::generate());
        let untrusted_authority = LocalCapabilityAuthority::new(Keypair::generate());
        let capability = issue_test_capability(&untrusted_authority)?;
        let trusted = vec![trusted_authority.authority_public_key()];
        let before = trusted.clone();

        let result = verify_issued_capability(&capability, &trusted);

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::UntrustedIssuer)
        ));
        assert_eq!(trusted, before);
        Ok(())
    }

    #[test]
    fn issuance_response_rejects_invalid_signature_from_trusted_issuer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let mut capability = issue_test_capability(&authority)?;
        capability.subject = Keypair::generate().public_key();

        let result = verify_issued_capability(&capability, &[authority.authority_public_key()]);

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn invalid_rotated_issuance_does_not_install_refreshed_trust(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = LocalCapabilityAuthority::new(Keypair::generate());
        let rotated = LocalCapabilityAuthority::new(Keypair::generate());
        let previous_key = previous.authority_public_key();
        let rotated_key = rotated.authority_public_key();
        let remote = remote_with_trusted_key(previous_key.clone())?;
        let mut capability = issue_test_capability(&rotated)?;
        capability.subject = Keypair::generate().public_key();
        let refreshed = AuthorityKeyCache {
            current: Some(rotated_key.clone()),
            trusted: vec![previous_key.clone(), rotated_key],
            refreshed_at: Instant::now(),
        };

        let result = remote.install_verified_status_cache(&capability, refreshed);

        assert!(matches!(
            result,
            Err(chio_kernel::KernelError::InvalidSignature)
        ));
        assert_eq!(remote.trusted_keys_snapshot(), vec![previous_key]);
        Ok(())
    }

    #[test]
    fn valid_rotated_issuance_installs_status_derived_trust(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = LocalCapabilityAuthority::new(Keypair::generate());
        let rotated = LocalCapabilityAuthority::new(Keypair::generate());
        let previous_key = previous.authority_public_key();
        let rotated_key = rotated.authority_public_key();
        let remote = remote_with_trusted_key(previous_key.clone())?;
        let capability = issue_test_capability(&rotated)?;
        let refreshed = AuthorityKeyCache {
            current: Some(rotated_key.clone()),
            trusted: vec![previous_key.clone(), rotated_key.clone()],
            refreshed_at: Instant::now(),
        };

        remote.install_verified_status_cache(&capability, refreshed)?;

        assert_eq!(
            remote.trusted_keys_snapshot(),
            vec![previous_key, rotated_key]
        );
        Ok(())
    }
}
