//! Finite OAuth cache custody in one injected clock domain.
use super::*;

impl A2aAdapter {
    pub(super) fn lookup_cached_bearer_token(
        &self,
        cache_key: &str,
    ) -> Result<Option<String>, AdapterError> {
        let now = self.clock.read()?;
        let mut cache = self.token_cache.lock().map_err(|_| {
            AdapterError::AuthNegotiation("OAuth token cache lock poisoned".to_string())
        })?;
        // Refuse clock faults before returning even an otherwise valid cache hit.
        for entry in cache.iter_mut() {
            match entry.deadline.remaining(now) {
                Ok(_) | Err(ClockError::Expired) => {}
                Err(error) => return Err(error.into()),
            }
        }
        cache.retain_mut(|entry| entry.deadline.remaining(now).is_ok());
        Ok(cache
            .iter()
            .find(|entry| entry.cache_key == cache_key)
            .map(|entry| entry.access_token.clone()))
    }

    pub(super) fn store_cached_bearer_token(
        &self,
        cache_key: String,
        access_token: String,
        expires_in: Option<u64>,
        requested_at: ClockReading,
    ) -> Result<(), AdapterError> {
        let now = self.clock.read()?;
        let cache_ttl = expires_in
            .and_then(|ttl| ttl.checked_sub(OAUTH_CACHE_SKEW_SECS))
            .filter(|ttl| *ttl > 0);
        let deadline = cache_ttl
            .map(|seconds| {
                let millis = seconds.checked_mul(1000).ok_or(ClockError::Overflow)?;
                let mut deadline = AuthorityDeadline::for_timeout_ms(requested_at, millis)?;
                match deadline.remaining(now) {
                    Ok(_) => Ok(Some(deadline)),
                    Err(ClockError::Expired) => Ok(None),
                    Err(error) => Err(error),
                }
            })
            .transpose()?
            .flatten();
        let mut cache = self.token_cache.lock().map_err(|_| {
            AdapterError::AuthNegotiation("OAuth token cache lock poisoned".to_string())
        })?;
        // Unknown expiry and lifetimes exhausted by skew or network latency
        // permit this acquisition only, never indefinite cache reuse.
        cache.retain(|entry| entry.cache_key != cache_key);
        if let Some(deadline) = deadline {
            cache.push(A2aCachedBearerToken {
                cache_key,
                access_token,
                deadline,
            });
        }
        Ok(())
    }
}
