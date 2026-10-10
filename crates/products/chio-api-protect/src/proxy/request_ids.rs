//! Request-id custody is serialized with budget reuse checks by the mediation kernel lock.
use std::collections::{BTreeSet, HashMap};

pub(crate) const MAX_LIVE_REQUEST_IDS: usize = 10_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RequestIdClaimError {
    #[error("chio_request_id_reused")]
    Reused,
    #[error("chio_request_id_capacity")]
    Capacity,
    #[error("chio_request_id_invalid_shape")]
    Shape,
    #[error("chio_request_id_invalid_time")]
    Time,
    #[error("chio_request_id_owner_exhausted")]
    OwnerExhausted,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RequestIdClaim {
    id: String,
    generation: u64,
}

pub(crate) struct MintedRequestIdWindow {
    ttl_secs: u64,
    live: HashMap<String, (u64, i64)>,
    expiries: BTreeSet<(i64, String)>,
    high_water: Option<i64>,
    generation: u64,
}
impl MintedRequestIdWindow {
    pub(crate) fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            live: HashMap::new(),
            expiries: BTreeSet::new(),
            high_water: None,
            generation: 0,
        }
    }
    pub(crate) fn claim(
        &mut self,
        id: &str,
        now: i64,
    ) -> Result<RequestIdClaim, RequestIdClaimError> {
        if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(RequestIdClaimError::Shape);
        }
        if now < 0 || self.high_water.is_some_and(|previous| now < previous) {
            return Err(RequestIdClaimError::Time);
        }
        let ttl = i64::try_from(self.ttl_secs).map_err(|_| RequestIdClaimError::Time)?;
        let expires = now
            .checked_add(ttl)
            .filter(|expires| *expires > now)
            .ok_or(RequestIdClaimError::Time)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(RequestIdClaimError::OwnerExhausted)?;
        self.high_water = Some(now);
        while self
            .expiries
            .first()
            .is_some_and(|(expiry, _)| *expiry <= now)
        {
            if let Some((_, id)) = self.expiries.pop_first() {
                self.live.remove(&id);
            }
        }
        if self.live.contains_key(id) {
            return Err(RequestIdClaimError::Reused);
        }
        if self.live.len() >= MAX_LIVE_REQUEST_IDS {
            return Err(RequestIdClaimError::Capacity);
        }
        self.generation = generation;
        self.live.insert(id.to_owned(), (generation, expires));
        self.expiries.insert((expires, id.to_owned()));
        Ok(RequestIdClaim {
            id: id.to_owned(),
            generation,
        })
    }
    /// Cleanup may remove only its own generation, even after a later reuse.
    pub(crate) fn release(&mut self, claim: &RequestIdClaim) {
        if let Some(&(generation, expires)) = self.live.get(&claim.id) {
            if generation == claim.generation {
                self.live.remove(&claim.id);
                self.expiries.remove(&(expires, claim.id.clone()));
            }
        }
    }
    /// A successful reservation retains the id through the actual signed nonce horizon.
    pub(crate) fn retain_until(&mut self, claim: &RequestIdClaim, signed_expiry: i64) {
        if let Some((generation, expires)) = self.live.get_mut(&claim.id) {
            if *generation == claim.generation && signed_expiry > *expires {
                self.expiries.remove(&(*expires, claim.id.clone()));
                *expires = signed_expiry;
                self.expiries.insert((signed_expiry, claim.id.clone()));
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn stale_cleanup_cannot_release_later_owner_and_retention_uses_signed_horizon() {
        let mut window = MintedRequestIdWindow::new(30);
        let old = window.claim("id", 100).unwrap();
        let new = window.claim("id", 130).unwrap();
        window.release(&old);
        assert_eq!(window.claim("id", 130), Err(RequestIdClaimError::Reused));
        window.retain_until(&new, 200);
        assert_eq!(window.claim("id", 160), Err(RequestIdClaimError::Reused));
        window.release(&new);
        assert!(window.expiries.is_empty());
        assert_eq!(window.len(), 0);
        assert!(window.claim("id", 160).is_ok());
    }
}
