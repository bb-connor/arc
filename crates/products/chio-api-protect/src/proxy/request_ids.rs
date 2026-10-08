//! Request-id custody. One flight per id serializes its budget reuse check,
//! claim, authorization and cleanup; different ids proceed concurrently.
use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;

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
    #[error("chio_request_id_custody_unavailable")]
    Unavailable,
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
    /// A successful reservation retains the id through the actual signed nonce
    /// horizon. The caller holds the id's flight, so an absent entry aged out
    /// while its owner was still deciding and is restored for the same owner.
    pub(crate) fn retain_until(&mut self, claim: &RequestIdClaim, signed_expiry: i64) {
        match self.live.get_mut(&claim.id) {
            Some((generation, expires)) => {
                if *generation == claim.generation && signed_expiry > *expires {
                    self.expiries.remove(&(*expires, claim.id.clone()));
                    *expires = signed_expiry;
                    self.expiries.insert((signed_expiry, claim.id.clone()));
                }
            }
            None => {
                self.live
                    .insert(claim.id.clone(), (claim.generation, signed_expiry));
                self.expiries.insert((signed_expiry, claim.id.clone()));
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live.len()
    }
}

/// Live request-id flights. A second request for an id that is still in flight
/// waits for the first owner to finish and then runs its whole sequence again,
/// so it observes the first owner's claim, hold and cleanup exactly as a
/// request that arrived afterwards would. No guard of this map is held while
/// a flight runs or while a waiter waits.
#[derive(Clone, Default)]
pub(crate) struct RequestFlights {
    live: Arc<Mutex<HashMap<String, watch::Sender<()>>>>,
}

impl RequestFlights {
    pub(crate) async fn enter(&self, id: &str) -> Result<RequestFlight, RequestIdClaimError> {
        loop {
            let mut finished = {
                let mut live = self
                    .live
                    .lock()
                    .map_err(|_| RequestIdClaimError::Unavailable)?;
                match live.entry(id.to_owned()) {
                    Entry::Occupied(owner) => owner.get().subscribe(),
                    Entry::Vacant(slot) => {
                        slot.insert(watch::channel(()).0);
                        return Ok(RequestFlight {
                            flights: self.clone(),
                            id: id.to_owned(),
                        });
                    }
                }
            };
            // The owner never sends; dropping its sender ends the flight.
            while finished.changed().await.is_ok() {}
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live
            .lock()
            .map(|live| live.len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().len())
    }
}

/// Ownership of one request id's flight. Dropping it, including on panic or
/// when a cancelled handler abandons it, wakes every waiter for the id.
pub(crate) struct RequestFlight {
    flights: RequestFlights,
    id: String,
}

impl Drop for RequestFlight {
    fn drop(&mut self) {
        // Only this owner inserted the entry and only this drop removes it.
        self.flights
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
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

    #[test]
    fn retention_restores_a_claim_that_aged_out_during_its_flight() {
        let mut window = MintedRequestIdWindow::new(30);
        let slow = window.claim("slow", 100).unwrap();
        assert!(window.claim("other", 131).is_ok());
        assert_eq!(window.len(), 1, "the slow claim aged out by TTL");
        window.retain_until(&slow, 200);
        assert_eq!(window.claim("slow", 150), Err(RequestIdClaimError::Reused));
        assert_eq!(window.len(), 2);
        assert!(window.claim("slow", 200).is_ok());
    }

    #[tokio::test]
    async fn one_request_id_has_one_flight_and_other_ids_do_not_wait() {
        let flights = RequestFlights::default();
        let owner = flights.enter("id").await.unwrap();
        let unrelated =
            tokio::time::timeout(std::time::Duration::from_secs(5), flights.enter("other"))
                .await
                .expect("an unrelated id must not wait for a live flight")
                .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), flights.enter("id"))
                .await
                .is_err(),
            "a second flight for a live id must wait for its owner"
        );
        let waiter = tokio::spawn({
            let flights = flights.clone();
            async move { flights.enter("id").await.map(drop) }
        });
        drop(owner);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the owner's drop must wake its waiter")
            .unwrap()
            .unwrap();
        assert_eq!(flights.len(), 1);
        drop(unrelated);
        assert_eq!(flights.len(), 0);
    }

    #[tokio::test]
    async fn a_panicking_flight_owner_still_releases_its_id() {
        let flights = RequestFlights::default();
        let owner = flights.enter("id").await.unwrap();
        let panicked = std::thread::spawn(move || {
            let _owner = owner;
            panic!("owner failed mid-flight");
        })
        .join();
        assert!(panicked.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(5), flights.enter("id"))
            .await
            .expect("a panicked owner must not strand its id")
            .unwrap();
    }
}
