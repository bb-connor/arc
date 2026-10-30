//! In-memory [`IssuanceRequestRepository`] holding the same invariants as the
//! durable stores, for domain and handler tests.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use super::{
    IssuanceDecision, IssuanceListQuery, IssuanceRequestPage, IssuanceRequestRecord,
    IssuanceRequestRepository, IssuanceRequestStatus, IssuanceRequestSummary, IssuanceStoreError,
    EXPIRED_REASON, MAX_PENDING_ISSUANCE_REQUESTS,
};

type Requests = BTreeMap<String, IssuanceRequestRecord>;

#[derive(Debug)]
pub struct InMemoryIssuanceRequestRepository {
    requests: Mutex<Requests>,
    pending_cap: usize,
}

impl Default for InMemoryIssuanceRequestRepository {
    fn default() -> Self {
        Self::with_pending_cap(MAX_PENDING_ISSUANCE_REQUESTS)
    }
}

impl InMemoryIssuanceRequestRepository {
    #[must_use]
    pub fn with_pending_cap(pending_cap: usize) -> Self {
        Self {
            requests: Mutex::new(BTreeMap::new()),
            pending_cap,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Requests>, IssuanceStoreError> {
        self.requests
            .lock()
            .map_err(|_| IssuanceStoreError::Unavailable)
    }

    fn expire_stale(requests: &mut Requests, now: u64) {
        for record in requests.values_mut() {
            if record.status == IssuanceRequestStatus::Pending && record.expires_at <= now {
                record.status = IssuanceRequestStatus::Denied;
                record.decided_at = Some(now);
                record.decision_reason = Some(EXPIRED_REASON.to_string());
            }
        }
    }
}

impl IssuanceRequestRepository for InMemoryIssuanceRequestRepository {
    fn submit(&self, record: &IssuanceRequestRecord, now: u64) -> Result<(), IssuanceStoreError> {
        if record.expires_at <= now {
            return Err(IssuanceStoreError::Expired(record.challenge_id.clone()));
        }
        let mut requests = self.lock()?;
        Self::expire_stale(&mut requests, now);
        if requests.contains_key(&record.challenge_id) {
            return Err(IssuanceStoreError::AlreadySubmitted(
                record.challenge_id.clone(),
            ));
        }
        let open = requests
            .values()
            .filter(|stored| {
                matches!(
                    stored.status,
                    IssuanceRequestStatus::Pending | IssuanceRequestStatus::Deciding
                )
            })
            .count();
        if open >= self.pending_cap {
            return Err(IssuanceStoreError::Full);
        }
        let stored = IssuanceRequestRecord {
            status: IssuanceRequestStatus::Pending,
            decided_at: None,
            capability_id: None,
            decision_reason: None,
            ..record.clone()
        };
        requests.insert(record.challenge_id.clone(), stored);
        Ok(())
    }

    fn get(&self, challenge_id: &str) -> Result<Option<IssuanceRequestRecord>, IssuanceStoreError> {
        Ok(self.lock()?.get(challenge_id).cloned())
    }

    fn list(
        &self,
        query: IssuanceListQuery<'_>,
        now: u64,
    ) -> Result<IssuanceRequestPage, IssuanceStoreError> {
        let mut requests = self.lock()?;
        Self::expire_stale(&mut requests, now);
        let cursor = match query.after {
            None => None,
            Some(id) => match requests.get(id) {
                Some(record) => Some((record.submitted_at, id)),
                None => return Err(IssuanceStoreError::NotFound(id.to_string())),
            },
        };
        let mut ordered: Vec<&IssuanceRequestRecord> = requests
            .values()
            .filter(|record| query.status.is_none_or(|status| record.status == status))
            .filter(|record| {
                cursor.is_none_or(|(at, id)| {
                    (record.submitted_at, record.challenge_id.as_str()) > (at, id)
                })
            })
            .collect();
        ordered.sort_by(|a, b| {
            (a.submitted_at, &a.challenge_id).cmp(&(b.submitted_at, &b.challenge_id))
        });
        let size = query.page_size();
        let more = ordered.len() > size;
        let requests: Vec<IssuanceRequestSummary> =
            ordered.into_iter().take(size).map(summary).collect();
        let next_after = if more {
            requests.last().map(|request| request.challenge_id.clone())
        } else {
            None
        };
        Ok(IssuanceRequestPage {
            requests,
            next_after,
        })
    }

    fn claim(
        &self,
        challenge_id: &str,
        now: u64,
    ) -> Result<IssuanceRequestRecord, IssuanceStoreError> {
        let mut requests = self.lock()?;
        Self::expire_stale(&mut requests, now);
        match requests.get_mut(challenge_id) {
            None => Err(IssuanceStoreError::NotFound(challenge_id.to_string())),
            Some(record) if record.status == IssuanceRequestStatus::Pending => {
                record.status = IssuanceRequestStatus::Deciding;
                Ok(record.clone())
            }
            Some(_) => Err(IssuanceStoreError::NotPending(challenge_id.to_string())),
        }
    }

    fn finish(
        &self,
        challenge_id: &str,
        decision: &IssuanceDecision,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), IssuanceStoreError> {
        let mut requests = self.lock()?;
        match requests.get_mut(challenge_id) {
            Some(record) if record.status == IssuanceRequestStatus::Deciding => {
                record.status = decision.status();
                record.decided_at = Some(now);
                record.capability_id = decision.capability_id().map(str::to_string);
                record.decision_reason = reason.map(str::to_string);
                Ok(())
            }
            _ => Err(IssuanceStoreError::NotClaimed(challenge_id.to_string())),
        }
    }

    fn release(&self, challenge_id: &str) -> Result<(), IssuanceStoreError> {
        let mut requests = self.lock()?;
        match requests.get_mut(challenge_id) {
            Some(record) if record.status == IssuanceRequestStatus::Deciding => {
                record.status = IssuanceRequestStatus::Pending;
                Ok(())
            }
            _ => Err(IssuanceStoreError::NotClaimed(challenge_id.to_string())),
        }
    }
}

fn summary(record: &IssuanceRequestRecord) -> IssuanceRequestSummary {
    IssuanceRequestSummary {
        challenge_id: record.challenge_id.clone(),
        subject: record.subject.clone(),
        verifier: record.verifier.clone(),
        submitted_at: record.submitted_at,
        expires_at: record.expires_at,
        status: record.status,
        decided_at: record.decided_at,
        capability_id: record.capability_id.clone(),
        decision_reason: record.decision_reason.clone(),
    }
}
