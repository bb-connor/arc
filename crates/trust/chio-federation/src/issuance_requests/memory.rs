//! In-memory [`IssuanceRequestRepository`] holding the same invariants as the
//! durable stores, for domain and handler tests.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use super::{
    IssuanceClaim, IssuanceClaimToken, IssuanceDecision, IssuanceListQuery, IssuanceRequestPage,
    IssuanceRequestRecord, IssuanceRequestRepository, IssuanceRequestStatus,
    IssuanceRequestSummary, IssuanceStoreError, EXPIRED_REASON, MAX_PENDING_ISSUANCE_REQUESTS,
};

type Requests = BTreeMap<String, IssuanceRequestRecord>;

#[derive(Debug, Default)]
struct State {
    requests: Requests,
    claim_epochs: BTreeMap<String, u64>,
}

impl State {
    fn claimed_mut(&mut self, token: &IssuanceClaimToken) -> Option<&mut IssuanceRequestRecord> {
        let id = token.challenge_id();
        if self.claim_epochs.get(id) != Some(&token.epoch()) {
            return None;
        }
        self.requests
            .get_mut(id)
            .filter(|record| record.status == IssuanceRequestStatus::Deciding)
    }
}

#[derive(Debug)]
pub struct InMemoryIssuanceRequestRepository {
    state: Mutex<State>,
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
            state: Mutex::new(State::default()),
            pending_cap,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, IssuanceStoreError> {
        self.state
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
        let mut state = self.lock()?;
        let requests = &mut state.requests;
        Self::expire_stale(requests, now);
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
        Ok(self.lock()?.requests.get(challenge_id).cloned())
    }

    fn list(
        &self,
        query: IssuanceListQuery<'_>,
        now: u64,
    ) -> Result<IssuanceRequestPage, IssuanceStoreError> {
        let mut state = self.lock()?;
        let requests = &mut state.requests;
        Self::expire_stale(requests, now);
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
        let size = query.limit.get();
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

    fn claim(&self, challenge_id: &str, now: u64) -> Result<IssuanceClaim, IssuanceStoreError> {
        let mut state = self.lock()?;
        let State {
            requests,
            claim_epochs,
        } = &mut *state;
        Self::expire_stale(requests, now);
        let record = match requests.get_mut(challenge_id) {
            None => return Err(IssuanceStoreError::NotFound(challenge_id.to_string())),
            Some(record) if record.status == IssuanceRequestStatus::Pending => record,
            Some(_) => return Err(IssuanceStoreError::NotPending(challenge_id.to_string())),
        };
        let epoch = claim_epochs.entry(challenge_id.to_string()).or_default();
        *epoch = epoch
            .checked_add(1)
            .ok_or(IssuanceStoreError::Unavailable)?;
        record.status = IssuanceRequestStatus::Deciding;
        Ok(IssuanceClaim {
            token: IssuanceClaimToken::new(challenge_id, *epoch),
            record: record.clone(),
        })
    }

    fn finish(
        &self,
        token: &IssuanceClaimToken,
        decision: &IssuanceDecision,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), IssuanceStoreError> {
        let mut state = self.lock()?;
        let record = state
            .claimed_mut(token)
            .ok_or_else(|| IssuanceStoreError::NotClaimed(token.challenge_id().to_string()))?;
        record.status = decision.status();
        record.decided_at = Some(now);
        record.capability_id = decision.capability_id().map(str::to_string);
        record.decision_reason = reason.map(str::to_string);
        Ok(())
    }

    fn release(&self, token: &IssuanceClaimToken) -> Result<(), IssuanceStoreError> {
        let mut state = self.lock()?;
        let record = state
            .claimed_mut(token)
            .ok_or_else(|| IssuanceStoreError::NotClaimed(token.challenge_id().to_string()))?;
        record.status = IssuanceRequestStatus::Pending;
        Ok(())
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
