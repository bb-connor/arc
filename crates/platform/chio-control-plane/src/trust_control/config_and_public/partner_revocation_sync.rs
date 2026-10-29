//! Strict HTTPS transport for a federation partner's passport revocation feed.
//!
//! One sync resolves the partner's trust-control host once, pins the checked
//! addresses, and runs the root fetch and every leaf page fetch as one bounded
//! job on the portable fetch pool. Every request is bounded by the time left
//! before the sync's single deadline. The mirror commit runs on the caller's
//! thread, and only for a job that returned before that deadline, so a job the
//! caller abandoned never writes the mirror.
use super::*;

use chio_egress_contract::{BlockingContractAgent, ContractLookup, HttpEgressContract};
use chio_revocation_oracle::{EpochRoot, SignedEpochRoot};

use crate::bounded_worker_pool::BoundedWorkerPool;
use crate::passport_revocation_feed::{
    PassportRevocationLeavesPage, PassportRevocationRootDocument,
    MAX_PASSPORT_REVOCATION_PAGE_BYTES,
};
use crate::passport_revocation_mirror::{
    PartnerRevocationError, PartnerRevocationMirror, PartnerRevocationSource, StagedPartnerSync,
};
use crate::revocation_partner::RevocationPartner;

use super::portable_issuer_fetch::{
    portable_fetch_agent, portable_fetch_response, run_portable_fetch, PortableFetchDeadline,
    PORTABLE_ISSUER_FETCH_POOL,
};

/// Largest accepted signed-root body, in bytes.
const MAX_SIGNED_ROOT_BYTES: usize = 16 * 1024;

/// A partner's feed, fetched over an agent pinned to its checked addresses.
pub(crate) struct PartnerRevocationFeed {
    partner_id: String,
    base: String,
    agent: BlockingContractAgent,
    deadline: PortableFetchDeadline,
}

impl PartnerRevocationFeed {
    pub(crate) fn new(
        partner_id: &str,
        base: &str,
        contract: &HttpEgressContract,
        lookup: ContractLookup,
        deadline: PortableFetchDeadline,
    ) -> Result<Self, CliError> {
        Ok(Self {
            partner_id: partner_id.to_owned(),
            base: base.to_owned(),
            agent: portable_fetch_agent(contract, &deadline, lookup)?,
            deadline,
        })
    }

    fn fetch_error(&self, error: CliError) -> PartnerRevocationError {
        PartnerRevocationError::Fetch(self.partner_id.clone(), error.to_string())
    }

    fn get<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        cap: usize,
        endpoint: &str,
    ) -> Result<T, PartnerRevocationError> {
        let remaining = self
            .deadline
            .remaining()
            .map_err(|error| self.fetch_error(error))?;
        let outcome = self
            .agent
            .get(url)
            .and_then(|request| request.deadline(remaining).call());
        let response =
            portable_fetch_response(outcome, endpoint).map_err(|error| self.fetch_error(error))?;
        crate::json_input::read(response.body(), cap).map_err(|error| self.fetch_error(error))
    }
}

impl PartnerRevocationSource for PartnerRevocationFeed {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError> {
        let document: PassportRevocationRootDocument = self.get(
            &format!("{}{PUBLIC_PASSPORT_REVOCATION_ROOT_PATH}", self.base),
            MAX_SIGNED_ROOT_BYTES,
            "partner revocation root endpoint",
        )?;
        document.into_signed_root().map_err(|error| {
            PartnerRevocationError::MalformedRoot(self.partner_id.clone(), error.to_string())
        })
    }

    fn leaves_after(
        &mut self,
        after: u64,
    ) -> Result<PassportRevocationLeavesPage, PartnerRevocationError> {
        self.get(
            &format!(
                "{}{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after={after}",
                self.base
            ),
            MAX_PASSPORT_REVOCATION_PAGE_BYTES,
            "partner revocation leaves endpoint",
        )
    }
}

/// The strict HTTPS egress contract for `partner`'s issuer host.
fn partner_feed_contract(partner: &RevocationPartner) -> Result<HttpEgressContract, CliError> {
    let url = Url::parse(&partner.issuer).map_err(|error| {
        CliError::cli_other_error(format!("partner trust-control URL is invalid: {error}"))
    })?;
    let contract = crate::anchor_egress::strict_https_contract(
        &url,
        "control-plane.partner-passport-revocations",
        crate::integer::count(MAX_PASSPORT_REVOCATION_PAGE_BYTES),
    )
    .map_err(CliError::cli_other_error)?;
    Ok(contract)
}

/// Syncs `mirror` from `partner` over the bounded strict transport, sampling
/// acceptance time from `clock` after the fetch.
pub fn sync_partner_revocation_mirror(
    mirror: Arc<PartnerRevocationMirror>,
    partner: RevocationPartner,
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> Result<EpochRoot, PartnerRevocationError> {
    let deadline = PortableFetchDeadline::start().map_err(|error| {
        PartnerRevocationError::Fetch(partner.partner_id.clone(), error.to_string())
    })?;
    sync_within(
        &PORTABLE_ISSUER_FETCH_POOL,
        deadline,
        mirror,
        partner,
        clock,
        stage_over_strict_transport,
    )
}

fn sync_within<S>(
    pool: &BoundedWorkerPool,
    deadline: PortableFetchDeadline,
    mirror: Arc<PartnerRevocationMirror>,
    partner: RevocationPartner,
    clock: Arc<dyn chio_security_types::clock::Clock>,
    stage: S,
) -> Result<EpochRoot, PartnerRevocationError>
where
    S: FnOnce(
            &PartnerRevocationMirror,
            &RevocationPartner,
            PortableFetchDeadline,
        ) -> Result<StagedPartnerSync, PartnerRevocationError>
        + Send
        + 'static,
{
    let staged = {
        let mirror = Arc::clone(&mirror);
        let partner = partner.clone();
        run_portable_fetch(pool, deadline, move |deadline| {
            Ok(stage(&mirror, &partner, deadline))
        })
    };
    let staged = staged.map_err(|error| {
        PartnerRevocationError::Fetch(partner.partner_id.clone(), error.to_string())
    })??;
    mirror.commit(&partner, staged, clock.as_ref())
}

fn stage_over_strict_transport(
    mirror: &PartnerRevocationMirror,
    partner: &RevocationPartner,
    deadline: PortableFetchDeadline,
) -> Result<StagedPartnerSync, PartnerRevocationError> {
    let fetch_error = |error: CliError| {
        PartnerRevocationError::Fetch(partner.partner_id.clone(), error.to_string())
    };
    let contract = partner_feed_contract(partner).map_err(fetch_error)?;
    let mut feed = PartnerRevocationFeed::new(
        &partner.partner_id,
        &partner.issuer,
        &contract,
        chio_egress_contract::system_lookup(),
        deadline,
    )
    .map_err(fetch_error)?;
    mirror.stage(partner, &mut feed)
}

#[cfg(test)]
#[path = "partner_revocation_sync_tests.rs"]
mod tests;
