//! Strict HTTPS transport for a federation partner's passport revocation feed.
//!
//! One sync resolves the partner's trust-control host once, pins the checked
//! addresses, and runs the root fetch, every leaf page fetch and the mirror
//! commit as one bounded job on the portable fetch pool.
use super::*;

use chio_egress_contract::HttpEgressContract;
use chio_revocation_oracle::{EpochRoot, SignedEpochRoot};

use crate::partner_card::PartnerCard;
use crate::passport_revocation_feed::{
    PassportRevocationLeavesPage, MAX_PASSPORT_REVOCATION_PAGE_BYTES,
};
use crate::passport_revocation_mirror::{
    PartnerRevocationError, PartnerRevocationMirror, PartnerRevocationSource,
};

use super::portable_issuer_fetch::{
    build_portable_fetch_agent, pin_checked_https_addrs, portable_fetch_transport_error,
    run_portable_fetch, system_resolve_host, PortableFetchDeadline, PORTABLE_ISSUER_FETCH_POOL,
};

/// Largest accepted signed-root body, in bytes.
const MAX_SIGNED_ROOT_BYTES: usize = 16 * 1024;

/// A partner's feed, fetched over an agent pinned to its checked addresses.
pub(crate) struct PartnerRevocationFeed {
    partner_id: String,
    base: String,
    agent: Agent,
}

impl PartnerRevocationFeed {
    pub(crate) fn new(partner_id: &str, base: &str, agent: Agent) -> Self {
        Self {
            partner_id: partner_id.to_owned(),
            base: base.to_owned(),
            agent,
        }
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
        let response =
            self.agent.get(url).call().map_err(|error| {
                self.fetch_error(portable_fetch_transport_error(endpoint, error))
            })?;
        crate::json_input::read(response.into_reader(), cap)
            .map_err(|error| self.fetch_error(error))
    }
}

impl PartnerRevocationSource for PartnerRevocationFeed {
    fn signed_root(&mut self) -> Result<SignedEpochRoot, PartnerRevocationError> {
        self.get(
            &format!("{}{PUBLIC_PASSPORT_REVOCATION_ROOT_PATH}", self.base),
            MAX_SIGNED_ROOT_BYTES,
            "partner revocation root endpoint",
        )
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

/// The strict HTTPS egress contract for `card`'s trust-control host.
fn partner_feed_contract(card: &PartnerCard) -> Result<(Url, HttpEgressContract), CliError> {
    let url = Url::parse(&card.trust_control_url).map_err(|error| {
        CliError::cli_other_error(format!("partner trust-control URL is invalid: {error}"))
    })?;
    let contract = crate::anchor_egress::strict_https_contract(
        &url,
        "control-plane.partner-passport-revocations",
        crate::integer::count(MAX_PASSPORT_REVOCATION_PAGE_BYTES),
    )
    .map_err(CliError::cli_other_error)?;
    Ok((url, contract))
}

/// Syncs the mirror at `mirror_path` from `card`'s partner over the bounded
/// strict transport, sampling acceptance time from `clock` after the fetch.
pub fn sync_partner_revocation_mirror(
    card: PartnerCard,
    mirror_path: PathBuf,
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> Result<EpochRoot, PartnerRevocationError> {
    let partner_id = card.partner_id.clone();
    let fetch_error =
        |error: CliError| PartnerRevocationError::Fetch(partner_id.clone(), error.to_string());
    let deadline = PortableFetchDeadline::start().map_err(fetch_error)?;
    let outcome = run_portable_fetch(&PORTABLE_ISSUER_FETCH_POOL, deadline, move |deadline| {
        Ok(sync_over_strict_transport(
            &card,
            &mirror_path,
            clock.as_ref(),
            &deadline,
        ))
    });
    outcome.map_err(fetch_error)?
}

fn sync_over_strict_transport(
    card: &PartnerCard,
    mirror_path: &Path,
    clock: &dyn chio_security_types::clock::Clock,
    deadline: &PortableFetchDeadline,
) -> Result<EpochRoot, PartnerRevocationError> {
    let fetch_error =
        |error: CliError| PartnerRevocationError::Fetch(card.partner_id.clone(), error.to_string());
    let (url, contract) = partner_feed_contract(card).map_err(fetch_error)?;
    let pinned =
        pin_checked_https_addrs(&contract, &url, system_resolve_host).map_err(fetch_error)?;
    let agent = build_portable_fetch_agent(pinned, true, deadline).map_err(fetch_error)?;
    let mirror = PartnerRevocationMirror::open(mirror_path, &card.partner_id)?;
    let mut feed = PartnerRevocationFeed::new(&card.partner_id, &card.trust_control_url, agent);
    mirror.sync(card, &mut feed, clock)
}
