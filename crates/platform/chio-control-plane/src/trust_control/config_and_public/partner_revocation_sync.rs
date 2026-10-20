//! Strict HTTPS transport for a federation partner's passport revocation feed.
//!
//! One sync resolves the partner's trust-control host once, pins the checked
//! addresses, and runs the root fetch, every leaf page fetch and the mirror
//! commit as one bounded job on the portable fetch pool.
use super::*;

use chio_egress_contract::HttpEgressContract;
use chio_revocation_oracle::{EpochRoot, SignedEpochRoot};

use crate::passport_revocation_feed::{
    PassportRevocationLeavesPage, PassportRevocationRootDocument,
    MAX_PASSPORT_REVOCATION_PAGE_BYTES,
};
use crate::passport_revocation_mirror::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
    PartnerRevocationSource,
};
use crate::revocation_partner::{RevocationPartner, RevocationPartnerRegistry};

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
fn partner_feed_contract(
    partner: &RevocationPartner,
) -> Result<(Url, HttpEgressContract), CliError> {
    let url = Url::parse(&partner.issuer).map_err(|error| {
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

/// Syncs the mirror at `mirror_path` from `partner` over the bounded
/// strict transport, sampling acceptance time from `clock` after the fetch.
pub fn sync_partner_revocation_mirror(
    partner: RevocationPartner,
    mirror_path: PathBuf,
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> Result<EpochRoot, PartnerRevocationError> {
    let partner_id = partner.partner_id.clone();
    let fetch_error =
        |error: CliError| PartnerRevocationError::Fetch(partner_id.clone(), error.to_string());
    let deadline = PortableFetchDeadline::start().map_err(fetch_error)?;
    let outcome = run_portable_fetch(&PORTABLE_ISSUER_FETCH_POOL, deadline, move |deadline| {
        Ok(sync_over_strict_transport(
            &partner,
            &mirror_path,
            clock.as_ref(),
            &deadline,
        ))
    });
    outcome.map_err(fetch_error)?
}

fn sync_over_strict_transport(
    partner: &RevocationPartner,
    mirror_path: &Path,
    clock: &dyn chio_security_types::clock::Clock,
    deadline: &PortableFetchDeadline,
) -> Result<EpochRoot, PartnerRevocationError> {
    let fetch_error = |error: CliError| {
        PartnerRevocationError::Fetch(partner.partner_id.clone(), error.to_string())
    };
    let (url, contract) = partner_feed_contract(partner).map_err(fetch_error)?;
    let pinned =
        pin_checked_https_addrs(&contract, &url, system_resolve_host).map_err(fetch_error)?;
    let agent = build_portable_fetch_agent(pinned, true, deadline).map_err(fetch_error)?;
    let mirror = PartnerRevocationMirror::open(mirror_path, &partner.partner_id)?;
    let mut feed = PartnerRevocationFeed::new(&partner.partner_id, &partner.issuer, agent);
    mirror.sync(partner, &mut feed, clock)
}

/// The verified issuer identity a presented passport carries.
#[derive(Clone, Copy)]
pub(crate) enum VerifiedPassportIssuer<'a> {
    /// The signed `iss` URL of an OID4VP credential.
    Url(&'a str),
    /// The issuer DIDs of a native passport's verified credentials.
    Dids(&'a [String]),
}

/// The issuer DIDs of a native passport's credentials. Callers pass them only
/// after the passport's credential signatures have verified.
pub(crate) fn native_passport_issuers(passport: &chio_credentials::AgentPassport) -> Vec<String> {
    passport
        .credentials
        .iter()
        .map(|credential| credential.unsigned.issuer.clone())
        .collect()
}

/// Refuses `passport_id` when its verified issuer is a registered revocation
/// partner whose mirror, synced on demand when stale, is not fresh or holds
/// the passport. The registry is read on every call under its size bound, and
/// an unreadable or invalid registry refuses. A service without a registry,
/// or a passport whose issuer names no partner, is not checked here.
pub(crate) fn check_partner_passport_revocation(
    config: &TrustServiceConfig,
    issuer: VerifiedPassportIssuer<'_>,
    passport_id: &str,
    clock: &Arc<dyn chio_security_types::clock::Clock>,
) -> Result<(), CliError> {
    check_partner_passport_revocation_with(config, issuer, passport_id, clock, &|partner, path| {
        sync_partner_revocation_mirror(partner.clone(), path.to_path_buf(), Arc::clone(clock))
            .map(|_| ())
    })
}

/// [`check_partner_passport_revocation`] with the mirror sync supplied.
pub(crate) fn check_partner_passport_revocation_with(
    config: &TrustServiceConfig,
    issuer: VerifiedPassportIssuer<'_>,
    passport_id: &str,
    clock: &Arc<dyn chio_security_types::clock::Clock>,
    sync: &dyn Fn(&RevocationPartner, &Path) -> Result<(), PartnerRevocationError>,
) -> Result<(), CliError> {
    let Some(registry_path) = config.revocation_partners_file.as_deref() else {
        return Ok(());
    };
    let refused = |error: String| CliError::policy_error(error);
    let registry = RevocationPartnerRegistry::load(registry_path)
        .map_err(|error| refused(error.to_string()))?;
    let partners = match issuer {
        VerifiedPassportIssuer::Url(url) => registry
            .by_issuer(url)
            .map_err(|error| refused(error.to_string()))?
            .into_iter()
            .collect(),
        VerifiedPassportIssuer::Dids(dids) => registry.by_issuer_dids(dids),
    };
    for partner in partners {
        check_partner(registry_path, partner, passport_id, clock, sync)
            .map_err(|error| refused(error.to_string()))?;
    }
    Ok(())
}

fn check_partner(
    registry_path: &Path,
    partner: &RevocationPartner,
    passport_id: &str,
    clock: &Arc<dyn chio_security_types::clock::Clock>,
    sync: &dyn Fn(&RevocationPartner, &Path) -> Result<(), PartnerRevocationError>,
) -> Result<(), PartnerRevocationError> {
    let mirror_path = partner_revocation_mirror_path(registry_path, &partner.partner_id)?;
    let mirror = PartnerRevocationMirror::open(&mirror_path, &partner.partner_id)?;
    if mirror.require_fresh(partner, clock_millis(clock)?).is_err() {
        sync(partner, &mirror_path)?;
    }
    mirror.check_passport(partner, passport_id, clock_millis(clock)?)
}

fn clock_millis(
    clock: &Arc<dyn chio_security_types::clock::Clock>,
) -> Result<u64, PartnerRevocationError> {
    clock
        .unix_millis()
        .map(|now| now.get())
        .map_err(|error| PartnerRevocationError::Clock(error.to_string()))
}
