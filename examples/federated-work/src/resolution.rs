//! A separately co-signed release of an unresolved review's local credit hold.
use crate::{common::*, incident, review::ReviewRequest};
use chio_kernel::{admission_operation::StoreMutationFence, payment::*};
use chio_store_sqlite::SqliteAdmissionOperationStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Offer {
        work: ReviewRequest,
    },
    Accept {
        work: ReviewRequest,
        consent: Box<CoSignedUnknownPaymentReleaseV1>,
    },
}

pub struct Service {
    pub store: SqliteAdmissionOperationStore,
    pub adapter: Box<dyn PaymentAdapter>,
    pub signer: chio_core_types::Keypair,
    pub peers: Peers,
    pub fence: StoreMutationFence,
    pub database: PathBuf,
}

impl Service {
    fn runtime(&self) -> UnknownPaymentReleaseRuntime<'_> {
        UnknownPaymentReleaseRuntime::new(
            &self.store,
            self.adapter.as_ref(),
            &self.signer,
            &self.fence,
        )
    }
    fn policy(&self) -> UnknownPaymentReleasePolicyV1 {
        UnknownPaymentReleasePolicyV1 {
            receiver_key: self.peers.provider.clone(),
            counterparty_key: self.peers.buyer.clone(),
            rail: self.adapter.rail_id().into(),
            currency: "TST".into(),
        }
    }
    pub fn recover(&self) -> Result<usize> {
        Ok(self.runtime().reconcile_pending(now_ms()?)?)
    }
    pub fn handle(&self, args: Value) -> Result<Value> {
        let request: Request = serde_json::from_value(args)?;
        let (work, consent) = match request {
            Request::Offer { work } => (work, None),
            Request::Accept { work, consent } => (work, Some(consent)),
        };
        work.validate(&self.peers)?;
        let incident: incident::Incident = serde_json::from_value(incident::delivery(
            &work.acceptance,
            &self.database,
            &self.store,
            &self.signer,
        )?)?;
        let id = incident::verify(&work, &incident)?;
        let policy = self.policy();
        if let Some(consent) = consent {
            if consent.proposal.body.operation_id != id
                || digest(&consent.proposal.body.incident)? != digest(incident.projection())?
            {
                return Err("release consent changes the retained work incident".into());
            }
            return Ok(serde_json::to_value(self.runtime().resolve(
                &policy,
                &consent,
                now_ms()?,
            )?)?);
        }
        if let Some(record) = self.store.load_unknown_release(&id, &self.fence)? {
            return Ok(serde_json::to_value(&record.request().proposal)?);
        }
        let (operation, journal) = self.store.unknown_release_source(&id, &self.fence)?;
        let at = now_ms()?;
        let proposal = UnknownPaymentReleaseProposalV1::sign(
            UnknownPaymentReleaseTermsV1 {
                schema: UNKNOWN_PAYMENT_RELEASE_SCHEMA.into(),
                policy_digest: unknown_release_digest(&policy)?,
                operation_id: id,
                terminal_projection_digest: operation
                    .terminal_replay()
                    .ok_or("unknown replay is absent")?
                    .projection_digest()
                    .as_str()
                    .into(),
                incident: incident.projection().clone(),
                capability: work.acceptance.ask.body.token_offer,
                authorized_journal: journal,
                issued_at_unix_ms: at,
                expires_at_unix_ms: at.checked_add(3_600_000).ok_or("release expiry overflow")?,
            },
            &self.signer,
        )?;
        Ok(serde_json::to_value(proposal)?)
    }
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicRelease {
    pub request: ReviewRequest,
    pub incident: incident::Incident,
    pub consent: CoSignedUnknownPaymentReleaseV1,
    pub receipt: SignedUnknownPaymentReleaseReceiptV1,
}

pub fn verify(peers: &Peers, public: &PublicRelease) -> Result<String> {
    public.request.validate(peers)?;
    let id = incident::verify(&public.request, &public.incident)?;
    verify_unknown_payment_release_receipt(&public.receipt, &peers.provider, &peers.buyer)?;
    let record = &public.receipt.body.record;
    if record.policy().rail != "finding-operator-ledger"
        || record.policy().currency != "TST"
        || record.original_journal().amount_units != 100
        || record.original_journal().grant_index != 0
        || record.operation_id() != id
        || digest(record.request())? != digest(&public.consent)?
        || digest(&public.consent.proposal.body.incident)? != digest(public.incident.projection())?
    {
        return Err("release receipt changes the public consent or original work".into());
    }
    Ok(id)
}
