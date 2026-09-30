//! One retained authority generation for an explicit set of broker routes.

use super::{
    canonical, rejected, BrokerAdmissionParticipant, BrokerQuotaVerifier, BrokerQuotaVerifierConfig,
};
use crate::{daemon::Clock, ipc_client::BrokerIpcClientConfig, Result};
use chio_core_types::SigningBackend;
use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use chio_kernel::supplemental_admission::{
    SupplementalAdmissionAuthorityBindingV1, SupplementalAdmissionParticipant,
    SupplementalAdmissionRegistrationContext,
};
use chio_kernel::supplemental_quota::{
    SupplementalQuotaVerificationContext, SupplementalQuotaVerificationRecord,
    SupplementalQuotaVerifier, SupplementalQuotaVerifierBinding, SupplementalQuotaVerifierError,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const MAX_BROKER_ROUTES: usize = 16;
const VERIFIER_ID: &str = "chio.secret-broker.route-quota-verifier.v1";
const PARTICIPANT_ID: &str = "chio.secret-broker.route-registration.v1";

/// Trusted composition inputs. Each audience names exactly one installed route.
/// Peers, receipt signers and signing authority never come from request data.
#[derive(Clone)]
pub struct BrokerRouteConfig {
    pub quota: BrokerQuotaVerifierConfig,
    pub ipc: BrokerIpcClientConfig,
    pub authority_signer: Arc<dyn SigningBackend>,
    pub revocation_authority_domain: String,
}

struct Route {
    verifier: BrokerQuotaVerifier,
    participant: Arc<BrokerAdmissionParticipant>,
}

/// Both verification and registration are installed from this same owner.
/// Adding/removing/rebinding any member changes the retained generation. Child
/// readers still check the original server/tool and audience, so the common
/// generation never authorizes one broker to observe another route's custody.
pub struct BrokerRouteSet {
    routes: BTreeMap<(String, String), Route>,
    verifier_binding: SupplementalQuotaVerifierBinding,
    participant_binding: SupplementalAdmissionAuthorityBindingV1,
}

impl BrokerRouteSet {
    pub fn new(mut configs: Vec<BrokerRouteConfig>, clock: Arc<dyn Clock>) -> Result<Self> {
        if configs.is_empty() || configs.len() > MAX_BROKER_ROUTES {
            return Err(rejected());
        }
        configs.sort_by(|a, b| {
            (&a.quota.server_id, &a.quota.tool_name).cmp(&(&b.quota.server_id, &b.quota.tool_name))
        });
        let mut servers = BTreeSet::new();
        let mut audiences = BTreeSet::new();
        let mut sockets = BTreeSet::new();
        let mut prepared = Vec::with_capacity(configs.len());
        for config in configs {
            // Capabilities sign the broker audience. Unique audiences prevent
            // substituting an otherwise identical capability on another route.
            if !servers.insert(config.quota.server_id.clone())
                || !audiences.insert(config.quota.audience.clone())
                || !sockets.insert(config.ipc.socket_path.clone())
            {
                return Err(rejected());
            }
            let verifier = BrokerQuotaVerifier::new(config.quota, clock.clone())?;
            prepared.push((
                verifier,
                config.ipc,
                config.authority_signer,
                config.revocation_authority_domain,
            ));
        }
        let quota_configs: Vec<_> = prepared
            .iter()
            .map(|(verifier, ..)| &verifier.config)
            .collect();
        let verifier_binding = SupplementalQuotaVerifierBinding {
            verifier_identity: VERIFIER_ID.into(),
            configuration_digest: hex::encode(Sha256::digest(canonical(&quota_configs)?)),
        };
        let mut members = Vec::with_capacity(prepared.len());
        for (mut verifier, ipc, signer, domain) in prepared {
            verifier.binding = verifier_binding.clone();
            let participant = BrokerAdmissionParticipant::new(ipc, signer, domain, &verifier)?;
            members.push((verifier, participant));
        }
        let identities: Vec<_> = members
            .iter()
            .map(|(verifier, participant)| {
                (&verifier.normalized_destination, participant.binding())
            })
            .collect();
        let participant_binding = SupplementalAdmissionAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("broker route participant", PARTICIPANT_ID)
                .map_err(|_| rejected())?,
            AdmissionDigest::try_new(
                "broker route configuration",
                hex::encode(Sha256::digest(canonical(&identities)?)),
            )
            .map_err(|_| rejected())?,
            AdmissionIdentifier::try_new("broker route verifier", VERIFIER_ID)
                .map_err(|_| rejected())?,
            AdmissionDigest::try_new(
                "broker route verifier configuration",
                &verifier_binding.configuration_digest,
            )
            .map_err(|_| rejected())?,
        );
        let routes = members
            .into_iter()
            .map(|(verifier, mut participant)| {
                participant.binding = participant_binding.clone();
                (
                    (participant.server_id.clone(), participant.tool_name.clone()),
                    Route {
                        verifier,
                        participant: Arc::new(participant),
                    },
                )
            })
            .collect();
        Ok(Self {
            routes,
            verifier_binding,
            participant_binding,
        })
    }

    #[must_use]
    pub fn verifier_binding(&self) -> &SupplementalQuotaVerifierBinding {
        &self.verifier_binding
    }

    #[must_use]
    pub fn participant_binding(&self) -> &SupplementalAdmissionAuthorityBindingV1 {
        &self.participant_binding
    }

    pub fn participant(&self, server: &str, tool: &str) -> Result<Arc<BrokerAdmissionParticipant>> {
        self.routes
            .iter()
            .find(|((s, t), _)| s == server && t == tool)
            .map(|(_, route)| route.participant.clone())
            .ok_or_else(rejected)
    }
}

impl SupplementalQuotaVerifier for BrokerRouteSet {
    fn verify(
        &self,
        bytes: &[u8],
        context: &SupplementalQuotaVerificationContext,
    ) -> std::result::Result<SupplementalQuotaVerificationRecord, SupplementalQuotaVerifierError>
    {
        self.routes
            .values()
            .find(|route| route.verifier.normalized_destination == context.normalized_destination)
            .ok_or_else(|| SupplementalQuotaVerifierError::new(rejected().diagnostic_code()))?
            .verifier
            .verify(bytes, context)
    }
}

impl SupplementalAdmissionParticipant for BrokerRouteSet {
    fn requires_registration(&self, server: &str, _tool: &str) -> bool {
        // Even an unrecognized tool on an installed broker server must not
        // evade supplemental authority by changing its requested tool name.
        self.routes.keys().any(|(selected, _)| selected == server)
    }

    fn register_original(
        &self,
        context: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> std::result::Result<(), SupplementalQuotaVerifierError> {
        self.participant(&context.request().server_id, &context.request().tool_name)
            .map_err(|error| SupplementalQuotaVerifierError::new(error.diagnostic_code()))?
            .register_original(context)
    }
}
