//! This service needs an advisory signer and explicit facts, not a kernel,
//! process runtime, disclosure issuer, provider or mutation port.
use crate::recovery::RecoveryRuntimeError;
use chio_core_types::{recovery::*, Ed25519Backend, SigningBackend};
use chio_recovery::{prepare_explanation_report, ExplanationAudience};
use chio_security_types::{recovery::*, InformationLabel};
use rand_core::{OsRng, RngCore};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const MAX_EXPLANATION_ACTORS: usize = 64;
const MAX_EXPLANATIONS_PER_WINDOW: u64 = 32;
const EXPLANATION_WINDOW_MS: u64 = 60_000;

mod cache;

struct Intake {
    started: u64,
    requests: u64,
}

/// Bounded active actor identities and fixed-window intake. Fully elapsed
/// windows expire; an active actor's probe allowance is never reset by eviction.
pub struct RecoveryExplanationService {
    pub(super) scope: RecoveryScopeV1,
    trust_domain: AuthorityDomainId,
    issuer: IssuerId,
    signer: Arc<Ed25519Backend>,
    pub(super) limits: ExplanationLimitsV1,
    intake: Mutex<BTreeMap<ActorId, Intake>>,
    graphs: Mutex<cache::GraphCache>,
}

#[derive(Clone)]
pub struct ProtectedRecoveryExplanationV1 {
    pub snapshot: RecoverySnapshotV1,
    pub registry: RecoveryRemedyRegistryV1,
    pub report: SignedRecoveryExplanationReportV1,
    pub view: SignedRecoveryExplanationViewV1,
    pub classification: InformationLabel,
    pub(super) audience_clearance: InformationLabel,
}
impl core::fmt::Debug for ProtectedRecoveryExplanationV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProtectedRecoveryExplanationV1([redacted])")
    }
}
impl core::fmt::Debug for RecoveryExplanationService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryExplanationService([redacted])")
    }
}
impl RecoveryExplanationService {
    pub fn new(
        scope: RecoveryScopeV1,
        trust_domain: AuthorityDomainId,
        issuer: IssuerId,
        signer: Arc<Ed25519Backend>,
        limits: ExplanationLimitsV1,
    ) -> Result<Self, RecoveryRuntimeError> {
        limits
            .validate()
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        if limits.work.get() < 2 {
            return Err(RecoveryRuntimeError::InvalidCommand);
        }
        Ok(Self {
            scope,
            trust_domain,
            issuer,
            signer,
            limits,
            intake: Mutex::new(BTreeMap::new()),
            graphs: Mutex::new(cache::GraphCache::new()?),
        })
    }
    pub fn public_key(&self) -> chio_core_types::PublicKey {
        self.signer.public_key()
    }

    pub(super) fn retain_native_graph(
        &self,
        workflow: &WorkflowId,
        artifact: ProtectedRecoveryExplanationV1,
        now: u64,
    ) -> Result<(), RecoveryRuntimeError> {
        artifact
            .snapshot
            .scope
            .ensure_matches(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        // Compact and measure outside the metadata lock. Each entry reserves
        // the same proved maximum, regardless of hidden label or evidence size.
        let graph = cache::compact(artifact)?;
        self.graphs
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .insert(workflow, graph, now)
    }

    pub(super) fn retained_native_graph(
        &self,
        workflow: &WorkflowId,
        reference: &ExplanationRef,
        now: u64,
    ) -> Result<Arc<ProtectedRecoveryExplanationV1>, RecoveryRuntimeError> {
        let (graph, expanded) = self
            .graphs
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .graph(workflow, reference, now)?;
        graph
            .scope()
            .ensure_matches(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        if let Some(expanded) = expanded {
            return Ok(expanded);
        }
        // Reconstruct exact original inputs and signatures, without observing,
        // planning or signing again, and without holding the cache lock.
        let expanded = Arc::new(graph.expand()?);
        self.graphs
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?
            .remember_expansion(workflow, reference, &graph, expanded, now)
    }

    /// Called by the authenticated host before loading any workflow. Per-actor
    /// availability depends on admitted requests, never on hidden membership.
    pub(super) fn admit(&self, actor: &ActorId, now: u64) -> Result<(), RecoveryRuntimeError> {
        let mut intake = self
            .intake
            .lock()
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        intake.retain(|_, entry| {
            now.checked_sub(entry.started)
                .is_none_or(|elapsed| elapsed < EXPLANATION_WINDOW_MS)
        });
        if !intake.contains_key(actor) && intake.len() >= MAX_EXPLANATION_ACTORS {
            return Err(RecoveryRuntimeError::Unavailable);
        }
        let entry = intake.entry(actor.clone()).or_insert(Intake {
            started: now,
            requests: 0,
        });
        let elapsed = now
            .checked_sub(entry.started)
            .ok_or(RecoveryRuntimeError::Unavailable)?;
        if elapsed >= EXPLANATION_WINDOW_MS {
            *entry = Intake {
                started: now,
                requests: 0,
            };
        }
        if entry.requests >= MAX_EXPLANATIONS_PER_WINDOW {
            return Err(RecoveryRuntimeError::Unavailable);
        }
        entry.requests = entry
            .requests
            .checked_add(1)
            .ok_or(RecoveryRuntimeError::Unavailable)?;
        Ok(())
    }

    /// Trusted dry-run API over already mediated facts. Its return object is
    /// classified; the network adapter returns only the separately signed view.
    pub fn evaluate(
        &self,
        snapshot: RecoverySnapshotV1,
        registry: RecoveryRemedyRegistryV1,
        audience: ExplanationAudience<'_>,
    ) -> Result<ProtectedRecoveryExplanationV1, RecoveryRuntimeError> {
        snapshot
            .scope
            .ensure_matches(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let invalid = |_| RecoveryRuntimeError::InvalidCommand;
        let snapshot = snapshot.normalized().map_err(invalid)?;
        let registry = registry.normalized(&snapshot).map_err(invalid)?;
        let report_ref = random_reference()?;
        let (view, body) = prepare_explanation_report(
            &snapshot,
            &registry,
            self.limits,
            &audience,
            &self.trust_domain,
            &self.issuer,
            report_ref,
        )
        .map_err(invalid)?;
        let mut classification = snapshot
            .context_label
            .join_restrictions(&registry.classification)
            .unwrap_or(InformationLabel::Top);
        for label in
            snapshot
                .observations
                .as_slice()
                .iter()
                .map(|fact| &fact.label)
                .chain(
                    registry.templates.as_slice().iter().flat_map(|template| {
                        [&template.classification, &template.disclosure_label]
                    }),
                )
        {
            classification = classification
                .join_restrictions(label)
                .unwrap_or(InformationLabel::Top);
        }
        // No lock or authority transaction spans signing.
        let report =
            SignedRecoveryExplanationReportV1::sign_with_backend(body, self.signer.as_ref())
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        let view = SignedRecoveryExplanationViewV1::sign_with_backend(view, self.signer.as_ref())
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        Ok(ProtectedRecoveryExplanationV1 {
            snapshot,
            registry,
            report,
            view,
            classification,
            audience_clearance: audience.clearance.clone(),
        })
    }
}

fn random_reference() -> Result<ExplanationRef, RecoveryRuntimeError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| RecoveryRuntimeError::Unavailable)?;
    let reference = format!(
        "advice:{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    ExplanationRef::new(&reference).map_err(|_| RecoveryRuntimeError::Unavailable)
}

#[cfg(test)]
mod cache_tests;

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn service() -> Result<RecoveryExplanationService, Box<dyn std::error::Error>> {
        Ok(RecoveryExplanationService::new(
            RecoveryScopeV1 {
                authority_domain: AuthorityDomainId::new("advisory-scope")?,
                tenant_id: RecoveryTenantId::new("tenant")?,
                process_id: ProcessId::new("process")?,
            },
            AuthorityDomainId::new("advisory-trust")?,
            IssuerId::new("advisory-issuer")?,
            Arc::new(Ed25519Backend::new(chio_core_types::Keypair::from_seed(
                &[83; 32],
            ))),
            ExplanationLimitsV1 {
                offers: SafeInteger::new(16)?,
                work: SafeInteger::new(4096)?,
            },
        )?)
    }

    #[test]
    fn explanation_intake_reclaims_fully_elapsed_actor_windows() -> TestResult {
        let service = service()?;
        for index in 0..MAX_EXPLANATION_ACTORS {
            service.admit(&ActorId::new(&format!("actor:{index}"))?, 0)?;
        }
        let next = ActorId::new("newly-assigned-actor")?;
        assert!(service.admit(&next, EXPLANATION_WINDOW_MS - 1).is_err());
        assert!(service.admit(&next, EXPLANATION_WINDOW_MS).is_ok());
        assert!(
            service.intake.lock().map_err(|_| "poisoned intake")?.len() <= MAX_EXPLANATION_ACTORS
        );
        Ok(())
    }

    #[test]
    fn explanation_intake_never_reclaims_an_active_probe_allowance() -> TestResult {
        let service = service()?;
        let active = ActorId::new("active")?;
        for _ in 0..MAX_EXPLANATIONS_PER_WINDOW {
            service.admit(&active, EXPLANATION_WINDOW_MS - 1)?;
        }
        for index in 1..MAX_EXPLANATION_ACTORS {
            service.admit(&ActorId::new(&format!("actor:{index}"))?, 0)?;
        }
        service.admit(
            &ActorId::new("newly-assigned-actor")?,
            EXPLANATION_WINDOW_MS,
        )?;
        assert!(service.admit(&active, EXPLANATION_WINDOW_MS).is_err());
        assert!(service.admit(&active, EXPLANATION_WINDOW_MS - 2).is_err());
        assert!(service
            .admit(&active, EXPLANATION_WINDOW_MS * 2 - 1)
            .is_ok());
        Ok(())
    }
}
