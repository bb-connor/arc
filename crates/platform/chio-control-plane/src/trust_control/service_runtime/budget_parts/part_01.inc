use super::client::{
    build_client, BudgetCostMutationRequest, BudgetMutationParts, BudgetSpendMutationRequest,
};
use super::errors::{into_budget_store_error, into_replay_budget_store_error};
use super::*;

#[derive(Debug, Clone)]
struct RemoteExactMutationEvent {
    record: BudgetMutationRecord,
    partition_escrow_evidence: Option<PartitionEscrowCommitEvidence>,
}

const MAX_REMOTE_COMPOSITE_HOLDS: usize = 4_096;

pub fn build_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn BudgetStore>, CliError> {
    Ok(Box::new(remote_budget_store(control_url, control_token)?))
}

#[cfg(test)]
pub(crate) fn build_shared_remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<Arc<RemoteBudgetStore>, CliError> {
    remote_budget_store(control_url, control_token).map(Arc::new)
}

fn remote_budget_store(
    control_url: &str,
    control_token: &str,
) -> Result<RemoteBudgetStore, CliError> {
    Ok(RemoteBudgetStore {
        client: build_client(control_url, control_token)?,
        partition_escrow_authority: None,
        cached_usage: Mutex::new(HashMap::new()),
        composite_holds: Arc::new(Mutex::new(HashMap::new())),
    })
}

pub fn build_remote_admission_capture_authority(
    control_url: &str,
    control_token: &str,
) -> Result<Box<dyn AdmissionCaptureAuthority>, CliError> {
    Ok(Box::new(RemoteAdmissionCaptureAuthority {
        client: build_client(control_url, control_token)?,
        partition_escrow_authority: None,
        composite_holds: Arc::new(Mutex::new(HashMap::new())),
    }))
}

pub struct PartitionEscrowRemoteAuthorityComposition {
    pub budget_store: Box<dyn BudgetStore>,
    pub admission_capture_authority: Arc<dyn AdmissionCaptureAuthority>,
    pub registry: Arc<chio_kernel::partition_escrow::PartitionEscrowRegistry>,
}

pub fn build_partition_escrow_remote_authority_composition(
    control_url: &str,
    control_token: &str,
    authority: Arc<SealedPartitionEscrowRemoteAuthority>,
) -> Result<PartitionEscrowRemoteAuthorityComposition, CliError> {
    let budget_client = build_client(control_url, control_token)?;
    validate_sealed_remote_client_endpoints(&budget_client, authority.as_ref())?;
    let capture_client = build_client(control_url, control_token)?;
    validate_sealed_remote_client_endpoints(&capture_client, authority.as_ref())?;
    let composite_holds = Arc::new(Mutex::new(HashMap::new()));
    Ok(PartitionEscrowRemoteAuthorityComposition {
        budget_store: Box::new(RemoteBudgetStore {
            client: budget_client,
            partition_escrow_authority: Some(Arc::clone(&authority)),
            cached_usage: Mutex::new(HashMap::new()),
            composite_holds: Arc::clone(&composite_holds),
        }),
        admission_capture_authority: Arc::new(RemoteAdmissionCaptureAuthority {
            client: capture_client,
            partition_escrow_authority: Some(Arc::clone(&authority)),
            composite_holds,
        }),
        registry: Arc::clone(authority.registry()),
    })
}

fn validate_sealed_remote_client_endpoints(
    client: &TrustControlClient,
    authority: &SealedPartitionEscrowRemoteAuthority,
) -> Result<(), CliError> {
    let mut endpoints = client.endpoints.as_ref().clone();
    endpoints.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if endpoints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CliError::cli_other_error(
            "partition escrow remote authority endpoints must be unique".to_string(),
        ));
    }
    authority.validate_service_endpoints(&endpoints)
}

fn current_unix_seconds_for_partition_escrow() -> Result<u64, BudgetStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "system clock is before the Unix epoch while validating partition escrow: {error}"
            ))
        })
}

impl AdmissionCaptureAuthority for RemoteAdmissionCaptureAuthority {
    fn query_admission_capture(
        &self,
        request: &AdmissionCaptureRequest,
    ) -> Result<Option<AdmissionCaptureDecision>, AdmissionCaptureError> {
        let expected = self.expected_partition_escrow_evidence(request)?;
        let capture_request = remote_admission_capture_wire_request(request)?;
        let response = self
            .client
            .query_admission_capture(&AdmissionCapturePointQueryRequest { capture_request })
            .map_err(|error| AdmissionCaptureError::Unavailable(error.to_string()))?;
        let admission_operation =
            request
                .budget()
                .admission_operation
                .as_ref()
                .ok_or_else(|| {
                    AdmissionCaptureError::InvalidRequest(
                        "remote admission capture query requires admission operation ownership"
                            .to_string(),
                    )
                })?;
        if response.operation_id != request.operation_id()
            || response.request_binding_hash != admission_operation.request_binding_hash()
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "remote admission capture query response changed its operation binding".to_string(),
            ));
        }
        let response = response
            .capture
            .map(|capture| {
                self.validate_admission_capture_response(request, capture, expected.as_ref())
            })
            .transpose()?;
        if let Some(decision) = response.as_ref() {
            self.remember_admission_capture(request, decision)?;
        }
        Ok(response)
    }

    fn capture_admission(
        &self,
        request: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        let expected = self.expected_partition_escrow_evidence(&request)?;
        let wire_request = remote_admission_capture_wire_request(&request)?;
        let response = self
            .client
            .capture_admission(&wire_request)
            .map_err(|error| AdmissionCaptureError::Unavailable(error.to_string()))?;
        let decision =
            self.validate_admission_capture_response(&request, response, expected.as_ref())?;
        self.remember_admission_capture(&request, &decision)?;
        Ok(decision)
    }
}

impl RemoteAdmissionCaptureAuthority {
    fn validate_admission_capture_response(
        &self,
        request: &AdmissionCaptureRequest,
        response: CombinedAdmissionCaptureResponse,
        expected: Option<&PartitionEscrowCommitEvidence>,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        let decision = validate_remote_admission_capture_response_for_authority(
            request,
            response,
            self.partition_escrow_authority.as_deref(),
            expected,
        )?;
        if let AdmissionCaptureDecision::Captured { budget, .. } = &decision {
            let event_id = request.budget().event_id.as_deref().ok_or_else(|| {
                AdmissionCaptureError::InvalidRequest(
                    "remote admission capture request omitted event_id".to_string(),
                )
            })?;
            let record = RemoteBudgetStore::query_exact_remote_mutation_event_with_context(
                &self.client,
                self.partition_escrow_authority.as_deref(),
                &self.composite_holds,
                event_id,
            )?
            .ok_or_else(|| {
                AdmissionCaptureError::InvalidRequest(
                    "remote admission capture has no quorum-attested durable budget event"
                        .to_string(),
                )
            })?;
            validate_exact_remote_mutation_decision(
                &record,
                budget,
                BudgetMutationKind::CaptureInvocations,
                request.budget().admission_operation.as_ref(),
            )?;
        }
        Ok(decision)
    }

    fn expected_partition_escrow_evidence(
        &self,
        request: &AdmissionCaptureRequest,
    ) -> Result<Option<PartitionEscrowCommitEvidence>, AdmissionCaptureError> {
        let Some(authority) = self.partition_escrow_authority.as_deref() else {
            return Ok(None);
        };
        authority.verify_persisted_configuration()?;
        let budget = request.budget();
        let hold_id = budget.hold_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "sealed remote admission capture requires hold_id".to_string(),
            )
        })?;
        let expected = cached_remote_composite_hold(&self.composite_holds, hold_id).ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(format!(
                "sealed remote admission capture has no exact cached authorization for hold `{hold_id}`"
            ))
        })?;
        if expected.capability_id != budget.capability_id
            || expected.grant_index != budget.grant_index
            || budget.authority.as_ref() != Some(&expected.authority)
            || budget.admission_operation.as_ref() != Some(&expected.admission_operation)
            || request.revocation_set() != &expected.revocation_set
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "sealed remote admission capture changed its cached authorization binding"
                    .to_string(),
            ));
        }
        let evidence = expected.partition_escrow_evidence.ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "sealed remote admission capture cached authorization omitted its partition proof"
                    .to_string(),
            )
        })?;
        authority.validate_persisted_commit_evidence(&evidence)?;
        Ok(Some(evidence))
    }

    fn remember_admission_capture(
        &self,
        request: &AdmissionCaptureRequest,
        decision: &AdmissionCaptureDecision,
    ) -> Result<(), AdmissionCaptureError> {
        let AdmissionCaptureDecision::Captured { budget, .. } = decision else {
            return Ok(());
        };
        let hold_id = request.budget().hold_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "remote admission capture request omitted hold_id".to_string(),
            )
        })?;
        update_remote_composite_hold(&self.composite_holds, hold_id, |expected| {
            let Some(event) = next_remote_composite_event(expected, budget)? else {
                return Ok(());
            };
            if budget.invocation_state != BudgetInvocationReservationState::Captured
                || budget.monetary_state != expected.monetary_state
                || budget.revocation_set.as_ref() != Some(&expected.revocation_set)
                || budget.metadata.partition_escrow_evidence != expected.partition_escrow_evidence
            {
                return Err(BudgetStoreError::Conflict(
                    "remote admission capture changed its cached composite evidence".to_string(),
                ));
            }
            if expected.invocation_state != BudgetInvocationReservationState::Authorized {
                return Err(BudgetStoreError::Conflict(
                    "remote admission capture cached an ineligible invocation state".to_string(),
                ));
            }
            validate_exact_invocation_capture_transition(
                &expected.invocation_counts_after,
                &budget.invocation_counts_after,
            )?;
            expected.invocation_counts_after = budget.invocation_counts_after.clone();
            expected.invocation_state = budget.invocation_state;
            expected.monetary_state = budget.monetary_state;
            finish_remote_composite_event(expected, event);
            Ok(())
        })?;
        Ok(())
    }
}

fn remote_admission_capture_wire_request(
    request: &AdmissionCaptureRequest,
) -> Result<CombinedAdmissionCaptureRequest, AdmissionCaptureError> {
    let budget = request.budget();
    let hold_id = budget.hold_id.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires hold_id".to_string(),
        )
    })?;
    let event_id = budget.event_id.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires event_id".to_string(),
        )
    })?;
    let authority = budget.authority.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires persisted authority".to_string(),
        )
    })?;
    let admission_operation = budget.admission_operation.as_ref().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "remote admission capture requires admission operation ownership".to_string(),
        )
    })?;
    Ok(CombinedAdmissionCaptureRequest {
        operation_id: request.operation_id().to_string(),
        request_binding_hash: admission_operation.request_binding_hash().to_string(),
        capability_id: budget.capability_id.clone(),
        grant_index: budget.grant_index,
        hold_id: hold_id.clone(),
        event_id: event_id.clone(),
        budget_authority: Some(BudgetMutationAuthorityView {
            authority_id: authority.authority_id.clone(),
            lease_id: authority.lease_id.clone(),
            lease_epoch: authority.lease_epoch,
        }),
        revocation_set: canonical_revocation_set_view(request.revocation_set()),
        bound_revocation_set_digest: request.bound_revocation_set_digest().to_string(),
        authorization_artifact_digests: request.authorization_artifact_digests().to_vec(),
        aggregate_root_capability_id: request
            .aggregate_root_capability_id()
            .map(ToOwned::to_owned),
        aggregate_root_binding_digest: request
            .aggregate_root_binding_digest()
            .map(ToOwned::to_owned),
        last_observed_revocation_index: request.last_observed_revocation_index(),
    })
}

impl BudgetStore for RemoteBudgetStore {
    fn authority_profile(&self) -> BudgetStoreProfile {
        BudgetStoreProfile::SharedLinearizable
    }

    fn budget_guarantee_level(&self) -> BudgetGuaranteeLevel {
        if self.partition_escrow_authority.is_some() {
            BudgetGuaranteeLevel::PartitionEscrowed
        } else {
            BudgetGuaranteeLevel::HaLinearizable
        }
    }

    fn partition_escrow_store_binding(
        &self,
    ) -> Result<Option<chio_kernel::budget_store::PartitionEscrowStoreBinding>, BudgetStoreError>
    {
        self.partition_escrow_authority
            .as_deref()
            .map(|authority| {
                authority.verify_persisted_configuration()?;
                Ok(authority.store_binding().clone())
            })
            .transpose()
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("try_increment")?;
        let response = self
            .client
            .try_increment_budget(capability_id, grant_index, max_invocations)
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            None,
            None,
        );
        Ok(response.allowed)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("try_charge_cost")?;
        let response = self
            .client
            .try_charge_cost(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(response.allowed)
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        _authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("try_charge_cost_with_ids")?;
        let response = self
            .client
            .try_charge_cost_with_ids(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_usage(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(response.allowed)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("reverse_charge_cost")?;
        let response = self
            .client
            .reverse_charge_cost(capability_id, grant_index, cost_units)
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("reverse_charge_cost_with_ids")?;
        let response = self
            .client
            .reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            authority,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("reduce_charge_cost")?;
        let response = self
            .client
            .reduce_charge_cost(capability_id, grant_index, cost_units)
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("reduce_charge_cost_with_ids")?;
        let response = self
            .client
            .reduce_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            authority,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("settle_charge_cost")?;
        let response = self
            .client
            .reconcile_budget_spend(
                capability_id,
                grant_index,
                exposed_cost_units,
                realized_cost_units,
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.reject_legacy_partition_escrow_path("settle_charge_cost_with_ids")?;
        let response = self
            .client
            .reconcile_budget_spend_with_ids_and_authority(BudgetSpendMutationRequest::new(
                BudgetMutationParts::new(capability_id, grant_index, hold_id, event_id, authority),
                exposed_cost_units,
                realized_cost_units,
            ))
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            authority,
        )?;
        self.cache_terminal_response(
            capability_id,
            grant_index,
            evidence.commit_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        );
        Ok(())
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "snapshot-derived authorization requires the committed replay operation"
                    .to_string(),
            ));
        }
        if request.invocation_admission_evidence().is_some() {
            return self.authorize_remote_composite_budget_hold(request, false);
        }
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            return Err(BudgetStoreError::Invariant(
                "remote composite budget request contains incomplete admission evidence"
                    .to_string(),
            ));
        }
        self.reject_legacy_partition_escrow_path("authorize_budget_hold")?;
        let response = self
            .client
            .try_charge_cost_with_ids(
                &request.capability_id,
                request.grant_index,
                request.max_invocations,
                request.requested_exposure_units,
                request.max_cost_per_invocation,
                request.max_total_cost_units,
                request.hold_id.as_deref(),
                request.event_id.as_deref(),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            None,
        )?;
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        let metadata = self.remote_budget_commit_metadata(&evidence, request.event_id.clone());
        let authorized_monetary_state = if request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        if response.allowed {
            self.cache_terminal_usage(
                &request.capability_id,
                request.grant_index,
                evidence.commit_index,
                invocation_count,
                total_cost_exposed,
                total_cost_realized_spend,
            );
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: request.hold_id,
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after: invocation_count,
                    invocation_counts_after: Vec::new(),
                    invocation_state: BudgetInvocationReservationState::Absent,
                    monetary_state: authorized_monetary_state,
                    revocation_set: None,
                    metadata,
                },
            ))
        } else {
            self.cache_usage(
                &request.capability_id,
                request.grant_index,
                None,
                None,
                None,
                None,
            );
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: request.hold_id,
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: invocation_count,
                invocation_counts_after: Vec::new(),
                invocation_state: BudgetInvocationReservationState::Denied,
                monetary_state: BudgetMonetaryHoldState::None,
                revocation_set: None,
                metadata,
            }))
        }
    }

    fn replay_budget_authorization(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if !request.requires_existing_authorization_replay() {
            return Err(BudgetStoreError::Invariant(
                "committed replay requires a snapshot-derived authorization request".to_string(),
            ));
        }
        if request.invocation_admission_evidence().is_none() {
            return Err(BudgetStoreError::Invariant(
                "remote committed replay requires verified composite admission evidence"
                    .to_string(),
            ));
        }
        self.authorize_remote_composite_budget_hold(request, true)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.capture_remote_invocation_reservations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote invocation capture query requires hold_id".to_string(),
            )
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote invocation capture query requires event_id".to_string(),
            )
        })?;
        let expected = self.cached_composite_hold(hold_id).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "remote invocation capture query has no exact cached evidence for hold `{hold_id}`"
            ))
        })?;
        if expected.capability_id != request.capability_id
            || expected.grant_index != request.grant_index
            || request.authority.as_ref() != Some(&expected.authority)
            || request.admission_operation.as_ref() != Some(&expected.admission_operation)
        {
            return Err(BudgetStoreError::Conflict(
                "remote invocation capture query changed the persisted operation binding"
                    .to_string(),
            ));
        }
        let capture_request = CaptureInvocationReservationsRequest {
            operation_id: expected.admission_operation.operation_id().to_string(),
            request_binding_hash: expected
                .admission_operation
                .request_binding_hash()
                .to_string(),
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: expected.authority.authority_id.clone(),
                lease_id: expected.authority.lease_id.clone(),
                lease_epoch: expected.authority.lease_epoch,
            }),
        };
        let response = self
            .client
            .query_invocation_capture(&CaptureInvocationPointQueryRequest { capture_request })
            .map_err(into_budget_store_error)?;
        if response.operation_id != expected.admission_operation.operation_id()
            || response.request_binding_hash != expected.admission_operation.request_binding_hash()
        {
            return Err(BudgetStoreError::Conflict(
                "remote invocation capture query response changed its operation binding"
                    .to_string(),
            ));
        }
        let decision = response
            .capture
            .map(|capture| {
                validate_invocation_capture_response_for_authority(
                    request,
                    &expected.invocation_quotas,
                    &expected.revocation_set,
                    expected.monetary_state,
                    capture,
                    self.partition_escrow_authority.as_deref(),
                    expected.partition_escrow_evidence.as_ref(),
                )
            })
            .transpose()?;
        if let Some(decision) = decision.as_ref() {
            self.validate_and_remember_invocation_capture(request, decision)?;
            self.cache_usage(
                &request.capability_id,
                request.grant_index,
                None,
                None,
                None,
                None,
            );
        }
        Ok(decision)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let expected_kind = if request.admission_operation.is_some() {
            BudgetMutationKind::ReverseInvocations
        } else {
            BudgetMutationKind::ReverseExposure
        };
        let replay_composite = request
            .hold_id
            .as_deref()
            .and_then(|hold_id| self.cached_composite_hold(hold_id));
        if let Some(decision) = self.replay_remote_terminal_if_committed(
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            expected_kind,
            request.reversed_exposure_units,
            0,
            replay_composite.as_ref(),
        )? {
            return Ok(decision);
        }
        let composite = self.composite_hold_for_terminal(
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            "composite reverse",
        )?;
        if let Some(expected) = composite.as_ref() {
            if expected.invocation_state != BudgetInvocationReservationState::Authorized {
                return Err(BudgetStoreError::Conflict(
                    "remote composite reverse cached an ineligible invocation state".to_string(),
                ));
            }
            let exposure_matches = match expected.monetary_state {
                BudgetMonetaryHoldState::Exposed => {
                    request.reversed_exposure_units == expected.remaining_exposure_units
                }
                BudgetMonetaryHoldState::None
                | BudgetMonetaryHoldState::Released
                | BudgetMonetaryHoldState::Reversed => request.reversed_exposure_units == 0,
                BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => false,
            };
            if !exposure_matches {
                return Err(BudgetStoreError::Conflict(
                    "remote composite reverse does not match the cached monetary hold".to_string(),
                ));
            }
        }
        let response = self
            .client
            .reverse_charge_cost_with_ids_authority_and_operation(BudgetCostMutationRequest::new(
                BudgetMutationParts::new(
                    &request.capability_id,
                    request.grant_index,
                    request.hold_id.as_deref(),
                    request.event_id.as_deref(),
                    request.authority.as_ref(),
                )
                .with_admission_operation(request.admission_operation.as_ref()),
                request.reversed_exposure_units,
            ))
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence_for_authority(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            self.partition_escrow_authority.as_deref(),
            composite
                .as_ref()
                .and_then(|expected| expected.partition_escrow_evidence.as_ref()),
            RemoteEscrowEvidenceValidation::PersistedMutation,
        )?;
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        let (invocation_counts_after, invocation_state, monetary_state, revocation_set) =
            if let Some(expected) = composite.as_ref() {
                let mut invocation_counts_after = expected.invocation_counts_after.clone();
                for usage in &mut invocation_counts_after {
                    usage.reserved_invocations_after = usage
                        .reserved_invocations_after
                        .checked_sub(1)
                        .ok_or_else(|| {
                            BudgetStoreError::Invariant(
                                "remote composite reverse has no reserved invocation to release"
                                    .to_string(),
                            )
                        })?;
                    usage.validate()?;
                }
                validate_primary_invocation_count(
                    &request.capability_id,
                    request.grant_index,
                    invocation_count,
                    &invocation_counts_after,
                )?;
                let monetary_state = match expected.monetary_state {
                    BudgetMonetaryHoldState::Exposed => BudgetMonetaryHoldState::Reversed,
                    BudgetMonetaryHoldState::None
                    | BudgetMonetaryHoldState::Released
                    | BudgetMonetaryHoldState::Reversed => expected.monetary_state,
                    BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                        return Err(BudgetStoreError::Conflict(
                            "remote composite reverse cached an ineligible monetary state"
                                .to_string(),
                        ));
                    }
                };
                (
                    invocation_counts_after,
                    BudgetInvocationReservationState::Reversed,
                    monetary_state,
                    Some(expected.revocation_set.clone()),
                )
            } else {
                (
                    Vec::new(),
                    BudgetInvocationReservationState::Reversed,
                    if request.reversed_exposure_units == 0 {
                        BudgetMonetaryHoldState::None
                    } else {
                        BudgetMonetaryHoldState::Reversed
                    },
                    None,
                )
            };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after,
            invocation_state,
            monetary_state,
            revocation_set,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        };
        self.validate_remote_terminal_decision(
            &decision,
            expected_kind,
            request.admission_operation.as_ref(),
        )?;
        if composite.is_some() {
            self.apply_exact_remote_composite_mutation(
                &decision,
                BudgetMutationKind::ReverseInvocations,
            )?;
            if let Some(hold_id) = decision.hold_id.as_deref() {
                self.forget_composite_hold(hold_id);
            }
        }
        Ok(decision)
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let replay_composite = request
            .hold_id
            .as_deref()
            .and_then(|hold_id| self.cached_composite_hold(hold_id));
        if let Some(decision) = self.replay_remote_terminal_if_committed(
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            BudgetMutationKind::ReleaseExposure,
            request.released_exposure_units,
            0,
            replay_composite.as_ref(),
        )? {
            return Ok(decision);
        }
        let composite = self.composite_hold_for_terminal(
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            "composite release",
        )?;
        if let Some(expected) = composite.as_ref() {
            if expected.monetary_state != BudgetMonetaryHoldState::Exposed
                || request.released_exposure_units > expected.remaining_exposure_units
                || !matches!(
                    expected.invocation_state,
                    BudgetInvocationReservationState::Authorized
                        | BudgetInvocationReservationState::Captured
                )
            {
                return Err(BudgetStoreError::Conflict(
                    "remote composite release does not match its cached hold state".to_string(),
                ));
            }
        }
        let response = self
            .client
            .reduce_charge_cost_with_ids_authority_and_operation(BudgetCostMutationRequest::new(
                BudgetMutationParts::new(
                    &request.capability_id,
                    request.grant_index,
                    request.hold_id.as_deref(),
                    request.event_id.as_deref(),
                    request.authority.as_ref(),
                )
                .with_admission_operation(request.admission_operation.as_ref()),
                request.released_exposure_units,
            ))
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence_for_authority(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            self.partition_escrow_authority.as_deref(),
            composite
                .as_ref()
                .and_then(|expected| expected.partition_escrow_evidence.as_ref()),
            RemoteEscrowEvidenceValidation::PersistedMutation,
        )?;
        if response.released_exposure_units != Some(request.released_exposure_units) {
            return Err(BudgetStoreError::Invariant(
                "remote budget release response does not match released exposure".to_string(),
            ));
        }
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        let (invocation_counts_after, invocation_state, monetary_state, revocation_set) =
            if let Some(expected) = composite.as_ref() {
                validate_primary_invocation_count(
                    &request.capability_id,
                    request.grant_index,
                    invocation_count,
                    &expected.invocation_counts_after,
                )?;
                let remaining = expected
                    .remaining_exposure_units
                    .checked_sub(request.released_exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "remote composite release exceeded cached remaining exposure"
                                .to_string(),
                        )
                    })?;
                (
                    expected.invocation_counts_after.clone(),
                    expected.invocation_state,
                    if remaining == 0 {
                        BudgetMonetaryHoldState::Released
                    } else {
                        BudgetMonetaryHoldState::Exposed
                    },
                    Some(expected.revocation_set.clone()),
                )
            } else {
                (
                    Vec::new(),
                    BudgetInvocationReservationState::Absent,
                    BudgetMonetaryHoldState::Released,
                    None,
                )
            };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after,
            invocation_state,
            monetary_state,
            revocation_set,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        };
        self.validate_remote_terminal_decision(
            &decision,
            BudgetMutationKind::ReleaseExposure,
            request.admission_operation.as_ref(),
        )?;
        if composite.is_some() {
            self.apply_exact_remote_composite_mutation(
                &decision,
                BudgetMutationKind::ReleaseExposure,
            )?;
            if decision.monetary_state == BudgetMonetaryHoldState::Released {
                if let Some(hold_id) = decision.hold_id.as_deref() {
                    self.forget_composite_hold(hold_id);
                }
            }
        }
        Ok(decision)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let replay_composite = request
            .hold_id
            .as_deref()
            .and_then(|hold_id| self.cached_composite_hold(hold_id));
        if let Some(decision) = self.replay_remote_terminal_if_committed(
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            BudgetMutationKind::ReconcileSpend,
            request.exposed_cost_units,
            request.realized_spend_units,
            replay_composite.as_ref(),
        )? {
            return Ok(decision);
        }
        let composite = self.composite_hold_for_terminal(
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            "composite reconciliation",
        )?;
        if let Some(expected) = composite.as_ref() {
            if expected.monetary_state != BudgetMonetaryHoldState::Exposed
                || request.exposed_cost_units != expected.remaining_exposure_units
                || !matches!(
                    expected.invocation_state,
                    BudgetInvocationReservationState::Authorized
                        | BudgetInvocationReservationState::Captured
                )
            {
                return Err(BudgetStoreError::Conflict(
                    "remote composite reconciliation does not match its cached hold state"
                        .to_string(),
                ));
            }
        }
        let response = self
            .client
            .reconcile_budget_spend_with_ids_authority_and_operation(
                BudgetSpendMutationRequest::new(
                    BudgetMutationParts::new(
                        &request.capability_id,
                        request.grant_index,
                        request.hold_id.as_deref(),
                        request.event_id.as_deref(),
                        request.authority.as_ref(),
                    )
                    .with_admission_operation(request.admission_operation.as_ref()),
                    request.exposed_cost_units,
                    request.realized_spend_units,
                ),
            )
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence_for_authority(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            self.partition_escrow_authority.as_deref(),
            composite
                .as_ref()
                .and_then(|expected| expected.partition_escrow_evidence.as_ref()),
            RemoteEscrowEvidenceValidation::PersistedMutation,
        )?;
        let expected_released_exposure = request
            .exposed_cost_units
            .checked_sub(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "realized spend cannot exceed reconciled exposure".to_string(),
                )
            })?;
        if response.released_exposure_units != Some(expected_released_exposure) {
            return Err(BudgetStoreError::Invariant(
                "remote budget reconcile response does not match released exposure".to_string(),
            ));
        }
        let (
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
            committed_cost_units_after,
        ) = required_remote_transition_snapshot(
            &request.capability_id,
            request.grant_index,
            &response.capability_id,
            response.grant_index,
            response.invocation_count,
            response.total_cost_exposed,
            response.total_cost_realized_spend,
        )?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        let (invocation_counts_after, invocation_state, revocation_set) =
            if let Some(expected) = composite.as_ref() {
                validate_primary_invocation_count(
                    &request.capability_id,
                    request.grant_index,
                    invocation_count,
                    &expected.invocation_counts_after,
                )?;
                (
                    expected.invocation_counts_after.clone(),
                    expected.invocation_state,
                    Some(expected.revocation_set.clone()),
                )
            } else {
                (Vec::new(), BudgetInvocationReservationState::Absent, None)
            };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after,
            invocation_state,
            monetary_state: BudgetMonetaryHoldState::Reconciled,
            revocation_set,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        };
        self.validate_remote_terminal_decision(
            &decision,
            BudgetMutationKind::ReconcileSpend,
            request.admission_operation.as_ref(),
        )?;
        if composite.is_some() {
            self.apply_exact_remote_composite_mutation(
                &decision,
                BudgetMutationKind::ReconcileSpend,
            )?;
            if let Some(hold_id) = decision.hold_id.as_deref() {
                self.forget_composite_hold(hold_id);
            }
        }
        Ok(decision)
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let replay_composite = request
            .hold_id
            .as_deref()
            .and_then(|hold_id| self.cached_composite_hold(hold_id));
        if let Some(decision) = self.replay_remote_terminal_if_committed(
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            BudgetMutationKind::CaptureExposure,
            request.exposed_cost_units,
            request.realized_spend_units,
            replay_composite.as_ref(),
        )? {
            return Ok(decision);
        }
        let composite = self.composite_hold_for_terminal(
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.admission_operation.as_ref(),
            "composite monetary capture",
        )?;
        if let Some(expected) = composite.as_ref() {
            if expected.monetary_state != BudgetMonetaryHoldState::Exposed
                || request.exposed_cost_units != expected.remaining_exposure_units
                || !matches!(
                    expected.invocation_state,
                    BudgetInvocationReservationState::Authorized
                        | BudgetInvocationReservationState::Captured
                )
            {
                return Err(BudgetStoreError::Conflict(
                    "remote composite monetary capture does not match its cached hold state"
                        .to_string(),
                ));
            }
        }
        let response = self
            .client
            .capture_budget_spend_with_ids_and_operation(BudgetSpendMutationRequest::new(
                BudgetMutationParts::new(
                    &request.capability_id,
                    request.grant_index,
                    request.hold_id.as_deref(),
                    request.event_id.as_deref(),
                    request.authority.as_ref(),
                )
                .with_admission_operation(request.admission_operation.as_ref()),
                request.exposed_cost_units,
                request.realized_spend_units,
            ))
            .map_err(into_budget_store_error)?;
        let evidence = validate_remote_budget_evidence_for_authority(
            response.budget_authority.as_ref(),
            response.budget_commit.as_ref(),
            request.authority.as_ref(),
            self.partition_escrow_authority.as_deref(),
            composite
                .as_ref()
                .and_then(|expected| expected.partition_escrow_evidence.as_ref()),
            RemoteEscrowEvidenceValidation::PersistedMutation,
        )?;
        if response.capability_id != request.capability_id
            || response.grant_index != request.grant_index
        {
            return Err(BudgetStoreError::Invariant(
                "remote budget capture response does not match capability/grant".to_string(),
            ));
        }
        let expected_released_exposure = request
            .exposed_cost_units
            .checked_sub(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "realized spend cannot exceed captured exposure".to_string(),
                )
            })?;
        if response.released_exposure_units != Some(expected_released_exposure) {
            return Err(BudgetStoreError::Invariant(
                "remote budget capture response does not match released exposure".to_string(),
            ));
        }
        let invocation_count = response.invocation_count.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget capture response omitted invocation_count".to_string(),
            )
        })?;
        let total_cost_exposed = response.total_cost_exposed.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget capture response omitted total exposed cost".to_string(),
            )
        })?;
        let total_cost_realized_spend = response.total_cost_realized_spend.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "remote budget capture response omitted total realized spend".to_string(),
            )
        })?;
        let committed_cost_units_after = total_cost_exposed
            .checked_add(total_cost_realized_spend)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "remote captured committed cost overflowed u64".to_string(),
                )
            })?;
        self.cache_terminal_usage(
            &request.capability_id,
            request.grant_index,
            evidence.commit_index,
            invocation_count,
            total_cost_exposed,
            total_cost_realized_spend,
        );
        let (invocation_counts_after, invocation_state, revocation_set) =
            if let Some(expected) = composite.as_ref() {
                validate_primary_invocation_count(
                    &request.capability_id,
                    request.grant_index,
                    invocation_count,
                    &expected.invocation_counts_after,
                )?;
                (
                    expected.invocation_counts_after.clone(),
                    expected.invocation_state,
                    Some(expected.revocation_set.clone()),
                )
            } else {
                (Vec::new(), BudgetInvocationReservationState::Absent, None)
            };
        let decision = BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after,
            invocation_state,
            monetary_state: BudgetMonetaryHoldState::Captured,
            revocation_set,
            metadata: self.remote_budget_commit_metadata(&evidence, request.event_id),
        };
        self.validate_remote_terminal_decision(
            &decision,
            BudgetMutationKind::CaptureExposure,
            request.admission_operation.as_ref(),
        )?;
        if composite.is_some() {
            self.apply_exact_remote_composite_mutation(
                &decision,
                BudgetMutationKind::CaptureExposure,
            )?;
            if let Some(hold_id) = decision.hold_id.as_deref() {
                self.forget_composite_hold(hold_id);
            }
        }
        Ok(decision)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.client
            .list_budgets(&BudgetQuery {
                capability_id: capability_id.map(ToOwned::to_owned),
                limit: Some(limit),
            })
            .map(|response| {
                let usages: Vec<_> = response
                    .usages
                    .into_iter()
                    .map(|usage| BudgetUsageRecord {
                        capability_id: usage.capability_id,
                        grant_index: usage.grant_index,
                        invocation_count: usage.invocation_count,
                        updated_at: usage.updated_at,
                        seq: usage.seq.unwrap_or(0),
                        total_cost_exposed: usage.total_cost_exposed,
                        total_cost_realized_spend: usage.total_cost_realized_spend,
                    })
                    .collect();
                self.replace_cached_usages(capability_id, &usages);
                usages
            })
            .map_err(into_budget_store_error)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        if let Some(cached) = self.cached_usage(capability_id, grant_index) {
            return Ok(Some(cached));
        }
        self.list_usages(MAX_LIST_LIMIT, Some(capability_id))
            .map(|usages| {
                usages
                    .into_iter()
                    .find(|usage| usage.grant_index == grant_index as u32)
            })
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        self.query_exact_remote_mutation_event(event_id)
    }
}

include!("part_01_remote_store.inc");
