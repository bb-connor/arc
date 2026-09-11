use super::{
    is_runtime_admission_bundle_schema, is_runtime_admission_profile_schema, passed,
    rejected_report, rejected_report_with_policy, runtime_admission_report_schema,
    validate_runtime_trust_input, RuntimeAdmissionInput,
};
use crate::error::ChioRuntimeError;
use crate::pheromone_policy::{evaluate_runtime_pheromone_policy, RuntimePolicyEvaluationInput};
use crate::types::*;

#[cfg(test)]
mod tests;

pub(crate) enum RuntimeAdmissionPreparation {
    Rejected(RuntimeAdmissionReport),
    Prepared(PreparedRuntimeAdmission),
}

/// Validated admission inputs, with no replay reservation or trust-floor mutation.
///
/// This value is local to one evaluation. It is not durable participant authority.
pub(crate) struct PreparedRuntimeAdmission {
    pub(crate) material_digest: String,
    pub(crate) bundle_digest: String,
    pub(super) report_schema: &'static str,
    pub(super) admission_id: String,
    pub(super) bundle: Box<RuntimeAdmissionBundle>,
    pub(super) checks: Vec<RuntimeAdmissionCheck>,
    pub(super) pheromone_advisory: Option<RuntimePheromoneAdvisory>,
    pub(super) policy_decision: Option<RuntimePheromonePolicyDecision>,
    pub(super) trust_floor_update: Option<(RuntimeTrustFloorEntry, Option<String>)>,
}

pub(super) fn prepare_runtime_admission(
    input: RuntimeAdmissionInput<'_>,
) -> Result<RuntimeAdmissionPreparation, ChioRuntimeError> {
    prepare_with_bundle_loader(&input, || input.store.bundle(input.admission_id))
}

/// Uses the caller's exact bundle snapshot without consulting the store.
pub(crate) fn prepare_runtime_admission_from_bundle(
    input: RuntimeAdmissionInput<'_>,
    bundle: Option<RuntimeAdmissionBundle>,
) -> Result<RuntimeAdmissionPreparation, ChioRuntimeError> {
    prepare_with_bundle_loader(&input, || Ok(bundle))
}

fn prepare_with_bundle_loader(
    input: &RuntimeAdmissionInput<'_>,
    load_bundle: impl FnOnce() -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError>,
) -> Result<RuntimeAdmissionPreparation, ChioRuntimeError> {
    let mut checks = Vec::new();
    let report_schema = runtime_admission_report_schema(&input.profile.schema);
    if !is_runtime_admission_profile_schema(&input.profile.schema) {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "unsupported_profile_schema",
            checks,
        )));
    }
    checks.push(passed("profile.schema"));
    if input.now_unix_ms < input.profile.issued_at_unix_ms
        || input.now_unix_ms >= input.profile.expires_at_unix_ms
    {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "stale_profile",
            checks,
        )));
    }
    checks.push(passed("profile.freshness"));

    let bundle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(load_bundle)) {
        Ok(Ok(Some(bundle))) => bundle,
        Ok(Ok(None)) => {
            return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
                report_schema,
                input.admission_id,
                "missing_admission_bundle",
                checks,
            )));
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
                report_schema,
                input.admission_id,
                "admission_bundle_store_error",
                checks,
            )));
        }
    };
    if !is_runtime_admission_bundle_schema(&bundle.schema) {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "unsupported_bundle_schema",
            checks,
        )));
    }
    checks.push(passed("bundle.schema"));
    if bundle.admission_id != input.admission_id {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "admission_bundle_id_mismatch",
            checks,
        )));
    }

    let mut trust_floor_update = None;
    if let Some(runtime_trust_input) = input.runtime_trust_input {
        if runtime_trust_input.body.verifier_id != input.profile.verifier_id {
            return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
                report_schema,
                input.admission_id,
                "runtime_trust_input_verifier_mismatch",
                checks,
            )));
        }
        checks.push(passed("runtime_trust.profile_verifier"));
        match validate_runtime_trust_input(
            runtime_trust_input,
            input.trusted_verifier_keys,
            &bundle,
            input.now_unix_ms,
            &mut checks,
        ) {
            Ok(entry) => {
                trust_floor_update =
                    Some((entry, runtime_trust_input.body.previous_hash_sha256.clone()));
            }
            Err(code) => {
                return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
                    report_schema,
                    input.admission_id,
                    code,
                    checks,
                )));
            }
        }
    } else if !input.trusted_verifier_keys.is_empty() {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "missing_runtime_trust_input",
            checks,
        )));
    }

    if bundle.binding.host_kernel_id != input.profile.local_kernel_id {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "host_kernel_mismatch",
            checks,
        )));
    }
    checks.push(passed("bundle.host_kernel"));

    if &bundle.binding != input.request {
        return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
            report_schema,
            input.admission_id,
            "request_binding_mismatch",
            checks,
        )));
    }
    checks.push(passed("request.binding"));

    if input.pheromone_query_report.is_some() {
        checks.push(passed("pheromone.query_report_signed"));
    }
    let (policy_decision, pheromone_advisory) =
        match evaluate_runtime_pheromone_policy(RuntimePolicyEvaluationInput {
            policy: input.runtime_pheromone_policy,
            peer_weights: input.runtime_peer_weights,
            query_report: input.pheromone_query_report,
            runtime_trust_input: input.runtime_trust_input,
            trusted_verifier_keys: input.trusted_verifier_keys,
            bundle: &bundle,
            action_class_id: input.action_class_id,
            now_unix_ms: input.now_unix_ms,
            checks: &mut checks,
        }) {
            Ok(result) => result,
            Err(code) => {
                return Ok(RuntimeAdmissionPreparation::Rejected(
                    rejected_report_with_policy(
                        report_schema,
                        input.admission_id,
                        code,
                        checks,
                        None,
                    ),
                ));
            }
        };
    if pheromone_advisory.is_some() {
        checks.push(passed("pheromone.observe_only"));
    }
    if let Some(decision) = policy_decision.as_ref() {
        if decision.decision == "deny" {
            return Ok(RuntimeAdmissionPreparation::Rejected(
                rejected_report_with_policy(
                    report_schema,
                    input.admission_id,
                    "runtime_pheromone_policy_deny",
                    checks,
                    Some(decision.clone()),
                ),
            ));
        }
        if decision.decision == "escalate" {
            return Ok(RuntimeAdmissionPreparation::Rejected(
                rejected_report_with_policy(
                    report_schema,
                    input.admission_id,
                    "runtime_pheromone_policy_escalate",
                    checks,
                    Some(decision.clone()),
                ),
            ));
        }
    }

    if bundle.destructive {
        if bundle.lease_id.is_none() {
            return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
                report_schema,
                input.admission_id,
                "missing_destructive_lease",
                checks,
            )));
        }
        if bundle.governance_receipt_id.is_none() {
            return Ok(RuntimeAdmissionPreparation::Rejected(rejected_report(
                report_schema,
                input.admission_id,
                "missing_governance_receipt",
                checks,
            )));
        }
    }

    let bundle_digest = crate::hash::runtime_admission_bundle_sha256(&bundle)?;
    let material_digest = crate::hash::canonical_sha256(&serde_json::json!({
        "schema": "chio.runtime-prepared-material.v1",
        "profile": input.profile,
        "bundle": &bundle,
        "request": input.request,
        "action_class_id": input.action_class_id,
        "runtime_trust_input": input.runtime_trust_input,
        "trusted_verifier_keys": input.trusted_verifier_keys,
        "pheromone_query_report": input.pheromone_query_report,
        "runtime_pheromone_policy": input.runtime_pheromone_policy,
        "runtime_peer_weights": input.runtime_peer_weights,
        "checks": &checks,
        "pheromone_advisory": &pheromone_advisory,
        "policy_decision": &policy_decision,
        "trust_floor_update": &trust_floor_update,
    }))?;
    Ok(RuntimeAdmissionPreparation::Prepared(
        PreparedRuntimeAdmission {
            material_digest,
            bundle_digest,
            report_schema,
            admission_id: input.admission_id.to_string(),
            bundle: Box::new(bundle),
            checks,
            pheromone_advisory,
            policy_decision,
            trust_floor_update,
        },
    ))
}
