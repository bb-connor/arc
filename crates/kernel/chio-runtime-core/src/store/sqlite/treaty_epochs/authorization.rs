use super::*;
use crate::{
    RuntimeAdmissionAuthorityCommit, RuntimeTreatyAuthorizationBinding,
    RuntimeTreatyAuthorizationRequest,
};
use chio_kernel::admission_operation::RuntimeSourceQualificationV1;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authorization {
    binding: RuntimeTreatyAuthorizationBinding,
    source_qualification: Vec<u8>,
    epoch_sequence: u64,
    authorized_at_unix_ms: u64,
}

fn claim_id(binding: &RuntimeTreatyAuthorizationBinding) -> Result<String, ChioRuntimeError> {
    crate::canonical_sha256(&("chio.runtime-treaty-authorization.v1", binding.reference()))
}

fn matches_scope(
    update: &VerifiedTreatyEpochUpdate,
    binding: &RuntimeTreatyAuthorizationBinding,
) -> Result<(), ChioRuntimeError> {
    let body = update.body();
    let scope = binding.scope();
    if body.verifier_id != *binding.verifier_id()
        || body.treaty_id.as_str() != scope.treaty_id
        || update.body_digest().as_str() != scope.revocation_epoch_sha256
        || body.trust_bundle_sha256.as_str() != scope.trust_bundle_sha256
        || body.participants.len() != scope.participant_kernel_ids.len()
        || body.participants.len() != scope.participant_public_keys.len()
        || body.participants.len() != scope.ladder_manifest_sha256s.len()
        || !body
            .participants
            .iter()
            .zip(&scope.participant_kernel_ids)
            .zip(&scope.participant_public_keys)
            .zip(&scope.ladder_manifest_sha256s)
            .all(|(((p, id), key), ladder)| {
                p.kernel_id.as_str() == id
                    && &p.public_key == key
                    && p.ladder_manifest_sha256.as_str() == ladder
            })
    {
        return Err(refusal(
            "treaty_epoch_binding_mismatch",
            "current treaty epoch does not match authenticated scope",
        ));
    }
    Ok(())
}

fn load_authorization(
    tx: &Connection,
    binding: &RuntimeTreatyAuthorizationBinding,
) -> Result<Option<Authorization>, ChioRuntimeError> {
    check_count(
        tx,
        "runtime_treaty_authorizations",
        MAX_AUTHORIZATIONS,
        false,
    )?;
    read_blob(tx, "SELECT CASE WHEN typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576 THEN canonical_bytes END FROM runtime_treaty_authorizations WHERE claim_id = ?1", params![claim_id(binding)?])?
        .map(|bytes| decode(&bytes)).transpose()
}

impl SqliteRuntimeOrchestrationStore {
    fn verify_authorization_context(
        &self,
        tx: &Connection,
        binding: &RuntimeTreatyAuthorizationBinding,
        source: &RuntimeSourceQualificationV1,
    ) -> Result<(), ChioRuntimeError> {
        let actual = self.load_source_qualification(tx)?.ok_or_else(|| {
            refusal(
                "runtime_source_qualification_invalid",
                "treaty authorization source qualification is absent",
            )
        })?;
        if actual != *source
            || binding.reference().episode_id() != binding.intent().episode_id()
            || binding.intent().runtime_authority_id().as_str() != source.runtime_authority_id()
            || binding.intent().qualification_id().as_str() != source.qualification_sha256()
        {
            return Err(refusal(
                "treaty_epoch_binding_mismatch",
                "treaty authorization claim differs from qualified source",
            ));
        }
        binding.intent().validate().map_err(|_| {
            refusal(
                "treaty_epoch_binding_mismatch",
                "treaty authorization intent is invalid",
            )
        })
    }

    fn authorize_current_treaty(
        &self,
        tx: &Connection,
        request: &RuntimeTreatyAuthorizationRequest,
    ) -> Result<(), ChioRuntimeError> {
        let binding = request.binding();
        self.verify_authorization_context(tx, binding, request.source_qualification())?;
        let treaty = AdmissionIdentifier::try_new("treaty_id", &binding.scope().treaty_id)
            .map_err(|_| {
                refusal(
                    "treaty_epoch_binding_mismatch",
                    "treaty identifier is invalid",
                )
            })?;
        let pin = load_pin(tx, binding.verifier_id(), &treaty)?;
        let key = authority_id(binding.verifier_id(), &treaty)?;
        let digest = load_head(tx, &key)?
            .ok_or_else(|| refusal("treaty_epoch_missing", "current treaty epoch is absent"))?;
        let update = load_record(tx, &pin, &digest)?;
        let now = self.clock.unix_millis()?.get();
        if now < request.now_unix_ms() {
            return Err(refusal(
                "treaty_epoch_expired",
                "authority clock precedes prepared admission",
            ));
        }
        update.validate_active_at(now).map_err(epoch_error)?;
        if digest.as_str() != binding.scope().revocation_epoch_sha256 {
            return Err(refusal(
                "treaty_epoch_stale",
                "authenticated scope does not name current epoch",
            ));
        }
        let maximum: Option<i64> = tx
            .query_row(
                "SELECT MAX(sequence) FROM runtime_treaty_epoch_records WHERE authority_id = ?1",
                params![key],
                |r| r.get(0),
            )
            .map_err(sqlite_error)?;
        if maximum.and_then(|n| u64::try_from(n).ok()) != Some(update.body().sequence) {
            return Err(refusal(
                "treaty_epoch_invalid",
                "current epoch is behind retained history",
            ));
        }
        matches_scope(&update, binding)?;
        if let Some(retained) = load_authorization(tx, binding)? {
            if retained.binding != *binding
                || retained.source_qualification != request.source_qualification().canonical_bytes()
                || retained.epoch_sequence != update.body().sequence
            {
                return Err(refusal(
                    "treaty_epoch_authorization_mismatch",
                    "retained treaty authorization differs from exact claim",
                ));
            }
            update
                .validate_active_at(retained.authorized_at_unix_ms)
                .map_err(epoch_error)?;
            return Ok(());
        }
        check_count(
            tx,
            "runtime_treaty_authorizations",
            MAX_AUTHORIZATIONS,
            true,
        )?;
        let record = Authorization {
            binding: binding.clone(),
            source_qualification: request.source_qualification().canonical_bytes().to_vec(),
            epoch_sequence: update.body().sequence,
            authorized_at_unix_ms: now,
        };
        tx.execute(
            "INSERT INTO runtime_treaty_authorizations (claim_id, canonical_bytes) VALUES (?1, ?2)",
            params![claim_id(binding)?, encode(&record)?],
        )
        .map_err(sqlite_error)?;
        Ok(())
    }

    pub(in crate::store::sqlite) fn commit_runtime_authority(
        &self,
        request: &RuntimeAdmissionAuthorityCommit,
    ) -> Result<(), ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(treaty) = request.treaty() {
            self.authorize_current_treaty(&tx, treaty)?;
        }
        if let Some(floor) = request.trust_floor() {
            Self::validate_and_store_runtime_trust_floor_in_transaction(
                &tx,
                floor.entry().clone(),
                floor.previous_hash_sha256(),
            )?;
        }
        tx.commit().map_err(sqlite_error)
    }

    pub(in crate::store::sqlite) fn verify_retained_treaty_authorization(
        &self,
        binding: &RuntimeTreatyAuthorizationBinding,
    ) -> Result<(), ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let retained = load_authorization(&tx, binding)?.ok_or_else(|| {
            refusal(
                "treaty_epoch_authorization_missing",
                "retained treaty authorization is absent",
            )
        })?;
        if retained.binding != *binding {
            return Err(refusal(
                "treaty_epoch_authorization_mismatch",
                "retained treaty authorization differs from original claim",
            ));
        }
        let source =
            RuntimeSourceQualificationV1::from_canonical_bytes(&retained.source_qualification)
                .map_err(|_| {
                    refusal(
                        "treaty_epoch_authorization_mismatch",
                        "retained source qualification is malformed",
                    )
                })?;
        self.verify_authorization_context(&tx, binding, &source)?;
        let treaty = AdmissionIdentifier::try_new("treaty_id", &binding.scope().treaty_id)
            .map_err(|_| {
                refusal(
                    "treaty_epoch_binding_mismatch",
                    "treaty identifier is invalid",
                )
            })?;
        let pin = load_pin(&tx, binding.verifier_id(), &treaty)?;
        let digest =
            AdmissionDigest::try_new("epoch_digest", &binding.scope().revocation_epoch_sha256)
                .map_err(|_| refusal("treaty_epoch_binding_mismatch", "epoch digest is invalid"))?;
        let update = load_record(&tx, &pin, &digest)?;
        if retained.epoch_sequence != update.body().sequence {
            return Err(refusal(
                "treaty_epoch_authorization_mismatch",
                "retained epoch sequence differs from signed history",
            ));
        }
        matches_scope(&update, binding)?;
        update
            .validate_active_at(retained.authorized_at_unix_ms)
            .map_err(epoch_error)?;
        tx.commit().map_err(sqlite_error)
    }
}
