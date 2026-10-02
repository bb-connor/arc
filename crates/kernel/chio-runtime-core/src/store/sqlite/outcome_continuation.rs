use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};
use crate::hash::canonical_sha256;
use crate::outcome_continuation::{
    OutcomeDispatchPermit, OutcomeEffectClaim, OutcomeEffectRequest, OutcomeEffectRule,
    OutcomeEffectSlot, OutcomeEffectState, OutcomeEffectStatus,
};
use crate::validation::{rejected, validate_non_empty};
use crate::ChioRuntimeError;

struct SlotRow {
    rule_sha256: String,
    rule: OutcomeEffectRule,
    revoked: bool,
    claim: Option<OutcomeEffectClaim>,
    result: Option<serde_json::Value>,
}

impl SlotRow {
    fn verify_ready(
        &self,
        request: &OutcomeEffectRequest,
        server_id: &str,
        tool_name: &str,
        now_unix_ms: u64,
    ) -> Result<(), ChioRuntimeError> {
        if self.revoked {
            return rejected(
                "outcome_effect_revoked",
                "receiver revoked this effect slot",
            );
        }
        self.rule
            .verify(request, server_id, tool_name, now_unix_ms)?;
        if self.claim.is_some() {
            return rejected(
                "outcome_effect_already_claimed",
                "logical effect slot already entered dispatch; fresh attempts cannot reset it",
            );
        }
        Ok(())
    }
}

fn decode_hashed<T: DeserializeOwned + serde::Serialize>(
    raw: &str,
    expected: &str,
) -> Result<T, ChioRuntimeError> {
    let value =
        serde_json::from_str(raw).map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    if canonical_sha256(&value)? != expected {
        return rejected(
            "outcome_store_hash_mismatch",
            "stored outcome record failed its content hash",
        );
    }
    Ok(value)
}

fn load_slot(connection: &Connection, slot_sha256: &str) -> Result<SlotRow, ChioRuntimeError> {
    let raw = connection.query_row(
        "SELECT rule_sha256, rule_json, revoked, claim_sha256, claim_json, result_sha256, result_json FROM runtime_outcome_effect_slots WHERE slot_sha256 = ?1",
        [slot_sha256],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?, row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?, row.get::<_, Option<String>>(6)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((
        rule_sha256,
        rule_json,
        revoked,
        claim_sha256,
        claim_json,
        result_sha256,
        result_json,
    )) = raw
    else {
        return rejected(
            "outcome_effect_unknown",
            "receiver has not activated this logical slot",
        );
    };
    let rule: OutcomeEffectRule = decode_hashed(&rule_json, &rule_sha256)?;
    rule.validate()?;
    if rule.slot.sha256()? != slot_sha256 || !matches!(revoked, 0 | 1) {
        return rejected(
            "outcome_store_binding_mismatch",
            "stored rule has an invalid slot binding or revocation flag",
        );
    }
    let claim: Option<OutcomeEffectClaim> = match (claim_json, claim_sha256) {
        (Some(raw), Some(hash)) => Some(decode_hashed(&raw, &hash)?),
        (None, None) => None,
        _ => return rejected("outcome_store_invalid_state", "claim record is incomplete"),
    };
    if let Some(claim) = &claim {
        if claim.slot != rule.slot || claim.rule_sha256 != rule_sha256 {
            return rejected(
                "outcome_store_binding_mismatch",
                "stored claim does not bind this rule",
            );
        }
    }
    let result = match (result_json, result_sha256) {
        (Some(raw), Some(hash)) if claim.is_some() => Some(decode_hashed(&raw, &hash)?),
        (None, None) => None,
        _ => {
            return rejected(
                "outcome_store_invalid_state",
                "result record lacks a claim or content hash",
            )
        }
    };
    Ok(SlotRow {
        rule_sha256,
        rule,
        revoked: revoked == 1,
        claim,
        result,
    })
}

impl SqliteRuntimeOrchestrationStore {
    /// Trusted local provisioning only. Repeating an identical rule is
    /// idempotent, including after revocation or consumption, without resetting
    /// either state. A different rule for the same logical slot is rejected.
    pub fn activate_outcome_effect(
        &self,
        rule: &OutcomeEffectRule,
    ) -> Result<(), ChioRuntimeError> {
        rule.validate()?;
        let slot_sha256 = rule.slot.sha256()?;
        let rule_sha256 = canonical_sha256(rule)?;
        let raw = serde_json::to_string(rule)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO runtime_outcome_effect_slots (slot_sha256, rule_sha256, rule_json) VALUES (?1, ?2, ?3)",
            params![slot_sha256, rule_sha256, raw],
        ).map_err(sqlite_error)?;
        if inserted == 0 && load_slot(&tx, &slot_sha256)?.rule != *rule {
            return rejected(
                "outcome_rule_conflict",
                "logical effect slot already has a different receiver rule",
            );
        }
        tx.commit().map_err(sqlite_error)
    }

    pub fn revoke_outcome_effect(&self, slot: &OutcomeEffectSlot) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let updated = connection
            .execute(
                "UPDATE runtime_outcome_effect_slots SET revoked = 1 WHERE slot_sha256 = ?1",
                [slot.sha256()?],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return rejected(
                "outcome_effect_unknown",
                "receiver has not activated this logical slot",
            );
        }
        Ok(())
    }

    /// Non-consuming preview. A successful preview is not permission to run an
    /// effect: the final dispatcher must still claim the slot atomically.
    pub fn preview_outcome_effect(
        &self,
        request: &OutcomeEffectRequest,
        server_id: &str,
        tool_name: &str,
        now_unix_ms: u64,
    ) -> Result<(), ChioRuntimeError> {
        let connection = self.lock_connection()?;
        load_slot(&connection, &request.evidence.body.slot.sha256()?)?.verify_ready(
            request,
            server_id,
            tool_name,
            now_unix_ms,
        )
    }

    /// Atomically verify live receiver state and spend the one logical effect
    /// slot. Call only at the protected tool's final dispatch boundary, after
    /// kernel admission. There is intentionally no release or timeout reset.
    /// Cross-database and external effects are not part of this transaction.
    pub fn claim_outcome_effect(
        &self,
        request: &OutcomeEffectRequest,
        server_id: &str,
        tool_name: &str,
        request_id: &str,
        now_unix_ms: u64,
    ) -> Result<OutcomeDispatchPermit, ChioRuntimeError> {
        validate_non_empty(request_id, "outcome_request_id_empty")?;
        let slot_sha256 = request.evidence.body.slot.sha256()?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let row = load_slot(&tx, &slot_sha256)?;
        row.verify_ready(request, server_id, tool_name, now_unix_ms)?;
        let claim = OutcomeEffectClaim {
            slot: row.rule.slot,
            rule_sha256: row.rule_sha256,
            evidence_sha256: canonical_sha256(&request.evidence)?,
            arguments: request.arguments.clone(),
            request_id: request_id.to_string(),
            claimed_at_unix_ms: now_unix_ms,
        };
        let claim_sha256 = canonical_sha256(&claim)?;
        let raw = serde_json::to_string(&claim)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        let updated = tx.execute(
            "UPDATE runtime_outcome_effect_slots SET claim_sha256 = ?2, claim_json = ?3 WHERE slot_sha256 = ?1 AND claim_sha256 IS NULL AND revoked = 0",
            params![slot_sha256, claim_sha256, raw],
        ).map_err(sqlite_error)?;
        if updated != 1 {
            return rejected(
                "outcome_effect_already_claimed",
                "logical effect slot is no longer available",
            );
        }
        tx.commit().map_err(sqlite_error)?;
        Ok(OutcomeDispatchPermit {
            slot_sha256,
            claim_sha256,
            claim,
        })
    }

    /// Record the trusted dispatcher's result without opening another slot.
    /// Losing the permit or crashing before this write leaves DispatchClaimed,
    /// never an implicit successful completion or permission to retry.
    pub fn complete_outcome_effect(
        &self,
        permit: OutcomeDispatchPermit,
        result: &serde_json::Value,
    ) -> Result<(), ChioRuntimeError> {
        let result_sha256 = canonical_sha256(result)?;
        let raw = serde_json::to_string(result)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE runtime_outcome_effect_slots SET result_sha256 = ?3, result_json = ?4 WHERE slot_sha256 = ?1 AND claim_sha256 = ?2 AND result_sha256 IS NULL",
            params![permit.slot_sha256, permit.claim_sha256, result_sha256, raw],
        ).map_err(sqlite_error)?;
        if updated != 1 {
            return rejected(
                "outcome_completion_conflict",
                "dispatch claim is absent, different, or already completed",
            );
        }
        Ok(())
    }

    pub fn outcome_effect_status(
        &self,
        slot: &OutcomeEffectSlot,
    ) -> Result<OutcomeEffectStatus, ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let row = load_slot(&connection, &slot.sha256()?)?;
        let state = match (row.claim, row.result) {
            (Some(claim), Some(result)) => OutcomeEffectState::Completed { claim, result },
            (Some(claim), None) => OutcomeEffectState::DispatchClaimed { claim },
            (None, None) => OutcomeEffectState::Waiting,
            (None, Some(_)) => {
                return rejected(
                    "outcome_store_invalid_state",
                    "result without a dispatch claim",
                )
            }
        };
        Ok(OutcomeEffectStatus {
            revoked: row.revoked,
            state,
        })
    }
}
