//! One owed native journal seal, priced before the effect it follows.
use super::global_envelope::{canonical_uuid_bytes, record_bytes};
use super::*;

/// The physical shape one native journal seal of an authority can occupy:
/// payload, its protected record and event rows, its global commit row and
/// projection index entry. Data only; it funds nothing until a verified plan
/// mints it into an allowance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeSealAllowanceData {
    authority: String,
    maximum_payload_bytes: u64,
    /// The protected record row and its immutable event row.
    maximum_record_bytes: u64,
    /// The global commit row and its projection index entry.
    maximum_index_record_bytes: u64,
}

impl NativeSealAllowanceData {
    pub(in crate::admission_operation_store) fn maximum_payload_bytes(&self) -> u64 {
        self.maximum_payload_bytes
    }
    /// A seal of this authority whose canonical payload stays within the price.
    pub(in crate::admission_operation_store) fn covers(
        &self,
        authority: &str,
        payload: &[u8],
    ) -> Result<(), AdmissionOperationStoreError> {
        if authority != self.authority
            || u64::try_from(payload.len()).map_err(invalid)? > self.maximum_payload_bytes
        {
            return Err(invalid("native journal seal exceeds its priced allowance"));
        }
        Ok(())
    }
}

/// Price one seal of the initialized authority from its widest canonical
/// seal and the actual serving owner's identifier widths.
pub(in crate::admission_operation_store) fn describe_native_seal_allowance(
    owner: &SqliteServingOwner,
    initialized: &SecurityParticipantStateInitialization,
) -> Result<NativeSealAllowanceData, AdmissionOperationStoreError> {
    let authority = initialized.authority.as_str();
    let (key, payload) = super::super::history::segments::seal_bounds(authority)?;
    let uuid = canonical_uuid_bytes(&owner.fence.store_uuid)?;
    let lease = canonical_uuid_bytes(&owner.fence.lease_id)?;
    let mutation = u64::try_from("recovery_transition".len()).map_err(invalid)?;
    let projection = u64::try_from("recovery".len()).map_err(invalid)?;
    let kind = u64::try_from("command".len()).map_err(invalid)?;
    let record = record_bytes(&[key, 64, kind, 8, payload, 0, 0])?
        .checked_add(record_bytes(&[8, key, 8, 64, 64, 64, 8])?)
        .ok_or_else(|| invalid("native seal record bound overflow"))?;
    let index = record_bytes(&[
        8, mutation, projection, key, 8, 64, 64, 64, 64, uuid, lease, 8,
    ])?
    .checked_add(record_bytes(&[projection, key, 8, 8])?)
    .ok_or_else(|| invalid("native seal index bound overflow"))?;
    Ok(NativeSealAllowanceData {
        authority: authority.to_owned(),
        maximum_payload_bytes: payload,
        maximum_record_bytes: record,
        maximum_index_record_bytes: index,
    })
}

/// The allowance a verified original finishing plan priced before its effect,
/// spendable only in that plan's own writer transaction.
pub(in crate::admission_operation_store) struct VerifiedNativeSealAllowance<'plan> {
    connection: usize,
    data: &'plan NativeSealAllowanceData,
}

impl<'plan> VerifiedNativeSealAllowance<'plan> {
    pub(super) fn from_plan(tx: &Transaction<'_>, data: &'plan NativeSealAllowanceData) -> Self {
        Self {
            connection: &**tx as *const Connection as usize,
            data,
        }
    }

    /// The allowance a Confirmed native finishing account froze before its
    /// effect, spendable only by an owed append in this writer transaction.
    pub(in crate::admission_operation_store::security_participant_state) fn from_account(
        tx: &Transaction<'_>,
        data: &'plan NativeSealAllowanceData,
    ) -> Self {
        Self::from_plan(tx, data)
    }

    /// The allowance funds a seal of its own authority in its own writer.
    pub(in crate::admission_operation_store) fn covers(
        &self,
        connection: &Connection,
        authority: &str,
    ) -> Result<&'plan NativeSealAllowanceData, AdmissionOperationStoreError> {
        if connection as *const Connection as usize != self.connection
            || self.data.authority != authority
        {
            return Err(invalid(
                "native seal allowance belongs to another writer or authority",
            ));
        }
        Ok(self.data)
    }
}
