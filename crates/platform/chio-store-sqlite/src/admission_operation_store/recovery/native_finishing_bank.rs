//! Generation slots retained by the existing native finishing bank.
//!
//! An Output join allocates one generation. Other native joins are ordinary
//! intake and cannot consume that slot. A retained width class also establishes
//! a floor for new context generations, so later inserts cannot increase the
//! number of existing context records whose integer encoding will grow.
use super::native_finishing_account::authenticated_authority_bank;
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingWidthRecipeV1 {
    pub(in crate::admission_operation_store) security_authority: String,
    pub(in crate::admission_operation_store) tenant_id: String,
    pub(in crate::admission_operation_store) width_class: u8,
    pub(in crate::admission_operation_store) n_grow: u64,
    pub(in crate::admission_operation_store) allocation_allowance: u64,
}

impl NativeFinishingWidthRecipeV1 {
    pub(in crate::admission_operation_store) fn validate(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.security_authority.is_empty()
            || self.security_authority.len()
                > chio_kernel::admission_operation::MAX_ADMISSION_IDENTIFIER_BYTES
            || self.tenant_id.is_empty()
            || self.tenant_id.len() > 256
            || width_class_ceiling(self.width_class).is_none()
            || self.allocation_allowance != 1
        {
            return Err(invariant("native Output width recipe is not canonical"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct NativeFinishingWidthReservationV1 {
    pub(in crate::admission_operation_store) security_authority: String,
    pub(in crate::admission_operation_store) tenant_id: String,
    pub(in crate::admission_operation_store) width_class: u8,
    pub(in crate::admission_operation_store) loans: u64,
    pub(in crate::admission_operation_store) n_grow: u64,
    pub(in crate::admission_operation_store) allowance: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeFinishingWidthDebtData {
    pub(crate) width_class: u8,
    pub(crate) loans: u64,
}

pub(crate) fn generation_width_class_floor(
    width_class: u8,
) -> Result<u64, AdmissionOperationStoreError> {
    chio_sqlite_file_identity::SqliteTreeWriteShapeData::generation_width_class_floor(u64::from(
        width_class,
    ))
    .map_err(invariant)
}

/// SQLite record serial types encode integer contents in these byte classes.
/// These are not the seven-bit widths of SQLite varints.
pub(crate) fn width_class_ceiling(width_class: u8) -> Option<u64> {
    match width_class {
        0 => Some(1),
        1 => Some(127),
        2 => Some(32_767),
        3 => Some(8_388_607),
        4 => Some(2_147_483_647),
        6 => Some(140_737_488_355_327),
        8 => Some(9_007_199_254_740_991),
        _ => None,
    }
}

pub(crate) fn native_finishing_width_debt(
    connection: &Connection,
    security_authority: &str,
    tenant_id: &str,
) -> Result<Option<NativeFinishingWidthDebtData>, AdmissionOperationStoreError> {
    let Some((_, bank)) = authenticated_authority_bank(connection, None)? else {
        return Ok(None);
    };
    let mut debt: Option<NativeFinishingWidthDebtData> = None;
    for entry in bank
        .files
        .iter()
        .filter(|entry| entry.file.role == NativeFinishingFileRoleV1::Native)
    {
        for reservation in &entry.width_reservations {
            if reservation.security_authority != security_authority
                || reservation.tenant_id != tenant_id
            {
                continue;
            }
            reservation_shape(reservation)?;
            let current = debt.get_or_insert(NativeFinishingWidthDebtData {
                width_class: reservation.width_class,
                loans: 0,
            });
            if current.width_class != reservation.width_class {
                return Err(invariant(
                    "native width reservations disagree on their retained class",
                ));
            }
            current.loans = current
                .loans
                .checked_add(reservation.loans)
                .ok_or_else(|| invariant("native finishing width loan overflow"))?;
        }
    }
    Ok(debt)
}

/// Called only by the existing owned native mutation, before STORE_SEQUENCE.
/// The Output owner supplies its already authenticated operation identity. The
/// protected account and aggregate are read in that same write transaction;
/// no reusable claim or mutable connection escapes to the domain caller.
/// Consuming Output and removing its one bank slot occur in this transaction.
pub(crate) fn prepare_native_finishing_generation(
    connection: &Connection,
    security_authority: &str,
    tenant_id: &str,
    output_operation: Option<&str>,
) -> Result<NativeGenerationReservation, AdmissionOperationStoreError> {
    if connection.is_autocommit() {
        return Err(invariant(
            "native generation requires its owned write transaction",
        ));
    }
    let debt = native_finishing_width_debt(connection, security_authority, tenant_id)?;
    let mut own_slot = 0;
    if let Some(operation_id) = output_operation {
        if let Some(retained) = load_native_finishing_account(connection, operation_id)? {
            let account = retained.account;
            if account.state != NativeFinishingStateV1::Confirmed
                || account.identity.security_authority != security_authority
            {
                return Err(invariant(
                    "native Output generation lost its confirmed authority",
                ));
            }
            let recipe = account
                .outstanding_in_slot(NativeFinishingPurposeV1::OutputJoin)
                .and_then(|liability| liability.width_recipe.as_ref())
                .ok_or_else(|| invariant("native Output generation lost its retained loan"))?;
            recipe.validate()?;
            if recipe.security_authority != security_authority
                || recipe.tenant_id != tenant_id
                || debt.is_none_or(|debt| debt.width_class != recipe.width_class)
            {
                return Err(invariant(
                    "native Output generation differs from its retained scope",
                ));
            }
            own_slot = 1;
        }
    }
    let bounds = match debt {
        None => None,
        Some(debt) => {
            let reserved = debt
                .loans
                .checked_sub(own_slot)
                .ok_or_else(|| invariant("native generation lost its own bank slot"))?;
            let ceiling = width_class_ceiling(debt.width_class)
                .and_then(|ceiling| ceiling.checked_sub(reserved))
                .ok_or_else(|| invariant("native generation reservation exceeds its class"))?;
            Some((generation_width_class_floor(debt.width_class)?, ceiling))
        }
    };
    Ok(NativeGenerationReservation {
        security_authority: security_authority.to_owned(),
        tenant_id: tenant_id.to_owned(),
        bounds,
    })
}

/// Private data retained by one affine flow owner after its bank readback and
/// before its SQL mutation scope. The scope forbids changes to bank/account
/// tables, so these bounds remain valid through that same transaction's join.
/// It is neither Clone nor a caller-provided authorization.
pub(crate) struct NativeGenerationReservation {
    security_authority: String,
    tenant_id: String,
    bounds: Option<(u64, u64)>,
}

impl NativeGenerationReservation {
    pub(crate) fn generation(
        &self,
        security_authority: &str,
        tenant_id: &str,
        proposed: u64,
    ) -> Result<u64, AdmissionOperationStoreError> {
        if self.security_authority != security_authority || self.tenant_id != tenant_id {
            return Err(invariant(
                "native generation reservation belongs to another scope",
            ));
        }
        let Some((floor, ceiling)) = self.bounds else {
            return Ok(proposed);
        };
        let generation = proposed.max(floor);
        if generation > ceiling {
            return Err(invariant(
                "native generation intake would consume an owed Output slot",
            ));
        }
        Ok(generation)
    }
}

pub(crate) fn native_finishing_generation(
    connection: &Connection,
    security_authority: &str,
    tenant_id: &str,
    proposed: u64,
    output_operation: Option<&str>,
) -> Result<u64, AdmissionOperationStoreError> {
    prepare_native_finishing_generation(
        connection,
        security_authority,
        tenant_id,
        output_operation,
    )?
    .generation(security_authority, tenant_id, proposed)
}

pub(in crate::admission_operation_store) fn reservation_shape(
    reservation: &NativeFinishingWidthReservationV1,
) -> Result<(), AdmissionOperationStoreError> {
    if reservation.security_authority.is_empty()
        || reservation.security_authority.len()
            > chio_kernel::admission_operation::MAX_ADMISSION_IDENTIFIER_BYTES
        || reservation.tenant_id.is_empty()
        || reservation.tenant_id.len() > 256
        || width_class_ceiling(reservation.width_class).is_none()
        || reservation.loans == 0
        || reservation.allowance != reservation.loans
    {
        return Err(invariant(
            "native finishing width reservation is not canonical",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_classes_follow_sqlite_record_integer_serial_types() {
        for (width, ceiling) in [
            (0, 1),
            (1, 127),
            (2, 32_767),
            (3, 8_388_607),
            (4, 2_147_483_647),
            (6, 140_737_488_355_327),
            (8, 9_007_199_254_740_991),
        ] {
            assert_eq!(width_class_ceiling(width), Some(ceiling));
        }
        for width in [5, 7, 9] {
            assert_eq!(width_class_ceiling(width), None);
        }
    }
}
