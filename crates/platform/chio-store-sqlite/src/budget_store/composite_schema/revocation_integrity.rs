use super::*;

pub(super) fn verify_revocation_set_digests(
    connection: &Connection,
) -> Result<(), BudgetStoreError> {
    for (kind, parent, id_column, members) in [
        (
            "hold",
            "budget_authorization_holds",
            "hold_id",
            "budget_hold_revocation_members",
        ),
        (
            "event",
            "budget_mutation_events",
            "event_id",
            "budget_event_revocation_members",
        ),
    ] {
        let parents = {
            let mut statement = connection.prepare(&format!(
                "SELECT {id_column}, revocation_set_digest FROM {parent} WHERE projection_kind = 'composite_v1'"
            ))?;
            let values = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            values
        };
        for (identity, digest) in parents {
            let ids = {
                let mut statement = connection.prepare(&format!(
                    "SELECT capability_id FROM {members} WHERE {id_column} = ?1 ORDER BY member_index"
                ))?;
                let values = statement
                    .query_map(params![&identity], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                values
            };
            let digest = digest.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "budget {kind} `{identity}` lost its revocation-set digest"
                ))
            })?;
            CanonicalRevocationSet::from_canonical_parts(ids, digest).map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "budget {kind} `{identity}` has an invalid revocation-set projection: {error}"
                ))
            })?;
        }
    }
    Ok(())
}
