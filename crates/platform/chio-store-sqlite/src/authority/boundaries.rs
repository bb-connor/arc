use super::*;

pub(super) fn authority_sqlite_integer(
    value: u64,
    field: &str,
) -> Result<i64, AuthorityStoreError> {
    i64::try_from(value).map_err(|_| {
        AuthorityStoreError::Fence(format!("authority {field} exceeds SQLite INTEGER range"))
    })
}

pub(super) fn authority_unsigned(value: i64, field: &str) -> Result<u64, AuthorityStoreError> {
    u64::try_from(value).map_err(|_| {
        AuthorityStoreError::Fence(format!("persisted authority {field} must be nonnegative"))
    })
}

pub(super) fn authority_generation(value: u64) -> Result<i64, AuthorityStoreError> {
    if value == 0 {
        return Err(AuthorityStoreError::Fence(
            "authority generation must be positive".to_owned(),
        ));
    }
    authority_sqlite_integer(value, "generation")
}

pub(super) fn persist_trusted_key(
    connection: &Connection,
    public_key: &str,
    generation: u64,
    activated_at: u64,
    lifecycle: &AuthorityKeyLifecycle,
) -> Result<PublicKey, AuthorityStoreError> {
    let key = PublicKey::from_hex(public_key.trim())?;
    connection.execute(
        "INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at, lifecycle_json)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            key.to_hex(),
            authority_generation(generation)?,
            authority_sqlite_integer(activated_at, "activation time")?,
            replication::encode_lifecycle(lifecycle)?
        ],
    )?;
    Ok(key)
}
