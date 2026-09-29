use super::*;


#[cfg(feature = "std")]
pub(super) fn sort_json_object_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                sort_json_object_keys(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                sort_json_object_keys(value);
            }
            values.sort_keys();
        }
        _ => {}
    }
}


#[cfg(feature = "std")]
pub(super) fn issuance_freeze_domain_hash(domain: &[u8], commitment: &impl Serialize) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let mut value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    sort_json_object_keys(&mut value);
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}
