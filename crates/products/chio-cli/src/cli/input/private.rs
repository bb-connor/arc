//! Private JSON custody decodes directly into wiping fields, without a Value tree.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

pub(crate) struct Seed(Zeroizing<String>);
impl Seed {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for Seed {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
impl Serialize for Seed {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

pub(crate) fn read<T: serde::de::DeserializeOwned + Serialize>(
    path: &std::path::Path,
) -> Result<T, crate::CliError> {
    let bytes = chio_control_plane::read_private_signing_custody(path, 16 * 1024)?;
    Ok(
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 16 * 1024)?
            .decode_canonical()?,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Key {
        seed: Seed,
    }
    #[cfg(unix)]
    #[test]
    fn private_json_rejects_duplicates_unknowns_permissions_and_links() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("key");
        for bytes in [
            r#"{"seed":"sensitive","seed":"other"}"#,
            r#"{"extra":true,"seed":"sensitive"}"#,
        ] {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error = read::<Key>(&path).err().unwrap();
            assert!(matches!(error, crate::CliError::SignedJson(_)), "{error}");
            assert!(!format!("{error:?} {error}").contains("sensitive"));
        }
        std::fs::write(&path, br#"{"seed":"value"}"#).unwrap();
        assert_eq!(read::<Key>(&path).unwrap().seed.as_str(), "value");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read::<Key>(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read::<Key>(&link).is_err());
    }
}
