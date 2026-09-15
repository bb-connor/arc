use std::fmt;

use zeroize::Zeroizing;

use crate::protocol::CredentialRef;
use crate::Result;

pub(crate) trait SecretBackend: Send + Sync {
    fn materialize(&self, credential: &CredentialRef) -> Result<SecretMaterial>;
}

pub(crate) struct SecretMaterial {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretMaterial {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Display for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TraitProbe<T>(std::marker::PhantomData<T>);

    trait DebugAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> DebugAmbiguity<()> for TraitProbe<T> {}
    impl<T: std::fmt::Debug> DebugAmbiguity<u8> for TraitProbe<T> {}

    trait CloneAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> CloneAmbiguity<()> for TraitProbe<T> {}
    impl<T: Clone> CloneAmbiguity<u8> for TraitProbe<T> {}

    trait SerializeAmbiguity<Marker> {
        fn assert_absent() {}
    }

    impl<T> SerializeAmbiguity<()> for TraitProbe<T> {}
    impl<T: serde::Serialize> SerializeAmbiguity<u8> for TraitProbe<T> {}

    #[test]
    fn display_never_exposes_secret_bytes() {
        let secret = SecretMaterial::new(b"unique-canary-credential".to_vec());
        let rendered = format!("{secret}");
        assert_eq!(rendered, "SecretMaterial(<redacted>)");
        assert!(!rendered.contains("unique-canary-credential"));
    }

    #[test]
    fn secret_material_exposes_no_debug_clone_or_serialize_trait() {
        <TraitProbe<SecretMaterial> as DebugAmbiguity<_>>::assert_absent();
        <TraitProbe<SecretMaterial> as CloneAmbiguity<_>>::assert_absent();
        <TraitProbe<SecretMaterial> as SerializeAmbiguity<_>>::assert_absent();
    }
}
