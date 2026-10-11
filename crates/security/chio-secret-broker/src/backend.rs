use std::fmt;

use secrecy::{ExposeSecret, SecretBox};

use crate::protocol::CredentialRef;
use crate::Result;

pub(crate) trait SecretBackend: Send + Sync {
    fn materialize(&self, credential: &CredentialRef) -> Result<SecretMaterial>;
}

pub(crate) struct SecretMaterial {
    bytes: SecretBox<Vec<u8>>,
}

impl SecretMaterial {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.bytes.expose_secret()
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
    fn secret_material_keeps_the_original_allocation() {
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(b"credential-with-spare-capacity");
        let allocation = bytes.as_ptr();
        let secret = SecretMaterial::new(bytes);
        assert_eq!(secret.expose_secret().as_ptr(), allocation);
        assert_eq!(secret.expose_secret(), b"credential-with-spare-capacity");
    }

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
