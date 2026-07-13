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

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatter_never_exposes_secret_bytes() {
        let secret = SecretMaterial::new(b"unique-canary-credential".to_vec());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretMaterial(<redacted>)");
        assert!(!rendered.contains("unique-canary-credential"));
    }
}
