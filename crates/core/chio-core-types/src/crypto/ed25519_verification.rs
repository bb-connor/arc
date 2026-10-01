//! Repeated verification of immutable Ed25519 evidence.
//!
//! A successful mathematical check remains true for the same key, signature,
//! verification mode and message. Retain at most 64 such checks per thread,
//! using SHA-512 commitments instead of retaining signed message plaintext.
//! This does not cache artifact validity, time, policy, revocation or authority.
//! Allocation failure, cache contention and thread teardown fall back to the
//! original verifier. `no_std` builds always use the original verifier.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub(super) fn verify(
    key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
    strict: bool,
) -> bool {
    let verify = || {
        if strict {
            key.verify_strict(message, signature).is_ok()
        } else {
            key.verify(message, signature).is_ok()
        }
    };
    #[cfg(feature = "std")]
    {
        cached(&CacheKey::new(key, message, signature, strict), verify)
    }
    #[cfg(not(feature = "std"))]
    verify()
}

#[cfg(feature = "std")]
#[derive(Clone, PartialEq, Eq)]
struct CacheKey {
    public_key: [u8; 32],
    signature: [u8; 64],
    message_sha512: [u8; 64],
    message_len: usize,
    strict: bool,
}

#[cfg(feature = "std")]
impl CacheKey {
    fn new(key: &VerifyingKey, message: &[u8], signature: &Signature, strict: bool) -> Self {
        use sha2::{Digest, Sha512};
        Self {
            public_key: key.to_bytes(),
            signature: signature.to_bytes(),
            message_sha512: Sha512::digest(message).into(),
            message_len: message.len(),
            strict,
        }
    }
}

#[cfg(feature = "std")]
const MAX_ENTRIES: usize = 64;

#[cfg(feature = "std")]
std::thread_local! {
    static VERIFIED: std::cell::RefCell<std::collections::VecDeque<CacheKey>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

#[cfg(feature = "std")]
fn cached(key: &CacheKey, verify: impl FnOnce() -> bool) -> bool {
    let hit = VERIFIED
        .try_with(|entries| {
            entries
                .try_borrow()
                .map(|entries| entries.contains(key))
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if hit {
        return true;
    }
    if !verify() {
        return false;
    }
    let _ = VERIFIED.try_with(|entries| {
        if let Ok(mut entries) = entries.try_borrow_mut() {
            if entries.len() == MAX_ENTRIES {
                let _ = entries.pop_front();
            }
            if entries.try_reserve(1).is_ok() {
                entries.push_back(key.clone());
            }
        }
    });
    true
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::cell::Cell;

    #[test]
    fn repeated_success_reuses_only_the_same_verification_input() {
        let signer = SigningKey::from_bytes(&[91; 32]);
        let key = signer.verifying_key();
        let message = b"original signed evidence";
        let signature = signer.sign(message);
        let cache_key = CacheKey::new(&key, message, &signature, true);
        let checks = Cell::new(0);
        for _ in 0..2 {
            assert!(cached(&cache_key, || {
                checks.set(checks.get() + 1);
                key.verify_strict(message, &signature).is_ok()
            }));
        }
        assert_eq!(checks.get(), 1);
        assert!(!verify(&key, b"changed signed evidence", &signature, true));
        let other_key = SigningKey::from_bytes(&[92; 32]).verifying_key();
        assert!(!verify(&other_key, message, &signature, true));
        let changed_signature = signer.sign(b"other signature");
        assert!(!verify(&key, message, &changed_signature, true));
    }

    #[test]
    fn ordinary_success_never_satisfies_strict_verification(
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let mut identity = [0; 32];
        identity[0] = 1;
        let key = VerifyingKey::from_bytes(&identity)?;
        let mut encoded = [0; 64];
        encoded[0] = 1;
        let signature = Signature::from_bytes(&encoded);
        let message = b"weak-key forgery";
        assert!(verify(&key, message, &signature, false));
        assert!(verify(&key, message, &signature, false));
        assert!(!verify(&key, message, &signature, true));
        Ok(())
    }

    #[test]
    fn failures_are_rechecked() {
        let signer = SigningKey::from_bytes(&[93; 32]);
        let key = signer.verifying_key();
        let signature = signer.sign(b"original");
        let message = b"changed";
        let cache_key = CacheKey::new(&key, message, &signature, true);
        let checks = Cell::new(0);
        for _ in 0..2 {
            assert!(!cached(&cache_key, || {
                checks.set(checks.get() + 1);
                key.verify_strict(message, &signature).is_ok()
            }));
        }
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn eviction_and_borrow_conflicts_fall_back_to_real_verification() {
        let signer = SigningKey::from_bytes(&[94; 32]);
        let key = signer.verifying_key();
        let original = signer.sign(b"evicted evidence");
        assert!(verify(&key, b"evicted evidence", &original, true));
        for index in 0..MAX_ENTRIES {
            let message = index.to_le_bytes();
            let signature = signer.sign(&message);
            assert!(verify(&key, &message, &signature, true));
        }
        VERIFIED.with(|entries| assert_eq!(entries.borrow().len(), MAX_ENTRIES));
        let rechecked = Cell::new(false);
        assert!(cached(
            &CacheKey::new(&key, b"evicted evidence", &original, true),
            || {
                rechecked.set(true);
                key.verify_strict(b"evicted evidence", &original).is_ok()
            }
        ));
        assert!(rechecked.get());
        VERIFIED.with(|entries| {
            let _borrow = entries.borrow_mut();
            assert!(verify(&key, b"evicted evidence", &original, true));
            assert!(!verify(&key, b"changed evidence", &original, true));
        });
    }
}
