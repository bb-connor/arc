//! Private PEM decoding whose scratch, DER and errors cannot retain secret copies.
use base64::Engine;
use rustls::pki_types::PrivateKeyDer;
use zeroize::Zeroizing;

/// Redacted syntax categories. Never retain lines, labels or decoded key bytes.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum PemError {
    #[error("invalid TLS PEM framing")]
    Framing,
    #[error("invalid TLS PEM encoding")]
    Encoding,
    #[error("TLS private PEM exceeds its byte limit")]
    TooLarge,
}

#[derive(Clone, Copy)]
enum KeyKind {
    Pkcs8,
    Pkcs1,
    Sec1,
}
impl KeyKind {
    fn begin(line: &[u8]) -> Result<Self, PemError> {
        match line {
            b"-----BEGIN PRIVATE KEY-----" => Ok(Self::Pkcs8),
            b"-----BEGIN RSA PRIVATE KEY-----" => Ok(Self::Pkcs1),
            b"-----BEGIN EC PRIVATE KEY-----" => Ok(Self::Sec1),
            _ => Err(PemError::Framing),
        }
    }
    fn end(self) -> &'static [u8] {
        match self {
            Self::Pkcs8 => b"-----END PRIVATE KEY-----",
            Self::Pkcs1 => b"-----END RSA PRIVATE KEY-----",
            Self::Sec1 => b"-----END EC PRIVATE KEY-----",
        }
    }
    fn protect(self, bytes: Vec<u8>) -> Zeroizing<PrivateKeyDer<'static>> {
        Zeroizing::new(match self {
            Self::Pkcs8 => PrivateKeyDer::Pkcs8(bytes.into()),
            Self::Pkcs1 => PrivateKeyDer::Pkcs1(bytes.into()),
            Self::Sec1 => PrivateKeyDer::Sec1(bytes.into()),
        })
    }
}

pub(super) fn private_key(input: &[u8]) -> Result<Zeroizing<PrivateKeyDer<'static>>, PemError> {
    if input.len() > 64 * 1024 {
        return Err(PemError::TooLarge);
    }
    // Fixed allocations never release an old, secret-bearing capacity on growth.
    let mut encoded = Zeroizing::new(vec![0; input.len()]);
    let mut length = 0;
    let mut lines = input
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|line| !line.is_empty());
    let kind = KeyKind::begin(lines.next().ok_or(PemError::Framing)?)?;
    let mut ended = false;
    for line in lines.by_ref() {
        if line == kind.end() {
            ended = true;
            break;
        }
        for byte in line
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
        {
            *encoded.get_mut(length).ok_or(PemError::TooLarge)? = byte;
            length += 1;
        }
    }
    // Reject a second key or trailing material before any DER exists.
    if !ended || length == 0 || lines.next().is_some() {
        return Err(PemError::Framing);
    }
    let mut decoded = Zeroizing::new(vec![0; input.len()]);
    let count = base64::engine::general_purpose::STANDARD
        .decode_slice(
            encoded.get(..length).ok_or(PemError::TooLarge)?,
            &mut decoded,
        )
        .map_err(|_| PemError::Encoding)?;
    decoded.truncate(count);
    // No fallible operation between moving the allocation and attaching its guard.
    Ok(kind.protect(std::mem::take(&mut *decoded)))
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn accepted_der_has_wiping_ownership_and_every_extra_block_is_refused() -> TestResult {
        fn wiping<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let pem = identity.key_pair.serialize_pem();
        let key = private_key(pem.as_bytes())?;
        wiping(&key);
        assert_eq!(key.secret_der(), identity.key_pair.serialize_der());
        for suffix in [
            pem.as_str(),
            "-----BEGIN PRIVATE-MARKER-----\n",
            "trailing secret",
        ] {
            assert!(private_key(format!("{pem}{suffix}").as_bytes()).is_err());
        }
        let crlf = pem.replace('\n', "\r\n");
        assert_eq!(private_key(crlf.as_bytes())?.secret_der(), key.secret_der());
        Ok(())
    }
}
