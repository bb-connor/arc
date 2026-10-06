//! Shared production TLS loading through bounded private-file custody.
use crate::CliError;
use chio_http_serve::{PreparedServerTransport, ServerTransportConfig};
use std::{fs::File, io::Read, net::SocketAddr, path::Path};

/// Validate the bind posture and load identity before any other startup effects.
pub fn prepare(
    config: &ServerTransportConfig,
    listen: SocketAddr,
) -> Result<PreparedServerTransport, CliError> {
    config.validate(listen).map_err(std::io::Error::other)?;
    match (&config.tls_cert, &config.tls_key) {
        (Some(certificate), Some(key)) => {
            let key = crate::read_private_signing_custody(key, 64 * 1024)?;
            let certificate = read_certificate(certificate)?;
            PreparedServerTransport::from_pem(&certificate, &key)
                .map_err(|error| std::io::Error::other(error).into())
        }
        _ => Ok(PreparedServerTransport::default()),
    }
}

fn read_certificate(path: &Path) -> Result<Vec<u8>, CliError> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{open, Mode, OFlags};
        File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?,
        )
    };
    #[cfg(not(unix))]
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS certificate must be a regular file",
        )
        .into());
    }
    const LIMIT: usize = 2 * 1024 * 1024;
    let mut certificate = Vec::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut certificate)?;
    if certificate.len() > LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS certificate exceeds its byte limit",
        )
        .into());
    }
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn rejects_custody(
        config: &ServerTransportConfig,
        address: SocketAddr,
        reason: &str,
    ) -> TestResult {
        let error = prepare(config, address)
            .err()
            .ok_or("unsafe custody accepted")?;
        assert!(
            matches!(error, CliError::Chio(_)),
            "wrong rejection: {error}"
        );
        assert!(
            error.to_string().contains(reason),
            "wrong custody rule: {error}"
        );
        Ok(())
    }

    #[test]
    fn production_tls_errors_never_render_private_pem_input() -> TestResult {
        let directory = chio_test_support::private_tempdir()?;
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, identity.cert.pem())?;
        let config = ServerTransportConfig {
            tls_cert: Some(cert),
            tls_key: Some(key.clone()),
            allow_plaintext: false,
        };
        for input in [
            "-----BEGIN PRIVATE KEY-----PRIVATE-MARKER\n",
            "-----BEGIN PRIVATE-MARKER-----\n",
        ] {
            std::fs::write(&key, input)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
            }
            let error = prepare(&config, "0.0.0.0:0".parse()?)
                .err()
                .ok_or("malformed key accepted")?;
            let mut source: Option<&dyn std::error::Error> = Some(&error);
            while let Some(error) = source {
                let diagnostic = format!("{error} {error:?}");
                assert!(!diagnostic.contains("PRIVATE-MARKER"));
                assert!(
                    !diagnostic.contains("80, 82, 73, 86, 65, 84, 69, 45, 77, 65, 82, 75, 69, 82")
                );
                source = error.source();
            }
        }
        Ok(())
    }

    #[test]
    fn private_tls_custody_is_required_and_loads_a_matching_identity() -> TestResult {
        let directory = chio_test_support::private_tempdir()?;
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, identity.cert.pem())?;
        std::fs::write(&key, identity.key_pair.serialize_pem())?;
        let config = ServerTransportConfig {
            tls_cert: Some(cert),
            tls_key: Some(key.clone()),
            allow_plaintext: false,
        };
        let address = "0.0.0.0:0".parse()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))?;
            rejects_custody(&config, address, "singly linked with mode 0600 or stricter")?;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
            let link = directory.path().join("link.pem");
            symlink(&key, &link)?;
            let linked = ServerTransportConfig {
                tls_key: Some(link.clone()),
                ..config.clone()
            };
            rejects_custody(&linked, address, "must be a regular file")?;
            std::fs::remove_file(&link)?;
            std::fs::hard_link(&key, &link)?;
            rejects_custody(&config, address, "singly linked with mode 0600 or stricter")?;
            std::fs::remove_file(&link)?;
        }
        assert!(prepare(&config, address)?.is_tls());
        std::fs::write(&key, vec![b'x'; 64 * 1024 + 1])?;
        rejects_custody(&config, address, "exceeds its byte limit")?;
        Ok(())
    }
}
