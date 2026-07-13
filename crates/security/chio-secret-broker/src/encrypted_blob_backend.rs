use std::fs::{self, File, OpenOptions};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chio_core_types::Keypair;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{SecretBackend, SecretMaterial};
use crate::protocol::CredentialRef;
use crate::{validate_identifier, BrokerError, Result};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const AEAD_VERSION: i64 = 1;
const INDEX_DOMAIN: &[u8] = b"chio.secret-broker.index.v1\0";
const AEAD_DOMAIN: &[u8] = b"chio.secret-broker.credential.v1\0";

struct BackendMasterKey([u8; KEY_BYTES]);

impl Drop for BackendMasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct SealedKeyFd {
    file: File,
    expected_owner: u32,
    consumed: bool,
}

impl SealedKeyFd {
    #[must_use]
    pub fn from_inherited_file(file: File, expected_owner: u32) -> Self {
        Self {
            file,
            expected_owner,
            consumed: false,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn read_once(mut self) -> Result<BackendMasterKey> {
        if self.consumed {
            return Err(BrokerError::Custody(
                "master-key descriptor was already consumed".to_string(),
            ));
        }
        let bytes = read_sealed_32(&mut self.file, self.expected_owner, "master key")?;
        self.consumed = true;
        Ok(BackendMasterKey(bytes))
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn read_once(self) -> Result<BackendMasterKey> {
        let Self {
            file,
            expected_owner,
            consumed,
        } = self;
        drop(file);
        let _ = (expected_owner, consumed);
        Err(BrokerError::Custody(
            "sealed master-key descriptors are unsupported on this platform".to_string(),
        ))
    }
}

pub struct SealedSigningKeyFd {
    file: File,
    expected_owner: u32,
    consumed: bool,
}

impl SealedSigningKeyFd {
    #[must_use]
    pub fn from_inherited_file(file: File, expected_owner: u32) -> Self {
        Self {
            file,
            expected_owner,
            consumed: false,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn into_keypair(mut self) -> Result<Keypair> {
        if self.consumed {
            return Err(BrokerError::Custody(
                "signing-key descriptor was already consumed".to_string(),
            ));
        }
        let mut seed = read_sealed_32(&mut self.file, self.expected_owner, "signing key")?;
        self.consumed = true;
        let keypair = Keypair::from_seed(&seed);
        seed.zeroize();
        Ok(keypair)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn into_keypair(self) -> Result<Keypair> {
        let Self {
            file,
            expected_owner,
            consumed,
        } = self;
        drop(file);
        let _ = (expected_owner, consumed);
        Err(BrokerError::Custody(
            "sealed signing-key descriptors are unsupported on this platform".to_string(),
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_sealed_32(file: &mut File, expected_owner: u32, label: &str) -> Result<[u8; KEY_BYTES]> {
    use rustix::fs::{fcntl_get_seals, fcntl_getfl, fstat, OFlags, SealFlags};

    let status = fcntl_getfl(&*file)
        .map_err(|error| BrokerError::Custody(format!("{label} FD flags failed: {error}")))?;
    if status.intersects(OFlags::WRONLY | OFlags::RDWR) {
        return Err(BrokerError::Custody(format!(
            "{label} descriptor is not read-only"
        )));
    }
    let seals = fcntl_get_seals(&*file)
        .map_err(|error| BrokerError::Custody(format!("{label} FD seals failed: {error}")))?;
    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    if !seals.contains(required) {
        return Err(BrokerError::Custody(format!(
            "{label} descriptor lacks required seals"
        )));
    }
    let metadata = fstat(&*file)
        .map_err(|error| BrokerError::Custody(format!("{label} FD metadata failed: {error}")))?;
    if metadata.st_uid != expected_owner || metadata.st_size != KEY_BYTES as i64 {
        return Err(BrokerError::Custody(format!(
            "{label} descriptor owner or length is invalid"
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| BrokerError::Custody(format!("{label} FD seek failed: {error}")))?;
    let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
    file.read_exact(&mut bytes[..])
        .map_err(|error| BrokerError::Custody(format!("{label} FD read failed: {error}")))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| BrokerError::Custody(format!("{label} FD final read failed: {error}")))?
        != 0
    {
        return Err(BrokerError::Custody(format!(
            "{label} descriptor has trailing bytes"
        )));
    }
    Ok(*bytes)
}

pub struct EncryptedBlobSecretBackend {
    connection: Mutex<Connection>,
    tenant_scope: String,
    master_key: BackendMasterKey,
}

impl EncryptedBlobSecretBackend {
    pub fn open(
        path: impl AsRef<Path>,
        tenant_scope: String,
        custody: SealedKeyFd,
    ) -> Result<Self> {
        let master_key = custody.read_once()?;
        Self::open_with_master_key(path, tenant_scope, master_key)
    }

    fn open_with_master_key(
        path: impl AsRef<Path>,
        tenant_scope: String,
        master_key: BackendMasterKey,
    ) -> Result<Self> {
        validate_identifier(&tenant_scope, "tenant scope", 512)?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    BrokerError::Storage(format!("secret store directory failed: {error}"))
                })?;
            }
        }
        prepare_database_file(path)?;
        let connection = Connection::open(path).map_err(storage)?;
        let backend = Self {
            connection: Mutex::new(connection),
            tenant_scope,
            master_key,
        };
        backend.migrate()?;
        Ok(backend)
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory_for_test(
        tenant_scope: &str,
        key: [u8; KEY_BYTES],
    ) -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(storage)?;
        let backend = Self {
            connection: Mutex::new(connection),
            tenant_scope: tenant_scope.to_string(),
            master_key: BackendMasterKey(key),
        };
        validate_identifier(&backend.tenant_scope, "tenant scope", 512)?;
        backend.migrate()?;
        Ok(backend)
    }

    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }

    pub(crate) fn provision(&self, credential: &CredentialRef, secret: &[u8]) -> Result<()> {
        credential.validate()?;
        if secret.is_empty() || secret.len() > 65_536 {
            return Err(BrokerError::InvalidRequest(
                "credential material is empty or oversized".to_string(),
            ));
        }
        let indexes = self.indexes(credential)?;
        let aad = credential_aad(&indexes, credential.version)?;
        let cipher = self.cipher();
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| BrokerError::Storage("credential encryption failed".to_string()))?;
        let connection = self.connection()?;
        connection
            .execute(
                r#"
                INSERT INTO broker_credentials (
                    tenant_index, provider_index, credential_index, version,
                    aead_version, nonce, ciphertext, enabled
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
                "#,
                params![
                    indexes.tenant,
                    indexes.provider,
                    indexes.credential,
                    sqlite_u64(credential.version, "credential version")?,
                    AEAD_VERSION,
                    nonce.as_slice(),
                    ciphertext,
                ],
            )
            .map_err(storage)?;
        Ok(())
    }

    pub(crate) fn disable(&self, credential: &CredentialRef) -> Result<()> {
        credential.validate()?;
        let indexes = self.indexes(credential)?;
        let changed = self
            .connection()?
            .execute(
                r#"
                UPDATE broker_credentials
                SET enabled = 0
                WHERE tenant_index = ?1 AND provider_index = ?2
                  AND credential_index = ?3 AND version = ?4
                "#,
                params![
                    indexes.tenant,
                    indexes.provider,
                    indexes.credential,
                    sqlite_u64(credential.version, "credential version")?,
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(BrokerError::Storage(format!(
                "credential reference {} was not found",
                credential.credential_id
            )));
        }
        Ok(())
    }

    pub(crate) fn delete(&self, credential: &CredentialRef) -> Result<()> {
        credential.validate()?;
        let indexes = self.indexes(credential)?;
        let changed = self
            .connection()?
            .execute(
                r#"
                DELETE FROM broker_credentials
                WHERE tenant_index = ?1 AND provider_index = ?2
                  AND credential_index = ?3 AND version = ?4
                "#,
                params![
                    indexes.tenant,
                    indexes.provider,
                    indexes.credential,
                    sqlite_u64(credential.version, "credential version")?,
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(BrokerError::Storage(format!(
                "credential reference {} was not found",
                credential.credential_id
            )));
        }
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| BrokerError::Storage("secret store lock is poisoned".to_string()))
    }

    fn migrate(&self) -> Result<()> {
        self.connection()?
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS broker_credentials (
                    tenant_index BLOB NOT NULL CHECK(length(tenant_index) = 32),
                    provider_index BLOB NOT NULL CHECK(length(provider_index) = 32),
                    credential_index BLOB NOT NULL CHECK(length(credential_index) = 32),
                    version INTEGER NOT NULL CHECK(version > 0),
                    aead_version INTEGER NOT NULL CHECK(aead_version = 1),
                    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                    ciphertext BLOB NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
                    PRIMARY KEY (tenant_index, provider_index, credential_index, version)
                ) STRICT;
                "#,
            )
            .map_err(storage)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.master_key.0))
    }

    fn indexes(&self, credential: &CredentialRef) -> Result<CredentialIndexes> {
        Ok(CredentialIndexes {
            tenant: keyed_index(&self.master_key.0, b"tenant", self.tenant_scope.as_bytes())?,
            provider: keyed_index(
                &self.master_key.0,
                b"provider",
                credential.provider.as_bytes(),
            )?,
            credential: keyed_index(
                &self.master_key.0,
                b"credential",
                credential.credential_id.as_bytes(),
            )?,
        })
    }
}

fn prepare_database_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(BrokerError::Storage(
                    "secret database path is not a regular file".to_string(),
                ));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(BrokerError::Storage(
                    "secret database permissions are not service-private".to_string(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            drop(options.open(path).map_err(|open_error| {
                BrokerError::Storage(format!("secret database creation failed: {open_error}"))
            })?);
        }
        Err(error) => {
            return Err(BrokerError::Storage(format!(
                "secret database metadata failed: {error}"
            )))
        }
    }
    Ok(())
}

impl SecretBackend for EncryptedBlobSecretBackend {
    fn materialize(&self, credential: &CredentialRef) -> Result<SecretMaterial> {
        credential.validate()?;
        let indexes = self.indexes(credential)?;
        let row = self
            .connection()?
            .query_row(
                r#"
                SELECT aead_version, nonce, ciphertext, enabled
                FROM broker_credentials
                WHERE tenant_index = ?1 AND provider_index = ?2
                  AND credential_index = ?3 AND version = ?4
                "#,
                params![
                    indexes.tenant,
                    indexes.provider,
                    indexes.credential,
                    sqlite_u64(credential.version, "credential version")?,
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((aead_version, nonce, ciphertext, enabled)) = row else {
            return Err(BrokerError::Storage(format!(
                "credential reference {} was not found",
                credential.credential_id
            )));
        };
        if aead_version != AEAD_VERSION || enabled != 1 || nonce.len() != NONCE_BYTES {
            return Err(BrokerError::Storage(format!(
                "credential reference {} is disabled or malformed",
                credential.credential_id
            )));
        }
        let aad = credential_aad(&indexes, credential.version)?;
        let plaintext = self
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                BrokerError::Storage(format!(
                    "credential reference {} failed authentication",
                    credential.credential_id
                ))
            })?;
        Ok(SecretMaterial::new(plaintext))
    }
}

struct CredentialIndexes {
    tenant: [u8; 32],
    provider: [u8; 32],
    credential: [u8; 32],
}

fn keyed_index(key: &[u8; 32], label: &[u8], value: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| BrokerError::Invariant("credential index key is invalid".to_string()))?;
    mac.update(INDEX_DOMAIN);
    mac.update(label);
    mac.update(&[0]);
    mac.update(value);
    Ok(mac.finalize().into_bytes().into())
}

fn credential_aad(indexes: &CredentialIndexes, version: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut aad = Zeroizing::new(Vec::with_capacity(
        AEAD_DOMAIN.len() + 32 + 32 + 32 + std::mem::size_of::<u64>(),
    ));
    aad.extend_from_slice(AEAD_DOMAIN);
    aad.extend_from_slice(&indexes.tenant);
    aad.extend_from_slice(&indexes.provider);
    aad.extend_from_slice(&indexes.credential);
    aad.extend_from_slice(&version.to_be_bytes());
    Ok(aad)
}

fn storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("secret SQLite operation failed: {error}"))
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BrokerError::InvalidRequest(format!("{label} exceeds SQLite range")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(version: u64) -> CredentialRef {
        CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-a".to_string(),
            version,
        }
    }

    #[test]
    fn encrypted_rows_have_only_keyed_indexes_and_ciphertext() {
        let backend = EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-a", [7; 32])
            .expect("backend");
        backend
            .provision(&credential(1), b"unique-secret-canary")
            .expect("provision");
        let connection = backend.connection().expect("connection");
        let dump: Vec<u8> = connection
            .query_row("SELECT ciphertext FROM broker_credentials", [], |row| {
                row.get(0)
            })
            .expect("ciphertext");
        assert!(!dump
            .windows(b"unique-secret-canary".len())
            .any(|window| window == b"unique-secret-canary"));
        drop(connection);
        let material = backend.materialize(&credential(1)).expect("materialize");
        assert_eq!(material.as_bytes(), b"unique-secret-canary");
    }

    #[test]
    fn wrong_key_tamper_and_disabled_version_fail_closed() {
        let path = tempfile::NamedTempFile::new().expect("tempfile");
        let backend = EncryptedBlobSecretBackend::open_with_master_key(
            path.path(),
            "tenant-a".to_string(),
            BackendMasterKey([7; 32]),
        )
        .expect("backend");
        backend
            .provision(&credential(1), b"unique-secret-canary")
            .expect("provision");
        backend.disable(&credential(1)).expect("disable");
        assert!(backend.materialize(&credential(1)).is_err());
        drop(backend);
        let wrong = EncryptedBlobSecretBackend::open_with_master_key(
            path.path(),
            "tenant-a".to_string(),
            BackendMasterKey([8; 32]),
        )
        .expect("wrong backend");
        assert!(wrong.materialize(&credential(1)).is_err());
    }

    #[test]
    fn tenant_scope_rotation_disable_delete_and_ciphertext_tamper_are_isolated() {
        let path = tempfile::NamedTempFile::new().expect("tempfile");
        let tenant_a = EncryptedBlobSecretBackend::open_with_master_key(
            path.path(),
            "tenant-a".to_string(),
            BackendMasterKey([7; 32]),
        )
        .expect("tenant a");
        tenant_a
            .provision(&credential(1), b"version-one")
            .expect("version one");
        tenant_a
            .provision(&credential(2), b"version-two")
            .expect("version two");
        let tenant_b = EncryptedBlobSecretBackend::open_with_master_key(
            path.path(),
            "tenant-b".to_string(),
            BackendMasterKey([7; 32]),
        )
        .expect("tenant b");
        assert!(tenant_b.materialize(&credential(1)).is_err());
        assert_eq!(
            tenant_a
                .materialize(&credential(1))
                .expect("version one material")
                .as_bytes(),
            b"version-one"
        );
        tenant_a.disable(&credential(1)).expect("disable one");
        assert!(tenant_a.materialize(&credential(1)).is_err());
        assert_eq!(
            tenant_a
                .materialize(&credential(2))
                .expect("version two material")
                .as_bytes(),
            b"version-two"
        );

        let indexes = tenant_a.indexes(&credential(2)).expect("indexes");
        let connection = tenant_a.connection().expect("connection");
        let mut ciphertext: Vec<u8> = connection
            .query_row(
                r#"
                SELECT ciphertext FROM broker_credentials
                WHERE tenant_index = ?1 AND provider_index = ?2
                  AND credential_index = ?3 AND version = 2
                "#,
                params![indexes.tenant, indexes.provider, indexes.credential],
                |row| row.get(0),
            )
            .expect("ciphertext");
        ciphertext[0] ^= 1;
        connection
            .execute(
                r#"
                UPDATE broker_credentials SET ciphertext = ?1
                WHERE tenant_index = ?2 AND provider_index = ?3
                  AND credential_index = ?4 AND version = 2
                "#,
                params![
                    ciphertext,
                    indexes.tenant,
                    indexes.provider,
                    indexes.credential
                ],
            )
            .expect("tamper");
        drop(connection);
        assert!(tenant_a.materialize(&credential(2)).is_err());
        tenant_a.delete(&credential(2)).expect("delete two");
        assert!(tenant_a.materialize(&credential(2)).is_err());
    }

    #[test]
    fn ordinary_or_unsealed_file_cannot_supply_startup_key() {
        let key_file = tempfile::NamedTempFile::new().expect("key file");
        std::fs::write(key_file.path(), [7_u8; 32]).expect("write key fixture");
        let file = File::open(key_file.path()).expect("open read-only fixture");
        let custody = SealedKeyFd::from_inherited_file(file, 0);
        let database = tempfile::NamedTempFile::new().expect("database");
        assert!(
            EncryptedBlobSecretBackend::open(database.path(), "tenant-a".to_string(), custody)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_database_rejects_public_permissions_and_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().expect("directory");
        let public = directory.path().join("public.sqlite");
        std::fs::write(&public, []).expect("database fixture");
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644))
            .expect("public permissions");
        assert!(EncryptedBlobSecretBackend::open_with_master_key(
            &public,
            "tenant-a".to_string(),
            BackendMasterKey([7; 32]),
        )
        .is_err());

        let target = directory.path().join("target.sqlite");
        std::fs::write(&target, []).expect("target fixture");
        let link = directory.path().join("link.sqlite");
        symlink(&target, &link).expect("symlink");
        assert!(EncryptedBlobSecretBackend::open_with_master_key(
            &link,
            "tenant-a".to_string(),
            BackendMasterKey([7; 32]),
        )
        .is_err());
    }
}
