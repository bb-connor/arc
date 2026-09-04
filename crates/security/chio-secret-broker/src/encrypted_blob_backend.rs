use chio_core_types::Keypair;
use chio_store_sqlite::{
    BlobReference, BlobReferenceMutationOutcome, SqliteEncryptedBlobStore, TenantId, TenantKey,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "android"))]
use zeroize::Zeroizing;

use crate::backend::{SecretBackend, SecretMaterial};
use crate::protocol::CredentialRef;
use crate::sqlite::DurableBrokerDatabaseFile;
use crate::{validate_identifier, BrokerError, Result};

#[cfg(any(test, target_os = "linux", target_os = "android"))]
const KEY_BYTES: usize = 32;
const INDEX_DOMAIN: &[u8] = b"chio.secret-broker.index.v1\0";
const REFERENCE_NAMESPACE: &str = "chio.secret-broker.credentials.v1";

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
    fn read_once(mut self) -> Result<TenantKey> {
        if self.consumed {
            return Err(BrokerError::Custody(
                "master-key descriptor was already consumed".to_string(),
            ));
        }
        let bytes = read_sealed_32(&mut self.file, self.expected_owner, "master key")?;
        self.consumed = true;
        Ok(TenantKey::from_bytes(*bytes))
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn read_once(self) -> Result<TenantKey> {
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
        let seed = read_sealed_32(&mut self.file, self.expected_owner, "signing key")?;
        self.consumed = true;
        let keypair = Keypair::from_seed(&seed);
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
fn read_sealed_32(
    file: &mut File,
    expected_owner: u32,
    label: &str,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
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
    Ok(bytes)
}

pub struct EncryptedBlobSecretBackend {
    store: SqliteEncryptedBlobStore,
    tenant_id: TenantId,
    tenant_key: TenantKey,
    durable_file: Option<DurableBrokerDatabaseFile>,
}

impl EncryptedBlobSecretBackend {
    pub fn open(
        path: impl AsRef<Path>,
        tenant_scope: String,
        custody: SealedKeyFd,
    ) -> Result<Self> {
        let tenant_key = custody.read_once()?;
        Self::open_with_tenant_key(path, tenant_scope, tenant_key)
    }

    pub(crate) fn open_with_tenant_key(
        path: impl AsRef<Path>,
        tenant_scope: String,
        tenant_key: TenantKey,
    ) -> Result<Self> {
        validate_identifier(&tenant_scope, "tenant scope", 512)?;
        let path = path.as_ref();
        let durable_file = DurableBrokerDatabaseFile::open(path)?;
        let store = SqliteEncryptedBlobStore::open(path).map_err(blob_storage)?;
        durable_file.validate()?;
        Ok(Self {
            store,
            tenant_id: TenantId::new(tenant_scope),
            tenant_key,
            durable_file: Some(durable_file),
        })
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory_for_test(
        tenant_scope: &str,
        key: [u8; KEY_BYTES],
    ) -> Result<Self> {
        validate_identifier(tenant_scope, "tenant scope", 512)?;
        Ok(Self {
            store: SqliteEncryptedBlobStore::open_in_memory().map_err(blob_storage)?,
            tenant_id: TenantId::new(tenant_scope),
            tenant_key: TenantKey::from_bytes(key),
            durable_file: None,
        })
    }

    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        self.tenant_id.as_str()
    }

    #[cfg(test)]
    pub(crate) fn provision(&self, credential: &CredentialRef, secret: &[u8]) -> Result<()> {
        credential.validate()?;
        if secret.is_empty() || secret.len() > 65_536 {
            return Err(BrokerError::InvalidRequest(
                "credential material is empty or oversized".to_string(),
            ));
        }
        let reference = self.reference(credential)?;
        self.store
            .write_encrypted_blob_with_reference(&reference, &self.tenant_key, secret)
            .map_err(blob_storage)?;
        Ok(())
    }

    pub(crate) fn provision_once(
        &self,
        credential: &CredentialRef,
        secret: &[u8],
        operation_id: &str,
        mutation_digest: &str,
    ) -> Result<BlobReferenceMutationOutcome> {
        credential.validate()?;
        if secret.is_empty() || secret.len() > 65_536 {
            return Err(BrokerError::InvalidRequest(
                "credential material is empty or oversized".to_string(),
            ));
        }
        let reference = self.reference(credential)?;
        self.store
            .write_encrypted_blob_with_reference_once(
                &reference,
                &self.tenant_key,
                secret,
                operation_id,
                mutation_digest,
            )
            .map(|(_, outcome)| outcome)
            .map_err(blob_storage)
    }

    #[cfg(test)]
    pub(crate) fn disable(&self, credential: &CredentialRef) -> Result<()> {
        credential.validate()?;
        self.store
            .disable_blob_reference(&self.reference(credential)?)
            .map_err(|_| missing_credential(credential))
    }

    pub(crate) fn disable_once(
        &self,
        credential: &CredentialRef,
        operation_id: &str,
        mutation_digest: &str,
    ) -> Result<BlobReferenceMutationOutcome> {
        credential.validate()?;
        self.store
            .disable_blob_reference_once(
                &self.reference(credential)?,
                operation_id,
                mutation_digest,
            )
            .map_err(blob_storage)
    }

    #[cfg(test)]
    pub(crate) fn delete(&self, credential: &CredentialRef) -> Result<()> {
        credential.validate()?;
        self.store
            .delete_blob_reference(&self.reference(credential)?)
            .map_err(|_| missing_credential(credential))
    }

    pub(crate) fn delete_once(
        &self,
        credential: &CredentialRef,
        operation_id: &str,
        mutation_digest: &str,
    ) -> Result<BlobReferenceMutationOutcome> {
        credential.validate()?;
        self.store
            .delete_blob_reference_once(&self.reference(credential)?, operation_id, mutation_digest)
            .map_err(blob_storage)
    }

    fn reference(&self, credential: &CredentialRef) -> Result<BlobReference> {
        if let Some(durable_file) = self.durable_file.as_ref() {
            durable_file.validate()?;
        }
        credential.validate()?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.tenant_key.as_bytes())
            .map_err(|_| BrokerError::Invariant("credential index key is invalid".to_string()))?;
        mac.update(INDEX_DOMAIN);
        for component in [
            self.tenant_id.as_str().as_bytes(),
            credential.provider.as_bytes(),
            credential.credential_id.as_bytes(),
        ] {
            mac.update(component);
            mac.update(&[0]);
        }
        mac.update(&credential.version.to_be_bytes());
        let reference_key = mac.finalize().into_bytes().into();
        BlobReference::new(REFERENCE_NAMESPACE, self.tenant_id.clone(), reference_key)
            .map_err(blob_storage)
    }
}

impl SecretBackend for EncryptedBlobSecretBackend {
    fn materialize(&self, credential: &CredentialRef) -> Result<SecretMaterial> {
        credential.validate()?;
        let reference = self.reference(credential)?;
        let handle = self
            .store
            .resolve_blob_reference(&reference)
            .map_err(|_| missing_credential(credential))?;
        let plaintext = self
            .store
            .read_encrypted_blob(&handle, &self.tenant_key)
            .map_err(|_| {
                BrokerError::Storage(format!(
                    "credential reference {} failed authentication",
                    credential.credential_id
                ))
            })?;
        Ok(SecretMaterial::new(plaintext))
    }
}

fn missing_credential(credential: &CredentialRef) -> BrokerError {
    BrokerError::Storage(format!(
        "credential reference {} was not found",
        credential.credential_id
    ))
}

fn blob_storage(error: chio_store_sqlite::BlobStoreError) -> BrokerError {
    BrokerError::Storage(format!("secret encrypted-blob operation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    type SealedKeyReader = fn(&mut File, u32, &str) -> Result<Zeroizing<[u8; KEY_BYTES]>>;

    fn credential(version: u64) -> CredentialRef {
        CredentialRef {
            provider: "generic-https".to_string(),
            credential_id: "credential-a".to_string(),
            version,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn sealed_reader_retains_zeroizing_custody() {
        let _reader: SealedKeyReader = read_sealed_32;
    }

    #[test]
    fn encrypted_rows_have_only_keyed_indexes_and_ciphertext() {
        let backend = EncryptedBlobSecretBackend::open_in_memory_for_test("tenant-a", [7; 32])
            .test_expect("backend");
        backend
            .provision(&credential(1), b"unique-secret-canary")
            .test_expect("provision");
        let reference = backend.reference(&credential(1)).test_expect("reference");
        let handle = backend
            .store
            .resolve_blob_reference(&reference)
            .test_expect("handle");
        let dump = backend
            .store
            .load_encrypted_blob(&handle)
            .test_expect("encrypted blob")
            .ciphertext;
        assert!(!dump
            .windows(b"unique-secret-canary".len())
            .any(|window| window == b"unique-secret-canary"));
        let material = backend
            .materialize(&credential(1))
            .test_expect("materialize");
        assert_eq!(material.as_bytes(), b"unique-secret-canary");
    }

    #[test]
    fn wrong_key_tamper_and_disabled_version_fail_closed() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let path = trusted_directory.join("secrets.sqlite3");
        let backend = EncryptedBlobSecretBackend::open_with_tenant_key(
            &path,
            "tenant-a".to_string(),
            TenantKey::from_bytes([7; 32]),
        )
        .test_expect("backend");
        backend
            .provision(&credential(1), b"unique-secret-canary")
            .test_expect("provision");
        backend.disable(&credential(1)).test_expect("disable");
        assert!(backend.materialize(&credential(1)).is_err());
        drop(backend);
        let wrong = EncryptedBlobSecretBackend::open_with_tenant_key(
            &path,
            "tenant-a".to_string(),
            TenantKey::from_bytes([8; 32]),
        )
        .test_expect("wrong backend");
        assert!(wrong.materialize(&credential(1)).is_err());
    }

    #[test]
    fn tenant_scope_rotation_disable_and_delete_are_isolated() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let path = trusted_directory.join("secrets.sqlite3");
        let tenant_a = EncryptedBlobSecretBackend::open_with_tenant_key(
            &path,
            "tenant-a".to_string(),
            TenantKey::from_bytes([7; 32]),
        )
        .test_expect("tenant a");
        tenant_a
            .provision(&credential(1), b"version-one")
            .test_expect("version one");
        tenant_a
            .provision(&credential(2), b"version-two")
            .test_expect("version two");
        let tenant_b = EncryptedBlobSecretBackend::open_with_tenant_key(
            &path,
            "tenant-b".to_string(),
            TenantKey::from_bytes([7; 32]),
        )
        .test_expect("tenant b");
        assert!(tenant_b.materialize(&credential(1)).is_err());
        assert_eq!(
            tenant_a
                .materialize(&credential(1))
                .test_expect("version one material")
                .as_bytes(),
            b"version-one"
        );
        tenant_a.disable(&credential(1)).test_expect("disable one");
        assert!(tenant_a.materialize(&credential(1)).is_err());
        assert_eq!(
            tenant_a
                .materialize(&credential(2))
                .test_expect("version two material")
                .as_bytes(),
            b"version-two"
        );

        tenant_a.delete(&credential(2)).test_expect("delete two");
        assert!(tenant_a.materialize(&credential(2)).is_err());
    }

    #[test]
    fn ordinary_or_unsealed_file_cannot_supply_startup_key() {
        let key_file = tempfile::NamedTempFile::new().test_expect("key file");
        std::fs::write(key_file.path(), [7_u8; 32]).test_expect("write key fixture");
        let file = File::open(key_file.path()).test_expect("open read-only fixture");
        let custody = SealedKeyFd::from_inherited_file(file, 0);
        let database = tempfile::NamedTempFile::new().test_expect("database");
        assert!(
            EncryptedBlobSecretBackend::open(database.path(), "tenant-a".to_string(), custody)
                .is_err()
        );

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use rustix::fs::{memfd_create, MemfdFlags};
            use std::io::Write;
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;

            let descriptor =
                memfd_create("chio-unsealed-key", MemfdFlags::ALLOW_SEALING).test_expect("memfd");
            let mut writable = File::from(descriptor);
            writable.write_all(&[7_u8; 32]).test_expect("write memfd");
            let mut read_only = File::open(format!("/proc/self/fd/{}", writable.as_raw_fd()))
                .test_expect("reopen memfd read-only");
            let expected_owner = read_only.metadata().test_expect("memfd metadata").uid();

            assert!(read_sealed_32(&mut read_only, expected_owner, "unsealed key").is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn secret_database_rejects_public_permissions_and_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let public = trusted_directory.join("public.sqlite");
        std::fs::write(&public, []).test_expect("database fixture");
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644))
            .test_expect("public permissions");
        assert!(EncryptedBlobSecretBackend::open_with_tenant_key(
            &public,
            "tenant-a".to_string(),
            TenantKey::from_bytes([7; 32]),
        )
        .is_err());

        let target = trusted_directory.join("target.sqlite");
        std::fs::write(&target, []).test_expect("target fixture");
        let link = trusted_directory.join("link.sqlite");
        symlink(&target, &link).test_expect("symlink");
        assert!(EncryptedBlobSecretBackend::open_with_tenant_key(
            &link,
            "tenant-a".to_string(),
            TenantKey::from_bytes([7; 32]),
        )
        .is_err());
    }
}
