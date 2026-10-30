//! Authority signing keys loaded through key custody.
use crate::{CliError, Keypair};
use chio_secure_ipc::seed_custody::{
    read_private_file, KeyCustodyError, KeyRef, OsSeedSource, SeedSource,
};
use std::path::Path;
use zeroize::Zeroizing;

const AUTHORITY_SEED_MAX_BYTES: usize = 256;

/// Load existing signing custody without creating or repairing it.
/// `path` is a key reference: `credential:<name>` or a seed file path.
pub fn load_existing_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    AuthoritySeeds::from_env()?.load_existing(path)
}

/// Public key of the authority seed `path` names; `None` when a seed file is absent.
pub fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<chio_core::PublicKey>, CliError> {
    AuthoritySeeds::from_env()?.public_key(path)
}

/// Replace the seed file with a fresh authority key. OS custody is never written.
pub fn rotate_authority_keypair(path: &Path) -> Result<chio_core::PublicKey, CliError> {
    AuthoritySeeds::from_env()?.rotate(path)
}

/// Load the authority seed, creating a seed file only for a missing file reference.
pub fn load_or_create_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    AuthoritySeeds::from_env()?.load_or_create(path)
}

/// The seed file a caller may create or replace. Credential references are
/// read-only, and required custody refuses every seed file.
pub fn writable_authority_seed_file(path: &Path) -> Result<&Path, CliError> {
    AuthoritySeeds::from_env()?.writable_seed_file(path)
}

/// Read existing private signing custody, bounded and wiped on every exit path.
pub fn read_private_signing_custody(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    Ok(read_private_file(path, maximum_bytes)?)
}

pub(crate) fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    crate::write_private_file_atomically(path, format!("{}\n", keypair.seed_hex()).as_bytes())
}

/// Authority keys over the seed source every entry point resolves through.
struct AuthoritySeeds<S> {
    source: S,
}

impl AuthoritySeeds<OsSeedSource> {
    fn from_env() -> Result<Self, CliError> {
        Ok(Self {
            source: OsSeedSource::from_env()?,
        })
    }
}

impl<S: SeedSource> AuthoritySeeds<S> {
    /// The seed file a caller may create or replace; OS custody is read-only.
    fn writable_seed_file<'a>(&self, path: &'a Path) -> Result<&'a Path, CliError> {
        match self.source.resolve(path)? {
            KeyRef::File(_) => Ok(path),
            KeyRef::SystemdCredential { .. } => Err(KeyCustodyError::ReadOnlyCustody.into()),
        }
    }

    fn load_existing(&self, path: &Path) -> Result<Keypair, CliError> {
        let key = self.source.resolve(path)?;
        self.load_key(&key)
    }

    /// `None` only for an absent seed file; a missing credential is an error.
    fn public_key(&self, path: &Path) -> Result<Option<chio_core::PublicKey>, CliError> {
        let key = self.source.resolve(path)?;
        match self.load_key(&key) {
            Ok(keypair) => Ok(Some(keypair.public_key())),
            Err(error) if is_missing_seed_file(&key, &error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn rotate(&self, path: &Path) -> Result<chio_core::PublicKey, CliError> {
        let path = self.writable_seed_file(path)?;
        let keypair = Keypair::generate();
        write_authority_seed_file(path, &keypair)?;
        Ok(keypair.public_key())
    }

    fn load_or_create(&self, path: &Path) -> Result<Keypair, CliError> {
        let key = self.source.resolve(path)?;
        match self.load_key(&key) {
            Err(error) if is_missing_seed_file(&key, &error) => {
                let keypair = Keypair::generate();
                write_authority_seed_file(path, &keypair)?;
                Ok(keypair)
            }
            loaded => loaded,
        }
    }

    fn load_key(&self, key: &KeyRef) -> Result<Keypair, CliError> {
        let seed_bytes = self.source.read_seed(key, AUTHORITY_SEED_MAX_BYTES)?;
        let seed_hex = std::str::from_utf8(&seed_bytes)
            .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8"))?;
        Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
    }
}

fn is_missing_seed_file(key: &KeyRef, error: &CliError) -> bool {
    matches!(key, KeyRef::File(_))
        && matches!(error, CliError::Io(error) if error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
#[path = "signing_custody_tests.rs"]
mod tests;
