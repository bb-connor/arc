use chio_core_types::{canonical_json_bytes, sha256_hex, Keypair, PublicKey};
use chio_kernel::{
    KernelConfig, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub const SERVER: &str = "security-review-provider";
pub const PROFILE: &str = "chio.example.security-review-agreement.v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Agreement {
    pub profile: String,
    pub job_id: String,
    pub input_sha256: String,
    pub buyer: PublicKey,
    pub provider: PublicKey,
    pub price_ceiling: u64,
    pub deadline: u64,
    pub checker: String,
    pub subcontracting: bool,
    pub credit_profile: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Peers {
    pub buyer: PublicKey,
    pub provider: PublicKey,
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}
pub fn read<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn key(state: &Path) -> Result<Keypair> {
    Ok(Keypair::from_seed_hex(
        fs::read_to_string(state.join("key.seed"))?.trim(),
    )?)
}
pub fn crash() -> Result<()> {
    std::process::Command::new("/usr/bin/kill")
        .args(["-KILL", &std::process::id().to_string()])
        .status()?;
    Err("crash injection did not terminate this process".into())
}
pub fn init(state: &Path) -> Result<PublicKey> {
    fs::create_dir_all(state)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(state, fs::Permissions::from_mode(0o700))?;
    }
    let key = Keypair::generate();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(state.join("key.seed"))?;
    file.write_all(key.seed_hex().as_bytes())?;
    file.sync_all()?;
    Ok(key.public_key())
}
pub fn validate_agreement(a: &Agreement, peers: &Peers) -> Result<()> {
    if a.profile != PROFILE
        || a.buyer != peers.buyer
        || a.provider != peers.provider
        || a.credit_profile != "buyer-local-credit-promise-v1"
        || a.subcontracting
        || a.checker != "openapi-explicit-auth-v1"
        || a.price_ceiling < 100
        || a.price_ceiling > 1000
        || a.job_id.is_empty()
        || a.job_id.len() > 128
        || !a
            .job_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || a.input_sha256.len() != 64
        || !a
            .input_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("agreement violates local work profile".into());
    }
    Ok(())
}
pub fn kernel_config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: sha256_hex(b"federated-work-example-v1"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}
