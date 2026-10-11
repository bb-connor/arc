//! Explicit operator-only cut point for the committed-claim-loss qualification.
//! This directory is outside every worker's native filesystem authority.
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use chio_core_types::canonical_json_bytes;
use chio_secret_broker::{BrokerError, Result};
use serde_json::{json, Value};

pub struct ClaimResponseLoss {
    directory: PathBuf,
    next: AtomicU64,
}

fn unavailable() -> BrokerError {
    BrokerError::Upstream("Claim response withheld; outcome must remain uncertain".into())
}

impl ClaimResponseLoss {
    pub fn new(directory: PathBuf) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(&directory).map_err(|_| unavailable())?;
        if !directory.is_absolute() || !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(unavailable());
        }
        Ok(Self {
            directory,
            next: AtomicU64::new(0),
        })
    }

    pub fn after_commit(&self, params: &Value, value: &Value) -> Result<()> {
        let next = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| unavailable())?;
        self.write(
            &format!("delivery-{next:04}.json"),
            &json!({
                "arguments": params["arguments"],
                "caller": params["_meta"]["chioCallerCapabilitySha256"]
            }),
        )?;
        if next != 0 {
            return Ok(());
        }
        self.write(
            "committed.json",
            &json!({
                "response_forwarded": false, "resource_result": value
            }),
        )?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let mut release = Vec::new();
            if std::fs::File::open(self.directory.join("release"))
                .and_then(|file| file.take(9).read_to_end(&mut release))
                .is_ok()
                && release == b"release\n"
            {
                self.write("released.json", &json!({"withheld_exchange_closed": true}))?;
                return Err(unavailable());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(unavailable())
    }

    fn write(&self, name: &str, value: &Value) -> Result<()> {
        let bytes = canonical_json_bytes(value).map_err(|_| unavailable())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(name))
            .map_err(|_| unavailable())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| unavailable())?;
        std::fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| unavailable())
    }
}
