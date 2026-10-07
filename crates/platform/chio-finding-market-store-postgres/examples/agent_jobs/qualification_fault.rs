//! Explicit host-owned qualification cut point after the first committed claim.
//! It withholds the reply until the driver has killed the actual kernel host.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use chio_secret_broker::{host_https::private_bytes, Result};
use serde_json::{json, Value};

pub(super) struct ClaimResponseLoss {
    directory: PathBuf,
    deliveries: AtomicU64,
}

impl ClaimResponseLoss {
    pub(super) fn new(directory: PathBuf) -> Result<Self> {
        let metadata = fs::symlink_metadata(&directory).map_err(|_| super::denied())?;
        if !directory.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || fs::read_dir(&directory)
                .map_err(|_| super::denied())?
                .next()
                .is_some()
        {
            return Err(super::denied());
        }
        Ok(Self {
            directory,
            deliveries: AtomicU64::new(0),
        })
    }

    fn record(&self, name: &str, value: &Value) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(name))
            .map_err(|_| super::unavailable())?;
        let bytes =
            chio_core_types::canonical_json_bytes(value).map_err(|_| super::unavailable())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| super::unavailable())
    }

    pub(super) fn before(&self, request: &Value) -> Result<Option<u64>> {
        if request["name"] != "assign" {
            return Ok(None);
        }
        let delivery = self
            .deliveries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| super::unavailable())?
            + 1;
        self.record(
            &format!("delivery-{delivery}.json"),
            &json!({
                "arguments": request["arguments"],
                "caller": request["_meta"]["chioCallerCapabilitySha256"],
            }),
        )?;
        Ok(Some(delivery))
    }

    pub(super) fn after(&self, delivery: Option<u64>, response: &Value) -> Result<()> {
        if delivery != Some(1) {
            return Ok(());
        }
        if response["structuredContent"]["status"] != "assigned"
            || response["structuredContent"]["jobs"]
                .as_array()
                .map(Vec::len)
                != Some(1)
        {
            return Err(super::unavailable());
        }
        self.record(
            "committed.json",
            &json!({"response_forwarded":false,
            "response":{"result":response}}),
        )?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(super::unavailable)?;
        while Instant::now() < deadline {
            if let Ok(bytes) = private_bytes(&self.directory.join("release"), 32) {
                if bytes.as_slice() == b"host-sigkill-observed\n" {
                    self.record(
                        "stopped.json",
                        &json!({
                            "response_forwarded":false, "release_observed":true,
                        }),
                    )?;
                    return Err(super::unavailable());
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(super::unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_reply_is_withheld_and_only_new_intent_can_make_a_second_delivery() -> Result<()> {
        let directory =
            chio_test_support::private_tempdir().map_err(|_| super::super::unavailable())?;
        let fault = ClaimResponseLoss::new(directory.path().to_owned())?;
        let request = json!({"name":"assign", "arguments":{"limit":1},
            "_meta":{"chioCallerCapabilitySha256":"a".repeat(64)}});
        assert_eq!(fault.before(&json!({"name":"inspect"}))?, None);
        assert_eq!(fault.before(&request)?, Some(1));
        fs::write(directory.path().join("release"), b"host-sigkill-observed\n")
            .map_err(|_| super::super::unavailable())?;
        fs::set_permissions(
            directory.path().join("release"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .map_err(|_| super::super::unavailable())?;
        let response =
            json!({"structuredContent":{"status":"assigned","jobs":[{"job_id":"first"}]}});
        assert!(fault.after(Some(1), &response).is_err());
        for name in ["committed.json", "stopped.json"] {
            let bytes = private_bytes(&directory.path().join(name), 4096)?;
            let record: Value =
                serde_json::from_slice(&bytes).map_err(|_| super::super::unavailable())?;
            assert_eq!(record["response_forwarded"], false);
        }
        assert_eq!(fault.before(&request)?, Some(2));
        assert!(fault.after(Some(2), &response).is_ok());
        assert!(ClaimResponseLoss::new(directory.path().to_owned()).is_err());
        Ok(())
    }
}
