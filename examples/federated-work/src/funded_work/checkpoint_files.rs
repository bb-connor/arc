//! Canonical file interfaces for checkpoint custody outside the provider process.
use super::{checkpoint_handoff as handoff, execution_evidence::Bundle, native::Native, observer};
use crate::common::Result;
use chio_core_types::canonical_json_bytes;
use serde::Serialize;
use std::{fs, io::Write, path::Path, sync::Arc};

/// This source cannot observe or authorize any financial successor.
struct Offline;
impl observer::FundingSource for Offline {
    fn observe(&self, _: &str) -> Result<observer::Observation> {
        Err("checkpoint file handoff has no funding observer".into())
    }
}

fn open(state: &Path) -> Result<Native> {
    Native::open_for_checkpoint(state, Arc::new(Offline))
}

pub(super) fn write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = canonical_json_bytes(value)?;
    if bytes.len() > super::wire::MAX_ARTIFACT_BYTES {
        return Err("checkpoint artifact exceeds bounded profile".into());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn export(state: &Path, request_id: &str, output: &Path) -> Result<serde_json::Value> {
    let native = open(state)?;
    let entry = native
        .journal
        .by_request(request_id)?
        .ok_or("original funded request missing")?;
    let request = handoff::export(&native, &entry.request)?;
    write(output, &request)?;
    Ok(serde_json::json!({"requestSha256":crate::common::digest(&request)?}))
}

pub fn import(state: &Path, request_id: &str, input: &Path) -> Result<serde_json::Value> {
    let bundle: Bundle = super::evidence::read(input)?;
    let native = open(state)?;
    let entry = native
        .journal
        .by_request(request_id)?
        .ok_or("original funded request missing")?;
    handoff::import(&native, &entry.request, &bundle)?;
    Ok(
        serde_json::json!({"bundleSha256":crate::common::digest(&bundle)?, "financialBacking":false}),
    )
}
