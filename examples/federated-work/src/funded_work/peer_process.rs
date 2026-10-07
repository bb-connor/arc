//! Real peer-service qualification, composed with the original local lifecycle.
use crate::common::Result;
use std::{path::Path, process::Command};

pub(super) fn exchange(root: &Path, request_id: &str, socket: &Path) -> Result<serde_json::Value> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("peer_transport.py");
    for (name, source) in [
        (
            "peer_transport.py",
            include_bytes!("../../peer_transport.py").as_slice(),
        ),
        (
            "peer_tls_fixture.py",
            include_bytes!("../../peer_tls_fixture.py").as_slice(),
        ),
    ] {
        if std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(name))? != source {
            return Err("peer qualification driver differs from compiled source".into());
        }
    }
    let output =
        Command::new(std::env::var_os("CHIO_FUNDED_PYTHON").ok_or("pinned Python required")?)
            .arg("-B")
            .arg(script)
            .arg(std::env::current_exe()?)
            .arg(root)
            .arg(request_id)
            .arg(socket)
            .output()?;
    if !output.status.success() {
        return Err(format!(
            "peer transport qualification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
