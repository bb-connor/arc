//! Owned subprocess observer for the private development-chain reproduction.
use super::observer::{FundingSource, Observation};
use crate::common::Result;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    time::Duration,
};

struct Worker {
    child: Child,
    input: ChildStdin,
    output: Receiver<Result<String>>,
    failed: bool,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct LocalChain(Mutex<Worker>);

const SOURCES: &[(&str, &[u8])] = &[
    (
        "work-claim-native-observer.mjs",
        include_bytes!("../../../../contracts/scripts/work-claim-native-observer.mjs"),
    ),
    (
        "work-claim-native-transactions.mjs",
        include_bytes!("../../../../contracts/scripts/work-claim-native-transactions.mjs"),
    ),
    (
        "work-claim-recovery.mjs",
        include_bytes!("../../../../contracts/scripts/work-claim-recovery.mjs"),
    ),
    (
        "work-claim-fixture.mjs",
        include_bytes!("../../../../contracts/scripts/work-claim-fixture.mjs"),
    ),
    (
        "work-claim-native-inventory.mjs",
        include_bytes!("../../../../contracts/scripts/work-claim-native-inventory.mjs"),
    ),
];

pub(super) fn implementation_digest() -> String {
    chio_core_types::sha256_hex(
        &SOURCES
            .iter()
            .flat_map(|(_, bytes)| *bytes)
            .copied()
            .collect::<Vec<_>>(),
    )
}

impl LocalChain {
    pub fn start() -> Result<Self> {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/scripts/work-claim-native-observer.mjs");
        let directory = script.parent().ok_or("observer script directory missing")?;
        for (name, pinned) in SOURCES {
            if std::fs::read(directory.join(name))? != *pinned {
                return Err("local chain source differs from pinned implementation".into());
            }
        }
        let mut child = Command::new("node")
            .arg(script)
            .env_remove("CHIO_CLAIM_MUTATION")
            .env_remove("NODE_OPTIONS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or("observer stdin unavailable")?;
        let output = child.stdout.take().ok_or("observer stdout unavailable")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let mut bytes = Vec::new();
                // Bound each message before JSON parsing. Closing the receiver
                // terminates this reader once the owned child is stopped.
                let read = (&mut reader)
                    .take(1024 * 1024 + 1)
                    .read_until(b'\n', &mut bytes);
                let result = match read {
                    Ok(0) => break,
                    Ok(_) if bytes.len() > 1024 * 1024 || !bytes.ends_with(b"\n") => {
                        Err("observer message exceeds limit".into())
                    }
                    Ok(_) => String::from_utf8(bytes).map_err(Into::into),
                    Err(error) => Err(error.into()),
                };
                let failed = result.is_err();
                if sender.send(result).is_err() || failed {
                    break;
                }
            }
        });
        Ok(Self(Mutex::new(Worker {
            child,
            input,
            output: receiver,
            failed: false,
        })))
    }

    pub fn request(&self, value: Value) -> Result<Value> {
        let mut worker = self.0.lock().map_err(|_| "observer lock poisoned")?;
        if worker.failed {
            return Err("observer transport is unavailable".into());
        }
        let mut request = || -> Result<Result<Value>> {
            let bytes = serde_json::to_vec(&value)?;
            if bytes.len() > 256 * 1024 {
                return Err("observer request exceeds limit".into());
            }
            worker.input.write_all(&bytes)?;
            worker.input.write_all(b"\n")?;
            worker.input.flush()?;
            let response = worker.output.recv_timeout(Duration::from_secs(30))??;
            let value: Value = serde_json::from_str(&response)?;
            if value.as_object().is_none_or(|object| object.len() != 1) {
                return Err("invalid observer response".into());
            }
            if let Some(error) = value.get("error") {
                let error = error.as_str().ok_or("malformed observer error response")?;
                // A well-framed negative response (including no receipt yet)
                // preserves channel alignment. It denies this observation but
                // must not disable recovery of the retained unbroadcast intent.
                return Ok(Err(format!("private observer: {error}").into()));
            }
            Ok(Ok(value
                .get("result")
                .cloned()
                .ok_or("observer result missing")?))
        };
        match request() {
            Ok(result) => result,
            Err(error) => {
                worker.failed = true;
                Err(error)
            }
        }
    }
}

impl FundingSource for LocalChain {
    fn observe(&self, allocation: &str) -> Result<Observation> {
        Ok(serde_json::from_value(self.request(
            json!({"method": "observe", "allocation": allocation}),
        )?)?)
    }
    fn prepare(
        &self,
        request: &super::settlement::ActionRequest,
    ) -> Result<super::settlement::Prepared> {
        Ok(serde_json::from_value(self.request(
            json!({"method":"prepare", "request":request}),
        )?)?)
    }
    fn transact(&self, prepared: &super::settlement::Prepared) -> Result<()> {
        self.request(json!({"method":"transact", "prepared":prepared}))?;
        Ok(())
    }
    fn observe_transaction(&self, prepared: &super::settlement::Prepared) -> Result<Observation> {
        Ok(serde_json::from_value(self.request(
            json!({"method":"observe-transaction", "prepared":prepared}),
        )?)?)
    }
}
