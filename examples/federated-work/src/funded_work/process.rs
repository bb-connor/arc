//! Actual worker process-loss tests against an independently owned local chain.
use super::{
    agreement::SignedAgreement,
    local_chain::LocalChain,
    native::Native,
    observer::{FundingSource, Observation},
    smoke::{setup, Scenario},
};
use crate::common::{self, Result};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        net::{UnixListener, UnixStream},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

fn read_message(reader: impl Read, limit: u64) -> Result<Value> {
    let mut bytes = Vec::new();
    BufReader::new(reader)
        .take(limit + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > limit || !bytes.ends_with(b"\n") {
        return Err("invalid observer frame".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) struct SocketSource(pub PathBuf);
impl SocketSource {
    pub(super) fn request(&self, request: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(request)?;
        if bytes.len() > 256 * 1024 {
            return Err("observer request exceeds limit".into());
        }
        let mut stream = UnixStream::connect(&self.0)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        stream.write_all(&bytes)?;
        stream.write_all(b"\n")?;
        let response = read_message(stream, 1024 * 1024)?;
        if response.as_object().is_none_or(|object| object.len() != 1) {
            return Err("malformed owned observer response".into());
        }
        if let Some(error) = response.get("error") {
            return Err(format!(
                "owned observer: {}",
                error.as_str().ok_or("malformed observer error")?
            )
            .into());
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| "observer result missing".into())
    }
}
impl FundingSource for SocketSource {
    fn observe(&self, allocation: &str) -> Result<Observation> {
        Ok(serde_json::from_value(self.request(&json!(allocation))?)?)
    }
    fn prepare(
        &self,
        request: &super::settlement::ActionRequest,
    ) -> Result<super::settlement::Prepared> {
        Ok(serde_json::from_value(self.request(
            &json!({"method":"prepare","request":request}),
        )?)?)
    }
    fn transact(&self, prepared: &super::settlement::Prepared) -> Result<()> {
        self.request(&json!({"method":"transact","prepared":prepared}))?;
        Ok(())
    }
    fn observe_transaction(&self, prepared: &super::settlement::Prepared) -> Result<Observation> {
        Ok(serde_json::from_value(self.request(
            &json!({"method":"observe-transaction","prepared":prepared}),
        )?)?)
    }
}

pub(super) struct Server {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<Result<()>>>,
}

impl Server {
    pub(super) fn start(path: &Path, allocation: String, chain: Arc<LocalChain>) -> Result<Self> {
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let handle = std::thread::spawn(move || -> Result<()> {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                        let response = read_message(&stream, 256 * 1024).and_then(|requested| {
                            if requested.as_str() == Some(&allocation) {
                                return Ok(serde_json::to_value(chain.observe(&allocation)?)?);
                            }
                            let requested_allocation = match requested["method"].as_str() {
                                Some("prepare") => &requested["request"]["allocationId"],
                                Some("transact" | "observe-transaction") => {
                                    &requested["prepared"]["intent"]["allocationId"]
                                }
                                Some("advance") => &requested["allocation"],
                                _ => return Err("unsupported owned observer operation".into()),
                            };
                            if requested_allocation.as_str() != Some(&allocation) {
                                return Err("observer allocation substitution".into());
                            }
                            chain.request(requested)
                        });
                        let response = match response {
                            Ok(value) => json!({"result":value}),
                            Err(error) => json!({"error":error.to_string()}),
                        };
                        let mut bytes = serde_json::to_vec(&response)?;
                        bytes.push(b'\n');
                        // A worker can disappear before acknowledgement. Its
                        // socket error must not kill the surviving chain owner
                        // or prevent the next worker from querying the outcome.
                        let _ = stream.write_all(&bytes);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        });
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| "observer service panicked")??;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub fn worker(state: &Path, socket: &Path, fault: &str) -> Result<Value> {
    if !["after-stage", "before-bind", "after-hold", "after-tool"].contains(&fault) {
        return Err("unsupported funded checkpoint".into());
    }
    let fault = fault.to_owned();
    let native = Native::open_with_checkpoint(
        state,
        Arc::new(SocketSource(socket.to_owned())),
        Arc::new(move |point| {
            if point == fault {
                common::crash()
            } else {
                Ok(())
            }
        }),
    )?;
    let agreement: SignedAgreement = common::read(state.join("original-agreement.json"))?;
    let request = common::read(state.join("original-request.json"))?;
    native.execute(&agreement, &request)
}

pub(super) fn counts(state: &Path) -> Result<Value> {
    use rusqlite::OptionalExtension;
    let connection = rusqlite::Connection::open_with_flags(
        state.join("authority.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let operations: i64 =
        connection.query_row("SELECT count(*) FROM admission_operations", [], |r| {
            r.get(0)
        })?;
    let holds: i64 =
        connection.query_row("SELECT count(*) FROM budget_authorization_holds", [], |r| {
            r.get(0)
        })?;
    let ids: Option<(String, String)> = connection
        .query_row(
            "SELECT operation_id,hold_id FROM payment_journal",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let disposition: Option<String> = connection
        .query_row(
            "SELECT disposition FROM budget_authorization_holds",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(json!({"operationCount": operations, "holdCount": holds,
        "holdDisposition": disposition,
        "operationId": ids.as_ref().map(|v| &v.0), "holdId": ids.as_ref().map(|v| &v.1)}))
}

pub fn run_fault(state: &Path, fault: &str) -> Result<Value> {
    if !["after-stage", "before-bind", "after-hold", "after-tool"].contains(&fault) {
        return Err("unsupported funded checkpoint".into());
    }
    let Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    } = setup(state)?;
    common::read::<Value>(state.join("funding-policy.json"))?;
    std::fs::write(
        state.join("original-agreement.json"),
        chio_core_types::canonical_json_bytes(&agreement)?,
    )?;
    std::fs::write(
        state.join("original-request.json"),
        chio_core_types::canonical_json_bytes(&request)?,
    )?;
    drop(native);
    let socket = state.join("observer.sock");
    let allocation = funding["allocationId"]
        .as_str()
        .ok_or("allocation missing")?
        .to_owned();
    let mut server = Server::start(&socket, allocation.clone(), chain.clone())?;
    let child = Command::new(std::env::current_exe()?)
        .args(["experimental-funded-worker"])
        .arg(state)
        .arg(&socket)
        .arg(fault)
        .stdin(Stdio::null())
        .output()?;
    server.finish()?;
    if child.status.signal() != Some(9) {
        return Err(format!(
            "funded checkpoint was not killed: {:?}: {}",
            child.status,
            String::from_utf8_lossy(&child.stderr)
        )
        .into());
    }
    let before = counts(state)?;
    let recovered = Native::open(state, chain.clone())?;
    let replay = recovered.execute(&agreement, &request)?;
    let again = recovered.execute(&agreement, &request)?;
    if replay["operationId"] != again["operationId"]
        || replay["holdId"] != again["holdId"]
        || replay["executions"] != again["executions"]
    {
        return Err("recovery replay changed native identity or execution".into());
    }
    let after = counts(state)?;
    let summary = chain.request(json!({"method": "summary", "allocation": allocation}))?;
    Ok(
        json!({"checkpoint": fault, "killedSignal": 9, "before": before, "after": after,
        "replay": again, "chain": summary}),
    )
}
