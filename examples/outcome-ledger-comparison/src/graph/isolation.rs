//! Linux namespace fixture. Mount policy is chosen by the trusted launcher,
//! never by a courier-supplied path or RPC argument.
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::model::{Endpoint, PublicJob, Reply, Rpc};
use super::transport::{self, Attempt};
use crate::Result;

const MAX_REQUEST: u64 = 1024 * 1024;
const MAX_REPLY: u64 = 4 * 1024 * 1024;

pub(super) struct ChildIdentity {
    pid: u32,
    start: String,
}

fn process_identity(pid: u32) -> Result<Option<(String, String)>> {
    let raw = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let fields: Vec<_> = raw
        .rsplit_once(')')
        .ok_or("process stat missing command")?
        .1
        .split_whitespace()
        .collect();
    Ok(Some((
        fields.first().ok_or("process state missing")?.to_string(),
        fields
            .get(19)
            .ok_or("process start time missing")?
            .to_string(),
    )))
}

/// Observe only descendants of the owned Bubblewrap child. Start times prevent
/// a recycled PID from being mistaken for a surviving sandbox process.
pub(super) fn descendants(parent: u32) -> Result<Vec<ChildIdentity>> {
    let mut pending = vec![parent];
    let mut result = Vec::new();
    while let Some(pid) = pending.pop() {
        let raw = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))?;
        for child in raw.split_whitespace() {
            let child: u32 = child.parse()?;
            let (_, start) =
                process_identity(child)?.ok_or("sandbox child disappeared before checkpoint")?;
            pending.push(child);
            result.push(ChildIdentity { pid: child, start });
            if result.len() > 64 {
                return Err("sandbox exceeded fixture process bound".into());
            }
        }
    }
    if result.is_empty() {
        return Err("sandbox checkpoint had no observable child".into());
    }
    Ok(result)
}

pub(super) fn require_terminated(children: &[ChildIdentity]) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut live = false;
        for child in children {
            if let Some((state, start)) = process_identity(child.pid)? {
                live |= start == child.start && state != "Z" && state != "X";
            }
        }
        if !live {
            eprintln!("ISOLATION_CHILDREN_TERMINATED count={}", children.len());
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("owned sandbox child survived dispatcher termination".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn base_command() -> Result<Command> {
    let mut command = Command::new("/usr/bin/bwrap");
    command
        .env_clear()
        .args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--ro-bind",
            "/usr/lib",
            "/usr/lib",
            "--symlink",
            "usr/lib",
            "/lib",
            "--ro-bind",
        ])
        .arg(std::env::current_exe()?)
        .arg("/app/chio")
        .args([
            "--proc", "/proc", "--dev", "/dev", "--size", "16777216", "--tmpfs", "/tmp", "--chdir",
            "/tmp",
        ]);
    Ok(command)
}

pub(super) fn receiver_command(directory: &Path) -> Result<Command> {
    let mut command = receiver_mounts(directory)?;
    command.args(["--", "/app/chio", "--graph-worker", "/receiver"]);
    Ok(command)
}

fn receiver_mounts(directory: &Path) -> Result<Command> {
    let directory = std::fs::canonicalize(directory)?;
    let mut command = base_command()?;
    command.arg("--bind").arg(&directory).arg("/receiver");
    for name in ["key.seed", "owner.json"] {
        command
            .arg("--ro-bind")
            .arg(directory.join(name))
            .arg(format!("/receiver/{name}"));
    }
    Ok(command)
}

pub struct Brokers {
    sockets: PathBuf,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Drop for Brokers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Brokers {
    pub fn start(root: &Path, job: &mut PublicJob) -> Result<Self> {
        let sockets = std::fs::canonicalize(root)?.join("sockets");
        std::fs::create_dir(&sockets)?;
        let stop = Arc::new(AtomicBool::new(false));
        let mut brokers = Self {
            sockets,
            stop,
            threads: Vec::new(),
        };
        for endpoint in &mut job.endpoints {
            let socket = brokers.sockets.join(format!("{}.sock", endpoint.role));
            let listener = UnixListener::bind(&socket)?;
            listener.set_nonblocking(true)?;
            let private = Endpoint {
                directory: endpoint.directory.clone(),
                key: endpoint.key.clone(),
                role: endpoint.role.clone(),
                socket: None,
            };
            let stop = brokers.stop.clone();
            brokers.threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = serve(stream, &private);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
            }));
            endpoint.socket = Some(socket);
        }
        Ok(brokers)
    }

    fn courier_mounts(&self, job: &Path) -> Result<Command> {
        let mut command = base_command()?;
        // Only this launcher-created socket directory is mounted. Endpoint
        // paths inside the public job cannot expand the mount policy.
        command
            .arg("--ro-bind")
            .arg(&self.sockets)
            .arg(&self.sockets)
            .arg("--ro-bind")
            .arg(std::fs::canonicalize(job)?)
            .arg("/job.json");
        Ok(command)
    }

    pub fn courier(&self, job: &Path, kill: bool) -> Result<Option<Value>> {
        let mut command = self.courier_mounts(job)?;
        command.args(["--", "/app/chio", "--graph-courier", "/job.json"]);
        transport::courier_command(command, kill)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReply {
    reply: Option<Box<Reply>>,
    error: Option<String>,
}

fn serve(mut stream: UnixStream, endpoint: &Endpoint) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new(&stream)
        .take(MAX_REQUEST + 1)
        .read_line(&mut line)?;
    let result = (|| -> Result<Reply> {
        if line.len() as u64 > MAX_REQUEST || !line.ends_with('\n') {
            return Err("invalid bounded RPC frame".into());
        }
        let rpc: Rpc = serde_json::from_str(&line)?;
        match transport::call_process(endpoint, rpc, "none", true)? {
            Attempt::Reply(reply) => Ok(*reply),
            Attempt::Killed => Err("receiver response lost".into()),
        }
    })();
    let wire = match result {
        Ok(reply) => WireReply {
            reply: Some(Box::new(reply)),
            error: None,
        },
        Err(error) => WireReply {
            reply: None,
            error: Some(error.to_string()),
        },
    };
    writeln!(stream, "{}", serde_json::to_string(&wire)?)?;
    Ok(())
}

pub(super) fn socket_call(path: &Path, rpc: &Rpc) -> Result<Reply> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let encoded = serde_json::to_string(rpc)?;
    if encoded.len() as u64 + 1 > MAX_REQUEST {
        return Err("RPC exceeds input bound".into());
    }
    writeln!(stream, "{encoded}")?;
    let mut line = String::new();
    BufReader::new(stream)
        .take(MAX_REPLY + 1)
        .read_line(&mut line)?;
    if line.len() as u64 > MAX_REPLY || !line.ends_with('\n') {
        return Err("invalid bounded response frame".into());
    }
    let wire: WireReply = serde_json::from_str(&line)?;
    match (wire.reply, wire.error) {
        (Some(reply), None) => Ok(*reply),
        (None, Some(error)) => Err(error.into()),
        _ => Err("invalid receiver response envelope".into()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub denied_paths: Vec<PathBuf>,
    pub host_namespaces: std::collections::BTreeMap<String, String>,
    pub host_tcp_port: u16,
    pub receiver: bool,
}

pub fn probe(path: &Path) -> Result<()> {
    let spec: Probe = serde_json::from_slice(&std::fs::read(path)?)?;
    let mut denied = Vec::new();
    for path in &spec.denied_paths {
        let read_denied = std::fs::File::open(path).is_err();
        let write_denied = std::fs::OpenOptions::new().write(true).open(path).is_err();
        if !read_denied || !write_denied {
            return Err("private host path accessible from sandbox".into());
        }
        denied.push(
            serde_json::json!({"path":path,"readDenied":read_denied,"writeDenied":write_denied}),
        );
        let proc_path = Path::new("/proc/1/root").join(path.strip_prefix("/")?);
        if std::fs::File::open(proc_path).is_ok() {
            return Err("host file accessible through proc root".into());
        }
    }
    let mut namespaces = std::collections::BTreeMap::new();
    for (name, host) in &spec.host_namespaces {
        let current = std::fs::read_link(format!("/proc/self/ns/{name}"))?
            .to_string_lossy()
            .into_owned();
        if current == *host {
            return Err("sandbox shares a required host namespace".into());
        }
        namespaces.insert(name.clone(), current);
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], spec.host_tcp_port));
    if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok() {
        return Err("sandbox reached host loopback listener".into());
    }
    std::os::unix::fs::symlink(&spec.denied_paths[0], "/tmp/escape")?;
    if std::fs::File::open("/tmp/escape").is_ok() {
        return Err("symlink escaped mount namespace".into());
    }
    let own_key = if spec.receiver {
        if std::fs::read("/receiver/key.seed")?.is_empty() {
            return Err("receiver key missing".into());
        }
        for name in ["key.seed", "owner.json"] {
            if std::fs::OpenOptions::new()
                .write(true)
                .open(format!("/receiver/{name}"))
                .is_ok()
            {
                return Err("trusted receiver configuration mount is writable".into());
            }
        }
        let canary = Path::new("/receiver/probe-canary");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(canary)?;
        file.write_all(b"owned state write control")?;
        file.sync_all()?;
        drop(file);
        std::fs::remove_file(canary)?;
        true
    } else {
        if Path::new("/receiver").exists() {
            return Err("courier received a receiver mount".into());
        }
        false
    };
    println!(
        "{}",
        serde_json::json!({"deniedPaths":denied,"namespaces":namespaces,"hostLoopbackDenied":true,"procRootDenied":true,"symlinkEscapeDenied":true,"ownReceiverKeyReadable":own_key,"receiverConfigReadonly":spec.receiver})
    );
    Ok(())
}

impl Brokers {
    pub fn probe_boundaries(&self, root: &Path, job_path: &Path, job: &PublicJob) -> Result<Value> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        drop(std::net::TcpStream::connect(listener.local_addr()?)?);
        let mut namespaces = std::collections::BTreeMap::new();
        for name in ["mnt", "pid", "net", "user", "ipc", "uts"] {
            namespaces.insert(
                name.into(),
                std::fs::read_link(format!("/proc/self/ns/{name}"))?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        let mut paths = Vec::new();
        for endpoint in &job.endpoints {
            for name in ["key.seed", "owner.json"] {
                paths.push(std::fs::canonicalize(endpoint.directory.join(name))?);
            }
            let database = endpoint.directory.join("receiver.sqlite");
            if database.exists() {
                paths.push(std::fs::canonicalize(database)?);
            }
        }
        let canary = root.join("host-only-canary");
        std::fs::write(&canary, b"host-only isolation control")?;
        paths.push(std::fs::canonicalize(canary)?);
        for path in &paths {
            drop(std::fs::File::open(path)?);
            // Opening for write tests the counterfactual without changing any
            // key, owner rule, or database bytes.
            drop(std::fs::OpenOptions::new().write(true).open(path)?);
        }
        let mut rows = Vec::new();
        for receiver in [None, Some(0), Some(1), Some(2)] {
            let label = receiver
                .map(|index| job.endpoints[index].role.as_str())
                .unwrap_or("courier");
            let spec = Probe {
                denied_paths: paths.clone(),
                host_namespaces: namespaces.clone(),
                host_tcp_port: port,
                receiver: receiver.is_some(),
            };
            let spec_path = root.join(format!("{label}-probe-input.json"));
            std::fs::write(&spec_path, serde_json::to_vec_pretty(&spec)?)?;
            let mut command = if let Some(index) = receiver {
                receiver_mounts(&job.endpoints[index].directory)?
            } else {
                self.courier_mounts(job_path)?
            };
            command
                .arg("--ro-bind")
                .arg(&spec_path)
                .arg("/probe.json")
                .args(["--", "/app/chio", "--graph-probe", "/probe.json"])
                .stdin(Stdio::null());
            let output = command.output()?;
            if !output.status.success() {
                return Err(format!(
                    "{label} isolation probe failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            let report: Value = serde_json::from_slice(&output.stdout)?;
            std::fs::write(
                root.join(format!("{label}-probe.json")),
                serde_json::to_vec_pretty(&report)?,
            )?;
            rows.push(serde_json::json!({"role":label,"report":report}));
        }
        Ok(serde_json::json!(rows))
    }
}
