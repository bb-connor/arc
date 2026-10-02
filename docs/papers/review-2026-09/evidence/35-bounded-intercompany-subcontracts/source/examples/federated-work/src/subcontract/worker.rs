//! Host-owned disclosure boundary and isolated procurement worker.
use super::*;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    specialist: PublicKey,
    delegate_state: PathBuf,
    origin: String,
    enrollment: Value,
    python_environment: PathBuf,
    buyer_code: PathBuf,
}

pub struct Worker {
    config: Configuration,
    delegate: chio_core_types::Keypair,
    receiver: chio_core_types::Keypair,
    root: PathBuf,
}

impl Worker {
    pub fn load(state: &Path) -> Result<Option<Arc<Self>>> {
        let path = state.join("subcontract.json");
        if !path.exists() {
            return Ok(None);
        }
        let config: Configuration = read(path)?;
        let delegate = key(&config.delegate_state)?;
        let receiver = key(state)?;
        if delegate.public_key() == receiver.public_key()
            || delegate.public_key() == config.specialist
            || !config.python_environment.is_absolute()
            || !config.buyer_code.is_absolute()
        {
            return Err(
                "subcontract worker must use a separate locally configured agent key and code"
                    .into(),
            );
        }
        let url = url::Url::parse(&config.origin)?;
        let port = url
            .port_or_known_default()
            .filter(|p| *p > 0)
            .ok_or("invalid specialist port")?;
        crate::https::origin(&config.origin, ([127, 0, 0, 1], port).into())?;
        super::enrollment::verify(
            &config.enrollment,
            &config.specialist,
            &delegate.public_key(),
            &config.origin,
        )?;
        if config.enrollment["body"]["subcontractPromisor"] != receiver.public_key().to_hex() {
            return Err(
                "specialist did not activate the provider kernel as procurement promisor".into(),
            );
        }
        Ok(Some(Arc::new(Self {
            config,
            delegate,
            receiver,
            root: state.join("subcontracts"),
        })))
    }

    pub fn check_policy(&self, agreement: &Agreement) -> Result<()> {
        let policy = agreement
            .subcontract
            .as_ref()
            .ok_or("no subcontract policy")?;
        policy.validate(agreement)?;
        if policy.specialist != self.config.specialist
            || policy.delegate != self.delegate.public_key()
        {
            return Err(
                "subcontract request differs from locally activated specialist or agent".into(),
            );
        }
        Ok(())
    }

    pub fn run(&self, request: &review::ReviewRequest) -> Result<Value> {
        self.check_policy(&request.acceptance.quote.agreement)?;
        let agreement = child_agreement(&request.acceptance.quote.agreement)?;
        let input = disclosure(request)?;
        let id = digest(&request.acceptance.quote.agreement)?;
        let _lock = self.lock(&id)?;
        let state = self.root.join(id);
        fs::create_dir_all(&state)?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
        // This is the distinct agent key, never the provider kernel's root key.
        retain(&state.join("key.seed"), self.delegate.seed_hex().as_bytes())?;
        retain(
            &state.join("agreement.json"),
            &chio_core_types::canonical_json_bytes(&agreement)?,
        )?;
        retain(&state.join("input.json"), input.as_bytes())?;
        retain(
            &state.join("subcontract-permit.json"),
            &chio_core_types::canonical_json_bytes(&super::permit::issue(
                request,
                &self.receiver,
            )?)?,
        )?;
        let result = self.execute(&state, false)?;
        if result["buyerVerified"] != true || result["reviewRejected"] != false {
            return Err("specialist has no verified successful delivery".into());
        }
        let result = json!({"request":result["request"],"delivery":result["delivery"]});
        verify_child(request, &result)?;
        Ok(result)
    }

    /// Recover an existing child account without replaying the parent call or
    /// issuing another procurement permit. Only the local operator exposes this.
    pub fn recover(&self, id: &str, release_unknown: bool) -> Result<Value> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid parent agreement digest".into());
        }
        let _lock = self.lock(id)?;
        let state = self.root.join(id);
        let agreement: Agreement = read(state.join("agreement.json"))?;
        let permit: super::permit::SignedPermit = read(state.join("subcontract-permit.json"))?;
        super::permit::verify(&permit, &agreement, &self.receiver.public_key(), None)?;
        if permit.body.parent_agreement_sha256 != id
            || agreement.buyer != self.delegate.public_key()
            || agreement.provider != self.config.specialist
            || key(&state)?.public_key() != self.delegate.public_key()
        {
            return Err("retained child differs from the selected relationship".into());
        }
        let result = self.execute(&state, release_unknown)?;
        let request: review::ReviewRequest = serde_json::from_value(result["request"].clone())?;
        let peers = Peers {
            buyer: agreement.buyer.clone(),
            provider: agreement.provider.clone(),
        };
        request.validate(&peers)?;
        if digest(&request.acceptance.quote.agreement)? != digest(&agreement)?
            || request.acceptance.quote.subcontract_permit.as_ref() != Some(&permit)
        {
            return Err("recovered child changes the retained procurement".into());
        }
        if result.get("delivery").is_some() {
            review::verify_terminal(&request, &result["delivery"])?;
        } else {
            crate::incident::verify(
                &request,
                &serde_json::from_value(result["incident"].clone())?,
            )?;
            if result.get("release").is_some() {
                crate::resolution::verify(
                    &peers,
                    &serde_json::from_value(result["release"].clone())?,
                )?;
            }
        }
        Ok(result)
    }

    fn lock(&self, id: &str) -> Result<fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        // Keep locks outside the writable worker mount, so a worker cannot
        // replace the inode and evade cross-process serialization.
        let directory = self.root.with_file_name("subcontract-locks");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join(id))?;
        lock.lock()?;
        Ok(lock)
    }

    fn execute(&self, state: &Path, release_unknown: bool) -> Result<Value> {
        // The host may rotate this public credential under the same local pins.
        self.write_owned(
            state,
            "enrollment.json",
            &chio_core_types::canonical_json_bytes(&self.config.enrollment)?,
        )?;
        self.invoke(
            state,
            &[
                "enroll",
                "/state",
                &self.config.specialist.to_hex(),
                &self.config.origin,
                "/state/enrollment.json",
            ],
        )?;
        retain(
            &state.join("egress.json"),
            b"{\"socket\":\"/state/egress.sock\"}",
        )?;
        let tunnel = Tunnel::start(&state.join("egress.sock"), &self.config.origin)?;
        let probe = self.invoke(state, &["probe-sandbox", "/state", &self.config.origin])?;
        if probe["directTcpConnected"] != false
            || probe["agentKey"] != self.delegate.public_key().to_hex()
        {
            return Err("subcontract worker isolation check failed".into());
        }
        self.write_owned(
            state,
            "worker-isolation.json",
            &chio_core_types::canonical_json_bytes(&probe)?,
        )?;
        let action = if release_unknown { "resolve" } else { "work" };
        let result = self.invoke(state, &[action, "/state", &self.config.origin]);
        drop(tunnel);
        let result = result.inspect_err(|error| {
            let _ = self.write_owned(state, "worker-error.txt", error.to_string().as_bytes());
        })?;
        Ok(result)
    }

    fn write_owned(&self, state: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        // The worker can create symlinks in its writable state. Stage outside
        // that mount, then replace the destination entry without following it.
        let directory = self.root.with_file_name("subcontract-staging");
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let id = state
            .file_name()
            .ok_or("child state has no id")?
            .to_string_lossy();
        let temporary = directory.join(format!("{id}-{name}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, state.join(name))?;
        fs::File::open(state)?.sync_all()?;
        Ok(())
    }

    fn invoke(&self, state: &Path, args: &[&str]) -> Result<Value> {
        let mut command = Command::new("/usr/bin/bwrap");
        command.args([
            "--die-with-parent",
            "--unshare-all",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
        ]);
        if Path::new("/lib64").exists() {
            command.args(["--ro-bind", "/lib64", "/lib64"]);
        }
        command
            .args([
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
            ])
            .arg(&self.config.buyer_code)
            .arg("/client")
            .arg("--ro-bind")
            .arg(&self.config.python_environment)
            .arg("/venv")
            .arg("--bind")
            .arg(state)
            .arg("/state")
            .args(["--chdir", "/state"]);
        for name in [
            "key.seed",
            "subcontract-permit.json",
            "agreement.json",
            "input.json",
            "enrollment.json",
            "egress.json",
            "egress.sock",
        ] {
            if state.join(name).exists() {
                command
                    .arg("--ro-bind")
                    .arg(state.join(name))
                    .arg(format!("/state/{name}"));
            }
        }
        if args.first() != Some(&"enroll") && state.join("connection.json").exists() {
            command
                .arg("--ro-bind")
                .arg(state.join("connection.json"))
                .arg("/state/connection.json");
        }
        command
            .args(["/venv/bin/python", "-B", "/client/client.py"])
            .args(args);
        run_bounded(command)
    }
}

fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut prior = Vec::new();
            fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut prior)?;
            if prior != bytes {
                return Err("retained child state binds another authority or disclosure".into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn run_bounded(mut command: Command) -> Result<Value> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("worker stdout is absent")?;
    let stderr = child.stderr.take().ok_or("worker stderr is absent")?;
    let output = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(4097).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(20) {
            child.kill()?;
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let bytes = output.join().map_err(|_| "worker output reader failed")??;
    let errors = errors.join().map_err(|_| "worker error reader failed")??;
    if !status.success() || bytes.len() > 1024 * 1024 || errors.len() > 4096 {
        return Err(format!(
            "isolated subcontract worker failed: {}",
            String::from_utf8_lossy(&errors)
        )
        .into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

struct Tunnel {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    path: PathBuf,
}
impl Tunnel {
    fn start(path: &Path, origin: &str) -> Result<Self> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err("egress socket path is not a socket".into());
            }
            fs::remove_file(path)?;
        }
        let url = url::Url::parse(origin)?;
        let address = (
            url.host_str().ok_or("specialist hostname is absent")?,
            url.port_or_known_default()
                .ok_or("specialist port is absent")?,
        )
            .to_socket_addrs()?
            .next()
            .ok_or("specialist address is absent")?;
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let halt = stop.clone();
        let thread = thread::spawn(move || {
            let mut handled = 0;
            while !halt.load(Ordering::SeqCst) && handled < 128 {
                match listener.accept() {
                    Ok((client, _)) => {
                        handled += 1;
                        thread::spawn(move || {
                            let relay = || -> std::io::Result<()> {
                                let mut remote =
                                    TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
                                remote.set_read_timeout(Some(Duration::from_secs(5)))?;
                                remote.set_write_timeout(Some(Duration::from_secs(5)))?;
                                client.set_read_timeout(Some(Duration::from_secs(5)))?;
                                client.set_write_timeout(Some(Duration::from_secs(5)))?;
                                let mut downstream = client.try_clone()?;
                                let upstream = remote.try_clone()?;
                                let response = thread::spawn(move || {
                                    let _ = std::io::copy(
                                        &mut upstream.take(2 * 1024 * 1024),
                                        &mut downstream,
                                    );
                                    let _ = downstream.shutdown(Shutdown::Write);
                                });
                                let _ =
                                    std::io::copy(&mut client.take(2 * 1024 * 1024), &mut remote);
                                let _ = remote.shutdown(Shutdown::Write);
                                let _ = response.join();
                                Ok(())
                            };
                            let _ = relay();
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
            path: path.into(),
        })
    }
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}
