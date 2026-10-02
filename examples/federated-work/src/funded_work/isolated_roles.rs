//! Same-host role namespaces. No host root, peer state or shared network mount.
use crate::common::Result;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

pub const ROLES: [&str; 5] = ["buyer", "provider", "verifier", "governance", "operator"];
pub struct Runner {
    pub root: PathBuf,
    counter: AtomicUsize,
}
pub struct Response {
    pub process: Output,
    pub directory: PathBuf,
}
impl Response {
    pub fn value(&self) -> Result<Value> {
        if !self.process.status.success() {
            return Err(format!(
                "isolated role failed: {}",
                String::from_utf8_lossy(&self.process.stderr)
            )
            .into());
        }
        Ok(serde_json::from_slice(&self.process.stdout)?)
    }
}
impl Runner {
    pub fn new(root: &Path) -> Result<Self> {
        if !fs::symlink_metadata(root)?.file_type().is_dir() || fs::read_dir(root)?.next().is_some()
        {
            return Err("isolated reproduction requires an empty real directory".into());
        }
        for name in ROLES.into_iter().chain(["transport", "public"]) {
            fs::create_dir(root.join(name))?;
        }
        Ok(Self {
            root: fs::canonicalize(root)?,
            counter: AtomicUsize::new(0),
        })
    }
    pub fn run(
        &self,
        role: &str,
        args: &[&str],
        inputs: &[(&str, &Path)],
        socket: Option<&Path>,
        checker: bool,
    ) -> Result<Response> {
        self.invoke(role, "/app", args, inputs, socket, checker)
    }
    fn invoke(
        &self,
        role: &str,
        program: &str,
        args: &[&str],
        inputs: &[(&str, &Path)],
        socket: Option<&Path>,
        checker: bool,
    ) -> Result<Response> {
        if !ROLES.contains(&role) {
            return Err("unknown isolated role".into());
        }
        let state = self.root.join(role);
        if !fs::symlink_metadata(&state)?.file_type().is_dir() {
            return Err("role state must not be an alias".into());
        }
        let directory = self
            .root
            .join("transport")
            .join(self.counter.fetch_add(1, Ordering::SeqCst).to_string());
        fs::create_dir(&directory)?;
        let incoming = directory.join("in");
        let outgoing = directory.join("out");
        fs::create_dir(&incoming)?;
        fs::create_dir(&outgoing)?;
        for (name, path) in inputs {
            if name.is_empty()
                || name.contains("..")
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || !fs::symlink_metadata(path)?.file_type().is_file()
            {
                return Err("invalid isolated public input".into());
            }
            let mut bytes = Vec::new();
            fs::File::open(path)?.take(262145).read_to_end(&mut bytes)?;
            if bytes.len() > 262144 {
                return Err("isolated input exceeds bound".into());
            }
            let mut target = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(incoming.join(name))?;
            target.write_all(&bytes)?;
        }
        let mut cmd = Command::new("/usr/bin/bwrap");
        cmd.args([
            "--die-with-parent",
            "--unshare-all",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
        ]);
        if Path::new("/lib64").exists() {
            cmd.args(["--ro-bind", "/lib64", "/lib64"]);
        }
        cmd.args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
        ])
        .arg(std::env::current_exe()?)
        .arg("/app")
        .arg("--bind")
        .arg(&state)
        .arg("/state")
        .arg("--ro-bind")
        .arg(&incoming)
        .arg("/in")
        .arg("--bind")
        .arg(&outgoing)
        .arg("/out")
        .args(["--chdir", "/state"]);
        for seed in ["key.seed", "checkpoint/key.seed", "status/key.seed"] {
            let path = state.join(seed);
            if path.try_exists()? {
                if !fs::symlink_metadata(&path)?.file_type().is_file() {
                    return Err("role seed must not be a symlink".into());
                }
                cmd.arg("--ro-bind")
                    .arg(&path)
                    .arg(format!("/state/{seed}"));
            }
        }
        if let Some(socket) = socket {
            cmd.arg("--ro-bind").arg(socket).arg("/observer.sock");
        }
        if checker {
            let python =
                std::env::var_os("CHIO_FUNDED_PYTHON").ok_or("pinned checker Python required")?;
            let python = Path::new(&python);
            let venv = python
                .parent()
                .and_then(Path::parent)
                .ok_or("Python environment root missing")?;
            cmd.arg("--ro-bind").arg(venv).arg("/venv").args([
                "--setenv",
                "CHIO_FUNDED_PYTHON",
                "/venv/bin/python",
            ]);
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
            for (name, _) in super::verification::SOURCES {
                let path = fs::canonicalize(manifest.join(name))?;
                cmd.arg("--ro-bind").arg(&path).arg(&path);
            }
        } else {
            cmd.args(["--setenv", "CHIO_FUNDED_PYTHON", "/unavailable-checker"]);
        }
        let process = cmd.arg(program).args(args).output()?;
        Ok(Response {
            process,
            directory: outgoing,
        })
    }
    pub fn probe(&self, role: &str) -> Result<Value> {
        let sentinel = self.root.join("host-sentinel");
        if !sentinel.exists() {
            fs::write(&sentinel, b"not visible to roles")?;
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let peers: Vec<_> = ROLES
            .iter()
            .filter(|name| **name != role)
            .map(|name| self.root.join(name))
            .collect();
        let config = self.root.join("public").join(format!("probe-{role}.json"));
        super::checkpoint_files::write(
            &config,
            &json!({"peers":peers,"sentinel":sentinel,"port":listener.local_addr()?.port()}),
        )?;
        let script = r#"import json,pathlib,socket
c=json.loads(pathlib.Path('/in/probe.json').read_bytes())
blocked=sum(not pathlib.Path(p).exists() for p in c['peers'])
assert blocked==4
absent=not pathlib.Path(c['sentinel']).exists() and not (pathlib.Path('/proc/1/root')/c['sentinel'].lstrip('/')).exists()
assert absent
readonly=False
try:pathlib.Path('/in/probe.json').write_text('corrupt')
except OSError:readonly=True
assert readonly
sock=socket.socket();sock.settimeout(1)
network=sock.connect_ex(('127.0.0.1',c['port']))!=0;sock.close()
assert network
print(json.dumps(dict(blockedPeerStates=blocked,hostSentinelAbsent=absent,inputReadOnly=readonly,hostNetworkUnreachable=network)))"#;
        let response = self.invoke(
            role,
            "/usr/bin/python3",
            &["-I", "-B", "-c", script],
            &[("probe.json", &config)],
            None,
            false,
        )?;
        let mut result = response.value()?;
        result["role"] = json!(role);
        if fs::read(sentinel)? != b"not visible to roles" {
            return Err("host sentinel changed".into());
        }
        Ok(result)
    }
    pub fn publish(&self, response: &Response, name: &str) -> Result<PathBuf> {
        response.value()?;
        let source = response.directory.join(name);
        let value: Value = super::evidence::read(&source)?;
        let target = self.root.join("public").join(name);
        super::checkpoint_files::write(&target, &value)?;
        Ok(target)
    }
}
