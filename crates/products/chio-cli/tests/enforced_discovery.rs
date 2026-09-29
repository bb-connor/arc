//! Mandatory privileged discovery composition on the native x86_64 runner.
#![cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
}

#[test]
fn privileged_discovery_enforces_identity_filesystem_deadline_and_cleanup() -> TestResult {
    assert_eq!(
        std::env::consts::ARCH,
        "x86_64",
        "native discovery requires x86_64"
    );
    // SAFETY: credential query has no arguments or side effects.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "native discovery requires the privileged runner"
    );
    let helper = std::fs::canonicalize(
        std::env::var_os("CHIO_CAGE_TEST_HELPER").ok_or("native helper missing")?,
    )?;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))?;
    let anchors = tempfile::Builder::new()
        .prefix("chio-discovery-anchors-")
        .tempdir_in("/dev/shm")?;
    std::fs::set_permissions(anchors.path(), std::fs::Permissions::from_mode(0o700))?;
    let target = root.path().join("discovery-peer");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/discovery_probe.c");
    let compiled = Command::new("cc")
        .args([
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
        ])
        .arg(source)
        .arg("-o")
        .arg(&target)
        .status()?;
    assert!(compiled.success(), "native discovery probe did not compile");
    let host = root.path().join("host-canary");
    write(&host, b"host filesystem must remain private")?;
    for mode in ["respond", "fork", "stall"] {
        let marker = root.path().join(format!("pid-{mode}"));
        let gate = root.path().join(format!("gate-{mode}"));
        write(&marker, b"")?;
        write(&gate, b"")?;
        let output_dir = root.path().join(format!("runtime-{mode}"));
        let stdout = root.path().join(format!("stdout-{mode}"));
        let stderr = root.path().join(format!("stderr-{mode}"));
        let started = Instant::now();
        let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
        command
            .args([
                "security",
                "provision-reference-runtime",
                "--discover-tools",
                "--stage",
                "enforced",
            ])
            .arg("--output-dir")
            .arg(&output_dir)
            .arg("--cage-init")
            .arg(&helper)
            .arg("--target")
            .arg(&target)
            .arg("--working-directory")
            .arg(root.path())
            .arg("--target-arg")
            .arg(&marker)
            .arg("--target-arg")
            .arg(&host)
            .arg("--target-arg")
            .arg(&gate)
            .args(["--target-arg", mode])
            .arg("--write-path")
            .arg(&marker)
            .arg("--read-path")
            .arg(&gate)
            .arg("--receipt-rollback-anchor-root")
            .arg(anchors.path())
            .args([
                "--execution-uid",
                "10001",
                "--execution-gid",
                "10001",
                "--execution-supplementary-gid",
                "10002",
                "--server-id",
                "confined-discovery",
            ])
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout)?)
            .stderr(std::fs::File::create(&stderr)?);
        let mut child = OwnedChild(command.spawn()?);
        let pid: u32 = loop {
            if let Ok(pid) = std::fs::read_to_string(&marker)?.parse() {
                break pid;
            }
            if let Some(status) = child.0.try_wait()? {
                return Err(format!(
                    "discovery exited before identity observation: {status}: {}",
                    std::fs::read_to_string(&stderr)?
                )
                .into());
            }
            if started.elapsed() >= Duration::from_secs(10) {
                return Err("discovery did not reach identity barrier".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        assert!(
            status
                .lines()
                .any(|line| line == "Uid:\t10001\t10001\t10001\t10001"),
            "{status}"
        );
        assert!(
            status
                .lines()
                .any(|line| line == "Gid:\t10001\t10001\t10001\t10001"),
            "{status}"
        );
        assert!(
            status.lines().any(|line| line.starts_with("Groups:")
                && line.split_whitespace().skip(1).collect::<Vec<_>>() == ["10002"]),
            "{status}"
        );
        write(&gate, b"go")?;
        let result = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            if started.elapsed() >= Duration::from_secs(25) {
                return Err("absolute discovery deadline or cleanup exceeded".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let error = std::fs::read_to_string(&stderr)?;
        if mode == "respond" {
            assert!(result.success(), "{error}");
            let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&stdout)?)?;
            assert_eq!(report["containmentEnforced"], true);
            assert_eq!(report["reviewedToolCount"], 1);
            assert_eq!(report["reviewedToolsSource"], "discovered");
            let reviewed: serde_json::Value =
                serde_json::from_slice(&std::fs::read(output_dir.join("reviewed-tools.json"))?)?;
            assert_eq!(reviewed["tools"][0]["name"], "confined_probe");
            assert_eq!(
                reviewed["tools"][0]["inputSchema"],
                serde_json::json!({"type":"object"})
            );
        } else {
            assert!(!result.success(), "hostile discovery reported success");
            assert!(
                error.contains(if mode == "stall" {
                    "discovery deadline"
                } else {
                    "closed its output"
                }),
                "{error}"
            );
        }
        assert_eq!(
            std::fs::read(&host)?,
            b"host filesystem must remain private"
        );
        assert_eq!(
            std::fs::read(&marker)?,
            b"filesystem-denied",
            "peer must observe EACCES, and the clone syscall must never return"
        );
        let reap_started = Instant::now();
        while Path::new(&format!("/proc/{pid}")).exists() {
            if reap_started.elapsed() >= Duration::from_secs(2) {
                return Err("discovery child survived cleanup".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}
