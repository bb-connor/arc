use super::*;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const CHILD_DIRECTORY: &str = "CHIO_COMBINED_CUSTODY_CRASH_DIRECTORY";
const CHILD_CUT: &str = "CHIO_COMBINED_CUSTODY_CRASH_CUT";

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct RestartState {
    request: ToolCallRequest,
    runtime_authority_id: String,
    expectation_id: String,
    origin_seed: String,
    local_seed: String,
}

impl RestartState {
    pub(super) fn prepare() -> TestResult<(FixtureDirectory, Self)> {
        let fixture = CombinedFixture::new()?;
        let state = Self {
            request: fixture.inner.request.clone(),
            runtime_authority_id: fixture
                .inner
                .binding
                .runtime_authority_id()
                .as_str()
                .to_owned(),
            expectation_id: fixture.inner.binding.expectation_id().as_str().to_owned(),
            origin_seed: fixture.origin_key.seed_hex(),
            local_seed: fixture.local_key.seed_hex(),
        };
        let directory = fixture.inner._directory;
        write_json(&directory.path().join("restart.json"), &state)?;
        worker::create_effect_store(directory.path())?;
        // All serving-owner handles are dropped before the child takes custody.
        Ok((directory, state))
    }

    pub(super) fn open(&self, path: &Path) -> TestResult<CombinedFixture> {
        Ok(CombinedFixture {
            inner: Fixture {
                _directory: FixtureDirectory::Existing(path.to_owned()),
                authority: SqliteAuthorityStore::open_serving(
                    path.join("authority.sqlite3"),
                    path.join("locks"),
                )?,
                source: SqliteRuntimeOrchestrationStore::open(path.join("runtime.sqlite3"))?,
                binding: RuntimeParticipantAuthorityBindingV1::new(
                    AdmissionIdentifier::try_new(
                        "runtime_authority_id",
                        &self.runtime_authority_id,
                    )?,
                    AdmissionIdentifier::try_new("expectation_id", &self.expectation_id)?,
                ),
                request: self.request.clone(),
                invocations: Arc::new(AtomicU64::new(0)),
            },
            origin_key: Keypair::from_seed_hex(&self.origin_seed)?,
            local_key: Keypair::from_seed_hex(&self.local_seed)?,
        })
    }
}

pub(super) fn write_json(path: &Path, value: &impl serde::Serialize) -> TestResult {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn child_directory(cut: Cut) -> TestResult<Option<PathBuf>> {
    let Some(path) = std::env::var_os(CHILD_DIRECTORY) else {
        return Ok(None);
    };
    assert_eq!(std::env::var(CHILD_CUT)?, cut.label());
    Ok(Some(PathBuf::from(path)))
}

pub(super) fn load_state(path: &Path) -> TestResult<RestartState> {
    Ok(serde_json::from_slice(&std::fs::read(
        path.join("restart.json"),
    )?)?)
}

// Own exactly the spawned child. Assertion failures and timeouts must reap it
// before the parent's TempDir is removed; no process-name or group kill is used.
pub(super) struct CrashChild(Child);

impl CrashChild {
    pub(super) fn spawn(path: &Path, cut: Cut, test: &str) -> TestResult<Self> {
        let module = module_path!()
            .strip_suffix("::harness")
            .and_then(|module| module.split_once("::").map(|(_, module)| module))
            .ok_or("crash harness must be in its integration test module")?;
        Ok(Self(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    &format!("{module}::{test}"),
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_DIRECTORY, path)
                .env(CHILD_CUT, cut.label())
                .spawn()?,
        ))
    }

    pub(super) fn wait_until_parked(&mut self, path: &Path) -> TestResult<StoreMutationFence> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Err(format!("crash worker exited before parent kill: {status}").into());
            }
            match std::fs::read(path.join("parked.json")) {
                Ok(bytes) => return Ok(serde_json::from_slice(&bytes)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Err("crash worker did not reach its durable boundary within 30s".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn kill_and_reap(mut self) -> TestResult {
        assert!(
            self.0.try_wait()?.is_none(),
            "worker must still hold the live future"
        );
        self.0.kill()?;
        let status = self.0.wait()?;
        assert_eq!(
            status.signal(),
            Some(9),
            "worker must die by SIGKILL: {status}"
        );
        Ok(())
    }
}

impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
