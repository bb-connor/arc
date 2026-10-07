//! Startup sweeps over a real SQLite authority that shares one injected clock
//! with the recovering kernel.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use std::sync::Mutex;

#[path = "recovery_sweep/authority_time.rs"]
mod authority_time;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Kernel,
    Store,
    Observer,
}

#[derive(Default)]
struct ClockState {
    elapsed_ms: u64,
    armed: bool,
    reads: Vec<(Role, Option<u64>)>,
    advance_after_store_read: Option<(usize, u64)>,
    advanced_after_read: Option<usize>,
}

/// Every read advances one millisecond on both the wall and monotonic axes.
/// While armed, reads are traced by role and a scheduled store read can be
/// followed by a real time advance.
struct SweepClock {
    epoch_ms: u64,
    state: Mutex<ClockState>,
}

struct ClockPort {
    source: Arc<SweepClock>,
    role: Role,
}

impl Clock for ClockPort {
    fn read(&self) -> Result<ClockReading, ClockError> {
        self.source.read_as(self.role)
    }
}

impl SweepClock {
    fn new() -> TestResult<Arc<Self>> {
        Ok(Arc::new(Self {
            epoch_ms: chio_test_support::clock::clock().unix_millis()?.get(),
            state: Mutex::new(ClockState::default()),
        }))
    }

    fn port(self: &Arc<Self>, role: Role) -> Arc<dyn Clock> {
        Arc::new(ClockPort {
            source: self.clone(),
            role,
        })
    }

    fn now_ms(&self) -> TestResult<u64> {
        Ok(self.read_as(Role::Observer)?.unix_millis().get())
    }

    fn advance_ms(&self, amount: u64) -> TestResult {
        let mut state = self.state.lock().map_err(|_| "clock state lock")?;
        state.elapsed_ms = state
            .elapsed_ms
            .checked_add(amount)
            .ok_or("clock advance overflow")?;
        Ok(())
    }

    fn arm(&self, advance_after_store_read: Option<(usize, u64)>) -> TestResult {
        let mut state = self.state.lock().map_err(|_| "clock state lock")?;
        state.armed = true;
        state.reads.clear();
        state.advance_after_store_read = advance_after_store_read;
        state.advanced_after_read = None;
        Ok(())
    }

    fn disarm(&self) -> TestResult<Vec<(Role, Option<u64>)>> {
        let mut state = self.state.lock().map_err(|_| "clock state lock")?;
        state.armed = false;
        Ok(std::mem::take(&mut state.reads))
    }

    fn advanced_after_read(&self) -> TestResult<Option<usize>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "clock state lock")?
            .advanced_after_read)
    }

    fn read_as(&self, role: Role) -> Result<ClockReading, ClockError> {
        let mut state = self.state.lock().map_err(|_| ClockError::Unavailable)?;
        state.elapsed_ms = state
            .elapsed_ms
            .checked_add(1)
            .ok_or(ClockError::Overflow)?;
        let now = self
            .epoch_ms
            .checked_add(state.elapsed_ms)
            .ok_or(ClockError::Overflow)?;
        let monotonic = MonotonicInstant::from_nanos(
            state
                .elapsed_ms
                .checked_mul(1_000_000)
                .ok_or(ClockError::Overflow)?,
        );
        if state.armed {
            state.reads.push((role, Some(now)));
            let store_reads = state
                .reads
                .iter()
                .filter(|(read, _)| *read == Role::Store)
                .count();
            if role == Role::Store && state.advanced_after_read.is_none() {
                if let Some((ordinal, amount)) = state.advance_after_store_read {
                    if ordinal == store_reads {
                        state.elapsed_ms = state
                            .elapsed_ms
                            .checked_add(amount)
                            .ok_or(ClockError::Overflow)?;
                        state.advanced_after_read = Some(state.reads.len());
                    }
                }
            }
        }
        Ok(ClockReading::new(UnixMillis::new(now), monotonic))
    }
}

fn provision() -> TestResult<(tempfile::TempDir, std::path::PathBuf, std::path::PathBuf)> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    Ok((temp, database, locks))
}

struct Serving {
    authority: SqliteAuthorityStore,
    operations: Arc<chio_store_sqlite::SqliteAdmissionOperationStore>,
    fence: StoreMutationFence,
}

impl Serving {
    fn open(
        database: &std::path::Path,
        locks: &std::path::Path,
        clock: &Arc<SweepClock>,
    ) -> TestResult<Self> {
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            database,
            locks,
            clock.port(Role::Store),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        Ok(Self {
            authority,
            operations,
            fence,
        })
    }

    /// A kernel bound to this serving owner whose clock fence is primed
    /// before any traced read.
    fn kernel(&self, keypair: Keypair, clock: &Arc<SweepClock>) -> TestResult<ChioKernel> {
        let mut kernel =
            ChioKernel::new_with_clock(kernel_config(keypair), clock.port(Role::Kernel));
        kernel.set_durable_admission_store(
            self.operations.clone(),
            Arc::new(self.authority.tool_outcome_store()),
            self.fence.clone(),
        )?;
        kernel.set_budget_store_handle(Arc::new(self.authority.budget_store()));
        kernel.authority_clock_reading()?;
        Ok(kernel)
    }
}
