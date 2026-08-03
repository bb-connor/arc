const DEFAULT_BROKER_IPC_DEADLINE_MS: u64 = 5_000;
const MAX_BROKER_IPC_DEADLINE_MS: u64 = 30_000;

/// Absolute read and write budgets for one accepted broker IPC connection.
///
/// The read budget starts when the endpoint begins handling an accepted stream.
/// The write budget starts when response emission begins. Kernel read and write
/// timeouts are installed immediately, and successful I/O does not extend the
/// corresponding absolute budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerIpcDeadlines {
    read: Duration,
    write: Duration,
}

impl BrokerIpcDeadlines {
    pub fn from_millis(read_timeout_ms: u64, write_timeout_ms: u64) -> Result<Self> {
        if read_timeout_ms == 0
            || read_timeout_ms > MAX_BROKER_IPC_DEADLINE_MS
            || write_timeout_ms == 0
            || write_timeout_ms > MAX_BROKER_IPC_DEADLINE_MS
        {
            return Err(BrokerError::InvalidRequest(
                "broker IPC deadlines must be between 1 and 30000 milliseconds".to_string(),
            ));
        }
        Ok(Self {
            read: Duration::from_millis(read_timeout_ms),
            write: Duration::from_millis(write_timeout_ms),
        })
    }
}

impl Default for BrokerIpcDeadlines {
    fn default() -> Self {
        Self {
            read: Duration::from_millis(DEFAULT_BROKER_IPC_DEADLINE_MS),
            write: Duration::from_millis(DEFAULT_BROKER_IPC_DEADLINE_MS),
        }
    }
}

/// Observable result for one accepted broker IPC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerIpcServeOutcome {
    ResponseWritten,
    ClientFault { diagnostic_code: &'static str },
}

#[cfg(unix)]
trait BrokerIpcDeadlineStream: Read + Write {
    fn set_broker_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_broker_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

#[cfg(unix)]
impl BrokerIpcDeadlineStream for std::os::unix::net::UnixStream {
    fn set_broker_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }

    fn set_broker_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

#[cfg(unix)]
struct BrokerIpcDeadlineIo<S> {
    stream: S,
    read_deadline: Instant,
    write_budget: Duration,
    write_deadline: Option<Instant>,
    read_deadline_setup_failed: bool,
    write_deadline_setup_failed: bool,
}

#[cfg(unix)]
impl<S: BrokerIpcDeadlineStream> BrokerIpcDeadlineIo<S> {
    fn new(stream: S, deadlines: BrokerIpcDeadlines) -> std::io::Result<Self> {
        let accepted_at = Instant::now();
        let read_deadline = accepted_at.checked_add(deadlines.read).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "IPC read deadline overflow")
        })?;
        stream.set_broker_read_timeout(Some(deadlines.read))?;
        stream.set_broker_write_timeout(Some(deadlines.write))?;
        Ok(Self {
            stream,
            read_deadline,
            write_budget: deadlines.write,
            write_deadline: None,
            read_deadline_setup_failed: false,
            write_deadline_setup_failed: false,
        })
    }

    fn stream(&self) -> &S {
        &self.stream
    }

    fn read_deadline_setup_failed(&self) -> bool {
        self.read_deadline_setup_failed
    }

    fn write_deadline_setup_failed(&self) -> bool {
        self.write_deadline_setup_failed
    }

    fn remaining(deadline: Instant, label: &'static str) -> std::io::Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, label))
    }

    fn write_remaining(&mut self) -> std::io::Result<Duration> {
        let deadline = match self.write_deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = Instant::now().checked_add(self.write_budget).ok_or_else(|| {
                    self.write_deadline_setup_failed = true;
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "IPC write deadline overflow",
                    )
                })?;
                self.write_deadline = Some(deadline);
                deadline
            }
        };
        Self::remaining(deadline, "broker IPC write deadline elapsed")
    }
}

#[cfg(unix)]
impl<S: BrokerIpcDeadlineStream> Read for BrokerIpcDeadlineIo<S> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = Self::remaining(self.read_deadline, "broker IPC read deadline elapsed")?;
        if let Err(error) = self.stream.set_broker_read_timeout(Some(remaining)) {
            self.read_deadline_setup_failed = true;
            return Err(error);
        }
        self.stream.read(buffer)
    }
}

#[cfg(unix)]
impl<S: BrokerIpcDeadlineStream> Write for BrokerIpcDeadlineIo<S> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.write_remaining()?;
        if let Err(error) = self.stream.set_broker_write_timeout(Some(remaining)) {
            self.write_deadline_setup_failed = true;
            return Err(error);
        }
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let remaining = self.write_remaining()?;
        if let Err(error) = self.stream.set_broker_write_timeout(Some(remaining)) {
            self.write_deadline_setup_failed = true;
            return Err(error);
        }
        self.stream.flush()
    }
}
