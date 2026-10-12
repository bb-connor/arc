//! Original dispatch custody until its return is recorded or terminal unknown.
use super::*;

impl ChioKernel {
    /// Time durable returns and streams on the authority clock's monotonic domain.
    /// An ordinary value has no elapsed-time consumer: stream limits ignore it,
    /// and no raw outcome is persisted. Preserve its observed value and cost
    /// without an unnecessary fallible end read; its unused duration is zero.
    /// Callers own the dispatch through an armed, started drop guard first. The
    /// dispatch future runs only after the start reading succeeds. A failed or
    /// regressed reading reaches the caller's post-commit failure arm, which
    /// keeps the operation and holds and records the outcome as unknown. An end
    /// reading failure discards the observed output without recording a successful
    /// return; the original committed operation remains authoritative for recovery.
    pub(super) async fn timed_dispatch(
        &self,
        durable: bool,
        dispatch: impl std::future::Future<
            Output = Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError>,
        >,
    ) -> Result<((ToolServerOutput, Option<ToolInvocationCost>), Duration), KernelError> {
        let started = self.authority_clock_reading()?.monotonic();
        let output = dispatch.await?;
        if !durable && matches!(output.0, ToolServerOutput::Value(_)) {
            return Ok((output, Duration::ZERO));
        }
        let finished = self.authority_clock_reading()?.monotonic();
        Ok((output, finished.duration_since(started)?))
    }
}
