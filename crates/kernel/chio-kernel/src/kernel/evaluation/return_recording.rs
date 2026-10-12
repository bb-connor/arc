//! Authority-clock timing for an invocation owned by its post-effect obligation.
use super::*;

impl ChioKernel {
    /// Time durable returns and streams on the authority clock's monotonic domain.
    /// An ordinary value has no elapsed-time consumer: stream limits ignore it,
    /// and no raw outcome is persisted. Preserve its observed value and cost
    /// without an unnecessary fallible end read; its unused duration is zero.
    /// The caller enters PostEffectObligation before polling this future. A
    /// failed start reading prevents connector polling; a failed or regressed
    /// end reading withholds output. The same owner retains evidence and holds,
    /// and a durable failure remains bound to its original saga.
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
