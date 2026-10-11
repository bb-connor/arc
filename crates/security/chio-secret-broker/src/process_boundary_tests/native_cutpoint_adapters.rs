//! Test-only interruption around the unchanged production authority adapters.
use super::*;
use crate::kernel_admission::{BrokerAdmissionParticipant, BrokerMcpToolConnection};
use chio_kernel::supplemental_admission::{
    SupplementalAdmissionParticipant, SupplementalAdmissionRegistrationContext,
};
use chio_kernel::supplemental_quota::SupplementalQuotaVerifierError;
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolDispatchContext, ToolInvocationContext, ToolInvocationCost,
    ToolServerConnection,
};

pub(in super::super) fn wrap_participant(
    inner: Arc<BrokerAdmissionParticipant>,
    control: Option<Arc<Control>>,
) -> Arc<dyn SupplementalAdmissionParticipant> {
    match control {
        Some(control) => Arc::new(Participant { inner, control }),
        None => inner,
    }
}

struct Participant {
    inner: Arc<BrokerAdmissionParticipant>,
    control: Arc<Control>,
}

impl SupplementalAdmissionParticipant for Participant {
    fn requires_registration(&self, server_id: &str, tool_name: &str) -> bool {
        self.inner.requires_registration(server_id, tool_name)
    }

    fn register_original(
        &self,
        context: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> std::result::Result<(), SupplementalQuotaVerifierError> {
        self.inner.register_original(context)?;
        *self
            .control
            .quotas
            .lock()
            .test_expect("original registration quotas") =
            context.budget().invocation_quotas.clone();
        self.control.kill_at(Point::Registered);
        Ok(())
    }
}

pub(in super::super) fn wrap_connection(
    inner: Arc<dyn BrokerMcpToolConnection>,
    control: Option<Arc<Control>>,
) -> Arc<dyn BrokerMcpToolConnection> {
    match control {
        Some(control) => Arc::new(Connection { inner, control }),
        None => inner,
    }
}

struct Connection {
    inner: Arc<dyn BrokerMcpToolConnection>,
    control: Arc<Control>,
}

#[async_trait::async_trait]
impl BrokerMcpToolConnection for Connection {
    async fn prepare_broker_delivery(
        &self,
        context: &ToolDispatchContext,
        stream: UnixStream,
    ) -> std::result::Result<(), KernelError> {
        self.inner.prepare_broker_delivery(context, stream).await
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for Connection {
    fn server_id(&self) -> &str {
        self.inner.server_id()
    }
    fn tool_names(&self) -> Vec<String> {
        self.inner.tool_names()
    }

    async fn invoke(
        &self,
        tool: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<serde_json::Value, KernelError> {
        self.inner.invoke(tool, arguments, bridge).await
    }

    async fn prepare_delivery(
        &self,
        context: &ToolDispatchContext,
    ) -> std::result::Result<(), KernelError> {
        self.inner.prepare_delivery(context).await
    }

    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        assert_eq!(
            self.control.dispatch_calls.fetch_add(1, Ordering::SeqCst),
            0,
            "replay reached the transport after broker death"
        );
        self.control.kill_at(Point::Captured);
        self.inner
            .invoke_with_cost_and_context(context, arguments, bridge)
            .await
    }
}
