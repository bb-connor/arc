use super::*;
pub(super) struct DurableUrlElicitationServer {
    pub(super) store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableUrlElicitationServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before URL elicitation"
        );
        Err(KernelError::UrlElicitationsRequired {
            message: DURABLE_URL_ELICITATION_MESSAGE.to_owned(),
            elicitations: durable_url_elicitations(),
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "URL elicitation server unexpectedly used value invocation".to_owned(),
        ))
    }
}

pub(super) const DURABLE_URL_ELICITATION_MESSAGE: &str =
    "URL elicitation required before tool execution";

pub(super) fn durable_url_elicitations() -> Vec<CreateElicitationOperation> {
    vec![CreateElicitationOperation::Url {
        meta: None,
        message: "Authorize the provider URL".to_owned(),
        url: "https://provider.example/authorize".to_owned(),
        elicitation_id: "durable-elicitation-1".to_owned(),
    }]
}

/// The caller receives the tool's typed URL elicitation with its full payload.
pub(super) fn assert_durable_url_elicitation(result: Result<ToolCallResponse, KernelError>) {
    match result {
        Err(KernelError::UrlElicitationsRequired {
            message,
            elicitations,
        }) => {
            assert_eq!(message, DURABLE_URL_ELICITATION_MESSAGE);
            assert_eq!(
                serde_json::to_value(&elicitations).expect("delivered elicitations"),
                serde_json::to_value(durable_url_elicitations()).expect("expected elicitations")
            );
        }
        other => panic!("durable URL elicitation must deliver its typed error: {other:?}"),
    }
}
