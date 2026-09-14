use super::{
    journal::Journal,
    native::{CURRENCY, SERVER},
};
use chio_kernel::{KernelError, NestedFlowBridge, ToolInvocationCost, ToolServerConnection};
use std::sync::Arc;

pub struct W0Tool(pub Arc<Journal>, pub super::Checkpoint);

#[async_trait::async_trait]
impl ToolServerConnection for W0Tool {
    fn server_id(&self) -> &str {
        SERVER
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["review".into()]
    }

    async fn invoke(
        &self,
        tool: &str,
        arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let run = || -> crate::common::Result<serde_json::Value> {
            if tool != "review" || arguments.as_object().is_none_or(|value| value.len() != 1) {
                return Err("unsupported funded W0 invocation".into());
            }
            let input = arguments["input"].as_str().ok_or("W0 input missing")?;
            let output = serde_json::to_value(crate::review::check_openapi(input)?)?;
            // Deliberately records every invocation. Duplicate prevention belongs
            // to native admission, not an idempotent mock tool.
            self.0.record_output(&output)?;
            (self.1)("after-tool")?;
            Ok(output)
        };
        run().map_err(|error| KernelError::ToolServerError(error.to_string()))
    }

    async fn invoke_with_cost(
        &self,
        tool: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke(tool, arguments, bridge).await?,
            Some(ToolInvocationCost {
                units: 100,
                currency: CURRENCY.into(),
                breakdown: None,
            }),
        ))
    }
}
