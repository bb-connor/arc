use super::*;

impl ChioKernel {
    pub fn evaluate_tool_call_blocking(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, None)
    }

    /// Crate-private sync entrypoint invoked by the
    /// [`crate::kernel::evaluator::ToolEvaluator`] default
    /// implementation. Wraps the long-form
    /// `evaluate_tool_call_sync_inner` so the trait body does
    /// not need to plumb the `session_filesystem_roots` /
    /// `extra_metadata` parameters; both default to `None` on this path,
    /// matching the previous direct delegation from
    /// `evaluate_tool_call`.
    pub(crate) fn evaluate_tool_call_sync(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_inner(request, None, None)
    }

    pub fn evaluate_tool_call_blocking_with_metadata(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        reject_reserved_receipt_metadata(extra_metadata.as_ref())?;
        self.evaluate_tool_call_sync_inner(request, None, extra_metadata)
    }

    /// Blocking bridge evaluation with an exact live-registry sidecar.
    pub fn evaluate_tool_call_blocking_with_manifest_security(
        &self,
        request: &ToolCallRequest,
        registry: &chio_manifest::VerifiedManifestRegistry,
        security: &chio_manifest::BridgeSecurityMetadata,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.require_manifest_flow_runtime(registry)?;
        let metadata = registry_validated_manifest_security_metadata(
            request,
            registry,
            security,
            extra_metadata,
        )?;
        self.evaluate_tool_call_sync_inner(request, None, Some(metadata))
    }

    /// Blocking bridge evaluation with exact live-registry metadata and
    /// authoritative identity and isolation state from a trusted runtime.
    pub fn evaluate_tool_call_blocking_with_manifest_security_and_security_context(
        &self,
        request: &ToolCallRequest,
        registry: &chio_manifest::VerifiedManifestRegistry,
        security: &chio_manifest::BridgeSecurityMetadata,
        extra_metadata: Option<serde_json::Value>,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        self.require_manifest_flow_runtime(registry)?;
        let metadata = registry_validated_manifest_security_metadata(
            request,
            registry,
            security,
            extra_metadata,
        )?;
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            Some(metadata),
            None,
            Some(security_context),
        ))
    }

    /// Blocking bridge evaluation with exact live-registry metadata and a
    /// security context bound to the session that authenticated the caller.
    pub fn evaluate_tool_call_blocking_with_manifest_security_and_authenticated_session_context(
        &self,
        request: &ToolCallRequest,
        registry: &chio_manifest::VerifiedManifestRegistry,
        security: &chio_manifest::BridgeSecurityMetadata,
        extra_metadata: Option<serde_json::Value>,
        authenticated_session_id: &SessionId,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        self.require_manifest_flow_runtime(registry)?;
        let metadata = registry_validated_manifest_security_metadata(
            request,
            registry,
            security,
            extra_metadata,
        )?;
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            Some(metadata),
            Some(authenticated_session_id),
            Some(security_context),
        ))
    }

    pub fn evaluate_tool_call_blocking_with_security_context(
        &self,
        request: &ToolCallRequest,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            None,
            None,
            Some(security_context),
        ))
    }

    pub fn evaluate_tool_call_blocking_with_metadata_and_security_context(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<serde_json::Value>,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        reject_reserved_receipt_metadata(extra_metadata.as_ref())?;
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            None,
            extra_metadata,
            None,
            Some(security_context),
        ))
    }

    #[doc(hidden)]
    fn evaluate_tool_call_sync_inner(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            None,
        )
    }

    /// Evaluate a tool call sync path with access to the owning session,
    /// so the kernel can tag the resulting receipt with the session's
    /// tenant_id (multi-tenant receipt isolation).
    ///
    /// `session_id` is the session that authenticated the caller, used only
    /// to resolve the tenant from `auth_context().enterprise_identity`. The
    /// tenant_id is NEVER read from `request` itself -- accepting a caller-
    /// provided tenant would defeat the isolation guarantee.
    pub(crate) fn evaluate_tool_call_sync_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_sync_with_session_and_security_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            session_id,
            None,
        )
    }

    pub(crate) fn evaluate_tool_call_sync_with_session_and_security_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_async_with_session_context(
            request,
            session_filesystem_roots,
            extra_metadata,
            session_id,
            security_context,
        ))
    }
}
