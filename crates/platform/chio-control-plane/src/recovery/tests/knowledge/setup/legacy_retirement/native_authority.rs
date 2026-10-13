//! Current local authority must install its actual native profile before inspecting history.
use super::*;

struct RetainedSetupAuthorityServer {
    contract: RecoveryEffectContractV1,
}

#[async_trait::async_trait]
impl ToolServerConnection for RetainedSetupAuthorityServer {
    fn server_id(&self) -> &str {
        "server-a"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["send".to_owned()]
    }

    fn recovery_effect_contract(&self) -> Option<RecoveryEffectContractV1> {
        Some(self.contract.clone())
    }

    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::Internal(
            "retained setup authority cannot invoke tools".to_owned(),
        ))
    }
}

pub(super) fn install_retained_setup_authority(
    kernel: &mut ChioKernel,
    path: &std::path::Path,
    current: &RecoveryDeploymentV1,
) -> TestResult {
    // The connector contract is an independently configured fixture constant,
    // checked against the authenticated deployment rather than copied from it.
    let contract = authority_history::fixture_effect_contract(path)?;
    assert_eq!(current.effect_contract, contract);
    assert_eq!(current.server_id.as_str(), "server-a");
    assert_eq!(current.tool_name.as_str(), "send");
    assert_eq!(current.security_context.as_v1().context_generation(), 1);
    assert_eq!(current.aggregate_issuer_id.as_str(), "aggregate");
    assert_eq!(
        current.aggregate_issuer,
        Keypair::from_seed(&[143; 32]).public_key()
    );
    assert_eq!(
        current.native_authority.security_authority_id().as_str(),
        "recovery-native"
    );
    assert_eq!(
        current.policy_digest.as_bytes(),
        chio_core::sha256(b"native-flow-policy-test").as_bytes(),
    );
    assert_eq!(
        current.contract_digest,
        ContractDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::EffectContract,
            &contract,
        )?),
    );
    let config = FlowResolverConfig::new(
        restricted_label(),
        category_labels(),
        BTreeMap::from([(
            RecordId::new("aggregate")?,
            Keypair::from_seed(&[143; 32]).public_key(),
        )]),
        60_000,
    )?;
    let registry = if path.join("semantic-kind").exists() {
        semantic::manifest(path)?
    } else {
        declassification_registry_with_output_floor(
            &current.purpose,
            authority_history::fixture_output_floor(path)?,
        )
    };
    let resolver = Arc::new(
        NativeFlowResolver::new(
            current.native_authority.clone(),
            registry,
            authority_history::fixture_classifier(path),
            fixture_native_clock(path),
            config,
        )?
        .with_captured_lifecycle(),
    );
    kernel.register_tool_server(Box::new(RetainedSetupAuthorityServer { contract }));
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    resolver.install_captured_on_kernel(kernel)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&kernel.recovery_deployment(&current.scope)?)?,
        chio_core::canonical_json_bytes(current)?,
    );
    Ok(())
}
