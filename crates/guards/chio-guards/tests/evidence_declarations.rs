//! Declared evidence disclosure of the default-constructible `chio-guards`
//! guards and of the composite pipelines. `evidence_declaration` is a required
//! trait method, so every other guard declares by compiling.

use chio_guards::{
    AdvisoryPipeline, BrowserAutomationGuard, CodeExecutionGuard, ComputerUseGuard,
    ContentReviewGuard, EgressAllowlistGuard, ForbiddenPathGuard, GuardPipeline,
    InputInjectionCapabilityGuard, InternalNetworkGuard, JailbreakGuard, McpToolGuard,
    MemoryGovernanceGuard, PatchIntegrityGuard, PathAllowlistGuard, PromotionPolicy,
    PromptInjectionGuard, RemoteDesktopSideChannelGuard, SecretLeakGuard, ShellCommandGuard,
};
use chio_kernel::{Guard, GuardEvidenceDeclaration};

#[test]
fn default_constructible_guards_declare_safe() {
    let safe: Vec<Box<dyn Guard>> = vec![
        Box::new(ForbiddenPathGuard::default()),
        Box::new(ShellCommandGuard::default()),
        Box::new(EgressAllowlistGuard::default()),
        Box::new(PathAllowlistGuard::default()),
        Box::new(McpToolGuard::default()),
        Box::new(SecretLeakGuard::default()),
        Box::new(PatchIntegrityGuard::default()),
        Box::new(JailbreakGuard::default()),
        Box::new(PromptInjectionGuard::default()),
        Box::new(InternalNetworkGuard::default()),
        Box::new(CodeExecutionGuard::default()),
        Box::new(ComputerUseGuard::default()),
        Box::new(BrowserAutomationGuard::default()),
        Box::new(RemoteDesktopSideChannelGuard::default()),
        Box::new(InputInjectionCapabilityGuard::default()),
        Box::new(ContentReviewGuard::default()),
        Box::new(MemoryGovernanceGuard::default()),
    ];
    for guard in &safe {
        assert_eq!(
            guard.evidence_declaration(),
            GuardEvidenceDeclaration::SAFE,
            "{}",
            guard.name()
        );
    }
}

#[test]
fn composite_guards_declare_unsafe() {
    let composites: Vec<Box<dyn Guard>> = vec![
        Box::new(GuardPipeline::default_pipeline()),
        Box::new(GuardPipeline::new()),
        Box::new(AdvisoryPipeline::new(PromotionPolicy::new())),
    ];
    for guard in &composites {
        assert_eq!(
            guard.evidence_declaration(),
            GuardEvidenceDeclaration::UNSAFE,
            "{}",
            guard.name()
        );
    }
}
