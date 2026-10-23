use super::*;
use chio_kernel::{ApprovalDecision, ApprovalFilter, ApprovalStoreError, ResolvedApproval};
use chio_security_types::schema::SchemaRefusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefusalAt {
    Pending,
    Resolution,
    Consumption,
    Resolve,
}

struct RefusingStore {
    inner: InMemoryApprovalStore,
    at: RefusalAt,
}

fn schema_error() -> ApprovalStoreError {
    ApprovalStoreError::Schema(SchemaRefusal::MissingSchema {
        store_key: "private-store-namespace".to_owned(),
    })
}

impl ApprovalStore for RefusingStore {
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        self.inner.store_pending(request)
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        match self.at {
            RefusalAt::Pending => Err(schema_error()),
            RefusalAt::Resolution => Ok(None),
            _ => self.inner.get_pending(id),
        }
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        self.inner.list_pending(filter)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        if self.at == RefusalAt::Resolve {
            return Err(schema_error());
        }
        self.inner.resolve(id, decision)
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        self.inner.count_approved(subject_id, policy_id)
    }

    fn is_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        if self.at == RefusalAt::Consumption {
            return Err(schema_error());
        }
        self.inner.is_consumed(token_id, parameter_hash)
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        if self.at == RefusalAt::Resolution {
            return Err(schema_error());
        }
        self.inner.get_resolution(id)
    }
}

fn setup(at: RefusalAt) -> (ApprovalAdmin, RespondRequest) {
    let subject = Keypair::generate();
    let approver = Keypair::generate();
    let inner = InMemoryApprovalStore::new();
    store_pending(&inner, "a-1", "h-1", &subject, &[approver.public_key()]);
    let token = sign_token(
        &approver,
        &subject,
        "a-1",
        "h-1",
        GovernedApprovalDecision::Approved,
    );
    let body = RespondRequest {
        outcome: ApprovalOutcome::Approved,
        reason: None,
        approver: approver.public_key(),
        token,
    };
    (
        ApprovalAdmin::new(Arc::new(RefusingStore { inner, at })),
        body,
    )
}

#[test]
fn single_response_redacts_each_schema_refusal() {
    for at in [
        RefusalAt::Pending,
        RefusalAt::Resolution,
        RefusalAt::Consumption,
        RefusalAt::Resolve,
    ] {
        let (admin, body) = setup(at);
        let error = handle_respond(&admin, "a-1", body, 500).unwrap_err();
        assert_eq!(error.status(), 500, "{at:?}");
        assert_eq!(
            error.body(),
            serde_json::json!({
                "error": "internal_error",
                "message": "urn:chio:error:kernel:internal-error"
            }),
            "{at:?}"
        );
    }
}

#[test]
fn batch_response_redacts_each_schema_refusal() {
    for at in [
        RefusalAt::Pending,
        RefusalAt::Resolution,
        RefusalAt::Consumption,
        RefusalAt::Resolve,
    ] {
        let (admin, body) = setup(at);
        let result = handle_batch_respond(
            &admin,
            BatchRespondRequest {
                decisions: vec![BatchDecisionEntry {
                    approval_id: "a-1".into(),
                    outcome: body.outcome,
                    reason: body.reason,
                    approver: body.approver,
                    token: body.token,
                }],
            },
            500,
        )
        .unwrap();
        assert_eq!(result.summary.total, 1, "{at:?}");
        assert_eq!(result.summary.rejected, 1, "{at:?}");
        assert_eq!(result.summary.approved, 0, "{at:?}");
        assert_eq!(result.summary.denied, 0, "{at:?}");
        let entry = result.results.first().unwrap();
        assert_eq!(entry.status, "rejected", "{at:?}");
        assert_eq!(entry.outcome, None, "{at:?}");
        assert_eq!(
            entry.error.as_deref(),
            Some("urn:chio:error:kernel:internal-error"),
            "{at:?}"
        );
    }
}
