//! Real owned nonce-preflight holds are not independent admission originals.
//! Fixture profiles are prepared before begin; all custody and ownership writes
//! use the actual serving owner, recovery lease and budget participants.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionNoncePreflightIdentityV1, NativeSecurityAuthorityBindingV1,
};
use chio_kernel::budget_store::BudgetReverseHoldRequest;
use chio_kernel::supplemental_admission::SupplementalAdmissionAuthorityBindingV1;
use chio_kernel::RevocationStore;

const VERIFIER: &str = "supplemental-selector-verifier";
const VERIFIER_CONFIG: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const MATERIAL: &[u8] = b"{\"fixture\":\"owned-supplemental-selector\"}";

struct SelectionFixture {
    fixture: Fixture,
    native: NativeSecurityAuthorityBindingV1,
    participant: SupplementalAdmissionAuthorityBindingV1,
    key: Keypair,
    digest: String,
}

impl SelectionFixture {
    fn new() -> TestResult<Self> {
        let fixture = fixture();
        let path = fixture._temp.path().join("selector-native-source.db");
        drop(crate::security_state::seeded_security_history(&path)?);
        let source = crate::security_state::SqliteSecurityParticipantSource::open(path)?;
        let selected = identifier("authority", "selector-native-source");
        let expected = fixture.store.expect_security_participant_source(
            &selected,
            &selected,
            &source,
            &fixture.fence,
            now_ms(),
        )?;
        fixture.store.import_security_participant_source(
            &selected,
            expected.expectation_id(),
            &source,
            &fixture.fence,
            now_ms(),
        )?;
        let native = fixture
            .store
            .hydrate_security_participant_state(
                &selected,
                expected.expectation_id(),
                &fixture.fence,
                now_ms(),
            )?
            .admission_binding()?;
        let participant = SupplementalAdmissionAuthorityBindingV1::new(
            identifier("participant", "supplemental-selector-participant"),
            digest("participant configuration", 'b'),
            identifier("verifier", VERIFIER),
            AdmissionDigest::try_new("verifier configuration", VERIFIER_CONFIG)?,
        );
        Ok(Self {
            fixture,
            native,
            participant,
            key: Keypair::generate(),
            digest: chio_kernel::supplemental_quota::supplemental_authorization_artifact_digest(
                MATERIAL,
            ),
        })
    }

    fn prepare(&self, name: &str) -> TestResult<AdmissionOperationV1> {
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            execution_nonce: true,
            supplemental_authorization: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let (base, original) = retained_request::original_with_intent_and_signer(
            &self.fixture.fence,
            name,
            requirements,
            None,
            &self.key,
        )?;
        let profile = original
            .authority_profile()
            .clone()
            .with_supplemental_participant(self.participant.clone());
        let security = serde_json::json!({
            "schema": "chio.admission-security-binding.v2",
            "context": {
                "tenant_id": "selector-tenant", "session_id": "selector-session",
                "principal_id": self.key.public_key().to_hex(),
                "isolation_epoch_id": "selector-epoch", "lineage_root_id": "selector-lineage",
                "context_generation": 1,
            },
            "pre_dispatch_required": true, "pre_dispatch_hook_installed": true,
            "native_authority": self.native,
        });
        let mut wire: serde_json::Value = serde_json::from_slice(original.canonical_bytes())?;
        wire["request"]["arguments"] = serde_json::from_slice(MATERIAL)?;
        wire["authority_profile"] = serde_json::to_value(&profile)?;
        wire["security_binding"] = security;
        let retained =
            RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&wire)?)?;
        let prior = sha256_hex(&canonical_json_bytes(&serde_json::json!({
            "schema": "chio.tool-admission-request.v3",
            "unbound_request_hash": retained_request::base_request_hash(retained.request_for_revalidation())?,
            "security_binding": wire["security_binding"],
        }))?);
        let immutable = sha256_hex(&canonical_json_bytes(&serde_json::json!({
            "schema": "chio.tool-admission-request.v4", "prior_request_hash": prior,
            "authority_profile": profile,
        }))?);
        let old = base.to_persisted().binding;
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: old.kind,
            namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
                "authority",
                &self.fixture.fence.store_uuid,
            ))?,
            request_id: old.request_id,
            capability_id: old.capability_id,
            authorization_capability_hash: old.authorization_capability_hash,
            request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
                AdmissionDigest::try_new("immutable", immutable)?,
                AdmissionDigest::try_new("action", sha256_hex(MATERIAL))?,
                requirements,
            )?,
            policy_hash: old.policy_hash,
            effect_class: old.effect_class,
        })?;
        let operation = AdmissionOperationV1::prepare(binding, self.fixture.fence.owner_epoch)?;
        retained.validate_binding(operation.binding())?;
        assert_eq!(
            retained.native_security_authority_binding(),
            Some(&self.native)
        );
        assert_eq!(
            retained.authority_profile().supplemental_participant(),
            Some(&self.participant)
        );
        self.fixture.store.begin_with_retained_tool_request(
            &operation,
            &retained,
            &self.fixture.fence,
            now_ms(),
        )?;
        let command = nonce_command(
            &self.fixture.store,
            &self.fixture.fence,
            &operation,
            &self.key,
            vec![AdmissionAttachment::SupplementalAuthorizationDigest(
                AdmissionDigest::try_new("supplemental", self.digest.clone())?,
            )],
            AdmissionOperationState::Prepared,
        )?;
        Ok(self
            .fixture
            .store
            .compare_and_swap(&command, now_ms())?
            .into_operation())
    }

    fn budget(&self, operation: &AdmissionOperationV1) -> TestResult<BudgetAuthorizeHoldRequest> {
        let mut request = lifecycle::budget_request(&self.fixture, operation);
        request.hold_id = Some(format!(
            "selector-hold:{}",
            operation.binding().operation_id().as_str()
        ));
        request.event_id = Some(format!(
            "selector-authorize:{}",
            operation.binding().operation_id().as_str()
        ));
        let binding = request.admission_binding.as_mut().ok_or("budget binding")?;
        binding
            .authorization_artifact_digests
            .push(self.digest.clone());
        binding.authorization_artifact_digests.sort();
        binding.authorization_artifact_digests.dedup();
        binding.supplemental_verifier_id = Some(VERIFIER.into());
        binding.supplemental_verifier_config_digest = Some(VERIFIER_CONFIG.into());
        binding.supplemental_authorization_artifact_digest = Some(self.digest.clone());
        binding.supplemental_authorization_expires_at = Some(now_ms() / 1_000 + 300);
        let observation = self
            .fixture
            .authority
            .revocation_store()
            .observe_revocation(operation.binding().capability_id().as_str())?;
        assert!(!observation.revoked);
        binding.last_observed_revocation =
            Some(observation.commit.ok_or("own revocation authority")?);
        Ok(request)
    }

    fn own_preflight(&self, operation: &AdmissionOperationV1) -> TestResult<AdmissionOperationV1> {
        let identity = AdmissionNoncePreflightIdentityV1::for_operation(operation, 0)?;
        let mut request = self.budget(operation)?;
        request
            .admission_binding
            .as_mut()
            .ok_or("binding")?
            .operation_id = identity.budget_operation_id().as_str().into();
        request.hold_id = Some(identity.hold_id().as_str().into());
        request.event_id = Some(identity.authorization_event_id().as_str().into());
        let command = nonce_command(
            &self.fixture.store,
            &self.fixture.fence,
            operation,
            &self.key,
            Vec::new(),
            AdmissionOperationState::Prepared,
        )?;
        let (decision, updated) = self.fixture.store.authorize_execution_nonce_preflight(
            operation,
            command.recovery_lease(),
            request.clone(),
            now_ms(),
        )?;
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        self.reverse(request)?;
        let owned = self
            .fixture
            .store
            .load_execution_nonce_preflight(
                updated.binding().operation_id(),
                &self.fixture.fence,
                now_ms(),
            )?
            .ok_or("authenticated preflight ownership")?;
        assert_eq!(owned.identity(), &identity);
        assert_eq!(
            owned.hold(),
            chio_kernel::admission_operation::AdmissionNoncePreflightHoldDisposition::Reversed
        );
        Ok(updated)
    }

    fn authorize(&self, operation: &AdmissionOperationV1) -> TestResult<AdmissionOperationV1> {
        let command = nonce_command(
            &self.fixture.store,
            &self.fixture.fence,
            operation,
            &self.key,
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                operation,
                operation.binding().request_id().as_str(),
            ))],
            AdmissionOperationState::BrokerAttemptRegistered,
        )?;
        let registered = self
            .fixture
            .store
            .compare_and_swap(&command, now_ms())?
            .into_operation();
        let command = nonce_command(
            &self.fixture.store,
            &self.fixture.fence,
            &registered,
            &self.key,
            Vec::new(),
            AdmissionOperationState::BudgetAuthorized,
        )?;
        let (decision, authorized) = self.fixture.store.authorize_budget_and_commit_admission(
            &registered,
            command.recovery_lease(),
            self.budget(&registered)?,
            None,
            None,
            &self.fixture.fence,
            now_ms(),
        )?;
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        assert_eq!(
            authorized.state(),
            AdmissionOperationState::BudgetAuthorized
        );
        let original = self
            .fixture
            .store
            .load_retained_tool_admission_custody(
                authorized.binding().operation_id(),
                &self.fixture.fence,
                now_ms(),
            )?
            .ok_or("genuine original custody")?;
        assert_eq!(original.operation, authorized);
        assert!(original.custody.is_some());
        Ok(authorized)
    }

    fn reverse(&self, request: BudgetAuthorizeHoldRequest) -> TestResult {
        self.fixture
            .authority
            .budget_store()
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: request.capability_id,
                grant_index: request.grant_index,
                reversed_exposure_units: 0,
                hold_id: request.hold_id,
                event_id: request.event_id.map(|event| format!("{event}:reverse")),
                expected_cumulative_approval_state: None,
                authority: request.authority,
            })?;
        Ok(())
    }

    fn select(
        &self,
    ) -> Result<Option<RetainedToolAdmissionCustodySnapshot>, AdmissionOperationStoreError> {
        self.fixture
            .store
            .load_retained_tool_admission_custody_by_supplemental_artifact(
                &self.digest,
                &self.native,
                &self.participant,
                &self.fixture.fence,
                now_ms(),
            )
    }

    fn counts(&self) -> TestResult<(i64, i64, i64, i64)> {
        Ok(self.fixture.store.connection()?.query_row(
            "SELECT (SELECT COUNT(*) FROM admission_operations), \
             (SELECT COUNT(*) FROM budget_authorization_holds), \
             (SELECT COUNT(*) FROM admission_nonce_preflight_holds), \
             (SELECT COUNT(*) FROM authority_global_commits)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?)
    }
}

#[test]
fn nonce_only_supplemental_custody_is_not_an_executable_admission_original() -> TestResult {
    let fixture = SelectionFixture::new()?;
    let operation = fixture.own_preflight(&fixture.prepare("nonce-only")?)?;
    assert_eq!(operation.state(), AdmissionOperationState::Prepared);
    assert!(operation.budget_hold_id().is_none());
    let before = fixture.counts()?;
    assert_eq!((before.0, before.1, before.2), (1, 1, 1));
    assert!(fixture.select()?.is_none());
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

#[test]
fn nonce_and_executable_hold_select_the_one_authenticated_parent_without_mutation() -> TestResult {
    let fixture = SelectionFixture::new()?;
    let prepared = fixture.own_preflight(&fixture.prepare("nonce-and-admission")?)?;
    let operation = fixture.authorize(&prepared)?;
    let before = fixture.counts()?;
    assert_eq!((before.0, before.1, before.2), (1, 2, 1));
    let selected = fixture.select()?.ok_or("one original must be selected")?;
    assert_eq!(selected.operation, operation);
    assert_eq!(
        selected.custody.ok_or("selected physical custody")?.hold_id,
        fixture.budget(&operation)?.hold_id.ok_or("hold")?
    );
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

#[test]
fn genuine_two_admission_originals_remain_ambiguous_after_nonce_alias_resolution() -> TestResult {
    let fixture = SelectionFixture::new()?;
    let first = fixture.own_preflight(&fixture.prepare("first-original")?)?;
    let first = fixture.authorize(&first)?;
    fixture.reverse(fixture.budget(&first)?)?;
    let second = fixture.authorize(&fixture.prepare("second-original")?)?;
    assert_ne!(
        first.binding().operation_id(),
        second.binding().operation_id()
    );
    let before = fixture.counts()?;
    assert_eq!((before.0, before.1, before.2), (2, 3, 1));
    assert!(
        matches!(fixture.select(), Err(AdmissionOperationStoreError::Invariant(ref reason))
        if reason == "supplemental authorization artifact has multiple original operations")
    );
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

#[test]
fn unowned_reserved_prefix_cannot_be_discarded_as_authenticated_nonce_custody() -> TestResult {
    let fixture = SelectionFixture::new()?;
    assert!(fixture.select()?.is_none());
    let invalid_id = format!(
        "{}{}",
        chio_kernel::admission_operation::NONCE_PREFLIGHT_BUDGET_PREFIX,
        "d".repeat(64)
    );
    let at = i64::try_from(now_ms())?;
    // Deliberate owner-connection corruption, not a legitimate preflight. The
    // reserved spelling alone may not authenticate or silently discard a row.
    fixture.fixture.store.connection()?.execute(
        "INSERT INTO budget_authorization_holds \
         (hold_id, capability_id, grant_index, authorized_exposure_units, \
          remaining_exposure_units, invocation_count_debited, invocation_captured, \
          disposition, created_at, updated_at, operation_id, supplemental_artifact_digest) \
         VALUES ('unowned-prefix-hold', 'unowned-prefix-capability', 0, 0, 0, 0, 0, 'open', ?1, ?1, ?2, ?3)",
        params![at, invalid_id, fixture.digest],
    )?;
    let before = fixture.counts()?;
    assert!(matches!(fixture.select(),
        Err(AdmissionOperationStoreError::Operation(chio_kernel::admission_operation::AdmissionOperationError::InvalidDigest { field }))
            if field == "operation_id"));
    assert_eq!(fixture.counts()?, before);
    Ok(())
}
