//! The trust-control route authorization table and the middleware that
//! enforces it on every request.
//!
//! Each router route has exactly one row naming its listener, the credential
//! kind it accepts, the scope it requires and its tenant rule. A request whose
//! method and matched route have no row refuses, a row on the other listener
//! refuses as absent, a peer signature is refused on caller routes and a
//! bearer credential is refused on peer routes. `HEAD` follows the `GET`
//! row of its route, as the router serves `HEAD` from `GET` handlers.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{MatchedPath, NestedPath, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use chio_security_types::clock::Clock;

use super::caller_credentials::{
    AuthenticatedCaller, AuthenticatedPeer, CallerAuthError, CredentialKind, PeerAuthError,
    PeerNonceCache, PeerRequestTarget, Scope, TenantAuthority, TrustAccess,
    CLUSTER_AUTH_BODY_SHA256_HEADER, CLUSTER_AUTH_NONCE_HEADER,
};
use super::*;

/// The listener a route is served on. Internal routes are never mounted on
/// the public listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Listener {
    Public,
    Internal,
}

/// The authentication a route accepts. `Anonymous`, `FindingSeller` and
/// `WalletHolder` routes keep their own non-credential authentication in the
/// handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteCredential {
    Anonymous,
    Caller,
    Deployment,
    Peer,
    FindingSeller,
    WalletHolder,
    /// A finding buyer bearer token, which the handler authenticates, or a
    /// caller credential holding the row's scope. A bearer that is a caller
    /// credential is held to the caller rules; any other bearer reaches the
    /// handler unchanged.
    FindingBuyerOrCaller,
}

/// Which tenant authority a route admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TenantRule {
    NotApplicable,
    DeploymentOnly,
    TenantScoped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl RouteMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RouteMethod::Get => "GET",
            RouteMethod::Post => "POST",
            RouteMethod::Put => "PUT",
            RouteMethod::Delete => "DELETE",
        }
    }

    #[must_use]
    pub fn from_method(method: &Method) -> Option<Self> {
        match *method {
            Method::GET | Method::HEAD => Some(RouteMethod::Get),
            Method::POST => Some(RouteMethod::Post),
            Method::PUT => Some(RouteMethod::Put),
            Method::DELETE => Some(RouteMethod::Delete),
            _ => None,
        }
    }
}

/// One row of the route table. `path_source` is the router's path expression
/// text, which pins each row to exactly one `.route(` registration.
#[derive(Clone, Copy, Debug)]
pub struct RouteRule {
    pub method: RouteMethod,
    pub path: &'static str,
    pub path_source: &'static str,
    pub listener: Listener,
    pub credential: RouteCredential,
    pub scope: Option<Scope>,
    pub tenant: TenantRule,
}

macro_rules! route {
    ($method:ident, $path:expr, $listener:ident, $credential:ident, $scope:expr, $tenant:ident) => {
        RouteRule {
            method: RouteMethod::$method,
            path: $path,
            path_source: stringify!($path),
            listener: Listener::$listener,
            credential: RouteCredential::$credential,
            scope: $scope,
            tenant: TenantRule::$tenant,
        }
    };
}

#[rustfmt::skip]
pub static ROUTE_TABLE: &[RouteRule] = &[
    route!(Get, OID4VP_VERIFIER_METADATA_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, CHIO_PASSPORT_JWT_VC_JSON_TYPE_METADATA_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PASSPORT_SD_JWT_TYPE_METADATA_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PASSPORT_ISSUER_JWKS_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PASSPORT_ISSUER_METADATA_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, HEALTH_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, "/metrics", Public, Caller, Some(Scope::MetricsRead), DeploymentOnly),
    route!(Post, SCIM_USERS_PATH, Public, Caller, Some(Scope::ScimWrite), DeploymentOnly),
    route!(Delete, SCIM_USER_PATH, Public, Caller, Some(Scope::ScimWrite), DeploymentOnly),
    route!(Post, EMERGENCY_RESUME_PATH, Public, Caller, Some(Scope::AdminEmergency), DeploymentOnly),
    route!(Get, EMERGENCY_STATUS_PATH, Public, Caller, Some(Scope::AdminEmergency), DeploymentOnly),
    route!(Post, EMERGENCY_STOP_PATH, Public, Caller, Some(Scope::AdminEmergency), DeploymentOnly),
    route!(Get, AGENT_RECEIPTS_PATH, Public, Caller, Some(Scope::ReceiptsRead), TenantScoped),
    route!(Get, AUTHORITY_PATH, Public, Deployment, Some(Scope::AuthorityRead), DeploymentOnly),
    route!(Post, AUTHORITY_PATH, Public, Caller, Some(Scope::AuthorityAdmin), DeploymentOnly),
    route!(Post, AUTHORITY_KEY_LOG_SYNC_PATH, Public, Caller, Some(Scope::AuthorityAdmin), DeploymentOnly),
    route!(Post, CREDIT_LOSS_LIFECYCLE_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, CREDIT_BOND_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Get, BUDGETS_PATH, Public, Deployment, Some(Scope::BudgetsRead), DeploymentOnly),
    route!(Post, BUDGET_AUTHORIZE_EXPOSURE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, BUDGET_CAPTURE_INVOCATION_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_CUMULATIVE_OPERATION_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_AUTHORIZE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_AUTHORIZE_CUMULATIVE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_CANCEL_CAPTURED_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_CAPTURE_INVOCATION_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_CAPTURE_SPEND_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_RECONCILE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_RELEASE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, STRUCTURED_BUDGET_FENCED_REVERSE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, BUDGET_INCREMENT_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, BUDGET_RECONCILE_SPEND_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, BUDGET_RELEASE_EXPOSURE_PATH, Public, Deployment, Some(Scope::BudgetsWrite), DeploymentOnly),
    route!(Post, ISSUE_CAPABILITY_PATH, Public, Deployment, Some(Scope::CapabilitiesIssue), DeploymentOnly),
    route!(Post, CAPITAL_ALLOCATION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, CAPITAL_INSTRUCTION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Get, CERTIFICATIONS_PATH, Public, Caller, Some(Scope::CertificationsRead), DeploymentOnly),
    route!(Post, CERTIFICATIONS_PATH, Public, Caller, Some(Scope::CertificationsWrite), DeploymentOnly),
    route!(Post, CERTIFICATION_DISCOVERY_CONSUME_PATH, Public, Caller, Some(Scope::CertificationsWrite), DeploymentOnly),
    route!(Post, CERTIFICATION_DISCOVERY_PATH, Public, Caller, Some(Scope::CertificationsWrite), DeploymentOnly),
    route!(Get, CERTIFICATION_DISCOVERY_RESOLVE_PATH, Public, Caller, Some(Scope::CertificationsRead), DeploymentOnly),
    route!(Get, CERTIFICATION_DISCOVERY_SEARCH_PATH, Public, Caller, Some(Scope::CertificationsRead), DeploymentOnly),
    route!(Get, CERTIFICATION_DISCOVERY_TRANSPARENCY_PATH, Public, Caller, Some(Scope::CertificationsRead), DeploymentOnly),
    route!(Get, CERTIFICATION_RESOLVE_PATH, Public, Caller, Some(Scope::CertificationsRead), DeploymentOnly),
    route!(Get, CERTIFICATION_PATH, Public, Caller, Some(Scope::CertificationsRead), DeploymentOnly),
    route!(Post, CERTIFICATION_DISPUTE_PATH, Public, Caller, Some(Scope::CertificationsWrite), DeploymentOnly),
    route!(Post, CERTIFICATION_REVOKE_PATH, Public, Caller, Some(Scope::CertificationsWrite), DeploymentOnly),
    route!(Post, EVIDENCE_EXPORT_PATH, Public, Caller, Some(Scope::EvidenceRead), TenantScoped),
    route!(Post, EVIDENCE_IMPORT_PATH, Public, Caller, Some(Scope::EvidenceWrite), DeploymentOnly),
    route!(Post, CREDIT_FACILITY_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, FEDERATED_ISSUE_PATH, Public, Caller, Some(Scope::FederationWrite), DeploymentOnly),
    route!(Get, FEDERATION_EVIDENCE_SHARES_PATH, Public, Caller, Some(Scope::FederationRead), DeploymentOnly),
    route!(Get, FEDERATION_POLICIES_PATH, Public, Caller, Some(Scope::FederationRead), DeploymentOnly),
    route!(Post, FEDERATION_POLICY_EVALUATE_PATH, Public, Caller, Some(Scope::FederationWrite), DeploymentOnly),
    route!(Delete, FEDERATION_POLICY_PATH, Public, Caller, Some(Scope::FederationWrite), DeploymentOnly),
    route!(Get, FEDERATION_POLICY_PATH, Public, Caller, Some(Scope::FederationRead), DeploymentOnly),
    route!(Put, FEDERATION_POLICY_PATH, Public, Caller, Some(Scope::FederationWrite), DeploymentOnly),
    route!(Get, FEDERATION_PROVIDERS_PATH, Public, Caller, Some(Scope::FederationRead), DeploymentOnly),
    route!(Delete, FEDERATION_PROVIDER_PATH, Public, Caller, Some(Scope::FederationWrite), DeploymentOnly),
    route!(Get, FEDERATION_PROVIDER_PATH, Public, Caller, Some(Scope::FederationRead), DeploymentOnly),
    route!(Put, FEDERATION_PROVIDER_PATH, Public, Caller, Some(Scope::FederationWrite), DeploymentOnly),
    route!(Post, FINDINGS_COLLATERAL_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Post, FINDING_VOLUNTARY_RETRACTION_PATH, Public, FindingSeller, None, NotApplicable),
    route!(Post, FINDING_VERIFIED_FIX_SUBMISSION_PATH, Public, FindingSeller, None, NotApplicable),
    route!(Post, FINDINGS_PROFILES_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Post, FINDINGS_PUBLISH_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Post, FINDINGS_RECIPES_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Get, FINDINGS_SEARCH_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, FINDINGS_SEARCH_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, FINDING_STATUS_INTENTS_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Get, FINDING_STATUS_PROOF_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, FINDING_STATUS_ROOT_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, FINDING_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, FINDING_ACTIVATE_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Get, FINDING_ADMISSION_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, FINDING_CHALLENGES_PATH, Public, FindingBuyerOrCaller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Get, FINDING_CHALLENGE_PATH, Public, FindingBuyerOrCaller, Some(Scope::FindingsRead), DeploymentOnly),
    route!(Post, FINDING_OPERATOR_LIVE_STATUS_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Post, FINDING_PARTICIPATION_PATH, Public, Caller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Get, FINDING_PROOF_BUNDLE_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, FINDING_PURCHASE_PATH, Public, FindingBuyerOrCaller, Some(Scope::FindingsWrite), DeploymentOnly),
    route!(Post, FISCAL_ACTIVATIONS_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Post, FISCAL_APPROVALS_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Post, FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH, Public, Caller, Some(Scope::ReportsRead), TenantScoped),
    route!(Post, FISCAL_MARKETPLACE_PRICE_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Post, FISCAL_PROPOSALS_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Post, FISCAL_PROPOSAL_ADMIT_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Post, FISCAL_PROPOSAL_PREVIEW_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Post, FISCAL_RESOLVE_PATH, Public, Caller, Some(Scope::FiscalWrite), DeploymentOnly),
    route!(Get, FISCAL_RUNTIME_STATUS_PATH, Public, Caller, Some(Scope::FiscalRead), DeploymentOnly),
    route!(Post, INTERNAL_ADMISSION_AUTHORITY_PATH, Internal, Deployment, Some(Scope::AdmissionAuthorityWrite), DeploymentOnly),
    route!(Get, INTERNAL_AUTHORITY_SNAPSHOT_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Get, INTERNAL_AUTHORITY_STATUS_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Get, INTERNAL_BUDGETS_DELTA_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Post, INTERNAL_CLUSTER_PARTITION_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Get, INTERNAL_CLUSTER_SNAPSHOT_PATH, Internal, Peer, Some(Scope::ClusterOpeningsReplicate), NotApplicable),
    route!(Get, INTERNAL_CLUSTER_STATUS_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Get, INTERNAL_LINEAGE_DELTA_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Get, INTERNAL_CHILD_RECEIPTS_DELTA_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Get, INTERNAL_TOOL_RECEIPTS_DELTA_PATH, Internal, Peer, Some(Scope::ClusterOpeningsReplicate), NotApplicable),
    route!(Get, INTERNAL_REVOCATIONS_DELTA_PATH, Internal, Peer, Some(Scope::ClusterReplicate), NotApplicable),
    route!(Post, LIABILITY_CLAIM_ADJUDICATION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_AUTO_BIND_DECISION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_BOUND_COVERAGE_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_PAYOUT_RECEIPT_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_RESPONSE_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_PACKAGE_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_CLAIM_DISPUTE_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_PLACEMENT_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_PRICING_AUTHORITY_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_PROVIDER_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Get, LIABILITY_PROVIDER_RESOLVE_PATH, Public, Caller, Some(Scope::CreditRead), DeploymentOnly),
    route!(Post, LIABILITY_QUOTE_REQUEST_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LIABILITY_QUOTE_RESPONSE_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, LINEAGE_RECORD_PATH, Public, Caller, Some(Scope::LineageWrite), DeploymentOnly),
    route!(Get, LINEAGE_PATH, Public, Caller, Some(Scope::LineageRead), DeploymentOnly),
    route!(Get, LINEAGE_CHAIN_PATH, Public, Caller, Some(Scope::LineageRead), DeploymentOnly),
    route!(Post, METERED_BILLING_RECONCILE_PATH, Public, Deployment, Some(Scope::SettlementWrite), DeploymentOnly),
    route!(Post, PASSPORT_CHALLENGES_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Post, PASSPORT_CHALLENGE_VERIFY_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Post, PASSPORT_ISSUANCE_CREDENTIAL_PATH, Public, WalletHolder, None, NotApplicable),
    route!(Post, PASSPORT_ISSUANCE_OFFERS_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Post, PASSPORT_ISSUANCE_TOKEN_PATH, Public, WalletHolder, None, NotApplicable),
    route!(Post, PASSPORT_OID4VP_REQUESTS_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Get, PASSPORT_STATUSES_PATH, Public, Caller, Some(Scope::PassportRead), DeploymentOnly),
    route!(Post, PASSPORT_STATUSES_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Get, PASSPORT_STATUS_RESOLVE_PATH, Public, Caller, Some(Scope::PassportRead), DeploymentOnly),
    route!(Get, PASSPORT_STATUS_PATH, Public, Caller, Some(Scope::PassportRead), DeploymentOnly),
    route!(Post, PASSPORT_STATUS_REVOKE_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Get, PASSPORT_VERIFIER_POLICIES_PATH, Public, Caller, Some(Scope::PassportRead), DeploymentOnly),
    route!(Delete, PASSPORT_VERIFIER_POLICY_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Get, PASSPORT_VERIFIER_POLICY_PATH, Public, Caller, Some(Scope::PassportRead), DeploymentOnly),
    route!(Put, PASSPORT_VERIFIER_POLICY_PATH, Public, Caller, Some(Scope::PassportWrite), DeploymentOnly),
    route!(Get, PUBLIC_CERTIFICATION_METADATA_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_CERTIFICATION_RESOLVE_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_CERTIFICATION_SEARCH_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_CERTIFICATION_TRANSPARENCY_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_CHALLENGE_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH, Public, Anonymous, None, NotApplicable),
    route!(Post, PUBLIC_PASSPORT_OID4VP_DIRECT_POST_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_OID4VP_LAUNCH_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_OID4VP_REQUEST_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_STATUS_RESOLVE_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_REVOCATION_ROOT_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_PASSPORT_WALLET_EXCHANGE_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_GENERIC_LISTINGS_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, PUBLIC_GENERIC_NAMESPACE_PATH, Public, Anonymous, None, NotApplicable),
    route!(Get, RECEIPT_ANALYTICS_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CHILD_RECEIPTS_PATH, Public, Caller, Some(Scope::ReceiptsRead), TenantScoped),
    route!(Post, CHILD_RECEIPTS_PATH, Public, Deployment, Some(Scope::ReceiptsAppend), DeploymentOnly),
    route!(Get, RECEIPT_QUERY_PATH, Public, Caller, Some(Scope::ReceiptsRead), TenantScoped),
    route!(Post, RECEIPT_QUERY_SNAPSHOT_RECOVERY_PATH, Public, Caller, Some(Scope::ReceiptsAdmin), DeploymentOnly),
    route!(Get, TOOL_RECEIPTS_PATH, Public, Caller, Some(Scope::ReceiptsRead), TenantScoped),
    route!(Post, TOOL_RECEIPTS_PATH, Public, Deployment, Some(Scope::ReceiptsAppend), DeploymentOnly),
    route!(Post, GENERIC_GOVERNANCE_CASE_EVALUATE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, GENERIC_GOVERNANCE_CASE_ISSUE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, GENERIC_GOVERNANCE_CHARTER_ISSUE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, OPEN_MARKET_FEE_SCHEDULE_ISSUE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, OPEN_MARKET_PENALTY_EVALUATE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, OPEN_MARKET_PENALTY_ISSUE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, GENERIC_TRUST_ACTIVATION_EVALUATE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Post, GENERIC_TRUST_ACTIVATION_ISSUE_PATH, Public, Caller, Some(Scope::RegistryWrite), DeploymentOnly),
    route!(Get, AUTHORIZATION_CONTEXT_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, AUTHORIZATION_PROFILE_METADATA_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, AUTHORIZATION_REVIEW_PACK_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, BEHAVIORAL_FEED_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_LOSS_LIFECYCLE_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_LOSS_LIFECYCLE_LIST_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_BOND_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Post, CREDIT_BONDED_EXECUTION_SIMULATION_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_BONDS_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CAPITAL_BOOK_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, COMPTROLLER_SURFACE_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, COST_ATTRIBUTION_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_BACKTEST_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_SCORECARD_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, ECONOMIC_COMPLETION_FLOW_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, ECONOMIC_RECEIPT_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, EXPOSURE_LEDGER_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_FACILITIES_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_FACILITY_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, LIABILITY_CLAIM_WORKFLOW_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, LIABILITY_MARKET_WORKFLOW_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, LIABILITY_PROVIDERS_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, METERED_BILLING_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, OPERATOR_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, CREDIT_PROVIDER_RISK_PACKAGE_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Post, RUNTIME_ATTESTATION_APPRAISAL_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Post, RUNTIME_ATTESTATION_APPRAISAL_RESULT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Post, RUNTIME_ATTESTATION_APPRAISAL_IMPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, SETTLEMENT_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, UNDERWRITING_DECISION_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, UNDERWRITING_DECISIONS_REPORT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Get, UNDERWRITING_INPUT_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Post, UNDERWRITING_SIMULATION_PATH, Public, Caller, Some(Scope::ReportsRead), DeploymentOnly),
    route!(Post, REPUTATION_COMPARE_PATH, Public, Caller, Some(Scope::ReputationWrite), DeploymentOnly),
    route!(Get, LOCAL_REPUTATION_PATH, Public, Caller, Some(Scope::ReputationRead), DeploymentOnly),
    route!(Post, PORTABLE_REPUTATION_EVALUATE_PATH, Public, Caller, Some(Scope::ReputationWrite), DeploymentOnly),
    route!(Post, PORTABLE_NEGATIVE_EVENT_ISSUE_PATH, Public, Caller, Some(Scope::ReputationWrite), DeploymentOnly),
    route!(Post, PORTABLE_REPUTATION_SUMMARY_ISSUE_PATH, Public, Caller, Some(Scope::ReputationWrite), DeploymentOnly),
    route!(Get, REVOCATIONS_PATH, Public, Caller, Some(Scope::RevocationsRead), DeploymentOnly),
    route!(Post, REVOCATIONS_PATH, Public, Caller, Some(Scope::RevocationsWrite), DeploymentOnly),
    route!(Post, SETTLEMENT_RECONCILE_PATH, Public, Deployment, Some(Scope::SettlementWrite), DeploymentOnly),
    route!(Post, UNDERWRITING_APPEALS_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, UNDERWRITING_APPEAL_RESOLVE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
    route!(Post, UNDERWRITING_DECISION_ISSUE_PATH, Public, Caller, Some(Scope::CreditWrite), DeploymentOnly),
];

/// What the middleware established for a request. Handlers read it from the
/// request extensions and recheck the scope they need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteGrant {
    /// The route keeps its own non-credential authentication.
    Unchanged,
    Caller(AuthenticatedCaller),
    Peer(AuthenticatedPeer),
}

/// The verified peer of a peer route, holding `scope`. A handler reached
/// without the route table middleware's peer grant, or with a grant whose
/// peer lacks `scope`, refuses.
pub(crate) fn require_peer_grant(
    grant: Option<&axum::Extension<RouteGrant>>,
    scope: Scope,
) -> Result<&AuthenticatedPeer, Response> {
    match grant {
        Some(axum::Extension(RouteGrant::Peer(peer))) if peer.scopes.contains(&scope) => Ok(peer),
        Some(axum::Extension(RouteGrant::Peer(_))) => {
            Err(PeerAuthError::MissingScope(scope).into_response())
        }
        _ => Err(PeerAuthError::Unauthenticated.into_response()),
    }
}

/// Enforces the route table for one listener.
pub struct RouteAuthorizer {
    listener: Listener,
    access: Arc<TrustAccess>,
    clock: Arc<dyn Clock>,
    nonces: PeerNonceCache,
    rules: HashMap<(RouteMethod, &'static str), &'static RouteRule>,
}

impl std::fmt::Debug for RouteAuthorizer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteAuthorizer")
            .field("listener", &self.listener)
            .field("deployment", &self.access.credentials().deployment())
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl RouteAuthorizer {
    /// The peer nonce cache starts at the receiver time read here, so a peer
    /// request issued at or before that time plus
    /// `CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS` refuses as stale.
    #[must_use]
    pub fn new(listener: Listener, access: Arc<TrustAccess>, clock: Arc<dyn Clock>) -> Self {
        let nonces = PeerNonceCache::new(unix_secs(clock.as_ref()), access.peers().iter().count());
        Self::with_nonce_cache(listener, access, clock, nonces)
    }

    /// As [`RouteAuthorizer::new`], with the given peer nonce cache.
    #[must_use]
    pub fn with_nonce_cache(
        listener: Listener,
        access: Arc<TrustAccess>,
        clock: Arc<dyn Clock>,
        nonces: PeerNonceCache,
    ) -> Self {
        let rules = ROUTE_TABLE
            .iter()
            .map(|rule| ((rule.method, rule.path), rule))
            .collect();
        Self {
            listener,
            access,
            clock,
            nonces,
            rules,
        }
    }

    #[must_use]
    pub const fn listener(&self) -> Listener {
        self.listener
    }

    fn rule(&self, method: &Method, matched_path: Option<&str>) -> Option<&'static RouteRule> {
        matched_path
            .zip(RouteMethod::from_method(method))
            .and_then(|(matched, method)| self.rules.get(&(method, matched)))
            .copied()
            .filter(|rule| rule.listener == self.listener)
    }

    fn serves_path(&self, matched_path: Option<&str>) -> bool {
        matched_path.is_some_and(|matched| {
            ROUTE_TABLE
                .iter()
                .any(|rule| rule.path == matched && rule.listener == self.listener)
        })
    }

    /// Authorize one request. `matched_path` is the router's matched route
    /// pattern; `path`, `query` and `body` are the concrete request parts a
    /// peer signature covers.
    pub fn authorize(
        &self,
        method: &Method,
        matched_path: Option<&str>,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<RouteGrant, Response> {
        let rule = match self.rule(method, matched_path) {
            Some(rule) => rule,
            None if self.serves_path(matched_path) => return Err(method_not_allowed()),
            None => return Err(route_absent()),
        };
        match rule.credential {
            RouteCredential::Anonymous
            | RouteCredential::FindingSeller
            | RouteCredential::WalletHolder => Ok(RouteGrant::Unchanged),
            RouteCredential::Caller | RouteCredential::Deployment => self
                .authorize_caller(rule, headers)
                .map(RouteGrant::Caller)
                .map_err(CallerAuthError::into_response),
            RouteCredential::FindingBuyerOrCaller => {
                if carries_peer_authentication(headers) {
                    return Err(CallerAuthError::PeerAuthenticationOnCallerRoute.into_response());
                }
                if self.access.credentials().authenticate(headers).is_err() {
                    return Ok(RouteGrant::Unchanged);
                }
                self.authorize_caller(rule, headers)
                    .map(RouteGrant::Caller)
                    .map_err(CallerAuthError::into_response)
            }
            RouteCredential::Peer => self
                .authorize_peer(rule, method, path, query, headers, body)
                .map(RouteGrant::Peer)
                .map_err(PeerAuthError::into_response),
        }
    }

    fn authorize_caller(
        &self,
        rule: &RouteRule,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedCaller, CallerAuthError> {
        if carries_peer_authentication(headers) {
            return Err(CallerAuthError::PeerAuthenticationOnCallerRoute);
        }
        let scope = rule.scope.ok_or(CallerAuthError::Unauthenticated)?;
        let caller = self.access.credentials().validate_caller(headers, scope)?;
        if rule.credential == RouteCredential::Deployment
            && caller.kind != CredentialKind::Deployment
        {
            return Err(CallerAuthError::DeploymentCredentialRequired);
        }
        match (rule.tenant, &caller.tenant_authority) {
            (TenantRule::TenantScoped, _) | (_, TenantAuthority::Deployment) => Ok(caller),
            (
                TenantRule::DeploymentOnly | TenantRule::NotApplicable,
                TenantAuthority::Tenant(_),
            ) => Err(CallerAuthError::TenantCredentialOnDeploymentRoute),
        }
    }

    fn authorize_peer(
        &self,
        rule: &RouteRule,
        method: &Method,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<AuthenticatedPeer, PeerAuthError> {
        self.precheck_peer(headers)?;
        let scope = rule.scope.ok_or(PeerAuthError::Unauthenticated)?;
        let now = unix_secs(self.clock.as_ref()).ok_or(PeerAuthError::ClockUnavailable)?;
        let target = PeerRequestTarget {
            method: method.as_str(),
            path,
            query,
            body,
        };
        self.access
            .peers()
            .verify(headers, &target, now, scope, &self.nonces)
    }

    /// The checks a peer row runs before its body is read: no bearer
    /// credential, well-formed authentication headers and a pinned node id.
    fn precheck_peer(&self, headers: &HeaderMap) -> Result<(), PeerAuthError> {
        if headers.contains_key(AUTHORIZATION) {
            return Err(PeerAuthError::CallerCredentialOnPeerRoute);
        }
        self.access.peers().precheck(headers)
    }
}

fn unix_secs(clock: &dyn Clock) -> Option<i64> {
    clock
        .unix_millis()
        .ok()
        .and_then(|now| i64::try_from(now.as_secs()).ok())
}

fn carries_peer_authentication(headers: &HeaderMap) -> bool {
    [
        CLUSTER_NODE_ID_HEADER,
        CLUSTER_AUTH_ISSUED_AT_HEADER,
        CLUSTER_AUTH_SIGNATURE_HEADER,
        CLUSTER_AUTH_TERM_HEADER,
        CLUSTER_AUTH_NONCE_HEADER,
        CLUSTER_AUTH_BODY_SHA256_HEADER,
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

fn method_not_allowed() -> Response {
    plain_http_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method is not served on this trust-control route",
    )
}

fn route_absent() -> Response {
    plain_http_error(
        StatusCode::NOT_FOUND,
        "route is not served on this trust-control listener",
    )
}

/// Middleware for a listener's whole router (`Router::layer`): a `/v1`
/// request that matched no route refuses as an absent route, so no fallback
/// (such as the dashboard files) answers an API path.
pub async fn refuse_unrouted_api_path(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let api_path = path == "/v1" || path.starts_with("/v1/");
    if api_path && request.extensions().get::<MatchedPath>().is_none() {
        return route_absent();
    }
    next.run(request).await
}

/// The matched route pattern relative to any outer nest. Axum includes every
/// outer nest prefix in `MatchedPath`; `NestedPath` is framework-owned route
/// context, so the prefix is removed without trusting request URI text.
fn relative_matched_path(request: &Request) -> Result<Option<String>, Response> {
    let Some(matched) = request.extensions().get::<MatchedPath>() else {
        return Ok(None);
    };
    match request.extensions().get::<NestedPath>() {
        None => Ok(Some(matched.as_str().to_string())),
        Some(prefix) => matched
            .as_str()
            .strip_prefix(prefix.as_str().trim_end_matches('/'))
            .map(|relative| Some(relative.to_string()))
            .ok_or_else(route_absent),
    }
}

/// Largest request body a peer route accepts; the body is buffered so the
/// signature can bind its digest.
pub const PEER_ROUTE_MAX_BODY_BYTES: usize = 64 * 1024;

/// Middleware enforcing the route table. Mount it with `route_layer` so the
/// matched route is known; the grant is inserted into the request extensions.
/// A peer row reads its body only after the header precheck passes.
pub async fn authorize_route(
    State(authorizer): State<Arc<RouteAuthorizer>>,
    request: Request,
    next: Next,
) -> Response {
    let matched = match relative_matched_path(&request) {
        Ok(matched) => matched,
        Err(response) => return response,
    };
    let (mut parts, body) = request.into_parts();
    let peer_route = authorizer
        .rule(&parts.method, matched.as_deref())
        .is_some_and(|rule| rule.credential == RouteCredential::Peer);
    let (body, signed_body) = if peer_route {
        if let Err(error) = authorizer.precheck_peer(&parts.headers) {
            return error.into_response();
        }
        match axum::body::to_bytes(body, PEER_ROUTE_MAX_BODY_BYTES).await {
            Ok(bytes) => (Body::from(bytes.clone()), bytes),
            Err(_) => {
                return plain_http_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "cluster peer request body exceeds its bound",
                );
            }
        }
    } else {
        (body, Bytes::new())
    };
    let grant = authorizer.authorize(
        &parts.method,
        matched.as_deref(),
        parts.uri.path(),
        parts.uri.query().unwrap_or_default(),
        &parts.headers,
        &signed_body,
    );
    match grant {
        Ok(grant) => {
            parts.extensions.insert(grant);
            next.run(Request::from_parts(parts, body)).await
        }
        Err(response) => response,
    }
}

#[cfg(test)]
#[path = "route_authorization_tests.rs"]
mod tests;
