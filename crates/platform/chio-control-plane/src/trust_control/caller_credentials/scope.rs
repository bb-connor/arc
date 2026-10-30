macro_rules! scopes {
    ($($variant:ident => $name:literal,)+) => {
        /// The closed trust-control scope set. A name outside it never parses.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Scope {
            $($variant,)+
        }

        impl Scope {
            pub const ALL: &'static [Scope] = &[$(Scope::$variant,)+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Scope::$variant => $name,)+
                }
            }

            #[must_use]
            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $($name => Some(Scope::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

scopes! {
    AdminEmergency => "admin:emergency",
    AdmissionAuthorityWrite => "admission-authority:write",
    AttestationWrite => "attestation:write",
    AuthorityAdmin => "authority:admin",
    AuthorityRead => "authority:read",
    BudgetsRead => "budgets:read",
    BudgetsWrite => "budgets:write",
    CapabilitiesIssue => "capabilities:issue",
    CertificationsRead => "certifications:read",
    CertificationsWrite => "certifications:write",
    ClusterReplicate => "cluster:replicate",
    ClusterOpeningsReplicate => "cluster-openings:replicate",
    CreditRead => "credit:read",
    CreditWrite => "credit:write",
    EvidenceRead => "evidence:read",
    EvidenceWrite => "evidence:write",
    FederationRead => "federation:read",
    FederationWrite => "federation:write",
    FindingsRead => "findings:read",
    FindingsWrite => "findings:write",
    FiscalRead => "fiscal:read",
    FiscalWrite => "fiscal:write",
    LineageRead => "lineage:read",
    LineageWrite => "lineage:write",
    MetricsRead => "metrics:read",
    PassportRead => "passport:read",
    PassportWrite => "passport:write",
    ReceiptOpeningsErase => "receipt-openings:erase",
    ReceiptOpeningsRead => "receipt-openings:read",
    ReceiptsAdmin => "receipts:admin",
    ReceiptsAppend => "receipts:append",
    ReceiptsRead => "receipts:read",
    RegistryWrite => "registry:write",
    ReportsRead => "reports:read",
    ReputationRead => "reputation:read",
    ReputationWrite => "reputation:write",
    RevocationsRead => "revocations:read",
    RootExchangeSign => "root-exchange:sign",
    RevocationsWrite => "revocations:write",
    ScimWrite => "scim:write",
    SettlementWrite => "settlement:write",
}

impl Scope {
    /// Cluster scopes belong only to pinned peers, never to caller credentials.
    #[must_use]
    pub const fn is_cluster(self) -> bool {
        matches!(
            self,
            Scope::ClusterReplicate | Scope::ClusterOpeningsReplicate
        )
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
