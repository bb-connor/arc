use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;
use serde::Serialize;

use crate::{canonicalize_federated_issuer, enterprise_provider_kind_name, SessionAuthMethod};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub(crate) enum RegistryDigestScope {
    Globals,
    OAuth {
        issuer: Option<String>,
        provider_kind: Option<String>,
        selected_provider: Option<String>,
    },
}

impl RegistryDigestScope {
    pub(crate) fn for_auth(method: &SessionAuthMethod) -> Self {
        match method {
            SessionAuthMethod::OAuthBearer {
                issuer,
                enterprise_identity,
                ..
            } => Self::OAuth {
                issuer: issuer.as_deref().map(canonicalize_federated_issuer),
                provider_kind: enterprise_identity
                    .as_ref()
                    .map(|identity| identity.provider_kind.clone()),
                selected_provider: enterprise_identity
                    .as_ref()
                    .and_then(|identity| identity.provider_record_id.clone()),
            },
            _ => Self::Globals,
        }
    }

    pub(super) fn selected_provider(&self) -> Option<&str> {
        match self {
            Self::Globals => None,
            Self::OAuth {
                selected_provider, ..
            } => selected_provider.as_deref(),
        }
    }

    pub(super) fn retain_cohort(&self, registry: &mut EnterpriseProviderRegistry) {
        registry.providers.retain(|id, provider| match self {
            Self::Globals => false,
            Self::OAuth {
                issuer,
                provider_kind,
                selected_provider,
            } => {
                selected_provider.as_deref() == Some(id.as_str())
                    || (provider_kind
                        .as_deref()
                        .is_none_or(|kind| kind == enterprise_provider_kind_name(&provider.kind))
                        && issuer.as_ref().is_none_or(|issuer| {
                            provider
                                .issuer
                                .as_deref()
                                .map(canonicalize_federated_issuer)
                                .as_ref()
                                == Some(issuer)
                        }))
            }
        });
    }
}
