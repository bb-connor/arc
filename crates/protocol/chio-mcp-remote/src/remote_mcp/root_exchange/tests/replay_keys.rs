//! Replay keys refuse parts that would make their digest ambiguous, and a
//! replay store refuses with a closed error that carries no backend text.

use super::*;
use crate::root_exchange::{ReplayKeyError, ReplayNamespace};
use chio_core::capability::anchor::AnchorKind;

const ID_JAG: ReplayNamespace = ReplayNamespace::Assertion(AnchorKind::OauthIdJag);
const CLIENT: ReplayNamespace = ReplayNamespace::ClientAssertion;

#[test]
fn a_nul_in_either_part_refuses_the_key_with_its_oauth_answer() {
    let cases = [
        (
            ID_JAG,
            "issuer\0a",
            "b",
            ReplayKeyError::IssuerContainsNul(ID_JAG),
        ),
        (
            ID_JAG,
            "issuer",
            "a\0b",
            ReplayKeyError::IdContainsNul(ID_JAG),
        ),
        (
            CLIENT,
            CLIENT_ID,
            "jti\u{0}1",
            ReplayKeyError::IdContainsNul(CLIENT),
        ),
    ];
    for (namespace, issuer, id, refusal) in cases {
        assert_eq!(ReplayKey::new(namespace, issuer, id), Err(refusal));
        let expected = if namespace == CLIENT {
            OAuthErrorCode::InvalidClient
        } else {
            OAuthErrorCode::InvalidGrant
        };
        assert_eq!(RootExchangeError::from(refusal).oauth_error(), expected);
    }
    let key = ReplayKey::new(ID_JAG, "issuer", "jti-1").unwrap();
    assert_eq!(
        (key.namespace(), key.issuer(), key.id()),
        (ID_JAG, "issuer", "jti-1")
    );
}

struct RefusingReplay(ReplayStoreError);

impl ExchangeReplayStore for RefusingReplay {
    fn bind(&self, _: &ReplayKey, _: u64, _: u64) -> Result<ReplayBinding, ReplayStoreError> {
        Err(self.0)
    }
}

#[tokio::test]
async fn a_replay_store_refusal_keeps_its_closed_kind_and_no_detail() {
    let harness = Harness::new();
    let body = jwt_bearer_body(&id_jag(), &client_assertion(&client_assertion_claims()));
    let grant = IdJagGrant::parse(&body, None).unwrap();
    for refusal in [
        ReplayStoreError::Unavailable,
        ReplayStoreError::Busy,
        ReplayStoreError::Corrupt,
    ] {
        let services = ExchangeServices {
            keys: &harness.keys,
            replay: &RefusingReplay(refusal),
            entropy: &harness.entropy,
        };
        let error = harness
            .exchange
            .exchange_id_jag(&grant, None, NOW, services)
            .await
            .unwrap_err();
        assert_eq!(error, RootExchangeError::ReplayStore(refusal));
        assert_eq!(error.oauth_error(), OAuthErrorCode::TemporarilyUnavailable);
        assert_eq!(error.client_description(), None);
    }
}
