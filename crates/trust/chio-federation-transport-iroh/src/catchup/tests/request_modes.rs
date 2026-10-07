use super::*;
use crate::admission::DirectoryGate;
use iroh::endpoint::presets::Minimal;
use iroh::protocol::Router;
use iroh::{EndpointAddr, TransportAddr};
use iroh_blobs::protocol::{ChunkRangesSeq, PushRequest};
use iroh_blobs::provider::events::{EventMask, EventSender, RequestMode};
use std::time::Duration;

#[derive(Clone, Copy)]
enum ReceiverMode {
    ProductionDefault,
    ReadOnly,
    PushEnabled,
}

async fn bind_endpoint(seed: u8, directory: Arc<VerifiedDirectory>) -> Endpoint {
    Endpoint::builder(Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .hooks(DirectoryGate::new(directory))
        .bind_addr("127.0.0.1:0")
        .expect("loopback address parses")
        .bind()
        .await
        .expect("endpoint binds")
}

async fn exercise_request_mode(mode: ReceiverMode) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let receiver_dir =
            chio_test_support::private_tempdir().expect("private receiver directory");
        let sender_dir = chio_test_support::private_tempdir().expect("private sender directory");
        let receiver_directory = issuer_signed_directory(91, "oracle-a", SEED_A);
        let sender_directory = issuer_signed_directory(90, "oracle-a", SEED_A);
        let receiver_endpoint = bind_endpoint(90, Arc::clone(&receiver_directory)).await;
        let sender_endpoint = bind_endpoint(91, Arc::clone(&sender_directory)).await;
        let receiver = BlobCatchupClient::load(
            receiver_dir.path(),
            receiver_endpoint.clone(),
            receiver_directory,
        )
        .await
        .expect("receiver store loads");
        let sender = BlobCatchupClient::load(
            sender_dir.path(),
            sender_endpoint,
            Arc::clone(&sender_directory),
        )
        .await
        .expect("sender store loads");
        let protocol = match mode {
            ReceiverMode::ProductionDefault => receiver.blobs_protocol(),
            ReceiverMode::ReadOnly => BlobsProtocol::new(
                receiver.store.as_ref(),
                Some(EventSender::DEFAULT.tracing(EventMask::ALL_READONLY)),
            ),
            ReceiverMode::PushEnabled => BlobsProtocol::new(
                receiver.store.as_ref(),
                Some(EventSender::DEFAULT.tracing(EventMask {
                    push: RequestMode::None,
                    ..EventMask::DEFAULT
                })),
            ),
        };
        let router = Router::builder(receiver_endpoint)
            .accept(iroh_blobs::ALPN, protocol)
            .spawn();
        let address = EndpointAddr::from_parts(
            router.endpoint().id(),
            router
                .endpoint()
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        );
        let connection = sender
            .endpoint
            .connect(address, iroh_blobs::ALPN)
            .await
            .expect("issuer-admitted peer connects");
        let oracle = signer("oracle-a", SEED_A);
        let root = signed_root(&oracle, 5);
        let root_hash = receiver
            .publish_signed_root(&root)
            .await
            .expect("root publishes");
        sender
            .store
            .remote()
            .fetch(connection.clone(), root_hash)
            .await
            .expect("legitimate signed-root transfer succeeds");
        let bytes = sender
            .store
            .blobs()
            .get_bytes(root_hash)
            .await
            .expect("root arrives");
        let pinned = resolve_pinned_signer(&sender_directory, "oracle-a", router.endpoint().id())
            .expect("issuer pins receiving endpoint");
        assert_eq!(
            decode_and_verify_root(&bytes, root_hash, pinned).unwrap(),
            root
        );

        let pushed_bytes = bytes::Bytes::from(vec![0xa5; 64 * 1024]);
        let pushed = sender
            .store
            .blobs()
            .add_bytes(pushed_bytes.clone())
            .await
            .expect("push source is stored");
        assert_eq!(
            receiver.store.blobs().status(pushed.hash).await.unwrap(),
            BlobStatus::NotFound
        );
        let push_result = sender
            .store
            .remote()
            .execute_push(
                connection.clone(),
                PushRequest::new(pushed.hash, ChunkRangesSeq::root()),
            )
            .await;
        // The push protocol does not acknowledge remote authorization. Keep the
        // connection alive and observe the actual receiver, with an enabled-push
        // positive control and a separate read over the same connection below.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = receiver.store.blobs().status(pushed.hash).await.unwrap();
        let received_push = if matches!(status, BlobStatus::Complete { .. }) {
            Some(receiver.store.blobs().get_bytes(pushed.hash).await.unwrap())
        } else {
            None
        };
        let next_root = signed_root(&oracle, 6);
        let next_hash = receiver.publish_signed_root(&next_root).await.unwrap();
        sender
            .store
            .remote()
            .fetch(connection.clone(), next_hash)
            .await
            .expect("fresh read still succeeds after the push attempt");
        let next_bytes = sender.store.blobs().get_bytes(next_hash).await.unwrap();
        assert_eq!(
            decode_and_verify_root(&next_bytes, next_hash, pinned).unwrap(),
            next_root
        );
        // The receiver protocol owns store shutdown through the router.
        router.shutdown().await.expect("receiver router shuts down");
        sender.endpoint.close().await;
        sender
            .store
            .as_ref()
            .shutdown()
            .await
            .expect("sender store shuts down");

        match mode {
            ReceiverMode::ProductionDefault | ReceiverMode::ReadOnly => {
                assert_eq!(
                    status,
                    BlobStatus::NotFound,
                    "disabled push mutated the receiver"
                );
                assert!(received_push.is_none());
            }
            ReceiverMode::PushEnabled => {
                assert!(push_result.is_ok(), "explicit push failed: {push_result:?}");
                assert_eq!(status, BlobStatus::Complete { size: 64 * 1024 });
                assert_eq!(received_push, Some(pushed_bytes));
            }
        }
    })
    .await
    .expect("request-permission exercise completes before timeout");
}

#[tokio::test]
async fn production_catchup_protocol_rejects_unsolicited_push() {
    exercise_request_mode(ReceiverMode::ProductionDefault).await;
}

#[tokio::test]
async fn readonly_catchup_protocol_rejects_unsolicited_push() {
    exercise_request_mode(ReceiverMode::ReadOnly).await;
}

#[tokio::test]
async fn explicit_push_permission_preserves_transfer() {
    exercise_request_mode(ReceiverMode::PushEnabled).await;
}
