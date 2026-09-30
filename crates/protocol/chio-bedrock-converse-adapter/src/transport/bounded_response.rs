//! Bound and validate original response bytes before the SDK's JSON decoder runs.
use std::pin::Pin;
use std::task::{Context, Poll};

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::{
    context::BeforeDeserializationInterceptorContextMut, Intercept,
};
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::{body::SdkBody, config_bag::ConfigBag};
use bytes::Bytes;
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use chio_provider_adapter_core::input::MAX_DOCUMENT_BYTES;
use http_body::{Body, Frame};

#[derive(Debug)]
pub(super) struct ValidateResponse;

impl Intercept for ValidateResponse {
    fn name(&self) -> &'static str {
        "ChioBoundedConverseResponse"
    }

    fn modify_before_deserialization(
        &self,
        context: &mut BeforeDeserializationInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let body = context.response_mut().body_mut();
        let inner = std::mem::replace(body, SdkBody::taken());
        *body = SdkBody::from_body_1_x(ValidatedBody::new(inner));
        Ok(())
    }
}

struct ValidatedBody {
    inner: SdkBody,
    bytes: Vec<u8>,
    trailers: Option<Frame<Bytes>>,
    finished: bool,
}

impl ValidatedBody {
    fn new(inner: SdkBody) -> Self {
        Self {
            inner,
            bytes: Vec::new(),
            trailers: None,
            finished: false,
        }
    }
}

impl Body for ValidatedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.finished {
            return Poll::Ready(self.trailers.take().map(Ok));
        }
        loop {
            match std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if data.len() > MAX_DOCUMENT_BYTES.saturating_sub(self.bytes.len()) {
                            self.finished = true;
                            let bytes = self.bytes.len().saturating_add(data.len());
                            self.bytes.clear();
                            self.trailers = None;
                            return Poll::Ready(Some(Err(Box::new(
                                UntrustedJsonError::TooLarge {
                                    bytes,
                                    bound: MAX_DOCUMENT_BYTES,
                                },
                            ))));
                        }
                        self.bytes.extend_from_slice(&data);
                    }
                    Err(frame) => self.trailers = Some(frame),
                },
                Some(Err(error)) => {
                    self.finished = true;
                    self.bytes.clear();
                    self.trailers = None;
                    return Poll::Ready(Some(Err(error)));
                }
                None => {
                    self.finished = true;
                    if let Err(error) =
                        UntrustedJsonText::from_wire(&self.bytes, MAX_DOCUMENT_BYTES)
                            .and_then(|text| text.canonicalize())
                    {
                        self.bytes.clear();
                        self.trailers = None;
                        return Poll::Ready(Some(Err(Box::new(error))));
                    }
                    return Poll::Ready(Some(Ok(Frame::data(
                        std::mem::take(&mut self.bytes).into(),
                    ))));
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    async fn first(bytes: Vec<u8>) -> Result<Frame<Bytes>, BoxError> {
        let mut body = ValidatedBody::new(SdkBody::from(bytes));
        std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn validates_original_bytes_before_exposing_any_data_to_sdk() {
        let valid = br#"{ "input": {"a":1} }"#.to_vec();
        assert_eq!(
            first(valid.clone()).await.unwrap().into_data().unwrap(),
            valid
        );
        for bytes in [
            br#"{"input":{"a":1,"a":2}}"#.to_vec(),
            vec![b' '; MAX_DOCUMENT_BYTES + 1],
        ] {
            let error = first(bytes).await.unwrap_err();
            assert!(error.downcast_ref::<UntrustedJsonError>().is_some());
        }
    }
}
