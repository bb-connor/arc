use super::*;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);
impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                let _ = write!(self.0, "{}={value:?};", field.name());
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        if let Ok(mut events) = self.0.lock() {
            events.push(fields.0);
        }
    }
}

#[test]
fn openapi_diagnostic_uses_actual_route_producer_and_redacted_local_sink(
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = Capture::default();
    let error = tracing::subscriber::with_default(capture.clone(), || {
        ProtectProxy::build_routes(r#"{"openapi":"3.1.0"}"#, false)
    })
    .err()
    .ok_or("missing info accepted")?;
    assert!(matches!(
        &error,
        ProtectError::SpecParse(chio_openapi::OpenApiError::MissingField(_))
    ));
    assert!(!format!("{error} {error:?}").contains("info"));
    let recorded = capture.0.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(recorded.len(), 1, "missing operator parse diagnostic");
    assert!(recorded[0].contains("missing_field"));
    assert!(recorded[0].contains("info"));
    drop(recorded);

    let capture = Capture::default();
    let secret = "sk_live_abcdefghijklmnopqrstuvwx";
    let document = serde_json::json!({"openapi":"3.1.0", "info":{"title":"test","version":"1"}, "paths":{
        "/test":{"get":{"responses":{"200":{"description":"ok", "$ref":format!("#/components/{secret}\nnext")}}}}
    }}).to_string();
    let error = tracing::subscriber::with_default(capture.clone(), || {
        ProtectProxy::build_routes(&document, false)
    })
    .err()
    .ok_or("bad reference accepted")?;
    assert!(!format!("{error} {error:?}").contains(secret));
    let recorded = capture.0.lock().map_err(|_| "capture poisoned")?;
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].contains("unresolved_ref"));
    assert!(!recorded[0].contains(secret));
    assert!(!recorded[0].contains('\n'));
    assert!(recorded[0].len() <= 4096);
    Ok(())
}
