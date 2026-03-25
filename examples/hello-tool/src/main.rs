//! # hello-tool
//!
//! A small native PACT service built with the higher-level authoring helpers in
//! `pact-mcp-adapter`. This example keeps the runtime concepts visible without
//! forcing the user to hand-write every kernel trait implementation.

use pact_core::crypto::Keypair;
use pact_core::{PromptMessage, ResourceContent};
use pact_kernel::{PromptProvider, ResourceProvider, ToolServerConnection, ToolServerEvent};
use pact_mcp_adapter::{NativePactServiceBuilder, NativePrompt, NativeResource, NativeTool};

fn build_service(public_key_hex: String) -> pact_mcp_adapter::NativePactService {
    NativePactServiceBuilder::new("srv-hello", public_key_hex)
        .server_name("Hello Tool Server")
        .server_version("0.1.0")
        .server_description("A tiny native PACT service that exposes a tool, resource, prompt, and priced manifest")
        .tool(
            NativeTool::new(
                "greet",
                "Returns a personalized greeting",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The name to greet"
                        }
                    },
                    "required": ["name"]
                }),
            )
            .output_schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "greeting": { "type": "string" }
                }
            }))
            .read_only()
            .per_invocation_price(25, "USD")
            .latency_hint(pact_manifest::LatencyHint::Instant),
            |arguments| {
                let name = arguments
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("stranger");
                Ok(serde_json::json!({
                    "greeting": format!("Hello, {name}! This greeting was served by a native PACT service.")
                }))
            },
        )
        .static_resource(
            NativeResource::new("memory://hello/template", "Greeting Template")
                .description("A static greeting template used by the hello example")
                .mime_type("text/plain"),
            vec![ResourceContent {
                uri: "memory://hello/template".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("Hello, {name}! This greeting was served by a native PACT service.".to_string()),
                blob: None,
                annotations: None,
            }],
        )
        .static_prompt(
            NativePrompt::new("compose_greeting")
                .description("Creates a user prompt that asks for a polite greeting"),
            pact_core::PromptResult {
                description: Some("Greeting composition prompt".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: serde_json::json!({
                        "type": "text",
                        "text": "Compose a short, polite greeting for Ada."
                    }),
                }],
            },
        )
        .build()
        .expect("build native PACT service")
}

fn main() {
    println!("=== PACT hello-tool example ===\n");

    let server_kp = Keypair::generate();
    let service = build_service(server_kp.public_key().to_hex());

    println!("Native manifest:");
    println!(
        "  Server: {} ({})",
        service.manifest().name,
        service.server_id()
    );
    for tool in &service.manifest().tools {
        println!("  Tool: {} - {}", tool.name, tool.description);
        if let Some(pricing) = &tool.pricing {
            let quoted = pricing
                .unit_price
                .as_ref()
                .map(|amount| format!("{} {}", amount.units, amount.currency))
                .or_else(|| {
                    pricing
                        .base_price
                        .as_ref()
                        .map(|amount| format!("{} {}", amount.units, amount.currency))
                })
                .unwrap_or_else(|| "n/a".to_string());
            println!(
                "    Pricing: {:?} ({quoted}{})",
                pricing.pricing_model,
                pricing
                    .billing_unit
                    .as_deref()
                    .map(|unit| format!(" per {unit}"))
                    .unwrap_or_default()
            );
        }
    }

    match pact_manifest::sign_manifest(service.manifest(), &server_kp) {
        Ok(_signed) => println!("\nManifest signed successfully."),
        Err(error) => {
            eprintln!("\nFailed to sign manifest: {error}");
            std::process::exit(1);
        }
    }

    let greeting = service
        .invoke("greet", serde_json::json!({ "name": "World" }), None)
        .expect("invoke greet");
    println!("\nTool invocation:");
    println!("  Input:  {{\"name\":\"World\"}}");
    println!("  Output: {greeting}");

    let resource = service
        .read_resource("memory://hello/template")
        .expect("read resource")
        .expect("resource exists");
    println!("\nResource read:");
    println!("  URI: {}", resource[0].uri);
    println!("  Text: {}", resource[0].text.as_deref().unwrap_or(""));

    let prompt = service
        .get_prompt("compose_greeting", serde_json::json!({}))
        .expect("get prompt")
        .expect("prompt exists");
    println!("\nPrompt:");
    println!(
        "  First message: {}",
        prompt.messages[0].content["text"].as_str().unwrap_or("")
    );

    service.emit_event(ToolServerEvent::ResourcesListChanged);
    let events = service.drain_events().expect("drain events");
    println!("\nLate events:");
    println!("  Count: {}", events.len());

    println!("\n=== done ===");
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::build_service;
    use pact_manifest::PricingModel;

    #[test]
    fn hello_tool_manifest_advertises_pricing_metadata() {
        let service = build_service(
            "7b0f6f631f6e66207140ead0b6b2e9418916d2c4b3c7448ba5f7ed27f5c8d038".to_string(),
        );
        let tool = &service.manifest().tools[0];

        assert_eq!(tool.name, "greet");
        assert_eq!(
            tool.pricing.as_ref().map(|pricing| pricing.pricing_model),
            Some(PricingModel::PerInvocation)
        );
        assert_eq!(
            tool.pricing
                .as_ref()
                .and_then(|pricing| pricing.unit_price.as_ref())
                .map(|amount| (amount.units, amount.currency.as_str())),
            Some((25, "USD"))
        );
        assert_eq!(
            tool.pricing
                .as_ref()
                .and_then(|pricing| pricing.billing_unit.as_deref()),
            Some("invocation")
        );
    }
}
