use serde_json::{json, Value};

fn tool(name: &str, description: &str, properties: Value) -> Value {
    let required: Vec<_> = properties
        .as_object()
        .into_iter()
        .flat_map(|o| o.keys())
        .collect();
    json!({"name":name,"description":description,
        "inputSchema":{"type":"object","additionalProperties":false,
        "properties":properties,"required":required}})
}

pub fn definitions(mode: &str) -> Vec<Value> {
    if mode == "operator" {
        return vec![
            tool("assign", "Claim a bounded batch of due jobs for a capability. Keep the same operation key when recovering; an unknown outcome does not authorize another claim.",
                json!({"owner_capability_sha256":{"type":"string"},
                    "lease_seconds":{"type":"integer","minimum":1,"maximum":3600},
                    "limit":{"type":"integer","minimum":1,"maximum":16}})),
            tool("release", "Return a matching lease to the pending queue. Its next claim receives a higher fence. Keep a stable operation key.",
                json!({"job_id":{"type":"string"},"owner_capability_sha256":{"type":"string"},
                    "expected_fence":{"type":"integer","minimum":1}})),
            tool("inspect", "Inspect the retained job, owner, fence and result. This observation does not authorize retry of an uncertain effect.",
                json!({"job_id":{"type":"string"}})),
        ];
    }
    vec![
        tool("task", "Read one assigned job's evidence and current lease fence.",
            json!({"job_id":{"type":"string"}})),
        tool("complete", "Commit your result under the observed lease fence. A superseded result means stop; already_completed means the resource retained that result, not that this call committed it.",
            json!({"job_id":{"type":"string"},"expected_fence":{"type":"integer","minimum":1},
                "result":{"type":"object"}})),
        tool("renew", "Renew your current lease without changing its fence. Stop if superseded.",
            json!({"job_id":{"type":"string"},"expected_fence":{"type":"integer","minimum":1},
                "lease_seconds":{"type":"integer","minimum":1,"maximum":3600}})),
    ]
}
