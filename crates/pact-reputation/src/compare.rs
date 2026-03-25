fn compute_history_depth(
    receipts: &[&PactReceipt],
    config: &ReputationConfig,
) -> HistoryDepthMetrics {
    if receipts.is_empty() {
        return HistoryDepthMetrics {
            score: MetricValue::Unknown,
            receipt_count: 0,
            active_days: 0,
            first_seen: None,
            last_seen: None,
            span_days: 0,
            activity_ratio: MetricValue::Unknown,
        };
    }

    let first_seen = receipts.iter().map(|receipt| receipt.timestamp).min();
    let last_seen = receipts.iter().map(|receipt| receipt.timestamp).max();
    let active_days: BTreeSet<u64> = receipts
        .iter()
        .map(|receipt| receipt.timestamp / SECONDS_PER_DAY)
        .collect();
    let span_days = match (first_seen, last_seen) {
        (Some(first), Some(last)) => ((last.saturating_sub(first)) / SECONDS_PER_DAY).max(1) + 1,
        _ => 0,
    };
    let activity_ratio = if span_days > 0 {
        active_days.len() as f64 / span_days as f64
    } else {
        0.0
    };
    let receipt_score =
        (receipts.len() as f64 / config.history_receipt_target.max(1) as f64).min(1.0);
    let day_score = (span_days as f64 / config.history_day_target.max(1) as f64).min(1.0);
    let normalized = (receipt_score + day_score + activity_ratio) / 3.0;

    HistoryDepthMetrics {
        score: MetricValue::known(normalized),
        receipt_count: receipts.len(),
        active_days: active_days.len(),
        first_seen,
        last_seen,
        span_days,
        activity_ratio: MetricValue::known(activity_ratio),
    }
}

fn compute_specialization(
    receipts: &[&PactReceipt],
    now: u64,
    config: &ReputationConfig,
) -> SpecializationMetrics {
    if receipts.is_empty() {
        return SpecializationMetrics {
            score: MetricValue::Unknown,
            distinct_tools: 0,
        };
    }

    let mut weights_by_tool: BTreeMap<(&str, &str), f64> = BTreeMap::new();
    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        *weights_by_tool
            .entry((receipt.tool_server.as_str(), receipt.tool_name.as_str()))
            .or_default() += weight;
    }

    let total_weight = weights_by_tool.values().sum::<f64>();
    let entropy = weights_by_tool
        .values()
        .map(|count| {
            let p = count / total_weight;
            -p * p.log2()
        })
        .sum::<f64>();
    let max_entropy = if weights_by_tool.len() > 1 {
        (weights_by_tool.len() as f64).log2()
    } else {
        0.0
    };
    let score = if max_entropy > 0.0 {
        entropy / max_entropy
    } else {
        0.0
    };

    SpecializationMetrics {
        score: MetricValue::known(score),
        distinct_tools: weights_by_tool.len(),
    }
}

fn compute_delegation_hygiene(
    delegations: &[&CapabilityLineageRecord],
    capability_map: &BTreeMap<&str, &CapabilityLineageRecord>,
    now: u64,
    config: &ReputationConfig,
) -> DelegationHygieneMetrics {
    if delegations.is_empty() {
        return DelegationHygieneMetrics {
            score: MetricValue::Unknown,
            delegations_observed: 0,
            scope_reduction_rate: MetricValue::Unknown,
            ttl_reduction_rate: MetricValue::Unknown,
            budget_reduction_rate: MetricValue::Unknown,
        };
    }

    let mut scope_signals = Vec::new();
    let mut ttl_signals = Vec::new();
    let mut budget_signals = Vec::new();

    for child in delegations {
        let Some(parent_id) = child.parent_capability_id.as_deref() else {
            continue;
        };
        let Some(parent) = capability_map.get(parent_id) else {
            continue;
        };

        let weight = decay_weight(now, child.issued_at, config.temporal_decay_half_life_days);
        scope_signals.push((
            bool_to_score(scope_reduced(&parent.scope, &child.scope)),
            weight,
        ));
        ttl_signals.push((bool_to_score(child.expires_at < parent.expires_at), weight));
        budget_signals.push((
            bool_to_score(budget_reduced(&parent.scope, &child.scope)),
            weight,
        ));
    }

    if scope_signals.is_empty() {
        return DelegationHygieneMetrics {
            score: MetricValue::Unknown,
            delegations_observed: 0,
            scope_reduction_rate: MetricValue::Unknown,
            ttl_reduction_rate: MetricValue::Unknown,
            budget_reduction_rate: MetricValue::Unknown,
        };
    }

    let scope_rate = weighted_average(&scope_signals);
    let ttl_rate = weighted_average(&ttl_signals);
    let budget_rate = weighted_average(&budget_signals);

    DelegationHygieneMetrics {
        score: MetricValue::known((scope_rate + ttl_rate + budget_rate) / 3.0),
        delegations_observed: scope_signals.len(),
        scope_reduction_rate: MetricValue::known(scope_rate),
        ttl_reduction_rate: MetricValue::known(ttl_rate),
        budget_reduction_rate: MetricValue::known(budget_rate),
    }
}

fn compute_reliability(
    receipts: &[&PactReceipt],
    now: u64,
    config: &ReputationConfig,
) -> ReliabilityMetrics {
    let mut allow_weight = 0.0;
    let mut cancelled_weight = 0.0;
    let mut incomplete_weight = 0.0;
    let mut observed = 0usize;

    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        match receipt.decision {
            Decision::Allow => {
                allow_weight += weight;
                observed += 1;
            }
            Decision::Cancelled { .. } => {
                cancelled_weight += weight;
                observed += 1;
            }
            Decision::Incomplete { .. } => {
                incomplete_weight += weight;
                observed += 1;
            }
            Decision::Deny { .. } => {}
        }
    }

    let total = allow_weight + cancelled_weight + incomplete_weight;
    if total == 0.0 {
        return ReliabilityMetrics {
            score: MetricValue::Unknown,
            completion_rate: MetricValue::Unknown,
            cancellation_rate: MetricValue::Unknown,
            incompletion_rate: MetricValue::Unknown,
            receipts_observed: observed,
        };
    }

    let completion_rate = allow_weight / total;
    let cancellation_rate = cancelled_weight / total;
    let incompletion_rate = incomplete_weight / total;

    ReliabilityMetrics {
        score: MetricValue::known(completion_rate),
        completion_rate: MetricValue::known(completion_rate),
        cancellation_rate: MetricValue::known(cancellation_rate),
        incompletion_rate: MetricValue::known(incompletion_rate),
        receipts_observed: observed,
    }
}

fn compute_incident_correlation(
    subject_key: &str,
    now: u64,
    corpus: &LocalReputationCorpus,
    config: &ReputationConfig,
) -> IncidentCorrelationMetrics {
    let Some(incidents) = corpus.incident_reports.as_ref() else {
        return IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        };
    };

    let _ = subject_key;
    let weighted_incidents = incidents
        .iter()
        .map(|incident| {
            decay_weight(
                now,
                incident.timestamp,
                config.temporal_decay_half_life_days,
            )
        })
        .sum::<f64>();
    let score = 1.0 - config.incident_penalty.max(0.0) * weighted_incidents;

    IncidentCorrelationMetrics {
        score: MetricValue::known(score),
        incidents_observed: Some(incidents.len()),
    }
}

