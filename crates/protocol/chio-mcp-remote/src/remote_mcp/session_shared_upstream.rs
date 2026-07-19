impl SharedUpstreamToolServer {
    fn new(upstream: Arc<AdaptedMcpServer>) -> Self {
        let manifest = upstream.manifest_clone();
        Self {
            server_id: manifest.server_id,
            tool_names: manifest
                .tools
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            upstream,
        }
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for SharedUpstreamToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tool_names.clone()
    }

    /// Delegate to the wrapped upstream so its manifest-derived read-only
    /// annotations (from the MCP `readOnlyHint`) survive the shared-upstream
    /// wrapping instead of falling back to the side-effecting default.
    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        self.upstream.tool_is_read_only(tool_name)
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        ToolServerConnection::invoke(
            self.upstream.as_ref(),
            tool_name,
            arguments,
            nested_flow_bridge,
        )
        .await
    }
}

impl SharedUpstreamOwner {
    fn new(
        config: &RemoteServeHttpConfig,
        admitted_manifest: &ToolManifest,
        admitted_manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<Self, CliError> {
        let wrapped_arg_refs = config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let native_launch = config.native_launch_factory.prepare_launch(
            &config.wrapped_command,
            &wrapped_arg_refs,
            &config.server_id,
            admitted_manifest_registry,
        )?;
        let notification_source: Arc<dyn McpTransport> = Arc::new(StdioMcpTransport::spawn(
            &config.wrapped_command,
            &wrapped_arg_refs,
            native_launch,
        )?);
        let adapter = McpAdapter::new(
            McpAdapterConfig {
                server_id: config.server_id.clone(),
                server_name: config.server_name.clone(),
                server_version: config.server_version.clone(),
                public_key: admitted_manifest.public_key.clone(),
            },
            Box::new(SerializedMcpTransport::from_arc(
                notification_source.clone(),
            )),
        );
        let upstream_server = Arc::new(AdaptedMcpServer::new(adapter)?);
        if let Err(error) = chio_mcp_adapter::verify_discovered_manifest_surface(
            upstream_server.manifest(),
            admitted_manifest,
        ) {
            return Err(upstream_admission_failure(&upstream_server, error));
        }
        let notification_subscribers =
            Arc::new(StdMutex::new(Vec::<Weak<StdMutex<VecDeque<Value>>>>::new()));
        let notification_stats = Arc::new(SharedUpstreamNotificationStats::default());
        let notification_source_for_thread = notification_source.clone();
        let notification_subscribers_for_thread = notification_subscribers.clone();
        let notification_stats_for_thread = notification_stats.clone();
        let notification_pump_stop = Arc::new(AtomicBool::new(false));
        let notification_pump_stop_for_thread = Arc::clone(&notification_pump_stop);
        let notification_pump_thread = thread::spawn(move || loop {
            if notification_pump_stop_for_thread.load(Ordering::SeqCst) {
                break;
            }
            let notifications = notification_source_for_thread.drain_notifications();
            fan_out_shared_upstream_notifications(
                &notification_subscribers_for_thread,
                notification_stats_for_thread.as_ref(),
                notifications,
            );
            thread::sleep(Duration::from_millis(
                DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS,
            ));
        });

        Ok(Self {
            upstream_server,
            notification_subscribers,
            notification_stats,
            notification_pump_stop,
            notification_pump_thread: StdMutex::new(Some(notification_pump_thread)),
        })
    }

    fn upstream_server(&self) -> Arc<AdaptedMcpServer> {
        self.upstream_server.clone()
    }

    fn notification_tap(&self) -> Arc<dyn McpTransport> {
        let queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut subscribers) = self.notification_subscribers.lock() {
            subscribers.push(Arc::downgrade(&queue));
        }
        Arc::new(SharedUpstreamNotificationTap { queue })
    }

    fn notification_stats_snapshot(&self) -> SharedUpstreamNotificationStatsSnapshot {
        SharedUpstreamNotificationStatsSnapshot {
            fanout_batches: self
                .notification_stats
                .fanout_batches
                .load(Ordering::Relaxed),
            fanout_notifications: self
                .notification_stats
                .fanout_notifications
                .load(Ordering::Relaxed),
            fanout_targets: self
                .notification_stats
                .fanout_targets
                .load(Ordering::Relaxed),
            pruned_subscribers: self
                .notification_stats
                .pruned_subscribers
                .load(Ordering::Relaxed),
            queue_lock_skips: self
                .notification_stats
                .queue_lock_skips
                .load(Ordering::Relaxed),
            subscriber_lock_failures: self
                .notification_stats
                .subscriber_lock_failures
                .load(Ordering::Relaxed),
        }
    }

    fn shutdown(&self) -> Result<(), CliError> {
        self.notification_pump_stop.store(true, Ordering::SeqCst);
        let mut failures = Vec::new();
        match self.notification_pump_thread.lock() {
            Ok(mut thread) => {
                if thread.take().is_some_and(|thread| thread.join().is_err()) {
                    failures.push("shared MCP notification pump panicked".to_string());
                }
            }
            Err(error) => failures.push(format!(
                "shared MCP notification pump ownership lock is poisoned: {error}"
            )),
        }
        if let Err(error) = self.upstream_server.shutdown() {
            failures.push(format!(
                "shared MCP terminal receipt persistence failed: {error}"
            ));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CliError::cli_other_error(failures.join("; ")))
        }
    }
}

impl McpTransport for SharedUpstreamNotificationTap {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn drain_notifications(&self) -> Vec<Value> {
        let Ok(mut queue) = self.queue.lock() else {
            return vec![];
        };
        queue.drain(..).collect()
    }

    fn shutdown(&self) -> Result<(), AdapterError> {
        // Session taps do not own the shared native child. The owner closes it
        // once after every session has reached a terminal state.
        Ok(())
    }
}

fn fan_out_shared_upstream_notifications(
    subscribers: &NotificationSubscriberList,
    stats: &SharedUpstreamNotificationStats,
    notifications: Vec<Value>,
) {
    if notifications.is_empty() {
        return;
    }
    stats.fanout_batches.fetch_add(1, Ordering::Relaxed);
    stats
        .fanout_notifications
        .fetch_add(notifications.len() as u64, Ordering::Relaxed);
    let Ok(mut subscribers) = subscribers.lock() else {
        stats
            .subscriber_lock_failures
            .fetch_add(1, Ordering::Relaxed);
        warn!("failed to lock shared hosted-owner notification subscribers");
        return;
    };
    let before_prune = subscribers.len();
    subscribers.retain(|subscriber| subscriber.strong_count() > 0);
    let pruned = before_prune.saturating_sub(subscribers.len());
    if pruned > 0 {
        stats
            .pruned_subscribers
            .fetch_add(pruned as u64, Ordering::Relaxed);
    }
    // Shared hosted-owner mode multiplexes one upstream subprocess across many
    // sessions. Each session-local ChioMcpEdge still applies its own resource
    // subscription and elicitation filtering before surfacing client-visible
    // notifications, so the shared tap can safely replay raw upstream
    // notifications into every live session queue.
    for subscriber in subscribers.iter() {
        let Some(queue) = subscriber.upgrade() else {
            continue;
        };
        let Ok(mut queue) = queue.lock() else {
            stats
                .queue_lock_skips
                .fetch_add(notifications.len() as u64, Ordering::Relaxed);
            warn!("failed to lock shared hosted-owner notification tap queue");
            continue;
        };
        stats.fanout_targets.fetch_add(1, Ordering::Relaxed);
        queue.extend(notifications.iter().cloned());
    }
}
