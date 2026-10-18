-- Hosted cognition-market schema: tables, guarded functions, row-level
-- security and the domain event contract registry.

CREATE TABLE public.chio_finding_market_jobs (
    tenant_id text NOT NULL,
    job_id text NOT NULL,
    job_kind text NOT NULL,
    request_sha256 character(64) NOT NULL,
    payload_sha256 character(64) NOT NULL,
    payload_json bytea NOT NULL,
    state text NOT NULL,
    attempt_count bigint DEFAULT 0 NOT NULL,
    available_at bigint NOT NULL,
    lease_owner text,
    lease_expires_at bigint,
    result_sha256 character(64),
    result_json bytea,
    last_error_code text,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    lease_fence bigint DEFAULT 0 NOT NULL,
    CONSTRAINT chio_finding_market_jobs_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT chio_finding_market_jobs_available_at_check CHECK ((available_at > 0)),
    CONSTRAINT chio_finding_market_jobs_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_jobs_error_v1 CHECK ((((state = ANY (ARRAY['pending'::text, 'completed'::text, 'leased'::text])) AND (last_error_code IS NULL)) OR ((state = ANY (ARRAY['failed'::text, 'exhausted'::text])) AND (last_error_code IS NOT NULL)))),
    CONSTRAINT chio_finding_market_jobs_fence_v13 CHECK (((lease_fence >= attempt_count) AND ((state = 'pending'::text) OR ((state <> 'pending'::text) AND (attempt_count > 0) AND (lease_fence > 0))))),
    CONSTRAINT chio_finding_market_jobs_lease_fence_check CHECK ((lease_fence >= 0)),
    CONSTRAINT chio_finding_market_jobs_lease_v1 CHECK ((((state = 'leased'::text) AND (lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL)) OR ((state <> 'leased'::text) AND (lease_owner IS NULL) AND (lease_expires_at IS NULL)))),
    CONSTRAINT chio_finding_market_jobs_result_v1 CHECK ((((state = 'completed'::text) AND (result_sha256 IS NOT NULL) AND (result_json IS NOT NULL)) OR ((state <> 'completed'::text) AND (result_sha256 IS NULL) AND (result_json IS NULL)))),
    CONSTRAINT chio_finding_market_jobs_state_v1 CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'completed'::text, 'failed'::text, 'exhausted'::text]))),
    CONSTRAINT chio_finding_market_jobs_updated_at_check CHECK ((updated_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_jobs FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_aggregate_checkpoints (
    tenant_id text NOT NULL,
    checkpoint_sha256 character(64) NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    revision bigint NOT NULL,
    event_sha256 character(64) NOT NULL,
    previous_checkpoint_sha256 character(64),
    signer_key_hex character(64) NOT NULL,
    checkpoint_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_aggregate_checkpoints_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_digest_v1 CHECK (((checkpoint_sha256 !~ '[^0-9a-f]'::text) AND (event_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((previous_checkpoint_sha256 IS NULL) OR (previous_checkpoint_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_envelope_size_v1 CHECK (((octet_length(checkpoint_envelope_json) >= 1) AND (octet_length(checkpoint_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_identifier_v1 CHECK ((((octet_length(aggregate_id) >= 1) AND (octet_length(aggregate_id) <= 256)) AND (aggregate_id !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_kind_v1 CHECK ((aggregate_kind = ANY (ARRAY['finding'::text, 'recipe'::text, 'profile'::text, 'collateral'::text, 'listing'::text, 'admission'::text, 'participation'::text, 'purchase'::text, 'reveal'::text, 'delivery'::text, 'purchase_terminal'::text, 'failed_delivery'::text, 'challenge'::text, 'challenge_outcome'::text, 'verified_fix'::text, 'retraction'::text, 'liability'::text, 'appeal'::text, 'penalty'::text, 'enforcement'::text, 'settlement'::text, 'status_epoch'::text, 'audit_round'::text]))),
    CONSTRAINT chio_finding_market_aggregate_checkpoints_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY public.chio_finding_market_aggregate_checkpoints FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_aggregate_events (
    tenant_id text NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    revision bigint NOT NULL,
    event_id text NOT NULL,
    event_kind text NOT NULL,
    previous_event_sha256 character(64),
    payload_sha256 character(64) NOT NULL,
    payload_json bytea NOT NULL,
    event_sha256 character(64) NOT NULL,
    committed_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_aggregate_events_check CHECK ((((revision = 1) AND (previous_event_sha256 IS NULL)) OR ((revision > 1) AND (previous_event_sha256 IS NOT NULL)))),
    CONSTRAINT chio_finding_market_aggregate_events_committed_at_check CHECK ((committed_at > 0)),
    CONSTRAINT chio_finding_market_aggregate_events_digest_v1 CHECK (((payload_sha256 !~ '[^0-9a-f]'::text) AND (event_sha256 !~ '[^0-9a-f]'::text) AND ((previous_event_sha256 IS NULL) OR (previous_event_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_aggregate_events_identifier_v1 CHECK ((((octet_length(aggregate_id) >= 1) AND (octet_length(aggregate_id) <= 256)) AND (aggregate_id !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(event_id) >= 1) AND (octet_length(event_id) <= 256)) AND (event_id !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(event_kind) >= 1) AND (octet_length(event_kind) <= 96)) AND (event_kind !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_aggregate_events_kind_v1 CHECK ((aggregate_kind = ANY (ARRAY['finding'::text, 'recipe'::text, 'profile'::text, 'collateral'::text, 'listing'::text, 'admission'::text, 'participation'::text, 'purchase'::text, 'reveal'::text, 'delivery'::text, 'purchase_terminal'::text, 'failed_delivery'::text, 'challenge'::text, 'challenge_outcome'::text, 'verified_fix'::text, 'retraction'::text, 'liability'::text, 'appeal'::text, 'penalty'::text, 'enforcement'::text, 'settlement'::text, 'status_epoch'::text, 'audit_round'::text]))),
    CONSTRAINT chio_finding_market_aggregate_events_payload_size_v1 CHECK (((octet_length(payload_json) >= 1) AND (octet_length(payload_json) <= 4194304))),
    CONSTRAINT chio_finding_market_aggregate_events_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY public.chio_finding_market_aggregate_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_aggregate_heads (
    tenant_id text NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    revision bigint NOT NULL,
    event_sha256 character(64) NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_aggregate_heads_digest_v1 CHECK ((event_sha256 !~ '[^0-9a-f]'::text)),
    CONSTRAINT chio_finding_market_aggregate_heads_identifier_v1 CHECK ((((octet_length(aggregate_id) >= 1) AND (octet_length(aggregate_id) <= 256)) AND (aggregate_id !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_aggregate_heads_kind_v1 CHECK ((aggregate_kind = ANY (ARRAY['finding'::text, 'recipe'::text, 'profile'::text, 'collateral'::text, 'listing'::text, 'admission'::text, 'participation'::text, 'purchase'::text, 'reveal'::text, 'delivery'::text, 'purchase_terminal'::text, 'failed_delivery'::text, 'challenge'::text, 'challenge_outcome'::text, 'verified_fix'::text, 'retraction'::text, 'liability'::text, 'appeal'::text, 'penalty'::text, 'enforcement'::text, 'settlement'::text, 'status_epoch'::text, 'audit_round'::text]))),
    CONSTRAINT chio_finding_market_aggregate_heads_revision_check CHECK ((revision > 0)),
    CONSTRAINT chio_finding_market_aggregate_heads_updated_at_check CHECK ((updated_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_aggregate_heads FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_api_keys (
    tenant_id text NOT NULL,
    key_id text NOT NULL,
    principal_id text NOT NULL,
    verifier_sha256 character(64) NOT NULL,
    allowed_actions text[] NOT NULL,
    active_from bigint NOT NULL,
    expires_at bigint NOT NULL,
    revoked_at bigint,
    rotated_from_key_id text,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_api_keys_active_from_check CHECK ((active_from > 0)),
    CONSTRAINT chio_finding_market_api_keys_allowed_actions_check CHECK (((cardinality(allowed_actions) >= 1) AND (cardinality(allowed_actions) <= 64))),
    CONSTRAINT chio_finding_market_api_keys_check CHECK ((expires_at > active_from)),
    CONSTRAINT chio_finding_market_api_keys_check1 CHECK (((revoked_at IS NULL) OR (revoked_at >= active_from))),
    CONSTRAINT chio_finding_market_api_keys_created_at_check CHECK ((created_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_api_keys FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_archive_manifests (
    tenant_id text NOT NULL,
    archive_sha256 character(64) NOT NULL,
    resource_kind text NOT NULL,
    resource_family text NOT NULL,
    resource_id text NOT NULL,
    resource_revision bigint NOT NULL,
    resource_sha256 character(64) NOT NULL,
    covered_checkpoint_sha256 character(64) NOT NULL,
    object_uri text NOT NULL,
    object_sha256 character(64) NOT NULL,
    object_size bigint NOT NULL,
    configuration_revision text NOT NULL,
    previous_archive_sha256 character(64),
    signer_key_hex character(64) NOT NULL,
    archive_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_archive_manifests_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_archive_manifests_digest_v1 CHECK (((archive_sha256 !~ '[^0-9a-f]'::text) AND (resource_sha256 !~ '[^0-9a-f]'::text) AND (covered_checkpoint_sha256 !~ '[^0-9a-f]'::text) AND (object_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((previous_archive_sha256 IS NULL) OR (previous_archive_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_archive_manifests_envelope_size_v1 CHECK (((octet_length(archive_envelope_json) >= 1) AND (octet_length(archive_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_archive_manifests_identifier_v1 CHECK ((((octet_length(resource_family) >= 1) AND (octet_length(resource_family) <= 96)) AND (resource_family !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(resource_id) >= 1) AND (octet_length(resource_id) <= 256)) AND (resource_id !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(configuration_revision) >= 1) AND (octet_length(configuration_revision) <= 256)) AND (configuration_revision !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(object_uri) >= 1) AND (octet_length(object_uri) <= 2048)))),
    CONSTRAINT chio_finding_market_archive_manifests_object_size_check CHECK ((object_size > 0)),
    CONSTRAINT chio_finding_market_archive_manifests_resource_kind_check CHECK ((resource_kind = ANY (ARRAY['aggregate'::text, 'job'::text]))),
    CONSTRAINT chio_finding_market_archive_manifests_resource_revision_check CHECK ((resource_revision >= 0))
);

ALTER TABLE ONLY public.chio_finding_market_archive_manifests FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_authority_state (
    tenant_id text NOT NULL,
    authority text NOT NULL,
    authority_epoch bigint NOT NULL,
    mode text NOT NULL,
    mutations_enabled boolean NOT NULL,
    last_replication_sequence bigint NOT NULL,
    last_outbox_sequence bigint NOT NULL,
    rollback_window_ends_at bigint,
    configuration_revision text NOT NULL,
    transition_sha256 character(64),
    updated_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_authority_s_last_replication_sequence_check CHECK ((last_replication_sequence >= 0)),
    CONSTRAINT chio_finding_market_authority_state_authority_check CHECK ((authority = ANY (ARRAY['sqlite'::text, 'postgres'::text]))),
    CONSTRAINT chio_finding_market_authority_state_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT chio_finding_market_authority_state_consistency_v1 CHECK ((((authority = 'sqlite'::text) AND (mode = ANY (ARRAY['shadow'::text, 'frozen'::text]))) OR ((authority = 'postgres'::text) AND (mode = ANY (ARRAY['rollback_window'::text, 'authoritative'::text, 'retired'::text, 'frozen'::text]))))),
    CONSTRAINT chio_finding_market_authority_state_last_outbox_sequence_check CHECK ((last_outbox_sequence >= 0)),
    CONSTRAINT chio_finding_market_authority_state_mode_check CHECK ((mode = ANY (ARRAY['shadow'::text, 'frozen'::text, 'rollback_window'::text, 'authoritative'::text, 'retired'::text]))),
    CONSTRAINT chio_finding_market_authority_state_revision_v1 CHECK ((((octet_length(configuration_revision) >= 1) AND (octet_length(configuration_revision) <= 256)) AND (configuration_revision !~ '[^A-Za-z0-9_.:/-]'::text) AND ((transition_sha256 IS NULL) OR (transition_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_authority_state_updated_at_check CHECK ((updated_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_authority_state FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_authority_transitions (
    tenant_id text NOT NULL,
    transition_sha256 character(64) NOT NULL,
    operation text NOT NULL,
    from_authority text NOT NULL,
    to_authority text NOT NULL,
    from_epoch bigint NOT NULL,
    to_epoch bigint NOT NULL,
    through_sequence bigint NOT NULL,
    source_checkpoint_sha256 character(64) NOT NULL,
    target_checkpoint_sha256 character(64) NOT NULL,
    configuration_revision text NOT NULL,
    rollback_window_ends_at bigint,
    signer_key_hex character(64) NOT NULL,
    transition_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_authority_transition_through_sequence_check CHECK ((through_sequence >= 0)),
    CONSTRAINT chio_finding_market_authority_transitions_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_authority_transitions_digest_v1 CHECK (((transition_sha256 !~ '[^0-9a-f]'::text) AND (source_checkpoint_sha256 !~ '[^0-9a-f]'::text) AND (target_checkpoint_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text))),
    CONSTRAINT chio_finding_market_authority_transitions_envelope_size_v1 CHECK (((octet_length(transition_envelope_json) >= 1) AND (octet_length(transition_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_authority_transitions_epoch_v1 CHECK (((to_epoch = (from_epoch + 1)) AND ((octet_length(configuration_revision) >= 1) AND (octet_length(configuration_revision) <= 256)) AND (configuration_revision !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_authority_transitions_from_authority_check CHECK ((from_authority = ANY (ARRAY['sqlite'::text, 'postgres'::text]))),
    CONSTRAINT chio_finding_market_authority_transitions_from_epoch_check CHECK ((from_epoch > 0)),
    CONSTRAINT chio_finding_market_authority_transitions_operation_check CHECK ((operation = ANY (ARRAY['freeze'::text, 'cutover'::text, 'rollback'::text, 'retire_sqlite'::text]))),
    CONSTRAINT chio_finding_market_authority_transitions_to_authority_check CHECK ((to_authority = ANY (ARRAY['sqlite'::text, 'postgres'::text]))),
    CONSTRAINT chio_finding_market_authority_transitions_to_epoch_check CHECK ((to_epoch > 0))
);

ALTER TABLE ONLY public.chio_finding_market_authority_transitions FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_capability_request_admissions (
    tenant_id text NOT NULL,
    capability_id text NOT NULL,
    request_sha256 character(64) NOT NULL,
    admitted_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_capability_request_admiss_admitted_at_check CHECK ((admitted_at > 0)),
    CONSTRAINT chio_finding_market_capability_request_admissi_expires_at_check CHECK ((expires_at > 0)),
    CONSTRAINT chio_finding_market_capability_request_digest_v1 CHECK ((request_sha256 !~ '[^0-9a-f]'::text))
);

ALTER TABLE ONLY public.chio_finding_market_capability_request_admissions FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_capability_uses (
    tenant_id text NOT NULL,
    capability_id text NOT NULL,
    used_count bigint NOT NULL,
    max_invocations bigint NOT NULL,
    expires_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_capability_uses_check CHECK ((used_count <= max_invocations)),
    CONSTRAINT chio_finding_market_capability_uses_expires_at_check CHECK ((expires_at > 0)),
    CONSTRAINT chio_finding_market_capability_uses_max_invocations_check CHECK ((max_invocations > 0)),
    CONSTRAINT chio_finding_market_capability_uses_updated_at_check CHECK ((updated_at > 0)),
    CONSTRAINT chio_finding_market_capability_uses_used_count_check CHECK ((used_count > 0))
);

ALTER TABLE ONLY public.chio_finding_market_capability_uses FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_domain_event_contracts (
    aggregate_kind text NOT NULL,
    event_kind text NOT NULL,
    artifact_schema text NOT NULL,
    signed_artifact boolean NOT NULL,
    CONSTRAINT chio_finding_market_domain_event_contracts_identifier_v1 CHECK ((((octet_length(aggregate_kind) >= 1) AND (octet_length(aggregate_kind) <= 96)) AND (aggregate_kind !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(event_kind) >= 1) AND (octet_length(event_kind) <= 96)) AND (event_kind !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(artifact_schema) >= 1) AND (octet_length(artifact_schema) <= 256)) AND (artifact_schema !~ '[^A-Za-z0-9_.:/-]'::text)))
);

CREATE TABLE public.chio_finding_market_domain_projections (
    tenant_id text NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    revision bigint NOT NULL,
    event_sha256 character(64) NOT NULL,
    event_kind text NOT NULL,
    artifact_schema text NOT NULL,
    payload_sha256 character(64) NOT NULL,
    payload_json bytea NOT NULL,
    updated_at bigint NOT NULL,
    subject_finding_id text,
    CONSTRAINT chio_finding_market_domain_projection_status_subject_v1 CHECK ((((aggregate_kind = ANY (ARRAY['retraction'::text, 'enforcement'::text])) AND (octet_length(subject_finding_id) = 64) AND (subject_finding_id !~ '[^0-9a-f]'::text)) OR ((aggregate_kind <> ALL (ARRAY['retraction'::text, 'enforcement'::text])) AND (subject_finding_id IS NULL)))),
    CONSTRAINT chio_finding_market_domain_projections_identifier_v1 CHECK ((((octet_length(aggregate_id) >= 1) AND (octet_length(aggregate_id) <= 256)) AND (aggregate_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (payload_sha256 !~ '[^0-9a-f]'::text) AND ((octet_length(payload_json) >= 1) AND (octet_length(payload_json) <= 4194304)))),
    CONSTRAINT chio_finding_market_domain_projections_revision_check CHECK ((revision > 0)),
    CONSTRAINT chio_finding_market_domain_projections_updated_at_check CHECK ((updated_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_domain_projections FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_dpop_admission_state (
    tenant_id text NOT NULL,
    live_nonces bigint DEFAULT 0 NOT NULL,
    last_swept_at bigint DEFAULT 0 NOT NULL,
    live_request_bindings bigint DEFAULT 0 NOT NULL,
    CONSTRAINT chio_finding_market_dpop_admission__live_request_bindings_check CHECK ((live_request_bindings >= 0)),
    CONSTRAINT chio_finding_market_dpop_admission_state_last_swept_at_check CHECK ((last_swept_at >= 0)),
    CONSTRAINT chio_finding_market_dpop_admission_state_live_nonces_check CHECK ((live_nonces >= 0))
);

ALTER TABLE ONLY public.chio_finding_market_dpop_admission_state FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_dpop_nonces (
    tenant_id text NOT NULL,
    capability_id text NOT NULL,
    nonce_sha256 character(64) NOT NULL,
    valid_through bigint NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_dpop_nonces_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_dpop_nonces_valid_through_check CHECK ((valid_through > 0))
);

ALTER TABLE ONLY public.chio_finding_market_dpop_nonces FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_gc_receipts (
    tenant_id text NOT NULL,
    receipt_sha256 character(64) NOT NULL,
    archive_sha256 character(64) NOT NULL,
    resource_kind text NOT NULL,
    resource_family text NOT NULL,
    resource_id text NOT NULL,
    signer_key_hex character(64) NOT NULL,
    receipt_envelope_json bytea NOT NULL,
    completed_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_gc_receipts_completed_at_check CHECK ((completed_at > 0)),
    CONSTRAINT chio_finding_market_gc_receipts_digest_v1 CHECK (((receipt_sha256 !~ '[^0-9a-f]'::text) AND (archive_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text))),
    CONSTRAINT chio_finding_market_gc_receipts_envelope_size_v1 CHECK (((octet_length(receipt_envelope_json) >= 1) AND (octet_length(receipt_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_gc_receipts_resource_kind_check CHECK ((resource_kind = ANY (ARRAY['aggregate'::text, 'job'::text])))
);

ALTER TABLE ONLY public.chio_finding_market_gc_receipts FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_journal_checkpoint_members (
    tenant_id text NOT NULL,
    checkpoint_sha256 character(64) NOT NULL,
    member_kind text NOT NULL,
    member_family text NOT NULL,
    member_id text NOT NULL,
    member_revision bigint NOT NULL,
    member_sha256 character(64) NOT NULL,
    CONSTRAINT chio_finding_market_journal_checkpoint_me_member_revision_check CHECK ((member_revision >= 0)),
    CONSTRAINT chio_finding_market_journal_checkpoint_member_member_kind_check CHECK ((member_kind = ANY (ARRAY['aggregate'::text, 'job'::text]))),
    CONSTRAINT chio_finding_market_journal_checkpoint_members_identifier_v1 CHECK ((((octet_length(member_family) >= 1) AND (octet_length(member_family) <= 96)) AND (member_family !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(member_id) >= 1) AND (octet_length(member_id) <= 256)) AND (member_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (member_sha256 !~ '[^0-9a-f]'::text)))
);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoint_members FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_journal_checkpoints (
    tenant_id text NOT NULL,
    checkpoint_sha256 character(64) NOT NULL,
    aggregate_heads_sha256 character(64) NOT NULL,
    terminal_jobs_sha256 character(64) NOT NULL,
    previous_checkpoint_sha256 character(64),
    migration_version bigint NOT NULL,
    configuration_revision text NOT NULL,
    signer_key_hex character(64) NOT NULL,
    checkpoint_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_journal_checkpoints_config_v1 CHECK ((((octet_length(configuration_revision) >= 1) AND (octet_length(configuration_revision) <= 256)) AND (configuration_revision !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_journal_checkpoints_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_journal_checkpoints_digest_v1 CHECK (((checkpoint_sha256 !~ '[^0-9a-f]'::text) AND (aggregate_heads_sha256 !~ '[^0-9a-f]'::text) AND (terminal_jobs_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((previous_checkpoint_sha256 IS NULL) OR (previous_checkpoint_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_journal_checkpoints_envelope_size_v1 CHECK (((octet_length(checkpoint_envelope_json) >= 1) AND (octet_length(checkpoint_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_journal_checkpoints_migration_version_check CHECK ((migration_version > 0))
);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoints FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_legal_hold_events (
    tenant_id text NOT NULL,
    hold_event_sha256 character(64) NOT NULL,
    hold_id text NOT NULL,
    resource_kind text NOT NULL,
    resource_family text NOT NULL,
    resource_id text NOT NULL,
    action text NOT NULL,
    previous_hold_event_sha256 character(64),
    signer_key_hex character(64) NOT NULL,
    hold_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_legal_hold_events_action_check CHECK ((action = ANY (ARRAY['placed'::text, 'released'::text]))),
    CONSTRAINT chio_finding_market_legal_hold_events_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_legal_hold_events_digest_v1 CHECK (((hold_event_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((previous_hold_event_sha256 IS NULL) OR (previous_hold_event_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_legal_hold_events_envelope_size_v1 CHECK (((octet_length(hold_envelope_json) >= 1) AND (octet_length(hold_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_legal_hold_events_identifier_v1 CHECK ((((octet_length(hold_id) >= 1) AND (octet_length(hold_id) <= 256)) AND (hold_id !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(resource_family) >= 1) AND (octet_length(resource_family) <= 96)) AND (resource_family !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(resource_id) >= 1) AND (octet_length(resource_id) <= 256)) AND (resource_id !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_legal_hold_events_resource_kind_check CHECK ((resource_kind = ANY (ARRAY['aggregate'::text, 'job'::text])))
);

ALTER TABLE ONLY public.chio_finding_market_legal_hold_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_principal_events (
    tenant_id text NOT NULL,
    event_sha256 character(64) NOT NULL,
    principal_id text NOT NULL,
    operation text NOT NULL,
    role text NOT NULL,
    capability_public_key_hex character(64),
    overlap_expires_at bigint,
    previous_event_sha256 character(64),
    signer_key_hex character(64) NOT NULL,
    event_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_principal_events_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_principal_events_envelope_size_v1 CHECK (((octet_length(event_envelope_json) >= 1) AND (octet_length(event_envelope_json) <= 1048576))),
    CONSTRAINT chio_finding_market_principal_events_identifier_v1 CHECK ((((octet_length(principal_id) >= 1) AND (octet_length(principal_id) <= 256)) AND (principal_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((capability_public_key_hex IS NULL) OR (capability_public_key_hex !~ '[^0-9a-f]'::text)) AND ((previous_event_sha256 IS NULL) OR (previous_event_sha256 !~ '[^0-9a-f]'::text)) AND ((overlap_expires_at IS NULL) OR (overlap_expires_at > created_at)))),
    CONSTRAINT chio_finding_market_principal_events_operation_check CHECK ((operation = ANY (ARRAY['provision'::text, 'disable'::text, 'role_change'::text, 'key_rotation'::text, 'emergency_revoke'::text]))),
    CONSTRAINT chio_finding_market_principal_events_role_check CHECK ((role = ANY (ARRAY['buyer'::text, 'seller'::text, 'evaluator'::text, 'auditor'::text, 'operator'::text])))
);

ALTER TABLE ONLY public.chio_finding_market_principal_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_principal_key_overlaps (
    tenant_id text NOT NULL,
    principal_id text NOT NULL,
    capability_public_key_hex character(64) NOT NULL,
    lifecycle_event_sha256 character(64) NOT NULL,
    valid_through bigint NOT NULL,
    CONSTRAINT chio_finding_market_principal_key_overlaps_identifier_v1 CHECK ((((octet_length(principal_id) >= 1) AND (octet_length(principal_id) <= 256)) AND (principal_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (capability_public_key_hex !~ '[^0-9a-f]'::text))),
    CONSTRAINT chio_finding_market_principal_key_overlaps_valid_through_check CHECK ((valid_through > 0))
);

ALTER TABLE ONLY public.chio_finding_market_principal_key_overlaps FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_principal_replication_events (
    tenant_id text NOT NULL,
    replication_event_sha256 character(64) NOT NULL,
    source_authority text NOT NULL,
    authority_epoch bigint NOT NULL,
    sequence bigint NOT NULL,
    principal_event_sha256 character(64) NOT NULL,
    principal_id text NOT NULL,
    operation text NOT NULL,
    role text NOT NULL,
    capability_public_key_hex character(64),
    overlap_expires_at bigint,
    previous_event_sha256 character(64),
    principal_signer_key_hex character(64) NOT NULL,
    principal_event_envelope_json bytea NOT NULL,
    source_signer_key_hex character(64) NOT NULL,
    replication_event_envelope_json bytea NOT NULL,
    committed_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_principal_replicatio_source_authority_check CHECK ((source_authority = ANY (ARRAY['sqlite'::text, 'postgres'::text]))),
    CONSTRAINT chio_finding_market_principal_replication_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT chio_finding_market_principal_replication_ev_committed_at_check CHECK ((committed_at > 0)),
    CONSTRAINT chio_finding_market_principal_replication_event_operation_check CHECK ((operation = ANY (ARRAY['provision'::text, 'disable'::text, 'role_change'::text, 'key_rotation'::text, 'emergency_revoke'::text]))),
    CONSTRAINT chio_finding_market_principal_replication_events_envelope_size_ CHECK ((((octet_length(principal_event_envelope_json) >= 1) AND (octet_length(principal_event_envelope_json) <= 1048576)) AND ((octet_length(replication_event_envelope_json) >= 1) AND (octet_length(replication_event_envelope_json) <= 4194304)))),
    CONSTRAINT chio_finding_market_principal_replication_events_identifier_v1 CHECK ((((octet_length(principal_id) >= 1) AND (octet_length(principal_id) <= 256)) AND (principal_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (replication_event_sha256 !~ '[^0-9a-f]'::text) AND (principal_event_sha256 !~ '[^0-9a-f]'::text) AND (principal_signer_key_hex !~ '[^0-9a-f]'::text) AND (source_signer_key_hex !~ '[^0-9a-f]'::text) AND ((capability_public_key_hex IS NULL) OR (capability_public_key_hex !~ '[^0-9a-f]'::text)) AND ((previous_event_sha256 IS NULL) OR (previous_event_sha256 !~ '[^0-9a-f]'::text)) AND ((overlap_expires_at IS NULL) OR (overlap_expires_at > committed_at)))),
    CONSTRAINT chio_finding_market_principal_replication_events_role_check CHECK ((role = ANY (ARRAY['buyer'::text, 'seller'::text, 'evaluator'::text, 'auditor'::text, 'operator'::text]))),
    CONSTRAINT chio_finding_market_principal_replication_events_sequence_check CHECK ((sequence > 0))
);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_principal_replication_outbox (
    tenant_id text NOT NULL,
    authority_epoch bigint NOT NULL,
    sequence bigint NOT NULL,
    principal_event_sha256 character(64) NOT NULL,
    principal_id text NOT NULL,
    operation text NOT NULL,
    role text NOT NULL,
    capability_public_key_hex character(64),
    overlap_expires_at bigint,
    previous_event_sha256 character(64),
    signer_key_hex character(64) NOT NULL,
    event_envelope_json bytea NOT NULL,
    committed_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_principal_replicatio_authority_epoch_check1 CHECK ((authority_epoch > 0)),
    CONSTRAINT chio_finding_market_principal_replication_ou_committed_at_check CHECK ((committed_at > 0)),
    CONSTRAINT chio_finding_market_principal_replication_outbo_operation_check CHECK ((operation = ANY (ARRAY['provision'::text, 'disable'::text, 'role_change'::text, 'key_rotation'::text, 'emergency_revoke'::text]))),
    CONSTRAINT chio_finding_market_principal_replication_outbox_identifier_v1 CHECK ((((octet_length(principal_id) >= 1) AND (octet_length(principal_id) <= 256)) AND (principal_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (principal_event_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((capability_public_key_hex IS NULL) OR (capability_public_key_hex !~ '[^0-9a-f]'::text)) AND ((previous_event_sha256 IS NULL) OR (previous_event_sha256 !~ '[^0-9a-f]'::text)) AND ((overlap_expires_at IS NULL) OR (overlap_expires_at > committed_at)) AND ((octet_length(event_envelope_json) >= 1) AND (octet_length(event_envelope_json) <= 1048576)))),
    CONSTRAINT chio_finding_market_principal_replication_outbox_role_check CHECK ((role = ANY (ARRAY['buyer'::text, 'seller'::text, 'evaluator'::text, 'auditor'::text, 'operator'::text]))),
    CONSTRAINT chio_finding_market_principal_replication_outbox_sequence_check CHECK ((sequence > 0))
);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_outbox FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_principals (
    tenant_id text NOT NULL,
    principal_id text NOT NULL,
    role text NOT NULL,
    capability_public_key_hex text,
    enabled boolean DEFAULT true NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_principals_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_principals_role_check CHECK ((role = ANY (ARRAY['buyer'::text, 'seller'::text, 'evaluator'::text, 'auditor'::text, 'operator'::text]))),
    CONSTRAINT chio_finding_market_principals_updated_at_check CHECK ((updated_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_principals FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_quota_alerts (
    tenant_id text NOT NULL,
    alert_sha256 character(64) NOT NULL,
    quota_kind text NOT NULL,
    observed_value bigint NOT NULL,
    limit_value bigint NOT NULL,
    signer_key_hex character(64) NOT NULL,
    alert_envelope_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_quota_alerts_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_quota_alerts_digest_v1 CHECK (((alert_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text))),
    CONSTRAINT chio_finding_market_quota_alerts_envelope_size_v1 CHECK (((octet_length(alert_envelope_json) >= 1) AND (octet_length(alert_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_quota_alerts_kind_v1 CHECK ((((octet_length(quota_kind) >= 1) AND (octet_length(quota_kind) <= 96)) AND (quota_kind !~ '[^A-Za-z0-9_.:/-]'::text))),
    CONSTRAINT chio_finding_market_quota_alerts_limit_value_check CHECK ((limit_value > 0)),
    CONSTRAINT chio_finding_market_quota_alerts_observed_value_check CHECK ((observed_value >= 0))
);

ALTER TABLE ONLY public.chio_finding_market_quota_alerts FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_replication_checks (
    tenant_id text NOT NULL,
    check_sha256 character(64) NOT NULL,
    source_authority text NOT NULL,
    authority_epoch bigint NOT NULL,
    through_sequence bigint NOT NULL,
    source_projection_sha256 character(64) NOT NULL,
    target_projection_sha256 character(64) NOT NULL,
    lag_seconds bigint NOT NULL,
    projection_difference_count bigint NOT NULL,
    security_counter_count bigint NOT NULL,
    signer_key_hex character(64) NOT NULL,
    check_envelope_json bytea NOT NULL,
    checked_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_replicati_projection_difference_count_check CHECK ((projection_difference_count >= 0)),
    CONSTRAINT chio_finding_market_replication_ch_security_counter_count_check CHECK ((security_counter_count >= 0)),
    CONSTRAINT chio_finding_market_replication_checks_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT chio_finding_market_replication_checks_checked_at_check CHECK ((checked_at > 0)),
    CONSTRAINT chio_finding_market_replication_checks_digest_v1 CHECK (((check_sha256 !~ '[^0-9a-f]'::text) AND (source_projection_sha256 !~ '[^0-9a-f]'::text) AND (target_projection_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text))),
    CONSTRAINT chio_finding_market_replication_checks_envelope_size_v1 CHECK (((octet_length(check_envelope_json) >= 1) AND (octet_length(check_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_replication_checks_lag_seconds_check CHECK ((lag_seconds >= 0)),
    CONSTRAINT chio_finding_market_replication_checks_source_authority_check CHECK ((source_authority = ANY (ARRAY['sqlite'::text, 'postgres'::text]))),
    CONSTRAINT chio_finding_market_replication_checks_through_sequence_check CHECK ((through_sequence >= 0))
);

ALTER TABLE ONLY public.chio_finding_market_replication_checks FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_replication_events (
    tenant_id text NOT NULL,
    replication_event_sha256 character(64) NOT NULL,
    source_authority text NOT NULL,
    authority_epoch bigint NOT NULL,
    sequence bigint NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    event_id text NOT NULL,
    event_kind text NOT NULL,
    artifact_schema text NOT NULL,
    expected_revision bigint NOT NULL,
    expected_event_sha256 character(64),
    payload_sha256 character(64) NOT NULL,
    payload_json bytea NOT NULL,
    signer_key_hex character(64) NOT NULL,
    event_envelope_json bytea NOT NULL,
    committed_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_replication_events_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT chio_finding_market_replication_events_committed_at_check CHECK ((committed_at > 0)),
    CONSTRAINT chio_finding_market_replication_events_expected_revision_check CHECK ((expected_revision >= 0)),
    CONSTRAINT chio_finding_market_replication_events_identifier_v1 CHECK ((((octet_length(aggregate_id) >= 1) AND (octet_length(aggregate_id) <= 256)) AND (aggregate_id !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(event_id) >= 1) AND (octet_length(event_id) <= 256)) AND (event_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (payload_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text) AND ((expected_event_sha256 IS NULL) OR (expected_event_sha256 !~ '[^0-9a-f]'::text)))),
    CONSTRAINT chio_finding_market_replication_events_payload_size_v1 CHECK ((((octet_length(payload_json) >= 1) AND (octet_length(payload_json) <= 4194304)) AND ((octet_length(event_envelope_json) >= 1) AND (octet_length(event_envelope_json) <= 4194304)))),
    CONSTRAINT chio_finding_market_replication_events_sequence_check CHECK ((sequence > 0)),
    CONSTRAINT chio_finding_market_replication_events_source_authority_check CHECK ((source_authority = ANY (ARRAY['sqlite'::text, 'postgres'::text])))
);

ALTER TABLE ONLY public.chio_finding_market_replication_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_replication_outbox (
    tenant_id text NOT NULL,
    authority_epoch bigint NOT NULL,
    sequence bigint NOT NULL,
    aggregate_kind text NOT NULL,
    aggregate_id text NOT NULL,
    expected_revision bigint NOT NULL,
    expected_event_sha256 character(64),
    event_id text NOT NULL,
    event_kind text NOT NULL,
    artifact_schema text NOT NULL,
    payload_sha256 character(64) NOT NULL,
    payload_json bytea NOT NULL,
    event_sha256 character(64) NOT NULL,
    committed_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_replication_outbox_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT chio_finding_market_replication_outbox_committed_at_check CHECK ((committed_at > 0)),
    CONSTRAINT chio_finding_market_replication_outbox_expected_revision_check CHECK ((expected_revision >= 0)),
    CONSTRAINT chio_finding_market_replication_outbox_identifier_v1 CHECK ((((octet_length(aggregate_id) >= 1) AND (octet_length(aggregate_id) <= 256)) AND (aggregate_id !~ '[^A-Za-z0-9_.:/-]'::text) AND ((octet_length(event_id) >= 1) AND (octet_length(event_id) <= 256)) AND (event_id !~ '[^A-Za-z0-9_.:/-]'::text) AND (payload_sha256 !~ '[^0-9a-f]'::text) AND (event_sha256 !~ '[^0-9a-f]'::text) AND ((expected_event_sha256 IS NULL) OR (expected_event_sha256 !~ '[^0-9a-f]'::text)) AND ((octet_length(payload_json) >= 1) AND (octet_length(payload_json) <= 4194304)))),
    CONSTRAINT chio_finding_market_replication_outbox_sequence_check CHECK ((sequence > 0))
);

ALTER TABLE ONLY public.chio_finding_market_replication_outbox FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_restore_verifications (
    tenant_id text NOT NULL,
    verification_sha256 character(64) NOT NULL,
    archive_sha256 character(64) NOT NULL,
    restored_resource_sha256 character(64) NOT NULL,
    signer_key_hex character(64) NOT NULL,
    verification_envelope_json bytea NOT NULL,
    verified_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_restore_verifications_digest_v1 CHECK (((verification_sha256 !~ '[^0-9a-f]'::text) AND (archive_sha256 !~ '[^0-9a-f]'::text) AND (restored_resource_sha256 !~ '[^0-9a-f]'::text) AND (signer_key_hex !~ '[^0-9a-f]'::text))),
    CONSTRAINT chio_finding_market_restore_verifications_envelope_size_v1 CHECK (((octet_length(verification_envelope_json) >= 1) AND (octet_length(verification_envelope_json) <= 4194304))),
    CONSTRAINT chio_finding_market_restore_verifications_verified_at_check CHECK ((verified_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_restore_verifications FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_security_events (
    tenant_id text NOT NULL,
    event_id text NOT NULL,
    event_kind text NOT NULL,
    artifact_sha256 character(64) NOT NULL,
    artifact_json bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_security_events_created_at_check CHECK ((created_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_security_events FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_spend_periods (
    tenant_id text NOT NULL,
    billing_period character(7) NOT NULL,
    consumed_units bigint DEFAULT 0 NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_spend_periods_billing_period_check CHECK ((billing_period ~ '^[0-9]{4}-[0-9]{2}$'::text)),
    CONSTRAINT chio_finding_market_spend_periods_consumed_units_check CHECK ((consumed_units >= 0)),
    CONSTRAINT chio_finding_market_spend_periods_updated_at_check CHECK ((updated_at >= 0))
);

ALTER TABLE ONLY public.chio_finding_market_spend_periods FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_spend_reservations (
    tenant_id text NOT NULL,
    reservation_id text NOT NULL,
    billing_period character(7) NOT NULL,
    units bigint NOT NULL,
    state text NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT chio_finding_market_spend_reservations_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_spend_reservations_state_check CHECK ((state = ANY (ARRAY['reserved'::text, 'committed'::text, 'released'::text]))),
    CONSTRAINT chio_finding_market_spend_reservations_units_check CHECK (((units >= 1) AND (units <= '9007199254740991'::bigint))),
    CONSTRAINT chio_finding_market_spend_reservations_updated_at_check CHECK ((updated_at > 0))
);

ALTER TABLE ONLY public.chio_finding_market_spend_reservations FORCE ROW LEVEL SECURITY;

CREATE TABLE public.chio_finding_market_tenants (
    tenant_id text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at bigint NOT NULL,
    max_concurrent_jobs integer DEFAULT 1 NOT NULL,
    max_queued_jobs bigint DEFAULT 1 NOT NULL,
    max_monthly_spend_units bigint DEFAULT 1 NOT NULL,
    configuration_revision text DEFAULT 'unconfigured'::text NOT NULL,
    CONSTRAINT chio_finding_market_tenants_configuration_revision_check CHECK (((length(configuration_revision) >= 1) AND (length(configuration_revision) <= 256))),
    CONSTRAINT chio_finding_market_tenants_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT chio_finding_market_tenants_max_concurrent_jobs_check CHECK (((max_concurrent_jobs >= 1) AND (max_concurrent_jobs <= 1024))),
    CONSTRAINT chio_finding_market_tenants_max_monthly_spend_units_check CHECK (((max_monthly_spend_units >= 1) AND (max_monthly_spend_units <= '9007199254740991'::bigint))),
    CONSTRAINT chio_finding_market_tenants_max_queued_jobs_check CHECK (((max_queued_jobs >= 1) AND (max_queued_jobs <= 10000000)))
);

ALTER TABLE ONLY public.chio_finding_market_tenants FORCE ROW LEVEL SECURITY;

CREATE FUNCTION public.chio_finding_market_append_aggregate_event(requested_tenant_id text, requested_aggregate_kind text, requested_aggregate_id text, expected_revision bigint, expected_event_sha256 text, requested_event_id text, requested_event_kind text, requested_payload_sha256 text, requested_payload_json bytea, requested_event_sha256 text, requested_committed_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    existing_event public.chio_finding_market_aggregate_events%ROWTYPE;
    existing_head public.chio_finding_market_aggregate_heads%ROWTYPE;
    requested_revision BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match append request'
            USING ERRCODE = '42501';
    END IF;
    IF expected_revision < 0
        OR (expected_revision = 0 AND expected_event_sha256 IS NOT NULL)
        OR (expected_revision > 0 AND expected_event_sha256 IS NULL)
    THEN
        RETURN 2;
    END IF;
    requested_revision := expected_revision + 1;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'chio.finding.hosted.aggregate-event-id.v1:'
                || requested_tenant_id || ':' || requested_event_id,
            0
        )
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'chio.finding.hosted.aggregate-lock.v1:'
                || requested_tenant_id || ':' || requested_aggregate_kind
                || ':' || requested_aggregate_id,
            0
        )
    );
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = requested_tenant_id
          AND resource_kind = 'aggregate'
          AND resource_family = requested_aggregate_kind
          AND resource_id = requested_aggregate_id
    ) THEN
        RETURN 2;
    END IF;

    SELECT * INTO existing_event
    FROM public.chio_finding_market_aggregate_events
    WHERE tenant_id = requested_tenant_id
      AND event_id = requested_event_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing_event.aggregate_kind = requested_aggregate_kind
            AND existing_event.aggregate_id = requested_aggregate_id
            AND existing_event.revision = requested_revision
            AND existing_event.event_kind = requested_event_kind
            AND existing_event.previous_event_sha256 IS NOT DISTINCT FROM expected_event_sha256
            AND existing_event.payload_sha256 = requested_payload_sha256
            AND existing_event.payload_json = requested_payload_json
            AND existing_event.event_sha256 = requested_event_sha256
            AND existing_event.committed_at = requested_committed_at
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;

    SELECT * INTO existing_head
    FROM public.chio_finding_market_aggregate_heads
    WHERE tenant_id = requested_tenant_id
      AND aggregate_kind = requested_aggregate_kind
      AND aggregate_id = requested_aggregate_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing_head.revision <> expected_revision
            OR existing_head.event_sha256 IS DISTINCT FROM expected_event_sha256
        THEN
            RETURN 2;
        END IF;
    ELSIF expected_revision <> 0 THEN
        RETURN 2;
    END IF;

    INSERT INTO public.chio_finding_market_aggregate_events (
        tenant_id, aggregate_kind, aggregate_id, revision, event_id,
        event_kind, previous_event_sha256, payload_sha256, payload_json,
        event_sha256, committed_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind, requested_aggregate_id,
        requested_revision, requested_event_id, requested_event_kind,
        expected_event_sha256, requested_payload_sha256, requested_payload_json,
        requested_event_sha256, requested_committed_at
    );
    INSERT INTO public.chio_finding_market_aggregate_heads (
        tenant_id, aggregate_kind, aggregate_id, revision, event_sha256, updated_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind, requested_aggregate_id,
        requested_revision, requested_event_sha256, requested_committed_at
    )
    ON CONFLICT (tenant_id, aggregate_kind, aggregate_id)
    DO UPDATE SET revision = EXCLUDED.revision,
                  event_sha256 = EXCLUDED.event_sha256,
                  updated_at = EXCLUDED.updated_at;
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_archive_manifest(requested_tenant_id text, requested_archive_sha256 text, requested_resource_kind text, requested_resource_family text, requested_resource_id text, requested_resource_revision bigint, requested_resource_sha256 text, requested_covered_checkpoint_sha256 text, requested_object_uri text, requested_object_sha256 text, requested_object_size bigint, requested_configuration_revision text, requested_previous_archive_sha256 text, requested_signer_key_hex text, requested_archive_envelope_json bytea, requested_created_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    previous_archive public.chio_finding_market_archive_manifests%ROWTYPE;
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid archive manifest request'
            USING ERRCODE = '42501';
    END IF;
    IF requested_resource_kind = 'aggregate' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'chio.finding.hosted.aggregate-lock.v1:'
                    || requested_tenant_id || ':' || requested_resource_family
                    || ':' || requested_resource_id,
                0
            )
        );
    ELSIF requested_resource_kind = 'job' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'chio.finding.hosted.retention-job-lock.v1:'
                    || requested_tenant_id || ':' || requested_resource_family
                    || ':' || requested_resource_id,
                0
            )
        );
    ELSE
        RETURN 2;
    END IF;
    SELECT archive_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_archive_manifests
    WHERE tenant_id = requested_tenant_id
      AND archive_sha256 = requested_archive_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_archive_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    SELECT * INTO previous_archive
    FROM public.chio_finding_market_archive_manifests
    WHERE tenant_id = requested_tenant_id
      AND resource_kind = requested_resource_kind
      AND resource_family = requested_resource_family
      AND resource_id = requested_resource_id
    ORDER BY created_at DESC, archive_sha256 DESC
    LIMIT 1;
    IF FOUND THEN
        IF requested_previous_archive_sha256 IS DISTINCT FROM previous_archive.archive_sha256
            OR requested_created_at <= previous_archive.created_at
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_previous_archive_sha256 IS NOT NULL THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_archive_manifests (
        tenant_id, archive_sha256, resource_kind, resource_family,
        resource_id, resource_revision, resource_sha256,
        covered_checkpoint_sha256, object_uri, object_sha256,
        object_size, configuration_revision, previous_archive_sha256,
        signer_key_hex, archive_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_archive_sha256, requested_resource_kind,
        requested_resource_family, requested_resource_id,
        requested_resource_revision, requested_resource_sha256,
        requested_covered_checkpoint_sha256, requested_object_uri,
        requested_object_sha256, requested_object_size,
        requested_configuration_revision, requested_previous_archive_sha256,
        requested_signer_key_hex, requested_archive_envelope_json,
        requested_created_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_domain_event(requested_tenant_id text, requested_aggregate_kind text, requested_aggregate_id text, expected_revision bigint, expected_event_sha256 text, requested_event_id text, requested_event_kind text, requested_artifact_schema text, requested_payload_sha256 text, requested_payload_json bytea, requested_event_sha256 text, requested_committed_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    append_outcome SMALLINT;
    requested_revision BIGINT;
    retained_event public.chio_finding_market_aggregate_events%ROWTYPE;
    retained_projection public.chio_finding_market_domain_projections%ROWTYPE;
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
BEGIN
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR NOT FOUND
        OR authority_row.authority <> 'postgres'
        OR authority_row.mutations_enabled <> TRUE
        OR authority_row.mode NOT IN ('rollback_window', 'authoritative', 'retired')
    THEN
        RETURN 2;
    END IF;
    requested_revision := expected_revision + 1;
    SELECT * INTO retained_event
    FROM public.chio_finding_market_aggregate_events
    WHERE tenant_id = requested_tenant_id
      AND event_id = requested_event_id;
    IF FOUND THEN
        SELECT * INTO retained_projection
        FROM public.chio_finding_market_domain_projections
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_aggregate_kind
          AND aggregate_id = requested_aggregate_id;
        IF retained_event.aggregate_kind = requested_aggregate_kind
            AND retained_event.aggregate_id = requested_aggregate_id
            AND retained_event.revision = requested_revision
            AND retained_event.event_kind = requested_event_kind
            AND retained_event.previous_event_sha256 IS NOT DISTINCT FROM expected_event_sha256
            AND retained_event.payload_sha256 = requested_payload_sha256
            AND retained_event.payload_json = requested_payload_json
            AND retained_event.event_sha256 = requested_event_sha256
            AND retained_event.committed_at = requested_committed_at
            AND FOUND
            AND retained_projection.revision = requested_revision
            AND retained_projection.event_sha256 = requested_event_sha256
            AND retained_projection.event_kind = requested_event_kind
            AND retained_projection.artifact_schema = requested_artifact_schema
            AND retained_projection.payload_sha256 = requested_payload_sha256
            AND retained_projection.payload_json = requested_payload_json
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_committed_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_committed_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
        OR NOT EXISTS (
            SELECT 1
            FROM (
                SELECT replication_check.*
                FROM public.chio_finding_market_replication_checks AS replication_check
                JOIN public.chio_finding_market_authority_state AS authority_state
                  ON authority_state.tenant_id = replication_check.tenant_id
                 AND authority_state.authority_epoch = replication_check.authority_epoch
                WHERE replication_check.tenant_id = requested_tenant_id
                ORDER BY replication_check.through_sequence DESC,
                         replication_check.checked_at DESC,
                         replication_check.check_sha256 DESC
                LIMIT 1
            ) AS replication_check
            WHERE replication_check.source_projection_sha256 = replication_check.target_projection_sha256
              AND replication_check.source_authority = 'postgres'
              AND replication_check.through_sequence
                  + (
                      SELECT COUNT(*)
                      FROM public.chio_finding_market_replication_outbox AS current_batch
                      WHERE current_batch.tenant_id = requested_tenant_id
                        AND current_batch.xmin = pg_current_xact_id()::xid
                  ) = authority_row.last_outbox_sequence
              AND replication_check.lag_seconds <= 30
              AND replication_check.checked_at <= floor(extract(epoch from clock_timestamp()))::bigint + 30
              AND replication_check.checked_at >= floor(extract(epoch from clock_timestamp()))::bigint - 30
              AND replication_check.projection_difference_count = 0
              AND replication_check.security_counter_count = 0
        )
        OR NOT EXISTS (
            SELECT 1
            FROM public.chio_finding_market_domain_event_contracts
            WHERE aggregate_kind = requested_aggregate_kind
              AND event_kind = requested_event_kind
              AND artifact_schema = requested_artifact_schema
        )
    THEN
        RETURN 2;
    END IF;
    append_outcome := public.chio_finding_market_append_aggregate_event(
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, expected_revision,
        expected_event_sha256, requested_event_id, requested_event_kind,
        requested_payload_sha256, requested_payload_json,
        requested_event_sha256, requested_committed_at
    );
    IF append_outcome = 2 THEN
        RETURN 2;
    END IF;
    IF append_outcome = 1 THEN
        SELECT * INTO retained_projection
        FROM public.chio_finding_market_domain_projections
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_aggregate_kind
          AND aggregate_id = requested_aggregate_id;
        IF NOT FOUND
            OR retained_projection.revision <> requested_revision
            OR retained_projection.event_sha256 <> requested_event_sha256
            OR retained_projection.event_kind <> requested_event_kind
            OR retained_projection.artifact_schema <> requested_artifact_schema
            OR retained_projection.payload_sha256 <> requested_payload_sha256
            OR retained_projection.payload_json <> requested_payload_json
        THEN
            RETURN 2;
        END IF;
        RETURN 1;
    END IF;
    INSERT INTO public.chio_finding_market_domain_projections (
        tenant_id, aggregate_kind, aggregate_id, revision, event_sha256,
        event_kind, artifact_schema, payload_sha256, payload_json, updated_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, requested_revision, requested_event_sha256,
        requested_event_kind, requested_artifact_schema,
        requested_payload_sha256, requested_payload_json,
        requested_committed_at
    )
    ON CONFLICT (tenant_id, aggregate_kind, aggregate_id)
    DO UPDATE SET revision = EXCLUDED.revision,
                  event_sha256 = EXCLUDED.event_sha256,
                  event_kind = EXCLUDED.event_kind,
                  artifact_schema = EXCLUDED.artifact_schema,
                  payload_sha256 = EXCLUDED.payload_sha256,
                  payload_json = EXCLUDED.payload_json,
                  updated_at = EXCLUDED.updated_at;
    IF authority_row.mode = 'rollback_window' THEN
        INSERT INTO public.chio_finding_market_replication_outbox (
            tenant_id, authority_epoch, sequence, aggregate_kind,
            aggregate_id, expected_revision, expected_event_sha256,
            event_id, event_kind, artifact_schema, payload_sha256,
            payload_json, event_sha256, committed_at
        ) VALUES (
            requested_tenant_id, authority_row.authority_epoch,
            authority_row.last_outbox_sequence + 1,
            requested_aggregate_kind, requested_aggregate_id,
            expected_revision, expected_event_sha256, requested_event_id,
            requested_event_kind, requested_artifact_schema,
            requested_payload_sha256, requested_payload_json,
            requested_event_sha256, requested_committed_at
        );
        UPDATE public.chio_finding_market_authority_state
        SET last_outbox_sequence = last_outbox_sequence + 1,
            updated_at = requested_committed_at
        WHERE tenant_id = requested_tenant_id;
    END IF;
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_journal_checkpoint(requested_tenant_id text, requested_checkpoint_sha256 text, requested_aggregate_heads_sha256 text, requested_terminal_jobs_sha256 text, requested_previous_checkpoint_sha256 text, requested_migration_version bigint, requested_configuration_revision text, requested_signer_key_hex text, requested_checkpoint_envelope_json bytea, requested_created_at bigint, requested_members jsonb) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    retained_envelope BYTEA;
    inserted_members BIGINT;
    previous_checkpoint public.chio_finding_market_journal_checkpoints%ROWTYPE;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR jsonb_typeof(requested_members) <> 'array'
    THEN
        RAISE EXCEPTION 'invalid journal checkpoint request'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended('journal-checkpoint:' || requested_tenant_id, 10)
    );
    SELECT checkpoint_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_journal_checkpoints
    WHERE tenant_id = requested_tenant_id
      AND checkpoint_sha256 = requested_checkpoint_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_checkpoint_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    SELECT * INTO previous_checkpoint
    FROM public.chio_finding_market_journal_checkpoints
    WHERE tenant_id = requested_tenant_id
    ORDER BY created_at DESC, checkpoint_sha256 DESC
    LIMIT 1;
    IF FOUND THEN
        IF requested_previous_checkpoint_sha256 IS DISTINCT FROM previous_checkpoint.checkpoint_sha256
            OR requested_created_at <= previous_checkpoint.created_at
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_previous_checkpoint_sha256 IS NOT NULL THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_journal_checkpoints (
        tenant_id, checkpoint_sha256, aggregate_heads_sha256,
        terminal_jobs_sha256, previous_checkpoint_sha256,
        migration_version, configuration_revision, signer_key_hex,
        checkpoint_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_checkpoint_sha256,
        requested_aggregate_heads_sha256, requested_terminal_jobs_sha256,
        requested_previous_checkpoint_sha256, requested_migration_version,
        requested_configuration_revision, requested_signer_key_hex,
        requested_checkpoint_envelope_json, requested_created_at
    );
    INSERT INTO public.chio_finding_market_journal_checkpoint_members (
        tenant_id, checkpoint_sha256, member_kind, member_family,
        member_id, member_revision, member_sha256
    )
    SELECT requested_tenant_id, requested_checkpoint_sha256,
           member.member_kind, member.member_family, member.member_id,
           member.member_revision, member.member_sha256
    FROM jsonb_to_recordset(requested_members) AS member(
        member_kind TEXT,
        member_family TEXT,
        member_id TEXT,
        member_revision BIGINT,
        member_sha256 TEXT
    );
    GET DIAGNOSTICS inserted_members = ROW_COUNT;
    IF inserted_members <> jsonb_array_length(requested_members) THEN
        RAISE EXCEPTION 'journal checkpoint member count mismatch'
            USING ERRCODE = '22023';
    END IF;
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_legal_hold_event(requested_tenant_id text, requested_hold_event_sha256 text, requested_hold_id text, requested_resource_kind text, requested_resource_family text, requested_resource_id text, requested_action text, requested_previous_hold_event_sha256 text, requested_signer_key_hex text, requested_hold_envelope_json bytea, requested_created_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    previous_hold public.chio_finding_market_legal_hold_events%ROWTYPE;
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid legal hold request'
            USING ERRCODE = '42501';
    END IF;
    IF requested_resource_kind = 'aggregate' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'chio.finding.hosted.aggregate-lock.v1:'
                    || requested_tenant_id || ':' || requested_resource_family
                    || ':' || requested_resource_id,
                0
            )
        );
    ELSIF requested_resource_kind = 'job' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'chio.finding.hosted.retention-job-lock.v1:'
                    || requested_tenant_id || ':' || requested_resource_family
                    || ':' || requested_resource_id,
                0
            )
        );
    ELSE
        RETURN 2;
    END IF;
    SELECT hold_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_legal_hold_events
    WHERE tenant_id = requested_tenant_id
      AND hold_event_sha256 = requested_hold_event_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_hold_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = requested_tenant_id
          AND resource_kind = requested_resource_kind
          AND resource_family = requested_resource_family
          AND resource_id = requested_resource_id
    ) THEN
        RETURN 2;
    END IF;
    SELECT * INTO previous_hold
    FROM public.chio_finding_market_legal_hold_events
    WHERE tenant_id = requested_tenant_id
      AND hold_id = requested_hold_id
    ORDER BY created_at DESC, hold_event_sha256 DESC
    LIMIT 1;
    IF FOUND THEN
        IF requested_previous_hold_event_sha256 IS DISTINCT FROM previous_hold.hold_event_sha256
            OR requested_resource_kind <> previous_hold.resource_kind
            OR requested_resource_family <> previous_hold.resource_family
            OR requested_resource_id <> previous_hold.resource_id
            OR requested_action = previous_hold.action
            OR requested_created_at <= previous_hold.created_at
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_action <> 'placed'
        OR requested_previous_hold_event_sha256 IS NOT NULL
    THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_legal_hold_events (
        tenant_id, hold_event_sha256, hold_id, resource_kind,
        resource_family, resource_id, action, previous_hold_event_sha256,
        signer_key_hex, hold_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_hold_event_sha256, requested_hold_id,
        requested_resource_kind, requested_resource_family,
        requested_resource_id, requested_action,
        requested_previous_hold_event_sha256, requested_signer_key_hex,
        requested_hold_envelope_json, requested_created_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_quota_alert(requested_tenant_id text, requested_alert_sha256 text, requested_quota_kind text, requested_observed_value bigint, requested_limit_value bigint, requested_signer_key_hex text, requested_alert_envelope_json bytea, requested_created_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid quota alert request'
            USING ERRCODE = '42501';
    END IF;
    SELECT alert_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_quota_alerts
    WHERE tenant_id = requested_tenant_id
      AND alert_sha256 = requested_alert_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_alert_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_quota_alerts (
        tenant_id, alert_sha256, quota_kind, observed_value,
        limit_value, signer_key_hex, alert_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_alert_sha256, requested_quota_kind,
        requested_observed_value, requested_limit_value,
        requested_signer_key_hex, requested_alert_envelope_json,
        requested_created_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_replication_check(requested_tenant_id text, requested_check_sha256 text, requested_source_authority text, requested_authority_epoch bigint, requested_through_sequence bigint, requested_source_projection_sha256 text, requested_target_projection_sha256 text, requested_lag_seconds bigint, requested_projection_difference_count bigint, requested_security_counter_count bigint, requested_signer_key_hex text, requested_check_envelope_json bytea, requested_checked_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    retained_envelope BYTEA;
    previous_checked_at BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match replication check'
            USING ERRCODE = '42501';
    END IF;
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR SHARE;
    IF NOT FOUND
        OR authority_row.authority_epoch <> requested_authority_epoch
        OR requested_source_authority NOT IN ('sqlite', 'postgres')
        OR authority_row.authority <> requested_source_authority
        OR (CASE requested_source_authority
            WHEN 'sqlite' THEN authority_row.last_replication_sequence
            ELSE authority_row.last_outbox_sequence
           END) <> requested_through_sequence
        OR requested_checked_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_checked_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
    THEN
        RETURN 2;
    END IF;
    SELECT check_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_replication_checks
    WHERE tenant_id = requested_tenant_id
      AND check_sha256 = requested_check_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_check_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    SELECT MAX(checked_at) INTO previous_checked_at
    FROM public.chio_finding_market_replication_checks
    WHERE tenant_id = requested_tenant_id
      AND authority_epoch = requested_authority_epoch
      AND source_authority = requested_source_authority;
    IF previous_checked_at IS NOT NULL
        AND requested_checked_at < previous_checked_at
    THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_replication_checks (
        tenant_id, check_sha256, source_authority, authority_epoch,
        through_sequence, source_projection_sha256,
        target_projection_sha256, lag_seconds,
        projection_difference_count, security_counter_count,
        signer_key_hex, check_envelope_json, checked_at
    ) VALUES (
        requested_tenant_id, requested_check_sha256,
        requested_source_authority, requested_authority_epoch,
        requested_through_sequence, requested_source_projection_sha256,
        requested_target_projection_sha256, requested_lag_seconds,
        requested_projection_difference_count, requested_security_counter_count,
        requested_signer_key_hex, requested_check_envelope_json,
        requested_checked_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_append_restore_verification(requested_tenant_id text, requested_verification_sha256 text, requested_archive_sha256 text, requested_restored_resource_sha256 text, requested_signer_key_hex text, requested_verification_envelope_json bytea, requested_verified_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    retained_envelope BYTEA;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'invalid restore verification request'
            USING ERRCODE = '42501';
    END IF;
    SELECT verification_envelope_json INTO retained_envelope
    FROM public.chio_finding_market_restore_verifications
    WHERE tenant_id = requested_tenant_id
      AND verification_sha256 = requested_verification_sha256;
    IF FOUND THEN
        IF retained_envelope = requested_verification_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_restore_verifications (
        tenant_id, verification_sha256, archive_sha256,
        restored_resource_sha256, signer_key_hex,
        verification_envelope_json, verified_at
    ) VALUES (
        requested_tenant_id, requested_verification_sha256,
        requested_archive_sha256, requested_restored_resource_sha256,
        requested_signer_key_hex, requested_verification_envelope_json,
        requested_verified_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_apply_authority_transition(requested_tenant_id text, requested_transition_sha256 text, requested_operation text, requested_from_authority text, requested_to_authority text, requested_from_epoch bigint, requested_to_epoch bigint, requested_through_sequence bigint, requested_source_checkpoint_sha256 text, requested_target_checkpoint_sha256 text, requested_configuration_revision text, requested_rollback_window_ends_at bigint, requested_signer_key_hex text, requested_transition_envelope_json bytea, requested_created_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    latest_check public.chio_finding_market_replication_checks%ROWTYPE;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match authority transition'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.authority.v1:' || requested_tenant_id,
        0
    ));
    IF EXISTS (
        SELECT 1 FROM public.chio_finding_market_authority_transitions
        WHERE tenant_id = requested_tenant_id
          AND transition_sha256 = requested_transition_sha256
          AND transition_envelope_json = requested_transition_envelope_json
    ) THEN
        RETURN 1;
    END IF;
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF NOT FOUND
        OR authority_row.authority <> requested_from_authority
        OR authority_row.authority_epoch <> requested_from_epoch
        OR requested_to_epoch <> requested_from_epoch + 1
        OR authority_row.configuration_revision <> requested_configuration_revision
        OR (CASE requested_from_authority
            WHEN 'sqlite' THEN authority_row.last_replication_sequence
            WHEN 'postgres' THEN authority_row.last_outbox_sequence
            ELSE -1
           END) <> requested_through_sequence
    THEN
        RETURN 2;
    END IF;
    SELECT * INTO latest_check
    FROM public.chio_finding_market_replication_checks
    WHERE tenant_id = requested_tenant_id
      AND authority_epoch = requested_from_epoch
      AND source_authority = requested_from_authority
    ORDER BY through_sequence DESC, checked_at DESC, check_sha256 DESC
    LIMIT 1;
    IF NOT FOUND
        OR latest_check.through_sequence <> requested_through_sequence
        OR latest_check.source_projection_sha256 <> latest_check.target_projection_sha256
        OR latest_check.target_projection_sha256 <> requested_target_checkpoint_sha256
        OR latest_check.lag_seconds <> 0
        OR latest_check.checked_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR latest_check.checked_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
        OR latest_check.projection_difference_count <> 0
        OR latest_check.security_counter_count <> 0
        OR requested_source_checkpoint_sha256 <> requested_target_checkpoint_sha256
        OR requested_created_at < latest_check.checked_at
        OR requested_created_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_created_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
    THEN
        RETURN 2;
    END IF;
    IF requested_operation = 'freeze' THEN
        IF requested_from_authority <> requested_to_authority
            OR authority_row.mode NOT IN ('shadow', 'rollback_window', 'authoritative')
            OR requested_rollback_window_ends_at IS NOT NULL
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority_epoch = requested_to_epoch, mode = 'frozen',
            mutations_enabled = FALSE, transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSIF requested_operation = 'cutover' THEN
        IF requested_from_authority <> 'sqlite'
            OR requested_to_authority <> 'postgres'
            OR authority_row.mode <> 'frozen'
            OR requested_rollback_window_ends_at <> requested_created_at + 604800
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority = 'postgres', authority_epoch = requested_to_epoch,
            mode = 'rollback_window', mutations_enabled = TRUE,
            rollback_window_ends_at = requested_rollback_window_ends_at,
            transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSIF requested_operation = 'rollback' THEN
        IF requested_from_authority <> 'postgres'
            OR requested_to_authority <> 'sqlite'
            OR authority_row.mode <> 'frozen'
            OR authority_row.rollback_window_ends_at IS NULL
            OR requested_created_at > authority_row.rollback_window_ends_at
            OR requested_rollback_window_ends_at IS NOT NULL
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority = 'sqlite', authority_epoch = requested_to_epoch,
            mode = 'shadow', mutations_enabled = TRUE,
            rollback_window_ends_at = NULL,
            transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSIF requested_operation = 'retire_sqlite' THEN
        IF requested_from_authority <> 'postgres'
            OR requested_to_authority <> 'postgres'
            OR authority_row.mode <> 'rollback_window'
            OR authority_row.rollback_window_ends_at IS NULL
            OR clock_timestamp() < to_timestamp(authority_row.rollback_window_ends_at)
            OR requested_rollback_window_ends_at IS NOT NULL
        THEN RETURN 2; END IF;
        UPDATE public.chio_finding_market_authority_state
        SET authority_epoch = requested_to_epoch, mode = 'retired',
            mutations_enabled = TRUE, transition_sha256 = requested_transition_sha256,
            updated_at = requested_created_at
        WHERE tenant_id = requested_tenant_id;
    ELSE
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_authority_transitions (
        tenant_id, transition_sha256, operation, from_authority,
        to_authority, from_epoch, to_epoch, through_sequence,
        source_checkpoint_sha256, target_checkpoint_sha256,
        configuration_revision, rollback_window_ends_at, signer_key_hex,
        transition_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_transition_sha256,
        requested_operation, requested_from_authority,
        requested_to_authority, requested_from_epoch, requested_to_epoch,
        requested_through_sequence, requested_source_checkpoint_sha256,
        requested_target_checkpoint_sha256, requested_configuration_revision,
        requested_rollback_window_ends_at, requested_signer_key_hex,
        requested_transition_envelope_json, requested_created_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_apply_principal_event(requested_tenant_id text, requested_event_sha256 text, requested_principal_id text, requested_operation text, requested_role text, requested_capability_public_key_hex text, requested_overlap_expires_at bigint, requested_previous_event_sha256 text, requested_signer_key_hex text, requested_event_envelope_json bytea, requested_created_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    principal_event public.chio_finding_market_principal_events%ROWTYPE;
    lifecycle_outcome SMALLINT;
    authority_found BOOLEAN;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match principal event'
            USING ERRCODE = '42501';
    END IF;
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    authority_found := FOUND;
    SELECT * INTO principal_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND event_sha256 = requested_event_sha256;
    IF FOUND THEN
        IF principal_event.principal_id = requested_principal_id
            AND principal_event.operation = requested_operation
            AND principal_event.role = requested_role
            AND principal_event.capability_public_key_hex IS NOT DISTINCT FROM requested_capability_public_key_hex
            AND principal_event.overlap_expires_at IS NOT DISTINCT FROM requested_overlap_expires_at
            AND principal_event.previous_event_sha256 IS NOT DISTINCT FROM requested_previous_event_sha256
            AND principal_event.signer_key_hex = requested_signer_key_hex
            AND principal_event.event_envelope_json = requested_event_envelope_json
            AND principal_event.created_at = requested_created_at
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR NOT authority_found
        OR authority_row.authority <> 'postgres'
        OR authority_row.mutations_enabled <> TRUE
        OR authority_row.mode NOT IN ('rollback_window', 'authoritative', 'retired')
        OR requested_created_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
        OR requested_created_at < floor(extract(epoch from clock_timestamp()))::bigint - 30
        OR NOT EXISTS (
            SELECT 1
            FROM (
                SELECT replication_check.*
                FROM public.chio_finding_market_replication_checks AS replication_check
                WHERE replication_check.tenant_id = requested_tenant_id
                  AND replication_check.authority_epoch = authority_row.authority_epoch
                  AND replication_check.source_authority = 'postgres'
                ORDER BY replication_check.through_sequence DESC,
                         replication_check.checked_at DESC,
                         replication_check.check_sha256 DESC
                LIMIT 1
            ) AS replication_check
            WHERE replication_check.source_projection_sha256 = replication_check.target_projection_sha256
              AND replication_check.through_sequence = authority_row.last_outbox_sequence
              AND replication_check.lag_seconds <= 30
              AND replication_check.checked_at <= floor(extract(epoch from clock_timestamp()))::bigint + 30
              AND replication_check.checked_at >= floor(extract(epoch from clock_timestamp()))::bigint - 30
              AND replication_check.projection_difference_count = 0
              AND replication_check.security_counter_count = 0
        )
    THEN
        RETURN 2;
    END IF;
    lifecycle_outcome := public.chio_finding_market_apply_principal_event_unfenced(
        requested_tenant_id, requested_event_sha256, requested_principal_id,
        requested_operation, requested_role, requested_capability_public_key_hex,
        requested_overlap_expires_at, requested_previous_event_sha256,
        requested_signer_key_hex, requested_event_envelope_json,
        requested_created_at
    );
    IF lifecycle_outcome <> 0 OR authority_row.mode <> 'rollback_window' THEN
        RETURN lifecycle_outcome;
    END IF;
    SELECT * INTO principal_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND event_sha256 = requested_event_sha256;
    IF NOT FOUND THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_principal_replication_outbox (
        tenant_id, authority_epoch, sequence, principal_event_sha256,
        principal_id, operation, role, capability_public_key_hex,
        overlap_expires_at, previous_event_sha256, signer_key_hex,
        event_envelope_json, committed_at
    ) VALUES (
        requested_tenant_id, authority_row.authority_epoch,
        authority_row.last_outbox_sequence + 1, principal_event.event_sha256,
        principal_event.principal_id, principal_event.operation,
        principal_event.role, principal_event.capability_public_key_hex,
        principal_event.overlap_expires_at, principal_event.previous_event_sha256,
        principal_event.signer_key_hex, principal_event.event_envelope_json,
        requested_created_at
    );
    UPDATE public.chio_finding_market_authority_state
    SET last_outbox_sequence = last_outbox_sequence + 1,
        updated_at = requested_created_at
    WHERE tenant_id = requested_tenant_id;
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_apply_principal_event_unfenced(requested_tenant_id text, requested_event_sha256 text, requested_principal_id text, requested_operation text, requested_role text, requested_capability_public_key_hex text, requested_overlap_expires_at bigint, requested_previous_event_sha256 text, requested_signer_key_hex text, requested_event_envelope_json bytea, requested_created_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    previous_event public.chio_finding_market_principal_events%ROWTYPE;
    existing_event public.chio_finding_market_principal_events%ROWTYPE;
    principal_row public.chio_finding_market_principals%ROWTYPE;
    principal_exists BOOLEAN;
    requested_enabled BOOLEAN;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match principal event'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.principal-lifecycle.v1:'
            || requested_tenant_id || ':' || requested_principal_id,
        0
    ));
    SELECT * INTO existing_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND event_sha256 = requested_event_sha256;
    IF FOUND THEN
        IF existing_event.principal_id = requested_principal_id
            AND existing_event.operation = requested_operation
            AND existing_event.role = requested_role
            AND existing_event.capability_public_key_hex IS NOT DISTINCT FROM requested_capability_public_key_hex
            AND existing_event.overlap_expires_at IS NOT DISTINCT FROM requested_overlap_expires_at
            AND existing_event.previous_event_sha256 IS NOT DISTINCT FROM requested_previous_event_sha256
            AND existing_event.signer_key_hex = requested_signer_key_hex
            AND existing_event.event_envelope_json = requested_event_envelope_json
            AND existing_event.created_at = requested_created_at
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    SELECT * INTO previous_event
    FROM public.chio_finding_market_principal_events
    WHERE tenant_id = requested_tenant_id
      AND principal_id = requested_principal_id
    ORDER BY created_at DESC, event_sha256 DESC
    LIMIT 1;
    principal_exists := FOUND;
    SELECT * INTO principal_row
    FROM public.chio_finding_market_principals
    WHERE tenant_id = requested_tenant_id
      AND principal_id = requested_principal_id
    FOR UPDATE;
    IF FOUND <> principal_exists THEN
        RETURN 2;
    END IF;
    IF requested_operation = 'provision' THEN
        IF principal_exists OR requested_previous_event_sha256 IS NOT NULL THEN
            RETURN 2;
        END IF;
        requested_enabled := TRUE;
    ELSE
        IF NOT principal_exists
            OR previous_event.event_sha256 IS DISTINCT FROM requested_previous_event_sha256
            OR requested_created_at <= previous_event.created_at
        THEN
            RETURN 2;
        END IF;
        requested_enabled := principal_row.enabled;
    END IF;
    IF requested_operation = 'key_rotation' THEN
        IF NOT principal_row.enabled
            OR requested_role <> principal_row.role
            OR previous_event.capability_public_key_hex IS NULL
            OR requested_capability_public_key_hex IS NULL
            OR principal_row.capability_public_key_hex IS DISTINCT FROM previous_event.capability_public_key_hex
            OR principal_row.capability_public_key_hex = requested_capability_public_key_hex
            OR requested_overlap_expires_at IS NULL
            OR requested_overlap_expires_at <= requested_created_at
            OR requested_overlap_expires_at > requested_created_at + 86400
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_operation = 'role_change' THEN
        IF NOT principal_row.enabled
            OR requested_role = principal_row.role
            OR requested_capability_public_key_hex IS DISTINCT FROM principal_row.capability_public_key_hex
        THEN
            RETURN 2;
        END IF;
    ELSIF requested_operation IN ('disable', 'emergency_revoke') THEN
        IF NOT principal_row.enabled
            OR requested_role <> principal_row.role
            OR requested_capability_public_key_hex IS DISTINCT FROM principal_row.capability_public_key_hex
        THEN
            RETURN 2;
        END IF;
        requested_enabled := FALSE;
    ELSIF requested_overlap_expires_at IS NOT NULL THEN
        RETURN 2;
    END IF;
    IF requested_capability_public_key_hex IS NOT NULL
        AND requested_operation IN ('provision', 'key_rotation')
        AND (
            EXISTS (
                SELECT 1 FROM public.chio_finding_market_principals
                WHERE tenant_id = requested_tenant_id
                  AND capability_public_key_hex = requested_capability_public_key_hex
                  AND principal_id <> requested_principal_id
            )
            OR EXISTS (
                SELECT 1
                FROM public.chio_finding_market_principal_key_overlaps
                WHERE tenant_id = requested_tenant_id
                  AND capability_public_key_hex = requested_capability_public_key_hex
                  AND valid_through >= requested_created_at
            )
        )
    THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_principal_events (
        tenant_id, event_sha256, principal_id, operation, role,
        capability_public_key_hex, overlap_expires_at,
        previous_event_sha256, signer_key_hex,
        event_envelope_json, created_at
    ) VALUES (
        requested_tenant_id, requested_event_sha256,
        requested_principal_id, requested_operation, requested_role,
        requested_capability_public_key_hex, requested_overlap_expires_at,
        requested_previous_event_sha256,
        requested_signer_key_hex, requested_event_envelope_json,
        requested_created_at
    );
    INSERT INTO public.chio_finding_market_principals (
        tenant_id, principal_id, role, capability_public_key_hex,
        enabled, created_at, updated_at
    ) VALUES (
        requested_tenant_id, requested_principal_id, requested_role,
        requested_capability_public_key_hex, requested_enabled,
        requested_created_at, requested_created_at
    )
    ON CONFLICT (tenant_id, principal_id)
    DO UPDATE SET
        role = EXCLUDED.role,
        capability_public_key_hex = EXCLUDED.capability_public_key_hex,
        enabled = EXCLUDED.enabled,
        updated_at = EXCLUDED.updated_at;
    IF requested_operation = 'key_rotation' THEN
        INSERT INTO public.chio_finding_market_principal_key_overlaps (
            tenant_id, principal_id, capability_public_key_hex,
            lifecycle_event_sha256, valid_through
        ) VALUES (
            requested_tenant_id, requested_principal_id,
            previous_event.capability_public_key_hex,
            requested_event_sha256, requested_overlap_expires_at
        );
    END IF;
    IF requested_operation IN ('disable', 'emergency_revoke') THEN
        UPDATE public.chio_finding_market_api_keys
        SET revoked_at = requested_created_at
        WHERE tenant_id = requested_tenant_id
          AND principal_id = requested_principal_id
          AND revoked_at IS NULL;
    END IF;
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_apply_principal_replication_event(requested_tenant_id text, requested_replication_event_sha256 text, requested_source_authority text, requested_authority_epoch bigint, requested_sequence bigint, requested_principal_event_sha256 text, requested_principal_id text, requested_operation text, requested_role text, requested_capability_public_key_hex text, requested_overlap_expires_at bigint, requested_previous_event_sha256 text, requested_principal_signer_key_hex text, requested_principal_event_envelope_json bytea, requested_source_signer_key_hex text, requested_replication_event_envelope_json bytea, requested_committed_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    existing_event public.chio_finding_market_principal_replication_events%ROWTYPE;
    lifecycle_outcome SMALLINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match principal replication event'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.replication.v1:' || requested_tenant_id,
        0
    ));
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF NOT FOUND
        OR authority_row.authority <> 'sqlite'
        OR authority_row.mode NOT IN ('shadow', 'frozen')
        OR authority_row.authority_epoch <> requested_authority_epoch
        OR requested_source_authority <> 'sqlite'
        OR requested_committed_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
    THEN
        RETURN 2;
    END IF;
    SELECT * INTO existing_event
    FROM public.chio_finding_market_principal_replication_events
    WHERE tenant_id = requested_tenant_id
      AND replication_event_sha256 = requested_replication_event_sha256;
    IF FOUND THEN
        IF existing_event.replication_event_envelope_json = requested_replication_event_envelope_json
            AND existing_event.principal_event_envelope_json = requested_principal_event_envelope_json
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_sequence <> authority_row.last_replication_sequence + 1
        OR EXISTS (
            SELECT 1
            FROM public.chio_finding_market_principal_replication_events
            WHERE tenant_id = requested_tenant_id
              AND principal_event_sha256 = requested_principal_event_sha256
        )
    THEN
        RETURN 2;
    END IF;
    lifecycle_outcome := public.chio_finding_market_apply_principal_event_unfenced(
        requested_tenant_id, requested_principal_event_sha256,
        requested_principal_id, requested_operation, requested_role,
        requested_capability_public_key_hex, requested_overlap_expires_at,
        requested_previous_event_sha256, requested_principal_signer_key_hex,
        requested_principal_event_envelope_json, requested_committed_at
    );
    IF lifecycle_outcome <> 0 THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_principal_replication_events (
        tenant_id, replication_event_sha256, source_authority,
        authority_epoch, sequence, principal_event_sha256, principal_id,
        operation, role, capability_public_key_hex, overlap_expires_at,
        previous_event_sha256, principal_signer_key_hex,
        principal_event_envelope_json, source_signer_key_hex,
        replication_event_envelope_json, committed_at
    ) VALUES (
        requested_tenant_id, requested_replication_event_sha256,
        requested_source_authority, requested_authority_epoch,
        requested_sequence, requested_principal_event_sha256,
        requested_principal_id, requested_operation, requested_role,
        requested_capability_public_key_hex, requested_overlap_expires_at,
        requested_previous_event_sha256, requested_principal_signer_key_hex,
        requested_principal_event_envelope_json, requested_source_signer_key_hex,
        requested_replication_event_envelope_json, requested_committed_at
    );
    UPDATE public.chio_finding_market_authority_state
    SET last_replication_sequence = requested_sequence,
        updated_at = requested_committed_at
    WHERE tenant_id = requested_tenant_id;
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_apply_replication_event(requested_tenant_id text, requested_replication_event_sha256 text, requested_source_authority text, requested_authority_epoch bigint, requested_sequence bigint, requested_aggregate_kind text, requested_aggregate_id text, requested_expected_revision bigint, requested_expected_event_sha256 text, requested_event_id text, requested_event_kind text, requested_artifact_schema text, requested_payload_sha256 text, requested_payload_json bytea, requested_event_sha256 text, requested_signer_key_hex text, requested_event_envelope_json bytea, requested_committed_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    authority_row public.chio_finding_market_authority_state%ROWTYPE;
    existing_event public.chio_finding_market_replication_events%ROWTYPE;
    append_outcome SMALLINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match replication event'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'chio.finding.hosted.replication.v1:' || requested_tenant_id,
        0
    ));
    SELECT * INTO authority_row
    FROM public.chio_finding_market_authority_state
    WHERE tenant_id = requested_tenant_id
    FOR UPDATE;
    IF NOT FOUND
        OR authority_row.authority <> 'sqlite'
        OR authority_row.mode NOT IN ('shadow', 'frozen')
        OR authority_row.authority_epoch <> requested_authority_epoch
        OR requested_source_authority <> 'sqlite'
        OR requested_committed_at > floor(extract(epoch from clock_timestamp()))::bigint + 30
    THEN
        RETURN 2;
    END IF;
    SELECT * INTO existing_event
    FROM public.chio_finding_market_replication_events
    WHERE tenant_id = requested_tenant_id
      AND replication_event_sha256 = requested_replication_event_sha256;
    IF FOUND THEN
        IF existing_event.event_envelope_json = requested_event_envelope_json THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF requested_sequence <> authority_row.last_replication_sequence + 1
        OR NOT EXISTS (
            SELECT 1 FROM public.chio_finding_market_domain_event_contracts
            WHERE aggregate_kind = requested_aggregate_kind
              AND event_kind = requested_event_kind
              AND artifact_schema = requested_artifact_schema
        )
    THEN
        RETURN 2;
    END IF;
    append_outcome := public.chio_finding_market_append_aggregate_event(
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, requested_expected_revision,
        requested_expected_event_sha256, requested_event_id,
        requested_event_kind, requested_payload_sha256,
        requested_payload_json, requested_event_sha256,
        requested_committed_at
    );
    IF append_outcome = 2 THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_domain_projections (
        tenant_id, aggregate_kind, aggregate_id, revision, event_sha256,
        event_kind, artifact_schema, payload_sha256, payload_json, updated_at
    ) VALUES (
        requested_tenant_id, requested_aggregate_kind,
        requested_aggregate_id, requested_expected_revision + 1,
        requested_event_sha256, requested_event_kind,
        requested_artifact_schema, requested_payload_sha256,
        requested_payload_json, requested_committed_at
    )
    ON CONFLICT (tenant_id, aggregate_kind, aggregate_id)
    DO UPDATE SET revision = EXCLUDED.revision,
                  event_sha256 = EXCLUDED.event_sha256,
                  event_kind = EXCLUDED.event_kind,
                  artifact_schema = EXCLUDED.artifact_schema,
                  payload_sha256 = EXCLUDED.payload_sha256,
                  payload_json = EXCLUDED.payload_json,
                  updated_at = EXCLUDED.updated_at;
    INSERT INTO public.chio_finding_market_replication_events (
        tenant_id, replication_event_sha256, source_authority,
        authority_epoch, sequence, aggregate_kind, aggregate_id,
        event_id, event_kind, artifact_schema, expected_revision,
        expected_event_sha256, payload_sha256, payload_json,
        signer_key_hex, event_envelope_json, committed_at
    ) VALUES (
        requested_tenant_id, requested_replication_event_sha256,
        requested_source_authority, requested_authority_epoch,
        requested_sequence, requested_aggregate_kind,
        requested_aggregate_id, requested_event_id,
        requested_event_kind, requested_artifact_schema,
        requested_expected_revision, requested_expected_event_sha256,
        requested_payload_sha256, requested_payload_json,
        requested_signer_key_hex, requested_event_envelope_json,
        requested_committed_at
    );
    UPDATE public.chio_finding_market_authority_state
    SET last_replication_sequence = requested_sequence,
        updated_at = requested_committed_at
    WHERE tenant_id = requested_tenant_id;
    RETURN append_outcome;
END
$$;

CREATE FUNCTION public.chio_finding_market_claim_jobs(requested_tenant_id text, requested_worker_id text, requested_lease_duration_secs bigint, requested_limit bigint) RETURNS SETOF public.chio_finding_market_jobs
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
DECLARE
    configured_limit BIGINT;
    active_leases BIGINT;
    available_slots BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR requested_worker_id IS NULL
        OR octet_length(requested_worker_id) NOT BETWEEN 1 AND 256
        OR requested_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR requested_lease_duration_secs NOT BETWEEN 1 AND 3600
        OR requested_limit NOT BETWEEN 1 AND 100
    THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(requested_tenant_id, 2));
    SELECT max_concurrent_jobs INTO configured_limit
    FROM public.chio_finding_market_tenants
    WHERE tenant_id = requested_tenant_id AND enabled
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT COUNT(*) INTO active_leases
    FROM public.chio_finding_market_jobs
    WHERE tenant_id = requested_tenant_id
      AND state = 'leased'
      AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint;
    available_slots := configured_limit - active_leases;
    IF available_slots <= 0 THEN
        RETURN;
    END IF;
    RETURN QUERY
    WITH clock AS (
        SELECT floor(extract(epoch from clock_timestamp()))::bigint AS now_secs
    ), due AS (
        SELECT jobs.tenant_id, jobs.job_id
        FROM public.chio_finding_market_jobs AS jobs CROSS JOIN clock
        WHERE jobs.tenant_id = requested_tenant_id
          AND jobs.available_at <= clock.now_secs
          AND (
              jobs.state IN ('pending', 'failed')
              OR (jobs.state = 'leased' AND jobs.lease_expires_at <= clock.now_secs)
          )
        ORDER BY jobs.available_at, jobs.created_at, jobs.job_id
        FOR UPDATE OF jobs SKIP LOCKED
        LIMIT LEAST(available_slots, requested_limit)
    )
    UPDATE public.chio_finding_market_jobs AS jobs
    SET state = 'leased', lease_owner = requested_worker_id,
        lease_expires_at = clock.now_secs + requested_lease_duration_secs,
        attempt_count = jobs.attempt_count + 1,
        lease_fence = jobs.lease_fence + 1,
        updated_at = clock.now_secs,
        last_error_code = NULL
    FROM due CROSS JOIN clock
    WHERE jobs.tenant_id = due.tenant_id AND jobs.job_id = due.job_id
    RETURNING jobs.*;
END
$_$;

CREATE FUNCTION public.chio_finding_market_complete_job(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_result_sha256 text, requested_result_json bytea) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
DECLARE
    retained public.chio_finding_market_jobs%ROWTYPE;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
        OR requested_result_sha256 !~ '^[0-9a-f]{64}$'
        OR requested_result_json IS NULL
        OR octet_length(requested_result_json) NOT BETWEEN 1 AND 4194304
        OR requested_result_sha256 <> encode(sha256(requested_result_json), 'hex')
    THEN
        RETURN 4;
    END IF;
    PERFORM 1
    FROM public.chio_finding_market_tenants
    WHERE tenant_id = requested_tenant_id AND enabled
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN 4;
    END IF;
    SELECT * INTO retained
    FROM public.chio_finding_market_jobs
    WHERE tenant_id = requested_tenant_id AND job_id = requested_job_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 3;
    END IF;
    IF retained.state = 'completed' THEN
        IF retained.result_sha256 = requested_result_sha256
            AND retained.result_json = requested_result_json
        THEN
            RETURN 1;
        END IF;
        RETURN 2;
    END IF;
    IF retained.state <> 'leased'
        OR retained.lease_owner <> requested_worker_id
        OR retained.lease_fence <> requested_lease_fence
        OR retained.lease_expires_at <= floor(extract(epoch from clock_timestamp()))::bigint
    THEN
        RETURN 4;
    END IF;
    UPDATE public.chio_finding_market_jobs
    SET state = 'completed', lease_owner = NULL, lease_expires_at = NULL,
        result_sha256 = requested_result_sha256,
        result_json = requested_result_json,
        updated_at = floor(extract(epoch from clock_timestamp()))::bigint
    WHERE tenant_id = requested_tenant_id AND job_id = requested_job_id
      AND state = 'leased' AND lease_owner = requested_worker_id
      AND lease_fence = requested_lease_fence
      AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint;
    IF NOT FOUND THEN
        RETURN 4;
    END IF;
    RETURN 0;
END
$_$;

CREATE FUNCTION public.chio_finding_market_derive_status_subject() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF NEW.aggregate_kind IN ('retraction', 'enforcement') THEN
        NEW.subject_finding_id := convert_from(NEW.payload_json, 'UTF8')::jsonb
            #>> '{body,finding_id}';
    ELSE
        NEW.subject_finding_id := NULL;
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.chio_finding_market_exhaust_job(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_error_code text) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    ), changed AS (
        UPDATE public.chio_finding_market_jobs
        SET state = 'exhausted', lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = requested_error_code,
            updated_at = floor(extract(epoch from clock_timestamp()))::bigint
        WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
          AND EXISTS (SELECT 1 FROM enabled_tenant)
          AND requested_error_code ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND tenant_id = requested_tenant_id AND job_id = requested_job_id
          AND state = 'leased' AND lease_owner = requested_worker_id
          AND lease_fence = requested_lease_fence
          AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint
        RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$_$;

CREATE FUNCTION public.chio_finding_market_fail_job(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_error_code text, requested_retry_delay_secs bigint) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $_$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    ), changed AS (
        UPDATE public.chio_finding_market_jobs
        SET state = 'failed', lease_owner = NULL, lease_expires_at = NULL,
            last_error_code = requested_error_code,
            available_at = floor(extract(epoch from clock_timestamp()))::bigint
                + requested_retry_delay_secs,
            updated_at = floor(extract(epoch from clock_timestamp()))::bigint
        WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
          AND EXISTS (SELECT 1 FROM enabled_tenant)
          AND requested_retry_delay_secs BETWEEN 1 AND 3600
          AND requested_error_code ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND tenant_id = requested_tenant_id AND job_id = requested_job_id
          AND state = 'leased' AND lease_owner = requested_worker_id
          AND lease_fence = requested_lease_fence
          AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint
        RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$_$;

CREATE FUNCTION public.chio_finding_market_gc_retained_resource(requested_tenant_id text, requested_archive_sha256 text, requested_resource_kind text, requested_resource_family text, requested_resource_id text, requested_resource_revision bigint, requested_resource_sha256 text, requested_receipt_sha256 text, requested_signer_key_hex text, requested_receipt_envelope_json bytea, requested_completed_at bigint) RETURNS smallint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    archive_row public.chio_finding_market_archive_manifests%ROWTYPE;
    current_aggregate_revision BIGINT;
    current_aggregate_sha256 TEXT;
    removed_count BIGINT;
BEGIN
    IF requested_tenant_id IS NULL
        OR requested_tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match retention request'
            USING ERRCODE = '42501';
    END IF;
    IF requested_resource_kind = 'aggregate' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'chio.finding.hosted.aggregate-lock.v1:'
                    || requested_tenant_id || ':' || requested_resource_family
                    || ':' || requested_resource_id,
                0
            )
        );
    ELSIF requested_resource_kind = 'job' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(requested_tenant_id, 0)
        );
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'chio.finding.hosted.retention-job-lock.v1:'
                    || requested_tenant_id || ':' || requested_resource_family
                    || ':' || requested_resource_id,
                0
            )
        );
    ELSE
        RETURN 2;
    END IF;
    SELECT * INTO archive_row
    FROM public.chio_finding_market_archive_manifests
    WHERE tenant_id = requested_tenant_id
      AND archive_sha256 = requested_archive_sha256
      AND resource_kind = requested_resource_kind
      AND resource_family = requested_resource_family
      AND resource_id = requested_resource_id
      AND resource_revision = requested_resource_revision
      AND resource_sha256 = requested_resource_sha256;
    IF NOT FOUND THEN
        RETURN 2;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM public.chio_finding_market_journal_checkpoint_members
        WHERE tenant_id = requested_tenant_id
          AND checkpoint_sha256 = archive_row.covered_checkpoint_sha256
          AND member_kind = requested_resource_kind
          AND member_family = requested_resource_family
          AND member_id = requested_resource_id
          AND member_revision = archive_row.resource_revision
          AND member_sha256 = archive_row.resource_sha256
    ) THEN
        RETURN 2;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM public.chio_finding_market_restore_verifications
        WHERE tenant_id = requested_tenant_id
          AND archive_sha256 = requested_archive_sha256
          AND restored_resource_sha256 = archive_row.resource_sha256
          AND verified_at <= requested_completed_at
    ) THEN
        RETURN 2;
    END IF;
    IF requested_completed_at < archive_row.created_at THEN
        RETURN 2;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (hold_id) action, created_at
            FROM public.chio_finding_market_legal_hold_events
            WHERE tenant_id = requested_tenant_id
              AND resource_kind = requested_resource_kind
              AND resource_family = requested_resource_family
              AND resource_id = requested_resource_id
            ORDER BY hold_id, created_at DESC, hold_event_sha256 DESC
        ) AS latest_holds
        WHERE action = 'placed'
    ) THEN
        RETURN 3;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_legal_hold_events
        WHERE tenant_id = requested_tenant_id
          AND resource_kind = requested_resource_kind
          AND resource_family = requested_resource_family
          AND resource_id = requested_resource_id
          AND created_at > requested_completed_at
    ) THEN
        RETURN 2;
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = requested_tenant_id
          AND receipt_sha256 = requested_receipt_sha256
    ) THEN
        RETURN 1;
    END IF;
    IF requested_resource_kind = 'job' THEN
        DELETE FROM public.chio_finding_market_jobs
        WHERE tenant_id = requested_tenant_id
          AND job_kind = requested_resource_family
          AND job_id = requested_resource_id
          AND state IN ('completed', 'exhausted');
        GET DIAGNOSTICS removed_count = ROW_COUNT;
    ELSIF requested_resource_kind = 'aggregate' THEN
        SELECT revision, event_sha256
        INTO current_aggregate_revision, current_aggregate_sha256
        FROM public.chio_finding_market_aggregate_heads
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id
        FOR UPDATE;
        IF NOT FOUND
            OR current_aggregate_revision <> requested_resource_revision
            OR current_aggregate_sha256 IS DISTINCT FROM requested_resource_sha256
        THEN
            RETURN 2;
        END IF;
        DELETE FROM public.chio_finding_market_aggregate_checkpoints
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id;
        DELETE FROM public.chio_finding_market_aggregate_heads
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id;
        DELETE FROM public.chio_finding_market_aggregate_events
        WHERE tenant_id = requested_tenant_id
          AND aggregate_kind = requested_resource_family
          AND aggregate_id = requested_resource_id;
        GET DIAGNOSTICS removed_count = ROW_COUNT;
    ELSE
        RETURN 2;
    END IF;
    IF removed_count = 0 THEN
        RETURN 2;
    END IF;
    INSERT INTO public.chio_finding_market_gc_receipts (
        tenant_id, receipt_sha256, archive_sha256, resource_kind,
        resource_family, resource_id, signer_key_hex,
        receipt_envelope_json, completed_at
    ) VALUES (
        requested_tenant_id, requested_receipt_sha256,
        requested_archive_sha256, requested_resource_kind,
        requested_resource_family, requested_resource_id,
        requested_signer_key_hex, requested_receipt_envelope_json,
        requested_completed_at
    );
    RETURN 0;
END
$$;

CREATE FUNCTION public.chio_finding_market_guard_domain_projection_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF session_user <> current_user
       AND current_user = pg_get_userbyid((
           SELECT relowner FROM pg_class WHERE oid = TG_RELID
       ))
    THEN
        IF TG_OP = 'UPDATE'
           AND NEW.tenant_id = OLD.tenant_id
           AND NEW.aggregate_kind = OLD.aggregate_kind
           AND NEW.aggregate_id = OLD.aggregate_id
           AND NEW.revision = OLD.revision + 1
           AND NEW.updated_at >= OLD.updated_at
        THEN
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'cognition-market domain projection cannot be mutated directly'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION public.chio_finding_market_initialize_authority_state() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    INSERT INTO public.chio_finding_market_authority_state (
        tenant_id, authority, authority_epoch, mode, mutations_enabled,
        last_replication_sequence, last_outbox_sequence, rollback_window_ends_at,
        configuration_revision, transition_sha256, updated_at
    ) VALUES (
        NEW.tenant_id, 'sqlite', 1, 'shadow', TRUE, 0, 0, NULL,
        NEW.configuration_revision, NULL, NEW.created_at
    );
    RETURN NEW;
END
$$;

CREATE FUNCTION public.chio_finding_market_maintain_dpop_live_nonces() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    subject TEXT;
    delta BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        subject := NEW.tenant_id;
        delta := 1;
    ELSE
        subject := OLD.tenant_id;
        delta := -1;
    END IF;
    INSERT INTO public.chio_finding_market_dpop_admission_state
        (tenant_id, live_nonces, last_swept_at)
    VALUES (subject, 0, 0)
    ON CONFLICT (tenant_id) DO NOTHING;
    -- This counter clamps where the spend accumulator denies, because the
    -- expiry sweep deletes a tenant's stale nonces and then resets this
    -- counter from an exact count. Raising here would fail the statement
    -- that repairs the skew; an undercount survives only until that sweep.
    UPDATE public.chio_finding_market_dpop_admission_state
    SET live_nonces = GREATEST(live_nonces + delta, 0)
    WHERE tenant_id = subject;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.chio_finding_market_maintain_request_bindings() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    subject TEXT;
    delta BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        subject := NEW.tenant_id;
        delta := 1;
    ELSE
        subject := OLD.tenant_id;
        delta := -1;
    END IF;
    INSERT INTO public.chio_finding_market_dpop_admission_state
        (tenant_id, live_nonces, last_swept_at)
    VALUES (subject, 0, 0)
    ON CONFLICT (tenant_id) DO NOTHING;
    -- Clamped for the same reason as the nonce counter: the expiry sweep
    -- re-derives it from an exact count, and raising here would fail the
    -- statement that repairs the skew.
    UPDATE public.chio_finding_market_dpop_admission_state
    SET live_request_bindings = GREATEST(live_request_bindings + delta, 0)
    WHERE tenant_id = subject;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.chio_finding_market_maintain_spend_period() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
DECLARE
    charged BIGINT := 0;
    consumed BIGINT;
    maximum BIGINT;
    period public.chio_finding_market_spend_reservations%ROWTYPE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IN ('reserved', 'committed') THEN
            charged := NEW.units;
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.state IN ('reserved', 'committed') THEN
            charged := -OLD.units;
        END IF;
    ELSE
        -- A reservation records what it charged, so only its state moves
        -- after it is written. Allowing its units to change would let a
        -- writer enlarge a reservation that is already charged without any
        -- state transition to account for, leaving the accumulator, and the
        -- ceiling enforced against it, holding the original amount.
        IF NEW.tenant_id <> OLD.tenant_id
           OR NEW.reservation_id <> OLD.reservation_id
           OR NEW.billing_period <> OLD.billing_period
           OR NEW.units <> OLD.units THEN
            RAISE EXCEPTION 'spend reservation identity and units are immutable'
                USING ERRCODE = '23000';
        END IF;
        IF OLD.state IN ('reserved', 'committed') AND NEW.state = 'released' THEN
            charged := -OLD.units;
        ELSIF OLD.state = 'released' AND NEW.state IN ('reserved', 'committed') THEN
            charged := NEW.units;
        END IF;
    END IF;
    IF charged = 0 THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    period := COALESCE(NEW, OLD);
    INSERT INTO public.chio_finding_market_spend_periods
        (tenant_id, billing_period, consumed_units, updated_at)
    VALUES (period.tenant_id, period.billing_period, 0, period.updated_at)
    ON CONFLICT (tenant_id, billing_period) DO NOTHING;
    SELECT consumed_units INTO consumed
    FROM public.chio_finding_market_spend_periods
    WHERE tenant_id = period.tenant_id
      AND billing_period = period.billing_period
    FOR UPDATE;
    IF consumed IS NULL THEN
        RAISE EXCEPTION 'spend period accumulator is not readable in this tenant context'
            USING ERRCODE = '42501';
    END IF;
    consumed := consumed + charged;
    -- Clamping a negative result at zero would discard the skew that
    -- produced it: the accumulator would then undercount the reservations
    -- still charged, and a later insert would pass a ceiling that actual
    -- reserved and committed spend already exceeds. Nothing re-derives this
    -- accumulator at runtime, so an underflow is unrecoverable accounting
    -- and denies rather than becoming authoritative.
    IF consumed < 0 THEN
        RAISE EXCEPTION 'spend period accumulator underflowed for tenant %', period.tenant_id
            USING ERRCODE = '23000';
    END IF;
    UPDATE public.chio_finding_market_spend_periods
    SET consumed_units = consumed,
        updated_at = period.updated_at
    WHERE tenant_id = period.tenant_id
      AND billing_period = period.billing_period;
    IF charged > 0 THEN
        SELECT max_monthly_spend_units INTO maximum
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = period.tenant_id;
        IF maximum IS NULL OR consumed > maximum THEN
            RAISE EXCEPTION 'tenant monthly spend ceiling exceeded'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'chio_finding_market_spend_period_ceiling_v1';
        END IF;
    END IF;
    RETURN COALESCE(NEW, OLD);
END
$$;

CREATE FUNCTION public.chio_finding_market_reject_gc_job_resurrection() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF NEW.tenant_id IS NULL
        OR NEW.tenant_id <> NULLIF(current_setting('chio.tenant_id', TRUE), '')
    THEN
        RAISE EXCEPTION 'tenant context does not match job insertion'
            USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'chio.finding.hosted.retention-job-lock.v1:'
                || NEW.tenant_id || ':' || NEW.job_kind || ':' || NEW.job_id,
            0
        )
    );
    IF EXISTS (
        SELECT 1
        FROM public.chio_finding_market_gc_receipts
        WHERE tenant_id = NEW.tenant_id
          AND resource_kind = 'job'
          AND resource_family = NEW.job_kind
          AND resource_id = NEW.job_id
    ) THEN
        RAISE EXCEPTION 'garbage-collected job identity cannot be reused'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chio_finding_market_jobs_gc_tombstone_v1';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION public.chio_finding_market_reject_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
BEGIN
    IF session_user <> current_user
       AND current_user = pg_get_userbyid((
           SELECT relowner FROM pg_class WHERE oid = TG_RELID
       ))
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'append-only cognition-market row cannot be mutated'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION public.chio_finding_market_relinquish_job_lease(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    ), changed AS (
        UPDATE public.chio_finding_market_jobs
        SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL,
            attempt_count = attempt_count - 1,
            available_at = floor(extract(epoch from clock_timestamp()))::bigint,
            last_error_code = NULL,
            updated_at = floor(extract(epoch from clock_timestamp()))::bigint
        WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
          AND EXISTS (SELECT 1 FROM enabled_tenant)
          AND tenant_id = requested_tenant_id AND job_id = requested_job_id
          AND state = 'leased' AND lease_owner = requested_worker_id
          AND lease_fence = requested_lease_fence AND attempt_count > 0
        RETURNING 1
    ) SELECT EXISTS(SELECT 1 FROM changed)
$$;

CREATE FUNCTION public.chio_finding_market_renew_job_lease(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_lease_duration_secs bigint) RETURNS bigint
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    WITH enabled_tenant AS MATERIALIZED (
        SELECT 1
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = requested_tenant_id AND enabled
        FOR SHARE
    )
    UPDATE public.chio_finding_market_jobs
    SET lease_expires_at = floor(extract(epoch from clock_timestamp()))::bigint
            + requested_lease_duration_secs,
        updated_at = floor(extract(epoch from clock_timestamp()))::bigint
    WHERE requested_tenant_id = NULLIF(current_setting('chio.tenant_id', TRUE), '')
      AND EXISTS (SELECT 1 FROM enabled_tenant)
      AND requested_lease_duration_secs BETWEEN 1 AND 3600
      AND tenant_id = requested_tenant_id AND job_id = requested_job_id
      AND state = 'leased' AND lease_owner = requested_worker_id
      AND lease_fence = requested_lease_fence
      AND lease_expires_at > floor(extract(epoch from clock_timestamp()))::bigint
    RETURNING lease_expires_at
$$;

ALTER TABLE ONLY public.chio_finding_market_aggregate_checkpoints
    ADD CONSTRAINT chio_finding_market_aggregate_checkpoints_pkey PRIMARY KEY (tenant_id, checkpoint_sha256);

ALTER TABLE ONLY public.chio_finding_market_aggregate_events
    ADD CONSTRAINT chio_finding_market_aggregate_events_pkey PRIMARY KEY (tenant_id, aggregate_kind, aggregate_id, revision);

ALTER TABLE ONLY public.chio_finding_market_aggregate_events
    ADD CONSTRAINT chio_finding_market_aggregate_events_revision_digest_v1 UNIQUE (tenant_id, aggregate_kind, aggregate_id, revision, event_sha256);

ALTER TABLE ONLY public.chio_finding_market_aggregate_events
    ADD CONSTRAINT chio_finding_market_aggregate_events_tenant_id_event_id_key UNIQUE (tenant_id, event_id);

ALTER TABLE ONLY public.chio_finding_market_aggregate_heads
    ADD CONSTRAINT chio_finding_market_aggregate_heads_pkey PRIMARY KEY (tenant_id, aggregate_kind, aggregate_id);

ALTER TABLE ONLY public.chio_finding_market_aggregate_checkpoints
    ADD CONSTRAINT chio_finding_market_aggregate_tenant_id_aggregate_kind_aggr_key UNIQUE (tenant_id, aggregate_kind, aggregate_id, revision);

ALTER TABLE ONLY public.chio_finding_market_api_keys
    ADD CONSTRAINT chio_finding_market_api_keys_pkey PRIMARY KEY (tenant_id, key_id);

ALTER TABLE ONLY public.chio_finding_market_archive_manifests
    ADD CONSTRAINT chio_finding_market_archive_m_tenant_id_resource_kind_resou_key UNIQUE (tenant_id, resource_kind, resource_family, resource_id, resource_revision, archive_sha256);

ALTER TABLE ONLY public.chio_finding_market_archive_manifests
    ADD CONSTRAINT chio_finding_market_archive_manifests_pkey PRIMARY KEY (tenant_id, archive_sha256);

ALTER TABLE ONLY public.chio_finding_market_authority_state
    ADD CONSTRAINT chio_finding_market_authority_state_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.chio_finding_market_authority_transitions
    ADD CONSTRAINT chio_finding_market_authority_transitions_pkey PRIMARY KEY (tenant_id, transition_sha256);

ALTER TABLE ONLY public.chio_finding_market_capability_request_admissions
    ADD CONSTRAINT chio_finding_market_capability_request_admissions_pkey PRIMARY KEY (tenant_id, capability_id, request_sha256);

ALTER TABLE ONLY public.chio_finding_market_capability_uses
    ADD CONSTRAINT chio_finding_market_capability_uses_pkey PRIMARY KEY (tenant_id, capability_id);

ALTER TABLE ONLY public.chio_finding_market_domain_event_contracts
    ADD CONSTRAINT chio_finding_market_domain_event_contracts_pkey PRIMARY KEY (aggregate_kind, event_kind, artifact_schema);

ALTER TABLE ONLY public.chio_finding_market_domain_projections
    ADD CONSTRAINT chio_finding_market_domain_projections_pkey PRIMARY KEY (tenant_id, aggregate_kind, aggregate_id);

ALTER TABLE ONLY public.chio_finding_market_dpop_admission_state
    ADD CONSTRAINT chio_finding_market_dpop_admission_state_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.chio_finding_market_dpop_nonces
    ADD CONSTRAINT chio_finding_market_dpop_nonces_pkey PRIMARY KEY (tenant_id, capability_id, nonce_sha256);

ALTER TABLE ONLY public.chio_finding_market_gc_receipts
    ADD CONSTRAINT chio_finding_market_gc_receipts_pkey PRIMARY KEY (tenant_id, receipt_sha256);

ALTER TABLE ONLY public.chio_finding_market_jobs
    ADD CONSTRAINT chio_finding_market_jobs_pkey PRIMARY KEY (tenant_id, job_id);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoint_members
    ADD CONSTRAINT chio_finding_market_journal_checkpoint_members_pkey PRIMARY KEY (tenant_id, checkpoint_sha256, member_kind, member_family, member_id);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoints
    ADD CONSTRAINT chio_finding_market_journal_checkpoints_pkey PRIMARY KEY (tenant_id, checkpoint_sha256);

ALTER TABLE ONLY public.chio_finding_market_legal_hold_events
    ADD CONSTRAINT chio_finding_market_legal_hol_tenant_id_hold_id_hold_event__key UNIQUE (tenant_id, hold_id, hold_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_legal_hold_events
    ADD CONSTRAINT chio_finding_market_legal_hold_events_pkey PRIMARY KEY (tenant_id, hold_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principal_events
    ADD CONSTRAINT chio_finding_market_principal_events_pkey PRIMARY KEY (tenant_id, event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principal_key_overlaps
    ADD CONSTRAINT chio_finding_market_principal_key_overlaps_pkey PRIMARY KEY (tenant_id, capability_public_key_hex, lifecycle_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_events
    ADD CONSTRAINT chio_finding_market_principal_replication_events_pkey PRIMARY KEY (tenant_id, replication_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_outbox
    ADD CONSTRAINT chio_finding_market_principal_replication_outbox_pkey PRIMARY KEY (tenant_id, authority_epoch, sequence);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_outbox
    ADD CONSTRAINT chio_finding_market_principal_tenant_id_authority_epoch_pri_key UNIQUE (tenant_id, authority_epoch, principal_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principals
    ADD CONSTRAINT chio_finding_market_principal_tenant_id_capability_public_k_key UNIQUE (tenant_id, capability_public_key_hex);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_events
    ADD CONSTRAINT chio_finding_market_principal_tenant_id_source_authority_a_key1 UNIQUE (tenant_id, source_authority, authority_epoch, principal_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_events
    ADD CONSTRAINT chio_finding_market_principal_tenant_id_source_authority_au_key UNIQUE (tenant_id, source_authority, authority_epoch, sequence);

ALTER TABLE ONLY public.chio_finding_market_principals
    ADD CONSTRAINT chio_finding_market_principals_pkey PRIMARY KEY (tenant_id, principal_id);

ALTER TABLE ONLY public.chio_finding_market_quota_alerts
    ADD CONSTRAINT chio_finding_market_quota_alerts_pkey PRIMARY KEY (tenant_id, alert_sha256);

ALTER TABLE ONLY public.chio_finding_market_replication_outbox
    ADD CONSTRAINT chio_finding_market_replicati_tenant_id_authority_epoch_eve_key UNIQUE (tenant_id, authority_epoch, event_id);

ALTER TABLE ONLY public.chio_finding_market_replication_events
    ADD CONSTRAINT chio_finding_market_replicati_tenant_id_source_authority_a_key1 UNIQUE (tenant_id, source_authority, authority_epoch, event_id);

ALTER TABLE ONLY public.chio_finding_market_replication_events
    ADD CONSTRAINT chio_finding_market_replicati_tenant_id_source_authority_au_key UNIQUE (tenant_id, source_authority, authority_epoch, sequence);

ALTER TABLE ONLY public.chio_finding_market_replication_checks
    ADD CONSTRAINT chio_finding_market_replication_checks_pkey PRIMARY KEY (tenant_id, check_sha256);

ALTER TABLE ONLY public.chio_finding_market_replication_events
    ADD CONSTRAINT chio_finding_market_replication_events_pkey PRIMARY KEY (tenant_id, replication_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_replication_outbox
    ADD CONSTRAINT chio_finding_market_replication_outbox_pkey PRIMARY KEY (tenant_id, authority_epoch, sequence);

ALTER TABLE ONLY public.chio_finding_market_restore_verifications
    ADD CONSTRAINT chio_finding_market_restore_verifications_pkey PRIMARY KEY (tenant_id, verification_sha256);

ALTER TABLE ONLY public.chio_finding_market_security_events
    ADD CONSTRAINT chio_finding_market_security_events_pkey PRIMARY KEY (tenant_id, event_id);

ALTER TABLE ONLY public.chio_finding_market_spend_periods
    ADD CONSTRAINT chio_finding_market_spend_periods_pkey PRIMARY KEY (tenant_id, billing_period);

ALTER TABLE ONLY public.chio_finding_market_spend_reservations
    ADD CONSTRAINT chio_finding_market_spend_reservations_pkey PRIMARY KEY (tenant_id, reservation_id);

ALTER TABLE ONLY public.chio_finding_market_tenants
    ADD CONSTRAINT chio_finding_market_tenants_pkey PRIMARY KEY (tenant_id);

CREATE INDEX chio_finding_market_aggregate_checkpoints_latest ON public.chio_finding_market_aggregate_checkpoints USING btree (tenant_id, aggregate_kind, aggregate_id, revision DESC);

CREATE INDEX chio_finding_market_aggregate_events_history ON public.chio_finding_market_aggregate_events USING btree (tenant_id, aggregate_kind, aggregate_id, revision);

CREATE INDEX chio_finding_market_api_keys_principal ON public.chio_finding_market_api_keys USING btree (tenant_id, principal_id, active_from, expires_at);

CREATE UNIQUE INDEX chio_finding_market_archive_manifests_genesis_v1 ON public.chio_finding_market_archive_manifests USING btree (tenant_id, resource_kind, resource_family, resource_id) WHERE (previous_archive_sha256 IS NULL);

CREATE UNIQUE INDEX chio_finding_market_archive_manifests_successor_v1 ON public.chio_finding_market_archive_manifests USING btree (tenant_id, resource_kind, resource_family, resource_id, previous_archive_sha256) WHERE (previous_archive_sha256 IS NOT NULL);

CREATE INDEX chio_finding_market_capability_request_expiry ON public.chio_finding_market_capability_request_admissions USING btree (tenant_id, expires_at);

CREATE INDEX chio_finding_market_capability_uses_expiry ON public.chio_finding_market_capability_uses USING btree (tenant_id, expires_at);

CREATE INDEX chio_finding_market_domain_projection_status_subject_v1 ON public.chio_finding_market_domain_projections USING btree (tenant_id, subject_finding_id, aggregate_kind, aggregate_id) WHERE (subject_finding_id IS NOT NULL);

CREATE INDEX chio_finding_market_dpop_nonces_expiry ON public.chio_finding_market_dpop_nonces USING btree (tenant_id, valid_through);

CREATE INDEX chio_finding_market_jobs_due ON public.chio_finding_market_jobs USING btree (tenant_id, state, available_at, created_at, job_id);

CREATE UNIQUE INDEX chio_finding_market_journal_checkpoints_genesis_v1 ON public.chio_finding_market_journal_checkpoints USING btree (tenant_id) WHERE (previous_checkpoint_sha256 IS NULL);

CREATE UNIQUE INDEX chio_finding_market_journal_checkpoints_successor_v1 ON public.chio_finding_market_journal_checkpoints USING btree (tenant_id, previous_checkpoint_sha256) WHERE (previous_checkpoint_sha256 IS NOT NULL);

CREATE UNIQUE INDEX chio_finding_market_legal_hold_events_genesis_v1 ON public.chio_finding_market_legal_hold_events USING btree (tenant_id, hold_id) WHERE (previous_hold_event_sha256 IS NULL);

CREATE UNIQUE INDEX chio_finding_market_legal_hold_events_successor_v1 ON public.chio_finding_market_legal_hold_events USING btree (tenant_id, hold_id, previous_hold_event_sha256) WHERE (previous_hold_event_sha256 IS NOT NULL);

CREATE INDEX chio_finding_market_spend_period ON public.chio_finding_market_spend_reservations USING btree (tenant_id, billing_period, state);

ALTER TABLE ONLY public.chio_finding_market_aggregate_checkpoints
    ADD CONSTRAINT chio_finding_market_aggregate_checkpoints_event_fk FOREIGN KEY (tenant_id, aggregate_kind, aggregate_id, revision, event_sha256) REFERENCES public.chio_finding_market_aggregate_events(tenant_id, aggregate_kind, aggregate_id, revision, event_sha256);

ALTER TABLE ONLY public.chio_finding_market_aggregate_checkpoints
    ADD CONSTRAINT chio_finding_market_aggregate_checkpoints_predecessor_fk FOREIGN KEY (tenant_id, previous_checkpoint_sha256) REFERENCES public.chio_finding_market_aggregate_checkpoints(tenant_id, checkpoint_sha256);

ALTER TABLE ONLY public.chio_finding_market_aggregate_checkpoints
    ADD CONSTRAINT chio_finding_market_aggregate_checkpoints_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_aggregate_events
    ADD CONSTRAINT chio_finding_market_aggregate_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_aggregate_heads
    ADD CONSTRAINT chio_finding_market_aggregate_heads_event_fk FOREIGN KEY (tenant_id, aggregate_kind, aggregate_id, revision) REFERENCES public.chio_finding_market_aggregate_events(tenant_id, aggregate_kind, aggregate_id, revision);

ALTER TABLE ONLY public.chio_finding_market_aggregate_heads
    ADD CONSTRAINT chio_finding_market_aggregate_heads_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_api_keys
    ADD CONSTRAINT chio_finding_market_api_keys_tenant_id_principal_id_fkey FOREIGN KEY (tenant_id, principal_id) REFERENCES public.chio_finding_market_principals(tenant_id, principal_id);

ALTER TABLE ONLY public.chio_finding_market_api_keys
    ADD CONSTRAINT chio_finding_market_api_keys_tenant_id_rotated_from_key_id_fkey FOREIGN KEY (tenant_id, rotated_from_key_id) REFERENCES public.chio_finding_market_api_keys(tenant_id, key_id);

ALTER TABLE ONLY public.chio_finding_market_archive_manifests
    ADD CONSTRAINT chio_finding_market_archive_m_tenant_id_covered_checkpoint_fkey FOREIGN KEY (tenant_id, covered_checkpoint_sha256) REFERENCES public.chio_finding_market_journal_checkpoints(tenant_id, checkpoint_sha256);

ALTER TABLE ONLY public.chio_finding_market_archive_manifests
    ADD CONSTRAINT chio_finding_market_archive_m_tenant_id_previous_archive_s_fkey FOREIGN KEY (tenant_id, previous_archive_sha256) REFERENCES public.chio_finding_market_archive_manifests(tenant_id, archive_sha256);

ALTER TABLE ONLY public.chio_finding_market_archive_manifests
    ADD CONSTRAINT chio_finding_market_archive_manifests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_authority_state
    ADD CONSTRAINT chio_finding_market_authority_state_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_authority_transitions
    ADD CONSTRAINT chio_finding_market_authority_transitions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_capability_request_admissions
    ADD CONSTRAINT chio_finding_market_capability_request_admission_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_capability_uses
    ADD CONSTRAINT chio_finding_market_capability_uses_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_domain_projections
    ADD CONSTRAINT chio_finding_market_domain_projection_contract_v1 FOREIGN KEY (aggregate_kind, event_kind, artifact_schema) REFERENCES public.chio_finding_market_domain_event_contracts(aggregate_kind, event_kind, artifact_schema);

ALTER TABLE ONLY public.chio_finding_market_domain_projections
    ADD CONSTRAINT chio_finding_market_domain_projection_head_v1 FOREIGN KEY (tenant_id, aggregate_kind, aggregate_id, revision, event_sha256) REFERENCES public.chio_finding_market_aggregate_events(tenant_id, aggregate_kind, aggregate_id, revision, event_sha256) ON DELETE CASCADE;

ALTER TABLE ONLY public.chio_finding_market_domain_projections
    ADD CONSTRAINT chio_finding_market_domain_projections_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_dpop_admission_state
    ADD CONSTRAINT chio_finding_market_dpop_admission_state_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_dpop_nonces
    ADD CONSTRAINT chio_finding_market_dpop_nonces_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_gc_receipts
    ADD CONSTRAINT chio_finding_market_gc_receipts_tenant_id_archive_sha256_fkey FOREIGN KEY (tenant_id, archive_sha256) REFERENCES public.chio_finding_market_archive_manifests(tenant_id, archive_sha256);

ALTER TABLE ONLY public.chio_finding_market_gc_receipts
    ADD CONSTRAINT chio_finding_market_gc_receipts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_jobs
    ADD CONSTRAINT chio_finding_market_jobs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoint_members
    ADD CONSTRAINT chio_finding_market_journal_ch_tenant_id_checkpoint_sha256_fkey FOREIGN KEY (tenant_id, checkpoint_sha256) REFERENCES public.chio_finding_market_journal_checkpoints(tenant_id, checkpoint_sha256);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoints
    ADD CONSTRAINT chio_finding_market_journal_checkpoints_previous_fk FOREIGN KEY (tenant_id, previous_checkpoint_sha256) REFERENCES public.chio_finding_market_journal_checkpoints(tenant_id, checkpoint_sha256);

ALTER TABLE ONLY public.chio_finding_market_journal_checkpoints
    ADD CONSTRAINT chio_finding_market_journal_checkpoints_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_legal_hold_events
    ADD CONSTRAINT chio_finding_market_legal_hol_tenant_id_previous_hold_even_fkey FOREIGN KEY (tenant_id, previous_hold_event_sha256) REFERENCES public.chio_finding_market_legal_hold_events(tenant_id, hold_event_sha256);

ALTER TABLE ONLY public.chio_finding_market_legal_hold_events
    ADD CONSTRAINT chio_finding_market_legal_hold_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_principal_events
    ADD CONSTRAINT chio_finding_market_principal_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_principal_key_overlaps
    ADD CONSTRAINT chio_finding_market_principal_key_overlaps_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_events
    ADD CONSTRAINT chio_finding_market_principal_replication_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_principal_replication_outbox
    ADD CONSTRAINT chio_finding_market_principal_replication_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_principal_key_overlaps
    ADD CONSTRAINT chio_finding_market_principal_tenant_id_lifecycle_event_sh_fkey FOREIGN KEY (tenant_id, lifecycle_event_sha256) REFERENCES public.chio_finding_market_principal_events(tenant_id, event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principal_events
    ADD CONSTRAINT chio_finding_market_principal_tenant_id_previous_event_sha_fkey FOREIGN KEY (tenant_id, previous_event_sha256) REFERENCES public.chio_finding_market_principal_events(tenant_id, event_sha256);

ALTER TABLE ONLY public.chio_finding_market_principals
    ADD CONSTRAINT chio_finding_market_principals_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_quota_alerts
    ADD CONSTRAINT chio_finding_market_quota_alerts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_replication_outbox
    ADD CONSTRAINT chio_finding_market_replicat_aggregate_kind_event_kind_ar_fkey1 FOREIGN KEY (aggregate_kind, event_kind, artifact_schema) REFERENCES public.chio_finding_market_domain_event_contracts(aggregate_kind, event_kind, artifact_schema);

ALTER TABLE ONLY public.chio_finding_market_replication_events
    ADD CONSTRAINT chio_finding_market_replicati_aggregate_kind_event_kind_ar_fkey FOREIGN KEY (aggregate_kind, event_kind, artifact_schema) REFERENCES public.chio_finding_market_domain_event_contracts(aggregate_kind, event_kind, artifact_schema);

ALTER TABLE ONLY public.chio_finding_market_replication_checks
    ADD CONSTRAINT chio_finding_market_replication_checks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_replication_events
    ADD CONSTRAINT chio_finding_market_replication_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_replication_outbox
    ADD CONSTRAINT chio_finding_market_replication_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_restore_verifications
    ADD CONSTRAINT chio_finding_market_restore_verif_tenant_id_archive_sha256_fkey FOREIGN KEY (tenant_id, archive_sha256) REFERENCES public.chio_finding_market_archive_manifests(tenant_id, archive_sha256);

ALTER TABLE ONLY public.chio_finding_market_restore_verifications
    ADD CONSTRAINT chio_finding_market_restore_verifications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_security_events
    ADD CONSTRAINT chio_finding_market_security_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_spend_periods
    ADD CONSTRAINT chio_finding_market_spend_periods_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

ALTER TABLE ONLY public.chio_finding_market_spend_reservations
    ADD CONSTRAINT chio_finding_market_spend_reservations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.chio_finding_market_tenants(tenant_id);

CREATE TRIGGER chio_finding_market_aggregate_checkpoints_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_aggregate_checkpoints FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_aggregate_events_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_aggregate_events FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_archive_manifests_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_archive_manifests FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_authority_transitions_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_authority_transitions FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_domain_event_contracts_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_domain_event_contracts FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_domain_projections_derive_status_subject BEFORE INSERT OR UPDATE ON public.chio_finding_market_domain_projections FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_derive_status_subject();

CREATE TRIGGER chio_finding_market_domain_projections_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_domain_projections FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_guard_domain_projection_mutation();

CREATE TRIGGER chio_finding_market_dpop_nonce_accounting AFTER INSERT OR DELETE ON public.chio_finding_market_dpop_nonces FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_maintain_dpop_live_nonces();

CREATE TRIGGER chio_finding_market_gc_receipts_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_gc_receipts FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_jobs_gc_tombstone BEFORE INSERT ON public.chio_finding_market_jobs FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_gc_job_resurrection();

CREATE TRIGGER chio_finding_market_journal_checkpoint_members_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_journal_checkpoint_members FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_journal_checkpoints_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_journal_checkpoints FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_legal_hold_events_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_legal_hold_events FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_principal_events_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_principal_events FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_principal_key_overlaps_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_principal_key_overlaps FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_principal_replication_events_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_principal_replication_events FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_principal_replication_outbox_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_principal_replication_outbox FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_quota_alerts_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_quota_alerts FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_replication_checks_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_replication_checks FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_replication_events_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_replication_events FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_replication_outbox_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_replication_outbox FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_request_binding_accounting AFTER INSERT OR DELETE ON public.chio_finding_market_capability_request_admissions FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_maintain_request_bindings();

CREATE TRIGGER chio_finding_market_restore_verifications_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_restore_verifications FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_security_events_immutable BEFORE DELETE OR UPDATE ON public.chio_finding_market_security_events FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_reject_immutable_mutation();

CREATE TRIGGER chio_finding_market_spend_period_accounting AFTER INSERT OR DELETE OR UPDATE ON public.chio_finding_market_spend_reservations FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_maintain_spend_period();

CREATE TRIGGER chio_finding_market_tenants_initialize_authority_state AFTER INSERT ON public.chio_finding_market_tenants FOR EACH ROW EXECUTE FUNCTION public.chio_finding_market_initialize_authority_state();

ALTER TABLE public.chio_finding_market_aggregate_checkpoints ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_aggregate_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_aggregate_heads ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_api_keys ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_archive_manifests ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_authority_state ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_authority_transitions ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_capability_request_admissions ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_capability_uses ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_domain_projections ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_dpop_admission_state ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_dpop_nonces ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_gc_receipts ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_jobs ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_journal_checkpoint_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_journal_checkpoints ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_legal_hold_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_principal_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_principal_key_overlaps ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_principal_replication_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_principal_replication_outbox ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_principals ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_quota_alerts ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_replication_checks ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_replication_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_replication_outbox ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_restore_verifications ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_security_events ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_spend_periods ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_spend_reservations ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.chio_finding_market_tenants ENABLE ROW LEVEL SECURITY;

CREATE POLICY chio_finding_market_aggregate_checkpoints_tenant_isolation ON public.chio_finding_market_aggregate_checkpoints USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_aggregate_events_tenant_isolation ON public.chio_finding_market_aggregate_events USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_aggregate_heads_tenant_isolation ON public.chio_finding_market_aggregate_heads USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_api_keys_tenant_isolation ON public.chio_finding_market_api_keys USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_archive_manifests_tenant_isolation ON public.chio_finding_market_archive_manifests USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_authority_state_tenant_isolation ON public.chio_finding_market_authority_state USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_authority_transitions_tenant_isolation ON public.chio_finding_market_authority_transitions USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_capability_request_admissions_tenant_isolat ON public.chio_finding_market_capability_request_admissions USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_capability_uses_tenant_isolation ON public.chio_finding_market_capability_uses USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_domain_projections_tenant_isolation ON public.chio_finding_market_domain_projections USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_dpop_admission_state_tenant_isolation ON public.chio_finding_market_dpop_admission_state USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_dpop_nonces_tenant_isolation ON public.chio_finding_market_dpop_nonces USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_gc_receipts_tenant_isolation ON public.chio_finding_market_gc_receipts USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_jobs_tenant_isolation ON public.chio_finding_market_jobs USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_journal_checkpoint_members_tenant_isolation ON public.chio_finding_market_journal_checkpoint_members USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_journal_checkpoints_tenant_isolation ON public.chio_finding_market_journal_checkpoints USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_legal_hold_events_tenant_isolation ON public.chio_finding_market_legal_hold_events USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_principal_events_tenant_isolation ON public.chio_finding_market_principal_events USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_principal_key_overlaps_tenant_isolation ON public.chio_finding_market_principal_key_overlaps USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_principal_replication_events_tenant_isolati ON public.chio_finding_market_principal_replication_events USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_principal_replication_outbox_tenant_isolati ON public.chio_finding_market_principal_replication_outbox USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_principals_tenant_isolation ON public.chio_finding_market_principals USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_quota_alerts_tenant_isolation ON public.chio_finding_market_quota_alerts USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_replication_checks_tenant_isolation ON public.chio_finding_market_replication_checks USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_replication_events_tenant_isolation ON public.chio_finding_market_replication_events USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_replication_outbox_tenant_isolation ON public.chio_finding_market_replication_outbox USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_restore_verifications_tenant_isolation ON public.chio_finding_market_restore_verifications USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_security_events_tenant_isolation ON public.chio_finding_market_security_events USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_spend_periods_tenant_isolation ON public.chio_finding_market_spend_periods USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_spend_reservations_tenant_isolation ON public.chio_finding_market_spend_reservations USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

CREATE POLICY chio_finding_market_tenants_tenant_isolation ON public.chio_finding_market_tenants USING ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))) WITH CHECK ((tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text)));

REVOKE ALL ON FUNCTION public.chio_finding_market_append_aggregate_event(requested_tenant_id text, requested_aggregate_kind text, requested_aggregate_id text, expected_revision bigint, expected_event_sha256 text, requested_event_id text, requested_event_kind text, requested_payload_sha256 text, requested_payload_json bytea, requested_event_sha256 text, requested_committed_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_archive_manifest(requested_tenant_id text, requested_archive_sha256 text, requested_resource_kind text, requested_resource_family text, requested_resource_id text, requested_resource_revision bigint, requested_resource_sha256 text, requested_covered_checkpoint_sha256 text, requested_object_uri text, requested_object_sha256 text, requested_object_size bigint, requested_configuration_revision text, requested_previous_archive_sha256 text, requested_signer_key_hex text, requested_archive_envelope_json bytea, requested_created_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_domain_event(requested_tenant_id text, requested_aggregate_kind text, requested_aggregate_id text, expected_revision bigint, expected_event_sha256 text, requested_event_id text, requested_event_kind text, requested_artifact_schema text, requested_payload_sha256 text, requested_payload_json bytea, requested_event_sha256 text, requested_committed_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_journal_checkpoint(requested_tenant_id text, requested_checkpoint_sha256 text, requested_aggregate_heads_sha256 text, requested_terminal_jobs_sha256 text, requested_previous_checkpoint_sha256 text, requested_migration_version bigint, requested_configuration_revision text, requested_signer_key_hex text, requested_checkpoint_envelope_json bytea, requested_created_at bigint, requested_members jsonb) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_legal_hold_event(requested_tenant_id text, requested_hold_event_sha256 text, requested_hold_id text, requested_resource_kind text, requested_resource_family text, requested_resource_id text, requested_action text, requested_previous_hold_event_sha256 text, requested_signer_key_hex text, requested_hold_envelope_json bytea, requested_created_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_quota_alert(requested_tenant_id text, requested_alert_sha256 text, requested_quota_kind text, requested_observed_value bigint, requested_limit_value bigint, requested_signer_key_hex text, requested_alert_envelope_json bytea, requested_created_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_replication_check(requested_tenant_id text, requested_check_sha256 text, requested_source_authority text, requested_authority_epoch bigint, requested_through_sequence bigint, requested_source_projection_sha256 text, requested_target_projection_sha256 text, requested_lag_seconds bigint, requested_projection_difference_count bigint, requested_security_counter_count bigint, requested_signer_key_hex text, requested_check_envelope_json bytea, requested_checked_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_append_restore_verification(requested_tenant_id text, requested_verification_sha256 text, requested_archive_sha256 text, requested_restored_resource_sha256 text, requested_signer_key_hex text, requested_verification_envelope_json bytea, requested_verified_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_apply_authority_transition(requested_tenant_id text, requested_transition_sha256 text, requested_operation text, requested_from_authority text, requested_to_authority text, requested_from_epoch bigint, requested_to_epoch bigint, requested_through_sequence bigint, requested_source_checkpoint_sha256 text, requested_target_checkpoint_sha256 text, requested_configuration_revision text, requested_rollback_window_ends_at bigint, requested_signer_key_hex text, requested_transition_envelope_json bytea, requested_created_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_apply_principal_event(requested_tenant_id text, requested_event_sha256 text, requested_principal_id text, requested_operation text, requested_role text, requested_capability_public_key_hex text, requested_overlap_expires_at bigint, requested_previous_event_sha256 text, requested_signer_key_hex text, requested_event_envelope_json bytea, requested_created_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_apply_principal_event_unfenced(requested_tenant_id text, requested_event_sha256 text, requested_principal_id text, requested_operation text, requested_role text, requested_capability_public_key_hex text, requested_overlap_expires_at bigint, requested_previous_event_sha256 text, requested_signer_key_hex text, requested_event_envelope_json bytea, requested_created_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_apply_principal_replication_event(requested_tenant_id text, requested_replication_event_sha256 text, requested_source_authority text, requested_authority_epoch bigint, requested_sequence bigint, requested_principal_event_sha256 text, requested_principal_id text, requested_operation text, requested_role text, requested_capability_public_key_hex text, requested_overlap_expires_at bigint, requested_previous_event_sha256 text, requested_principal_signer_key_hex text, requested_principal_event_envelope_json bytea, requested_source_signer_key_hex text, requested_replication_event_envelope_json bytea, requested_committed_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_apply_replication_event(requested_tenant_id text, requested_replication_event_sha256 text, requested_source_authority text, requested_authority_epoch bigint, requested_sequence bigint, requested_aggregate_kind text, requested_aggregate_id text, requested_expected_revision bigint, requested_expected_event_sha256 text, requested_event_id text, requested_event_kind text, requested_artifact_schema text, requested_payload_sha256 text, requested_payload_json bytea, requested_event_sha256 text, requested_signer_key_hex text, requested_event_envelope_json bytea, requested_committed_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_claim_jobs(requested_tenant_id text, requested_worker_id text, requested_lease_duration_secs bigint, requested_limit bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_complete_job(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_result_sha256 text, requested_result_json bytea) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_derive_status_subject() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_exhaust_job(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_error_code text) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_fail_job(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_error_code text, requested_retry_delay_secs bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_gc_retained_resource(requested_tenant_id text, requested_archive_sha256 text, requested_resource_kind text, requested_resource_family text, requested_resource_id text, requested_resource_revision bigint, requested_resource_sha256 text, requested_receipt_sha256 text, requested_signer_key_hex text, requested_receipt_envelope_json bytea, requested_completed_at bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_initialize_authority_state() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_maintain_dpop_live_nonces() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_maintain_request_bindings() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_maintain_spend_period() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_reject_gc_job_resurrection() FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_relinquish_job_lease(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint) FROM PUBLIC;

REVOKE ALL ON FUNCTION public.chio_finding_market_renew_job_lease(requested_tenant_id text, requested_job_id text, requested_worker_id text, requested_lease_fence bigint, requested_lease_duration_secs bigint) FROM PUBLIC;

INSERT INTO public.chio_finding_market_domain_event_contracts (
    aggregate_kind, event_kind, artifact_schema, signed_artifact
) VALUES
    ('admission', 'admission.admitted', 'chio.finding.admission.v1', TRUE),
    ('appeal', 'appeal.finalized', 'chio.finding.challenge-enforcement.v1', TRUE),
    ('audit_round', 'audit.finalized', 'chio.finding.audit-report.v1', TRUE),
    ('challenge', 'challenge.submitted', 'chio.finding.challenge.v1', TRUE),
    ('challenge_outcome', 'challenge.finalized', 'chio.finding.challenge-outcome.v1', TRUE),
    ('collateral', 'collateral.registered', 'chio.finding.bond-backing.v1', TRUE),
    ('delivery', 'delivery.accepted', 'chio.finding.hosted-authenticated-delivery.v1', TRUE),
    ('enforcement', 'enforcement.finalized', 'chio.finding.challenge-enforcement.v1', TRUE),
    ('failed_delivery', 'delivery.failed', 'chio.finding.failed-delivery.v1', TRUE),
    ('finding', 'finding.published', 'chio.finding.v1', TRUE),
    ('liability', 'liability.assessed', 'chio.finding.liability.v1', TRUE),
    ('listing', 'listing.activated', 'chio.finding.market-terms.v1', TRUE),
    ('participation', 'participation.admitted', 'chio.finding.claim-allocation.v1', TRUE),
    ('penalty', 'penalty.assessed', 'chio.registry.market-penalty.v1', TRUE),
    ('profile', 'profile.registered', 'chio.finding.challenge-verifier-profile.v1', TRUE),
    ('purchase', 'purchase.authorized', 'chio.finding.purchase-record.v1', TRUE),
    ('purchase_terminal', 'purchase.settled', 'chio.finding.purchase-result.v1', TRUE),
    ('recipe', 'recipe.registered', 'chio.finding.replay-recipe-input.v1', FALSE),
    ('retraction', 'retraction.voluntary', 'chio.finding.voluntary-retraction.v1', TRUE),
    ('reveal', 'reveal.committed', 'chio.finding.purchase-result.v1', TRUE),
    ('settlement', 'settlement.terminal', 'chio.commerce.settlement-packet.v1', FALSE),
    ('status_epoch', 'status.published', 'chio.finding.status-epoch.v1', TRUE),
    ('verified_fix', 'verified_fix.submitted', 'chio.finding.verified-fix-submission.v1', TRUE);
