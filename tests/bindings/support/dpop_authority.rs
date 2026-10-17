// Shared live DPoP custody for protocol-edge tests. Retain this fixture while
// exercising the kernel so its qualified authority directory remains present.
use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use chio_kernel::dpop::authority::{DpopReplayAuthority, DpopReplayAuthorityInput};
use chio_kernel::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use chio_kernel::{dpop::DpopNonceStore, ChioKernel};
use chio_store_sqlite::SqliteAuthorityStore;
use std::{error::Error, sync::Arc};

pub struct ActivatedDpopAuthority {
    pub domain: DpopReplayAuthority,
    _authority: SqliteAuthorityStore,
    _directory: tempfile::TempDir,
}

impl ActivatedDpopAuthority {
    pub fn install(
        kernel: &mut ChioKernel,
        proof_ttl_secs: u64,
        max_clock_skew_secs: u64,
    ) -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let database = directory.path().join("authority.db");
        let locks = directory.path().join("locks");
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        let clock = kernel.authority_clock();
        let authority =
            SqliteAuthorityStore::open_serving_with_clock(&database, &locks, clock.clone())?;
        let operations = Arc::new(authority.admission_operation_store());
        let fence = authority.mutation_fence();
        let source = DpopNonceStore::with_clock(
            8,
            8,
            chio_kernel::dpop::DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
            std::time::Duration::from_secs(3600),
            clock.clone(),
        )?;
        let authority_id = AdmissionIdentifier::try_new("dpop_authority", "protocol-edge-dpop")?;
        let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: authority_id.clone(),
            destination_authority_id: AdmissionIdentifier::try_new(
                "destination",
                &fence.store_uuid,
            )?,
        })?;
        let instance = AdmissionIdentifier::try_new("instance", snapshot.instance_id())?;
        let now = clock.unix_millis()?.get();
        let pinned =
            operations.expect_dpop_replay_source(&instance, &authority_id, &source, &fence, now)?;
        let imported = operations.import_dpop_replay_source(
            &authority_id,
            pinned.expectation_id(),
            &source,
            &fence,
            now,
        )?;
        let domain = DpopReplayAuthority::new(DpopReplayAuthorityInput {
            destination_store_uuid: AdmissionIdentifier::try_new(
                "destination",
                imported.snapshot().destination_authority_id(),
            )?,
            dpop_authority_id: authority_id,
            expectation_id: AdmissionDigest::try_new(
                "expectation",
                imported.expectation_id().as_str(),
            )?,
            proof_ttl_secs,
            max_clock_skew_secs,
        })?;
        if !operations
            .activate_dpop_replay_source(&domain, &source, &fence, now)?
            .is_active()
        {
            return Err("DPoP fixture source did not activate".into());
        }
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_durable_admission_store(
            operations,
            Arc::new(authority.tool_outcome_store()),
            fence,
        )?;
        kernel.set_operation_owned_dpop_authority(domain.clone())?;
        Ok(Self {
            domain,
            _authority: authority,
            _directory: directory,
        })
    }
}
