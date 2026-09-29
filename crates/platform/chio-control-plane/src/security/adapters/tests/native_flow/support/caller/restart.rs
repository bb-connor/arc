// Close original owners and reopen the same authority, with the original pins.
use super::*;

pub(super) fn reopen(
    fixture: Fixture,
    executor: &CallerExecutorIdentityV1,
    disclosure: Option<&Keypair>,
) -> TestResult<Fixture> {
    let witness = super::super::process_recovery::caller_restart_witness(&fixture, disclosure);
    let previous_fence = fixture.authority.mutation_fence();
    let Fixture {
        kernel,
        authority,
        binding,
        request,
        context,
        invocations: _,
        hook,
        agent,
        signer,
        _directory,
    } = fixture;
    drop(kernel);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(
        _directory.path().join("admission.db"),
        _directory.path().join("locks"),
    )?;
    assert_ne!(authority.mutation_fence(), previous_fence);
    let (mut kernel, invocations) = open_kernel(_directory.path(), &authority, &signer)?;
    let (_, original) = authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &request.request_id)?,
            &authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("original native caller request")?;
    super::super::process_recovery::configure_caller_restart(&mut kernel, &original, &witness)?;
    kernel.set_caller_executor(executor.clone())?;
    kernel.reconcile_durable_admission_startup()?;
    Ok(Fixture {
        kernel,
        authority,
        binding,
        request,
        context,
        invocations,
        hook,
        agent,
        signer,
        _directory,
    })
}

#[test]
fn native_caller_original_delivery_survives_restart_and_authority_expiry() -> TestResult {
    for combined in [false, true] {
        for declassification in [false, true] {
            let (mut fixture, disclosure) = if declassification {
                let (fixture, key) = super::super::declassification::profile(combined, 300)?;
                (fixture, Some(key))
            } else {
                (
                    if combined {
                        Fixture::combined_native_credentials()?
                    } else {
                        Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?
                    },
                    None,
                )
            };
            let legacy = if declassification {
                super::super::nonce::execution::install_nonce(&mut fixture, 120)
            } else {
                super::super::nonce::execution::configure(&mut fixture, true)?
            };
            exercise_delivery(
                fixture,
                legacy,
                DeliveryMode::Restart {
                    disclosure: disclosure.map(Box::new),
                    expire: true,
                },
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "restart combined={combined} declassification={declassification}: {error}"
                ))
            })?;
        }
    }
    Ok(())
}
