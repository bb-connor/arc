# Independent review disposition

Reviewer: `native_acp_openapi_final_review`. One reviewer was used for the batch;
the implementer performed the repairs and executed the checks.

| Finding | Repair | Evidence |
| --- | --- | --- |
| CLI certificate generation flattened the compliance error source. | Added registered source-preserving CLI errors with redacted reports; migrated the certificate caller. | `local/review-repairs-cli.log`, `registered_cli_source_remains_inspectable_without_public_disclosure`. |
| Sender-key decoding and non-text sender headers lost native causes. | Typed key/header causes and bounded original header processing before replay custody. | `local/sender-owner-final.log`, key-redaction and non-text-header regressions. |
| Signed deployment ceilings retained a removable staging output directory. | Separate discovery exclusions from deployed runtime/anchor exclusions. | `native/authority-path-tests.log`, `deployed_policy_does_not_require_the_staging_filesystem`. |
| Positive cage wire vectors retained the old seccomp constraint shape. | Updated canonical positive vectors and hashes to OR alternatives of AND constraints. | `local/security-wire-vectors-terminal.log` and `local/schema-registry-terminal.log`. |

The native follow-up examined all-branch `prlimit64` and `execveat` restrictions,
empty/duplicate alternatives, broker FD restriction and the F_GETFD/F_SETFD
boundary. The final privileged probe additionally executes denied duplication
and denied clearing of close-on-exec. Full mini-SWE transport composition was
not implemented or approved by this review.
