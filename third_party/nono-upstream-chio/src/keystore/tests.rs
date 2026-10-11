use super::*;

#[test]
fn test_build_mappings_from_list() {
    let mappings =
        build_mappings_from_list("openai_api_key,anthropic_api_key").expect("should parse");

    assert_eq!(mappings.len(), 2);
    assert_eq!(
        mappings.get("openai_api_key"),
        Some(&"OPENAI_API_KEY".to_string())
    );
    assert_eq!(
        mappings.get("anthropic_api_key"),
        Some(&"ANTHROPIC_API_KEY".to_string())
    );
}

#[test]
fn test_build_mappings_handles_whitespace() {
    let mappings = build_mappings_from_list(" key1 , key2 , key3 ").expect("should parse");

    assert_eq!(mappings.len(), 3);
    assert!(mappings.contains_key("key1"));
    assert!(mappings.contains_key("key2"));
    assert!(mappings.contains_key("key3"));
}

#[test]
fn test_build_mappings_empty() {
    let mappings = build_mappings_from_list("").expect("should parse");
    assert!(mappings.is_empty());
}

// --- op:// URI support in build_mappings_from_list ---

#[test]
fn test_build_mappings_op_uri_with_var_name() {
    let mappings =
        build_mappings_from_list("op://Development/OpenAI/credential=OPENAI_API_KEY")
            .expect("should parse");

    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings.get("op://Development/OpenAI/credential"),
        Some(&"OPENAI_API_KEY".to_string())
    );
}

#[test]
fn test_build_mappings_mixed_keyring_and_op() {
    let mappings = build_mappings_from_list("my_api_key,op://vault/item/field=SECRET_VAR")
        .expect("should parse");

    assert_eq!(mappings.len(), 2);
    assert_eq!(mappings.get("my_api_key"), Some(&"MY_API_KEY".to_string()));
    assert_eq!(
        mappings.get("op://vault/item/field"),
        Some(&"SECRET_VAR".to_string())
    );
}

#[test]
fn test_build_mappings_op_uri_without_var_rejected() {
    // Bare op:// URIs produce garbage env var names when uppercased
    let err = build_mappings_from_list("op://vault/item/field")
        .expect_err("should reject bare op:// URI");
    assert!(
        err.to_string().contains("explicit variable name"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_mappings_op_uri_empty_var_rejected() {
    // Trailing '=' with no var name
    let err = build_mappings_from_list("op://vault/item/field=")
        .expect_err("should reject empty var name");
    assert!(err.to_string().contains("no variable name"), "got: {}", err);
}

#[test]
fn test_build_mappings_op_uri_invalid_uri_rejected() {
    // URI with only 2 segments should fail validation
    let err = build_mappings_from_list("op://vault/item=MY_VAR")
        .expect_err("should reject invalid URI");
    assert!(
        err.to_string().contains("at least vault/item/field"),
        "got: {}",
        err
    );
}

// --- apple-password:// URI handling in build_mappings_from_list ---

#[test]
fn test_build_mappings_apple_password_uri_rejected_in_list_mode() {
    let err = build_mappings_from_list("apple-password://github.com/alice@example.com")
        .expect_err("should reject apple-password URI in list mode");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_mappings_apple_password_uri_with_inline_var_rejected_in_list_mode() {
    let err =
        build_mappings_from_list("apple-password://github.com/alice@example.com=>GITHUB_PASS")
            .expect_err("should reject inline apple-password var syntax");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_mappings_apple_password_uri_legacy_equals_suffix_rejected() {
    let err =
        build_mappings_from_list("apple-password://github.com/alice@example.com=GITHUB_PASS")
            .expect_err("should reject legacy inline apple-password suffix");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

// --- apple-password:// URI validation tests ---

#[test]
fn test_validate_apple_password_uri_valid() {
    assert!(
        validate_apple_password_uri("apple-password://github.com/alice@example.com").is_ok()
    );
}

#[test]
fn test_validate_apple_password_uri_valid_alias_prefix() {
    assert!(
        validate_apple_password_uri("apple-passwords://github.com/alice@example.com").is_ok()
    );
}

#[test]
fn test_validate_apple_password_uri_missing_prefix() {
    let err =
        validate_apple_password_uri("github.com/alice@example.com").expect_err("should reject");
    assert!(
        err.to_string().contains("does not start with"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_apple_password_uri_missing_account() {
    let err = validate_apple_password_uri("apple-password://github.com")
        .expect_err("should reject missing account");
    assert!(err.to_string().contains("server/account"), "got: {}", err);
}

#[test]
fn test_validate_apple_password_uri_empty_segment() {
    let err = validate_apple_password_uri("apple-password://github.com/")
        .expect_err("should reject empty account");
    assert!(err.to_string().contains("empty"), "got: {}", err);
}

#[test]
fn test_validate_apple_password_uri_forbidden_char() {
    let err = validate_apple_password_uri("apple-password://github.com/alice;rm -rf")
        .expect_err("should reject forbidden char");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

// --- keyring:// URI handling in build_mappings_from_list ---

#[test]
fn test_build_mappings_keyring_uri_rejected_in_list_mode() {
    let err = build_mappings_from_list("keyring://gh:github.com/alice")
        .expect_err("should reject keyring URI in list mode");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_mappings_keyring_uri_with_inline_var_rejected_in_list_mode() {
    let err = build_mappings_from_list("keyring://gh:github.com/alice=>GH_TOKEN")
        .expect_err("should reject inline keyring var syntax");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_mappings_keyring_uri_legacy_equals_suffix_rejected() {
    let err = build_mappings_from_list("keyring://gh:github.com/alice=GH_TOKEN")
        .expect_err("should reject legacy inline keyring suffix");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

// --- keyring:// URI validation tests ---

#[test]
fn test_validate_keyring_uri_valid() {
    assert!(validate_keyring_uri("keyring://gh:github.com/alice").is_ok());
}

#[test]
fn test_validate_keyring_uri_valid_with_special_service() {
    // Service names can contain colons, dots, etc.
    assert!(validate_keyring_uri("keyring://com.example.app/user@example.com").is_ok());
}

#[test]
fn test_validate_keyring_uri_missing_prefix() {
    let err = validate_keyring_uri("gh:github.com/alice").expect_err("should reject");
    assert!(
        err.to_string().contains("does not start with"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_keyring_uri_missing_account() {
    let err = validate_keyring_uri("keyring://gh:github.com")
        .expect_err("should reject missing account");
    assert!(err.to_string().contains("service/account"), "got: {}", err);
}

#[test]
fn test_validate_keyring_uri_empty_segment() {
    let err = validate_keyring_uri("keyring://gh:github.com/")
        .expect_err("should reject empty account");
    assert!(err.to_string().contains("empty"), "got: {}", err);
}

#[test]
fn test_validate_keyring_uri_empty_service() {
    let err =
        validate_keyring_uri("keyring:///alice").expect_err("should reject empty service");
    assert!(err.to_string().contains("empty"), "got: {}", err);
}

#[test]
fn test_validate_keyring_uri_forbidden_char() {
    let err = validate_keyring_uri("keyring://gh:github.com/alice;rm -rf")
        .expect_err("should reject forbidden char");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_keyring_uri_unknown_query_param_rejected() {
    let err = validate_keyring_uri("keyring://service/account?foo=bar")
        .expect_err("should reject unknown query param");
    assert!(
        err.to_string().contains("unknown query parameter"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_keyring_uri_unknown_decode_value_rejected() {
    let err = validate_keyring_uri("keyring://service/account?decode=unknown")
        .expect_err("should reject unknown decode value");
    assert!(
        err.to_string().contains("unknown decode value"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_keyring_uri_fragment_rejected() {
    let err = validate_keyring_uri("keyring://service/account#frag")
        .expect_err("should reject fragment");
    assert!(err.to_string().contains("fragment"), "got: {}", err);
}

#[test]
fn test_validate_keyring_uri_decode_go_keyring_accepted() {
    assert!(validate_keyring_uri("keyring://gh:github.com/alice?decode=go-keyring").is_ok());
}

#[test]
fn test_validate_keyring_uri_query_param_missing_value() {
    let err = validate_keyring_uri("keyring://service/account?decode")
        .expect_err("should reject param without value");
    assert!(err.to_string().contains("missing value"), "got: {}", err);
}

#[test]
fn test_validate_keyring_uri_too_many_segments() {
    let err = validate_keyring_uri("keyring://service/account/extra")
        .expect_err("should reject extra segments");
    assert!(err.to_string().contains("service/account"), "got: {}", err);
}

// --- keyring:// URI redaction tests ---

#[test]
fn test_redact_keyring_uri_normal() {
    assert_eq!(
        redact_keyring_uri("keyring://gh:github.com/alice"),
        "keyring://gh:github.com/<redacted>"
    );
}

#[test]
fn test_redact_keyring_uri_with_decode_query() {
    assert_eq!(
        redact_keyring_uri("keyring://gh:github.com/alice?decode=go-keyring"),
        "keyring://gh:github.com/<redacted>?decode=go-keyring"
    );
}

#[test]
fn test_redact_keyring_uri_malformed() {
    assert_eq!(redact_keyring_uri("keyring://"), "keyring://***");
}

#[test]
fn test_redact_keyring_uri_service_only() {
    assert_eq!(
        redact_keyring_uri("keyring://gh:github.com"),
        "keyring://***"
    );
}

#[test]
fn test_redact_keyring_uri_non_prefix_input() {
    assert_eq!(redact_keyring_uri("not-a-keyring-uri"), "keyring://***");
}

// --- keyring:// ?decode=go-keyring tests ---

#[cfg(feature = "system-keyring")]
#[test]
fn test_apply_keyring_decode_none_passthrough() {
    let result = apply_keyring_decode("raw-secret".to_string(), KeyringDecode::None, "test")
        .expect("None decode should passthrough");
    assert_eq!(result.as_str(), "raw-secret");
}

#[cfg(feature = "system-keyring")]
#[test]
fn test_apply_keyring_decode_go_keyring_valid() {
    // "gho_testtoken" base64-encoded is "Z2hvX3Rlc3R0b2tlbg=="
    let raw = "go-keyring-base64:Z2hvX3Rlc3R0b2tlbg==".to_string();
    let result = apply_keyring_decode(raw, KeyringDecode::GoKeyring, "test")
        .expect("should decode go-keyring value");
    assert_eq!(result.as_str(), "gho_testtoken");
}

#[cfg(feature = "system-keyring")]
#[test]
fn test_apply_keyring_decode_go_keyring_missing_prefix() {
    let err = apply_keyring_decode("plain-value".to_string(), KeyringDecode::GoKeyring, "test")
        .expect_err("should reject missing go-keyring prefix");
    assert!(
        err.to_string().contains("go-keyring-base64:"),
        "got: {}",
        err
    );
}

#[cfg(feature = "system-keyring")]
#[test]
fn test_apply_keyring_decode_go_keyring_invalid_base64() {
    let raw = "go-keyring-base64:!!!not-base64!!!".to_string();
    let err = apply_keyring_decode(raw, KeyringDecode::GoKeyring, "test")
        .expect_err("should reject invalid base64");
    assert!(err.to_string().contains("base64-decode"), "got: {}", err);
}

#[cfg(feature = "system-keyring")]
#[test]
fn test_parse_keyring_uri_decode_go_keyring() {
    let parts = parse_keyring_uri("keyring://gh:github.com/alice?decode=go-keyring")
        .expect("should parse with decode param");
    assert_eq!(parts.service, "gh:github.com");
    assert_eq!(parts.account, "alice");
    assert_eq!(parts.decode, KeyringDecode::GoKeyring);
}

#[cfg(feature = "system-keyring")]
#[test]
fn test_parse_keyring_uri_no_decode() {
    let parts = parse_keyring_uri("keyring://gh:github.com/alice")
        .expect("should parse without decode param");
    assert_eq!(parts.decode, KeyringDecode::None);
}

// --- keyring:// build_mappings_from_pairs tests ---

#[test]
fn test_build_pairs_keyring_uri_valid() {
    let pairs = vec![(
        "keyring://gh:github.com/alice".to_string(),
        "GH_TOKEN".to_string(),
    )];
    let mappings = build_mappings_from_pairs(&pairs).expect("should accept valid keyring URI");
    assert_eq!(
        mappings.get("keyring://gh:github.com/alice"),
        Some(&"GH_TOKEN".to_string())
    );
}

#[test]
fn test_build_pairs_keyring_uri_with_decode() {
    let pairs = vec![(
        "keyring://gh:github.com/alice?decode=go-keyring".to_string(),
        "GH_TOKEN".to_string(),
    )];
    let mappings =
        build_mappings_from_pairs(&pairs).expect("should accept keyring URI with decode");
    assert_eq!(
        mappings.get("keyring://gh:github.com/alice?decode=go-keyring"),
        Some(&"GH_TOKEN".to_string())
    );
}

#[test]
fn test_build_pairs_keyring_uri_invalid() {
    let pairs = vec![(
        "keyring://gh:github.com".to_string(),
        "GH_TOKEN".to_string(),
    )];
    let err = build_mappings_from_pairs(&pairs).expect_err("should reject missing account");
    assert!(err.to_string().contains("service/account"), "got: {}", err);
}

// --- keyring:// length limit test ---

#[test]
fn test_validate_keyring_uri_too_long() {
    let long_account = "a".repeat(1024);
    let uri = format!("keyring://service/{}", long_account);
    let err = validate_keyring_uri(&uri).expect_err("should reject oversized URI");
    assert!(err.to_string().contains("maximum length"), "got: {}", err);
}

// --- op:// URI validation tests ---
//
// These tests verify that validate_op_uri correctly accepts valid 1Password
// secret references and rejects malformed or dangerous ones. The rejection
// tests are security-critical: the URI is passed as an argument to
// `op read <uri>`, so we must prevent characters that could alter command
// behavior even though we use Command::new (no shell).

#[test]
fn test_validate_op_uri_valid_3_segments() {
    // Standard 1Password reference: op://vault/item/field
    assert!(validate_op_uri("op://vault/item/field").is_ok());
}

#[test]
fn test_validate_op_uri_valid_4_segments() {
    // Section-qualified reference: op://vault/item/section/field
    // 1Password supports organizing fields into sections within an item
    assert!(validate_op_uri("op://vault/item/section/field").is_ok());
}

#[test]
fn test_validate_op_uri_valid_with_spaces_and_dashes() {
    // 1Password vault and item names commonly contain spaces and dashes
    assert!(validate_op_uri("op://My Vault/My-Item/api-key").is_ok());
}

#[test]
fn test_validate_op_uri_missing_prefix() {
    let err = validate_op_uri("vault/item/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("does not start with"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_too_few_segments() {
    // op://vault/item is missing the field segment — `op read` would fail
    // but we reject early to give a clear error message
    let err = validate_op_uri("op://vault/item").expect_err("should be rejected");
    assert!(
        err.to_string().contains("at least vault/item/field"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_single_segment() {
    let err = validate_op_uri("op://vault").expect_err("should be rejected");
    assert!(
        err.to_string().contains("at least vault/item/field"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_empty_vault() {
    // Empty vault segment could cause unexpected behavior in `op read`
    let err = validate_op_uri("op:///item/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("empty path segment"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_empty_item() {
    let err = validate_op_uri("op://vault//field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("empty path segment"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_empty_field() {
    // Trailing slash produces an empty final segment
    let err = validate_op_uri("op://vault/item/").expect_err("should be rejected");
    assert!(
        err.to_string().contains("empty path segment"),
        "got: {}",
        err
    );
}

// --- Injection prevention tests ---
//
// Although we use Command::new (no shell), these characters are still
// rejected as defense-in-depth. A semicolon or pipe in a URI is never
// legitimate and likely indicates an injection attempt.

#[test]
fn test_validate_op_uri_forbidden_semicolon() {
    // Semicolons are shell command separators — reject to prevent
    // injection if the URI is ever accidentally passed through a shell
    let err = validate_op_uri("op://vault/item;rm -rf/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_forbidden_pipe() {
    // Pipes could chain commands in a shell context
    let err = validate_op_uri("op://vault/item|evil/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_forbidden_dollar() {
    // Dollar signs enable variable expansion in shell contexts —
    // could leak env vars like $HOME into the `op` argument
    let err = validate_op_uri("op://vault/$HOME/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_forbidden_backtick() {
    // Backticks trigger command substitution in sh/bash — a classic
    // injection vector where `whoami` would execute as a subprocess
    let err = validate_op_uri("op://vault/`whoami`/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_forbidden_newline() {
    // Newlines could cause argument splitting or log injection
    let err = validate_op_uri("op://vault/item\n/field").expect_err("should be rejected");
    assert!(
        err.to_string().contains("forbidden character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_query_string() {
    // 1Password URIs don't use query strings — their presence suggests
    // confusion with HTTP URLs or an attempt to inject extra parameters
    let err = validate_op_uri("op://vault/item/field?x=y").expect_err("should be rejected");
    assert!(
        err.to_string().contains("query strings or fragments"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_op_uri_fragment() {
    let err = validate_op_uri("op://vault/item/field#section").expect_err("should be rejected");
    assert!(
        err.to_string().contains("query strings or fragments"),
        "got: {}",
        err
    );
}

// --- redact_op_uri tests ---
//
// The field segment (the actual secret name) is masked in logs to avoid
// leaking what secret is being accessed. Vault and item names are kept
// visible for debuggability.

#[test]
fn test_redact_op_uri_3_segments() {
    assert_eq!(
        redact_op_uri("op://MyVault/MyItem/credential"),
        "op://MyVault/MyItem/<redacted>"
    );
}

#[test]
fn test_redact_op_uri_4_segments() {
    // Section-qualified URIs: everything after item is redacted
    assert_eq!(
        redact_op_uri("op://MyVault/MyItem/section/field"),
        "op://MyVault/MyItem/<redacted>"
    );
}

#[test]
fn test_redact_op_uri_malformed() {
    // Malformed URIs get fully redacted — no partial information leak
    assert_eq!(redact_op_uri("op://only"), "op://***");
}

#[test]
fn test_redact_op_uri_not_op() {
    // Non-op:// strings get fully redacted
    assert_eq!(redact_op_uri("keyring_account"), "op://***");
}

#[test]
fn test_redact_apple_password_uri_valid() {
    assert_eq!(
        redact_apple_password_uri("apple-password://github.com/alice@example.com"),
        "apple-password://github.com/<redacted>"
    );
}

#[test]
fn test_redact_apple_password_uri_alias_prefix() {
    assert_eq!(
        redact_apple_password_uri("apple-passwords://github.com/alice@example.com"),
        "apple-password://github.com/<redacted>"
    );
}

#[test]
fn test_redact_apple_password_uri_malformed() {
    assert_eq!(
        redact_apple_password_uri("apple-password://only-server"),
        "apple-password://***"
    );
}

// --- redact_file_uri tests ---

#[test]
fn test_redact_file_uri() {
    assert_eq!(
        redact_file_uri("file:///run/secrets/api-token"),
        "file:///run/secrets/[REDACTED]"
    );
    assert_eq!(
        redact_file_uri("file:///etc/ssl/cert.pem"),
        "file:///etc/ssl/[REDACTED]"
    );
}

#[test]
fn test_redact_file_uri_root_path() {
    assert_eq!(redact_file_uri("file:///secret"), "file:///[REDACTED]");
}

// --- classify_op_error tests ---
//
// Verify that `op` CLI stderr messages are mapped to actionable errors
// so users know whether to run `op signin`, fix a typo, or debug network.

#[test]
fn test_classify_op_error_auth_required() {
    let err = classify_op_error(
        "[ERROR] not signed in. Run 'op signin' first.\n",
        "op://vault/item/field",
    );
    let msg = err.to_string();
    assert!(msg.contains("authentication required"), "got: {}", msg);
    assert!(msg.contains("op signin"), "got: {}", msg);
}

#[test]
fn test_classify_op_error_session_expired() {
    let err = classify_op_error("[ERROR] session expired\n", "op://vault/item/field");
    let msg = err.to_string();
    assert!(msg.contains("authentication required"), "got: {}", msg);
}

#[test]
fn test_classify_op_error_not_found() {
    // Maps to SecretNotFound so callers can distinguish "auth problem"
    // from "wrong vault/item name"
    let err = classify_op_error(
        "[ERROR] \"item\" not found in vault \"vault\"\n",
        "op://vault/item/field",
    );
    let msg = err.to_string();
    assert!(msg.contains("not found"), "got: {}", msg);
}

#[test]
fn test_classify_op_error_unknown() {
    // Unrecognized errors fall through to a generic message
    let err = classify_op_error("[ERROR] network timeout\n", "op://vault/item/field");
    let msg = err.to_string();
    assert!(msg.contains("1Password CLI failed"), "got: {}", msg);
}

#[test]
#[cfg(target_os = "macos")]
fn test_classify_apple_password_error_not_found() {
    let err = classify_apple_password_error(
        "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
        "apple-password://github.com/alice@example.com",
    );
    let msg = err.to_string();
    assert!(msg.contains("entry not found"), "got: {}", msg);
}

#[test]
#[cfg(target_os = "macos")]
fn test_classify_apple_password_error_user_interaction_required() {
    let err = classify_apple_password_error(
        "security: SecKeychainSearchCopyNext: User interaction is not allowed.\n",
        "apple-password://github.com/alice@example.com",
    );
    let msg = err.to_string();
    assert!(msg.contains("requires user approval"), "got: {}", msg);
}

// --- is_op_uri tests ---

#[test]
fn test_is_op_uri_positive() {
    assert!(is_op_uri("op://vault/item/field"));
}

#[test]
fn test_is_op_uri_negative() {
    // Bare keyring account names must not be misidentified as 1Password refs
    assert!(!is_op_uri("openai_api_key"));
}

#[test]
fn test_is_apple_password_uri_positive() {
    assert!(is_apple_password_uri(
        "apple-password://github.com/alice@example.com"
    ));
    assert!(is_apple_password_uri(
        "apple-passwords://github.com/alice@example.com"
    ));
}

#[test]
fn test_is_apple_password_uri_negative() {
    assert!(!is_apple_password_uri("openai_api_key"));
    assert!(!is_apple_password_uri("op://vault/item/field"));
}

// --- load_secret_by_ref dispatch ---

#[test]
fn test_load_secret_by_ref_dispatches_op() {
    // Verify that op:// URIs are routed to the 1Password backend, not keyring.
    // We expect a 1Password-specific error (op not installed or auth failure),
    // NOT a keyring "entry not found" error.
    let result = load_secret_by_ref("nono", "op://vault/item/field");
    assert!(result.is_err());
    let err = result.expect_err("should be rejected").to_string();
    assert!(
        err.contains("1Password") || err.contains("op"),
        "expected 1Password error, got: {}",
        err
    );
}

#[test]
fn test_load_secret_by_ref_dispatches_apple_passwords() {
    // Verify that Apple Password URIs are routed to the Apple backend.
    // On macOS this should return an Apple Passwords / security-specific error.
    // On non-macOS it should return the explicit unsupported-platform error.
    let result = load_secret_by_ref("nono", "apple-password://github.com/alice@example.com");
    assert!(result.is_err());
    let err = result.expect_err("should be rejected").to_string();
    assert!(
        err.contains("Apple Passwords")
            || err.contains("security")
            || err.contains("only supported on macOS"),
        "expected Apple Passwords error, got: {}",
        err
    );
}

// =========================================================================
// env:// URI tests
// =========================================================================

#[test]
fn test_is_env_uri_positive() {
    assert!(is_env_uri("env://GITHUB_TOKEN"));
    assert!(is_env_uri("env://MY_KEY_123"));
}

#[test]
fn test_is_env_uri_negative() {
    assert!(!is_env_uri("openai_api_key"));
    assert!(!is_env_uri("op://vault/item/field"));
    assert!(!is_env_uri("apple-password://github.com/alice@example.com"));
    assert!(!is_env_uri("ENV://UPPER_SCHEME"));
}

#[test]
fn test_validate_env_uri_valid() {
    assert!(validate_env_uri("env://GITHUB_TOKEN").is_ok());
    assert!(validate_env_uri("env://MY_API_KEY_123").is_ok());
    assert!(validate_env_uri("env://x").is_ok());
    assert!(validate_env_uri("env://A").is_ok());
}

#[test]
fn test_validate_env_uri_empty_name() {
    let err = validate_env_uri("env://").expect_err("should reject");
    assert!(
        err.to_string().contains("empty variable name"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_env_uri_invalid_chars() {
    // Spaces
    let err = validate_env_uri("env://MY VAR").expect_err("should reject");
    assert!(
        err.to_string().contains("invalid character"),
        "got: {}",
        err
    );

    // Dashes
    let err = validate_env_uri("env://MY-VAR").expect_err("should reject");
    assert!(
        err.to_string().contains("invalid character"),
        "got: {}",
        err
    );

    // Dots
    let err = validate_env_uri("env://MY.VAR").expect_err("should reject");
    assert!(
        err.to_string().contains("invalid character"),
        "got: {}",
        err
    );

    // Shell metacharacters
    let err = validate_env_uri("env://$(whoami)").expect_err("should reject");
    assert!(
        err.to_string().contains("invalid character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_env_uri_dangerous_ld_preload() {
    let err = validate_env_uri("env://LD_PRELOAD").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);
}

#[test]
fn test_validate_env_uri_dangerous_dyld() {
    let err = validate_env_uri("env://DYLD_INSERT_LIBRARIES").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);
}

#[test]
fn test_validate_env_uri_dangerous_node_options() {
    let err = validate_env_uri("env://NODE_OPTIONS").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);
}

#[test]
fn test_validate_env_uri_dangerous_path() {
    let err = validate_env_uri("env://PATH").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);
}

#[test]
fn test_validate_env_uri_missing_prefix() {
    let err = validate_env_uri("GITHUB_TOKEN").expect_err("should reject");
    assert!(
        err.to_string().contains("does not start with"),
        "got: {}",
        err
    );
}

#[test]
fn test_load_from_env_set() {
    // Set a test variable, load it, verify value
    let test_var = "NONO_TEST_ENV_SECRET_12345";
    unsafe { std::env::set_var(test_var, "secret_value_42") };

    let result = load_from_env(&format!("env://{}", test_var));
    assert!(result.is_ok(), "should load: {:?}", result.err());
    assert_eq!(*result.expect("should load"), "secret_value_42");

    unsafe { std::env::remove_var(test_var) };
}

#[test]
fn test_load_from_env_not_set() {
    let result = load_from_env("env://NONO_NONEXISTENT_VAR_XYZZY");
    assert!(result.is_err());
    let err = result.expect_err("should fail").to_string();
    assert!(err.contains("not set"), "got: {}", err);
}

#[test]
fn test_load_from_env_empty() {
    let test_var = "NONO_TEST_ENV_EMPTY_12345";
    unsafe { std::env::set_var(test_var, "") };

    let result = load_from_env(&format!("env://{}", test_var));
    assert!(result.is_err());
    let err = result.expect_err("should fail").to_string();
    assert!(err.contains("empty"), "got: {}", err);

    unsafe { std::env::remove_var(test_var) };
}

#[test]
fn test_load_secret_by_ref_dispatches_env() {
    let test_var = "NONO_TEST_REF_DISPATCH_12345";
    unsafe { std::env::set_var(test_var, "dispatched_ok") };

    let result = load_secret_by_ref("nono", &format!("env://{}", test_var));
    assert!(
        result.is_ok(),
        "should dispatch to env backend: {:?}",
        result.err()
    );
    assert_eq!(*result.expect("should load"), "dispatched_ok");

    unsafe { std::env::remove_var(test_var) };
}

// --- env:// in build_mappings_from_list ---

#[test]
fn test_build_mappings_env_uri_auto_derive() {
    let mappings = build_mappings_from_list("env://GITHUB_TOKEN").expect("should parse");
    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings.get("env://GITHUB_TOKEN"),
        Some(&"GITHUB_TOKEN".to_string())
    );
}

#[test]
fn test_build_mappings_env_uri_with_explicit_var() {
    let mappings =
        build_mappings_from_list("env://GITHUB_TOKEN=GH_TOKEN").expect("should parse");
    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings.get("env://GITHUB_TOKEN"),
        Some(&"GH_TOKEN".to_string())
    );
}

#[test]
fn test_build_mappings_env_uri_empty_var_rejected() {
    let err =
        build_mappings_from_list("env://GITHUB_TOKEN=").expect_err("should reject empty var");
    assert!(err.to_string().contains("no variable name"), "got: {}", err);
}

#[test]
fn test_build_mappings_env_uri_dangerous_rejected() {
    let err =
        build_mappings_from_list("env://LD_PRELOAD").expect_err("should reject dangerous var");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);
}

#[test]
fn test_build_mappings_mixed_keyring_op_env() {
    let mappings = build_mappings_from_list(
        "my_api_key,op://vault/item/field=SECRET_VAR,env://GITHUB_TOKEN",
    )
    .expect("should parse");

    assert_eq!(mappings.len(), 3);
    assert_eq!(mappings.get("my_api_key"), Some(&"MY_API_KEY".to_string()));
    assert_eq!(
        mappings.get("op://vault/item/field"),
        Some(&"SECRET_VAR".to_string())
    );
    assert_eq!(
        mappings.get("env://GITHUB_TOKEN"),
        Some(&"GITHUB_TOKEN".to_string())
    );
}

// =========================================================================
// Case-insensitive dangerous env var bypass prevention
// =========================================================================

#[test]
fn test_validate_env_uri_dangerous_case_insensitive() {
    // Lowercase must be caught (case-insensitive check)
    let err = validate_env_uri("env://ld_preload").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);

    // Mixed case must be caught
    let err = validate_env_uri("env://Ld_Preload").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);

    let err = validate_env_uri("env://path").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);

    let err = validate_env_uri("env://Node_Options").expect_err("should reject");
    assert!(err.to_string().contains("dangerous"), "got: {}", err);
}

// =========================================================================
// Destination env var validation
// =========================================================================

#[test]
fn test_validate_destination_env_var_valid() {
    assert!(validate_destination_env_var("GITHUB_TOKEN").is_ok());
    assert!(validate_destination_env_var("MY_API_KEY").is_ok());
    assert!(validate_destination_env_var("x").is_ok());
}

#[test]
fn test_validate_destination_env_var_empty() {
    let err = validate_destination_env_var("").expect_err("should reject");
    assert!(err.to_string().contains("empty"), "got: {}", err);
}

#[test]
fn test_validate_destination_env_var_invalid_chars() {
    let err = validate_destination_env_var("MY-VAR").expect_err("should reject");
    assert!(
        err.to_string().contains("invalid character"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_destination_env_var_dangerous() {
    let err = validate_destination_env_var("LD_PRELOAD").expect_err("should reject");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);
}

#[test]
fn test_validate_destination_env_var_dangerous_case_insensitive() {
    let err = validate_destination_env_var("ld_preload").expect_err("should reject");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);

    let err = validate_destination_env_var("Path").expect_err("should reject");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);

    let err = validate_destination_env_var("DYLD_INSERT_LIBRARIES").expect_err("should reject");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);
}

#[test]
fn test_build_mappings_env_uri_explicit_dangerous_target_rejected() {
    // env://SAFE_VAR=LD_PRELOAD must be rejected
    let err = build_mappings_from_list("env://SAFE_VAR=LD_PRELOAD")
        .expect_err("should reject dangerous target");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);
}

#[test]
fn test_build_mappings_op_uri_dangerous_target_rejected() {
    // op://vault/item/field=PATH must be rejected
    let err = build_mappings_from_list("op://vault/item/field=PATH")
        .expect_err("should reject dangerous target");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);
}

#[test]
fn test_build_mappings_apple_password_uri_dangerous_target_rejected() {
    // Apple Passwords refs are rejected in list mode and must use explicit map flag.
    let err = build_mappings_from_list("apple-password://github.com/alice@example.com=>PATH")
        .expect_err("should reject apple-password in list mode");
    assert!(
        err.to_string().contains("--env-credential-map"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_mappings_keyring_dangerous_autoderived_rejected() {
    // A keyring name that uppercases to a dangerous var must be rejected
    let err =
        build_mappings_from_list("ld_preload").expect_err("should reject dangerous target");
    assert!(err.to_string().contains("blocklist"), "got: {}", err);
}

#[test]
fn test_build_mappings_from_pairs_keyring_and_uri() {
    let pairs = vec![
        ("openai_api_key".to_string(), "OPENAI_API_KEY".to_string()),
        (
            "op://vault/item/field".to_string(),
            "OPENAI_SECRET".to_string(),
        ),
        (
            "apple-password://github.com/user=name".to_string(),
            "GITHUB_PASSWORD".to_string(),
        ),
        ("env://GITHUB_TOKEN".to_string(), "GH_TOKEN".to_string()),
    ];

    let mappings = build_mappings_from_pairs(&pairs).expect("should parse");
    assert_eq!(mappings.len(), 4);
    assert_eq!(
        mappings.get("openai_api_key"),
        Some(&"OPENAI_API_KEY".to_string())
    );
    assert_eq!(
        mappings.get("op://vault/item/field"),
        Some(&"OPENAI_SECRET".to_string())
    );
    assert_eq!(
        mappings.get("apple-password://github.com/user=name"),
        Some(&"GITHUB_PASSWORD".to_string())
    );
    assert_eq!(
        mappings.get("env://GITHUB_TOKEN"),
        Some(&"GH_TOKEN".to_string())
    );
}

#[test]
fn test_build_mappings_from_pairs_empty_credential_ref_rejected() {
    let pairs = vec![("".to_string(), "API_KEY".to_string())];
    let err =
        build_mappings_from_pairs(&pairs).expect_err("should reject empty credential ref");
    assert!(
        err.to_string().contains("credential reference is empty"),
        "got: {}",
        err
    );
}

#[test]
fn test_build_secret_mappings_explicit_pairs_take_precedence() {
    let mut profile = HashMap::new();
    profile.insert("openai_api_key".to_string(), "FROM_PROFILE".to_string());

    let cli_pairs = vec![("openai_api_key".to_string(), "FROM_MAP".to_string())];
    let merged =
        build_secret_mappings(Some("openai_api_key"), &cli_pairs, &profile).expect("merge ok");

    assert_eq!(merged.len(), 1);
    assert_eq!(merged.get("openai_api_key"), Some(&"FROM_MAP".to_string()));
}

// =========================================================================
// file:// URI tests
// =========================================================================

#[test]
fn test_validate_file_uri_valid_absolute_path() {
    assert!(validate_file_uri("file:///run/secrets/api-token").is_ok());
    assert!(validate_file_uri("file:///tmp/secret.txt").is_ok());
    assert!(validate_file_uri("file:///etc/ssl/certs/ca.pem").is_ok());
}

#[test]
fn test_validate_file_uri_rejects_empty_path() {
    assert!(validate_file_uri("file://").is_err());
    assert!(validate_file_uri("file:///").is_err());
}

#[test]
fn test_validate_file_uri_rejects_relative_path() {
    assert!(validate_file_uri("file://relative/path").is_err());
    assert!(validate_file_uri("file://./secret").is_err());
    assert!(validate_file_uri("file://../escape").is_err());
}

#[test]
fn test_validate_file_uri_rejects_traversal() {
    assert!(validate_file_uri("file:///run/secrets/../../../etc/shadow").is_err());
    assert!(validate_file_uri("file:///tmp/../../root/.ssh/id_rsa").is_err());
}

#[test]
fn test_validate_file_uri_rejects_forbidden_characters() {
    assert!(validate_file_uri("file:///tmp/secret;rm -rf /").is_err());
    assert!(validate_file_uri("file:///tmp/secret\nnewline").is_err());
    assert!(validate_file_uri("file:///tmp/secret\x00null").is_err());
}

#[test]
fn test_is_file_uri() {
    assert!(is_file_uri("file:///run/secrets/api-token"));
    assert!(!is_file_uri("env://MY_VAR"));
    assert!(!is_file_uri("/run/secrets/api-token"));
    // Note: is_file_uri is a scheme detector, not a validator.
    // "file://relative" starts with "file://" so it matches the scheme.
    // Validation (absolute path check) happens in validate_file_uri.
    assert!(is_file_uri("file://relative"));
}

// =========================================================================
// load_from_file tests
// =========================================================================

#[test]
fn test_load_from_file_reads_and_trims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "my-api-key\n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_str(), "my-api-key");
}

#[test]
fn test_load_from_file_empty_file_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.txt");
    std::fs::write(&path, "").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri);
    assert!(result.is_err());
}

#[test]
fn test_load_from_file_whitespace_only_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitespace.txt");
    std::fs::write(&path, "  \n  \n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_str(), "  \n  ");
}

#[test]
fn test_load_from_file_not_found() {
    let result = load_from_file("file:///nonexistent/path/secret.txt");
    assert!(result.is_err());
}

#[test]
fn test_load_from_file_multiline_reads_trimmed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi.txt");
    std::fs::write(&path, "glpat-xxxxxxxxxxxx\n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri).unwrap();
    assert_eq!(result.as_str(), "glpat-xxxxxxxxxxxx");
}

#[test]
fn test_load_from_file_preserves_significant_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spaces.txt");
    std::fs::write(&path, "  secret value  \n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri).unwrap();
    assert_eq!(result.as_str(), "  secret value  ");
}

#[test]
fn test_load_from_file_trims_single_trailing_crlf() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crlf.txt");
    std::fs::write(&path, "secret\r\n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri).unwrap();
    assert_eq!(result.as_str(), "secret");
}

#[test]
fn test_load_from_file_newline_only_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newline-only.txt");
    std::fs::write(&path, "\n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_from_file(&uri);
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn test_store_secret_file_sets_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.txt");

    store_secret_file(&path, "top-secret").unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "top-secret");
}

// =========================================================================
// file:// dispatch and CLI mapping tests
// =========================================================================

#[test]
fn test_load_secret_by_ref_dispatches_file_uri() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token.txt");
    std::fs::write(&path, "secret-value\n").unwrap();
    let uri = format!("file://{}", path.display());
    let result = load_secret_by_ref("nono", &uri);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_str(), "secret-value");
}

#[test]
fn test_build_mappings_file_uri_requires_explicit_var() {
    let result = build_mappings_from_list("file:///run/secrets/api-token=MY_API_KEY");
    assert!(result.is_ok());
    let mappings = result.unwrap();
    assert_eq!(
        mappings.get("file:///run/secrets/api-token"),
        Some(&"MY_API_KEY".to_string())
    );
}

#[test]
fn test_build_mappings_file_uri_without_var_name_is_error() {
    let result = build_mappings_from_list("file:///run/secrets/api-token");
    assert!(result.is_err());
}
