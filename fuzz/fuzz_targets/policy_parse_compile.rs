#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chio_policy::CompiledPolicy;
use libfuzzer_sys::fuzz_target;

const MAX_RAW_BYTES: usize = 16 * 1024;
const POLICY_SEEDS: &[&[u8]] = &[
    include_bytes!("../corpus/fuzz_policy_parse_compile/canonical-hushspec.yaml"),
    include_bytes!("../corpus/fuzz_policy_parse_compile/hushspec-base.yaml"),
    include_bytes!("../corpus/fuzz_policy_parse_compile/hushspec-block-all.yaml"),
    include_bytes!("../corpus/fuzz_policy_parse_compile/hushspec-guard-heavy.yaml"),
    include_bytes!("../corpus/fuzz_policy_parse_compile/hushspec-reputation.yaml"),
    include_bytes!("../corpus/fuzz_policy_parse_compile/hushspec-tool-allow.yaml"),
];

#[derive(Arbitrary, Debug)]
struct PolicyInput {
    raw_yaml: Vec<u8>,
    structured: StructuredPolicy,
}

#[derive(Arbitrary, Debug)]
struct StructuredPolicy {
    name_selector: u8,
    include_forbidden_paths: bool,
    include_egress: bool,
    include_secret_patterns: bool,
    include_tool_access: bool,
    include_shell_commands: bool,
    default_blocks_tools: bool,
    max_args_size: u16,
}

fn selected<'a>(selector: u8, values: &'a [&'a str]) -> &'a str {
    values[usize::from(selector) % values.len()]
}

fn structured_yaml(input: &StructuredPolicy) -> String {
    let policy_name = selected(
        input.name_selector,
        &["fuzz-default", "fuzz-ci", "fuzz-agent", "fuzz-operator"],
    );
    let default_action = if input.default_blocks_tools {
        "block"
    } else {
        "allow"
    };
    let max_args_size = 1 + usize::from(input.max_args_size % 8192);

    let mut yaml = format!(
        "hushspec: \"0.1.0\"\nname: {policy_name}\ndescription: fuzz generated policy\nrules:\n"
    );

    if input.include_forbidden_paths {
        yaml.push_str(
            "  forbidden_paths:\n    enabled: true\n    patterns:\n      - \"**/.env\"\n      - \"/etc/shadow\"\n    exceptions:\n      - \"/tmp/safe.env\"\n",
        );
    }
    if input.include_egress {
        yaml.push_str(
            "  egress:\n    enabled: true\n    allow:\n      - \"api.github.com\"\n      - \"*.openai.com\"\n    block:\n      - \"metadata.google.internal\"\n    default: block\n",
        );
    }
    if input.include_secret_patterns {
        yaml.push_str(
            "  secret_patterns:\n    enabled: true\n    patterns:\n      - name: github_token\n        pattern: \"gh[ps]_[A-Za-z0-9]{36}\"\n        severity: critical\n    skip_paths:\n      - \"**/tests/**\"\n",
        );
    }
    if input.include_tool_access {
        yaml.push_str(&format!(
            "  tool_access:\n    enabled: true\n    allow:\n      - read_file\n      - list_tools\n    block:\n      - shell_exec\n    require_confirmation: []\n    default: {default_action}\n    max_args_size: {max_args_size}\n",
        ));
    }
    if input.include_shell_commands {
        yaml.push_str(
            "  shell_commands:\n    enabled: true\n    forbidden_patterns:\n      - \"(?i)rm\\\\s+-rf\"\n      - \"(?i)curl\\\\s+[^|]*\\\\|\\\\s*sh\"\n",
        );
    }

    if !input.include_forbidden_paths
        && !input.include_egress
        && !input.include_secret_patterns
        && !input.include_tool_access
        && !input.include_shell_commands
    {
        yaml.push_str("  tool_access:\n    enabled: true\n    default: allow\n");
    }

    yaml
}

fn compiled_summary(compiled: &CompiledPolicy) -> (Vec<String>, String) {
    let mut guard_names = compiled.guard_names.clone();
    guard_names.sort();
    let scope = match chio_core::canonical_json_string(&compiled.default_scope) {
        Ok(scope) => scope,
        Err(error) => panic!("compiled default scope should canonicalize: {error}"),
    };
    (guard_names, scope)
}

fn is_exact_seed(data: &[u8], seeds: &[&[u8]]) -> bool {
    seeds.contains(&data)
}

#[derive(Copy, Clone, Debug)]
enum PolicyInputKind {
    MutatedRaw,
    ExactSeed,
    Structured,
}

impl PolicyInputKind {
    fn expects_valid(self) -> bool {
        matches!(self, Self::ExactSeed | Self::Structured)
    }

    fn label(self) -> &'static str {
        match self {
            Self::MutatedRaw => "mutated raw policy",
            Self::ExactSeed => "exact seed policy",
            Self::Structured => "structured policy",
        }
    }
}

fn exercise_yaml(yaml: &str, input_kind: PolicyInputKind) {
    let _ = chio_policy::is_hushspec_format(yaml);

    let spec = match chio_policy::HushSpec::parse(yaml) {
        Ok(spec) => spec,
        Err(error) if input_kind.expects_valid() => {
            panic!("{} should parse: {error}", input_kind.label())
        }
        Err(_error) => return,
    };

    let validation = chio_policy::validate(&spec);
    let compiled = chio_policy::compile_policy(&spec);

    if input_kind.expects_valid() {
        assert!(
            validation.is_valid(),
            "{} should validate: {:?}",
            input_kind.label(),
            validation.errors
        );
    }

    if validation.is_valid() {
        assert!(
            compiled.is_ok(),
            "valid policy should compile: {:?}",
            compiled.err()
        );
    }

    if let Ok(roundtrip_yaml) = spec.to_yaml() {
        let reparsed = chio_policy::HushSpec::parse(&roundtrip_yaml);
        if validation.is_valid() {
            let reparsed = match reparsed {
                Ok(reparsed) => reparsed,
                Err(error) => panic!("valid policy should parse after YAML roundtrip: {error}"),
            };
            let revalidation = chio_policy::validate(&reparsed);
            assert!(
                revalidation.is_valid(),
                "roundtripped policy should validate: {:?}",
                revalidation.errors
            );

            let recompiled = match chio_policy::compile_policy(&reparsed) {
                Ok(recompiled) => recompiled,
                Err(error) => panic!("roundtripped valid policy should compile: {error}"),
            };
            let compiled = match compiled {
                Ok(compiled) => compiled,
                Err(error) => panic!("valid policy should compile before roundtrip: {error}"),
            };
            assert_eq!(compiled_summary(&compiled), compiled_summary(&recompiled));
        }
    }
}

fn exercise_generated(input: PolicyInput) {
    exercise_raw(&input.raw_yaml);

    let generated = structured_yaml(&input.structured);
    exercise_yaml(&generated, PolicyInputKind::Structured);
}

fn exercise_raw(data: &[u8]) {
    if data.len() > MAX_RAW_BYTES {
        return;
    }

    let input_kind = if is_exact_seed(data, POLICY_SEEDS) {
        PolicyInputKind::ExactSeed
    } else {
        PolicyInputKind::MutatedRaw
    };

    match std::str::from_utf8(data) {
        Ok(raw) => exercise_yaml(raw, input_kind),
        Err(error) if input_kind.expects_valid() => {
            panic!("{} should be UTF-8: {error}", input_kind.label())
        }
        Err(_error) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_raw(data);

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = PolicyInput::arbitrary(&mut unstructured) {
        exercise_generated(input);
    }
});
