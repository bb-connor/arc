pub fn is_credential_or_injection_name(name: &str) -> bool {
    let normalized = name.to_ascii_uppercase();
    let name = normalized.as_str();
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || name.starts_with("BASH_FUNC_")
        || name.starts_with("MALLOC_")
        || matches!(
            name,
            "BASH_ENV"
                | "DOCKER_CONFIG"
                | "ENV"
                | "GCONV_PATH"
                | "GEM_HOME"
                | "GEM_PATH"
                | "GIT_ASKPASS"
                | "GLIBC_TUNABLES"
                | "GPG_AGENT_INFO"
                | "IFS"
                | "JAVA_TOOL_OPTIONS"
                | "JDK_JAVA_OPTIONS"
                | "KRB5CCNAME"
                | "LOCPATH"
                | "NETRC"
                | "NLSPATH"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "NPM_CONFIG_USERCONFIG"
                | "PERL5OPT"
                | "PERL5LIB"
                | "PYTHONHOME"
                | "PYTHONINSPECT"
                | "PYTHONPATH"
                | "PYTHONSTARTUP"
                | "RUBYLIB"
                | "RUBYOPT"
                | "RUSTC_WRAPPER"
                | "SSLKEYLOGFILE"
                | "SSL_CERT_DIR"
                | "SSL_CERT_FILE"
                | "SSH_AUTH_SOCK"
                | "SUDO_ASKPASS"
                | "ZDOTDIR"
                | "_JAVA_OPTIONS"
        )
        || [
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "CREDENTIAL",
            "API_KEY",
            "PRIVATE_KEY",
            "ACCESS_KEY",
            "AUTHORIZATION",
        ]
        .iter()
        .any(|marker| name.contains(marker))
}
