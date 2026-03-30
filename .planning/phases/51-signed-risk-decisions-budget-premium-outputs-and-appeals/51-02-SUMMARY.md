# Summary 51-02

Persisted signed underwriting decisions and appeals in SQLite, exposed issue,
list, and appeal endpoints through trust-control and the CLI, and kept the
current lifecycle state as a store projection so supersession never rewrites a
previously signed decision artifact.
