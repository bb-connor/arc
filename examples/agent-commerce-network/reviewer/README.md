# Reviewer

The reviewer role is intentionally separate from buyer and provider.

The first live version can stay very small:

- shell or Python script
- reads exported evidence bundle from `artifacts/`
- verifies lineage and trust boundaries
- does **not** silently upgrade imported evidence into local issuance

The reviewer should answer:

- what was locally issued?
- what was imported?
- what receipts and reconciliation artifacts are present?
- what remains non-authoritative?

## Run the verifier

```bash
examples/agent-commerce-network/reviewer/run-verify.sh \
  "$(ls -td examples/agent-commerce-network/artifacts/happy-path/* | head -1)"
```

If you have a live capability id and trust token, the verifier can also query
the latest receipt chain:

```bash
examples/agent-commerce-network/reviewer/run-verify.sh \
  "$(ls -td examples/agent-commerce-network/artifacts/happy-path/* | head -1)" \
  --control-url http://127.0.0.1:8940 \
  --auth-token demo-token \
  --capability-id <capability-id>
```
