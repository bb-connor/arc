# CI validation for `examples/istio-ext-authz`

Static checks that run without a Kubernetes cluster or live Istio control
plane. Use these in CI to catch schema drift before the manifests hit a
real mesh.

## 1. `kubeconform` for core Kubernetes schemas

[kubeconform](https://github.com/yannh/kubeconform) validates manifests
against the upstream OpenAPI schemas. Use the `-strict` flag so unknown
fields fail the build, and point `-schema-location` at the Istio CRD
bundle so `AuthorizationPolicy`, `VirtualService`, and `IstioOperator`
resolve cleanly.

```bash
# Install (binary release or Homebrew)
brew install kubeconform

# Validate every manifest in this directory. The Istio schema bundle lives
# in the community-maintained datreeio/CRDs-catalog mirror; pin a specific
# commit in CI for reproducibility.
kubeconform \
  -strict \
  -summary \
  -kubernetes-version 1.28.0 \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  examples/istio-ext-authz/00-chio-sidecar-deployment.yaml \
  examples/istio-ext-authz/01-meshconfig-patch.yaml \
  examples/istio-ext-authz/02-authorization-policy.yaml \
  examples/istio-ext-authz/03-demo-workload.yaml
```

Expected output:

```
Summary: 13 resources found parsing stdin - Valid: 13, Invalid: 0, Errors: 0, Skipped: 0
```

## 2. Python YAML fallback

When `kubeconform` is unavailable (for example, ephemeral CI runners
without network egress), fall back to a structural YAML load that still
catches parse errors, duplicate keys, and tab/space mishaps. **Every
manifest in this directory is multi-document**, so use `safe_load_all`.

```bash
python3 - <<'PY'
import sys, glob, yaml

paths = sorted(glob.glob("examples/istio-ext-authz/*.yaml"))
errors = 0
for p in paths:
    with open(p, "r", encoding="utf-8") as fh:
        try:
            docs = list(yaml.safe_load_all(fh))
        except yaml.YAMLError as exc:
            print(f"FAIL {p}: {exc}", file=sys.stderr)
            errors += 1
            continue
        print(f"OK   {p}: {len(docs)} document(s)")
sys.exit(1 if errors else 0)
PY
```

## 3. `istioctl analyze` for mesh-level diagnostics

`istioctl analyze` runs Istio's lint rules (deprecated fields, selector
mismatches, conflicting policies). It does not need a live cluster -- use
`--use-kube=false` to force offline mode.

```bash
istioctl analyze --use-kube=false \
  --revision default \
  examples/istio-ext-authz/01-meshconfig-patch.yaml \
  examples/istio-ext-authz/02-authorization-policy.yaml \
  examples/istio-ext-authz/03-demo-workload.yaml
```

## 4. Shell lint for `test-harness.sh`

```bash
shellcheck examples/istio-ext-authz/test-harness.sh
bash -n examples/istio-ext-authz/test-harness.sh
```

## 5. Suggested CI wiring

Add a job to the workspace CI pipeline that runs the three steps above in
order and fails the build on any non-zero exit. Example GitHub Actions
snippet:

```yaml
- name: Validate Istio ext_authz manifests
  run: |
    python3 -c "
    import glob, yaml, sys
    for p in sorted(glob.glob('examples/istio-ext-authz/*.yaml')):
        list(yaml.safe_load_all(open(p)))
        print(f'ok {p}')
    "
    shellcheck examples/istio-ext-authz/test-harness.sh

- name: Validate Istio ext_authz manifests (kubeconform)
  if: runner.os == 'Linux'
  run: |
    curl -fsSL https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-amd64.tar.gz \
      | tar xz kubeconform
    ./kubeconform -strict -summary \
      -kubernetes-version 1.28.0 \
      -schema-location default \
      -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
      examples/istio-ext-authz/*.yaml
```
