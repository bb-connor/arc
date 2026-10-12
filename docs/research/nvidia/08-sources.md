# Sources for the NVIDIA stack research

This file lists every source cited in documents [01](01-nvidia-stack.md) to [07](07-ideas-backlog.md) of this set, and the sources read for the set that no document cites. Each entry gives the source, its date, its status, and the documents that use it. The last section describes the local test of OpenShell v0.1.2: its setup, its published artifacts in [spike/](spike/README.md), and the logs that were not published.

## How to read this list

| Status | Meaning |
|---|---|
| VERIFIED | A primary source read on 2026-09-28 to 2026-09-29: a publisher's own page, a repository at the commit shown, a release page, an issue tracker, or a legal or standards text. Some repository states are dated 2026-09-29 UTC. A vendor's page is primary for the vendor's own statements. The documents mark behavior observed in the local test of OpenShell v0.1.2 on 2026-09-29 as VERIFIED, local test; the last section describes that test. |
| REPORTED | A secondary source: press coverage, commentary, meeting agendas and minutes, copies of another publisher's text, or one vendor's post about another vendor's product. Not independently confirmed. |
| Unavailable | The source could not be read on the date given. The entry records the attempt. |
| Read at main | A Chio repository file read at main `f5566d9a76` (2026-09-03). |
| Read on branch | A Chio file that exists only on an unmerged branch, read at the commit named in its row. |

INFERRED and PROPOSED label statements, not sources, so they do not appear here. A status describes the source. The label a document gives a statement drawn from that source still governs the statement.

The Date column gives the source's own date where it shows one: published, updated, opened, merged, or committed. "Undated; read" gives the read date of a page that shows no date. "Not documented" means neither the source nor the reading record gives a date.

The Used in column names the documents that cite the source: [01](01-nvidia-stack.md), [02](02-chio-today.md), [03](03-overlap-matrix.md), [04](04-integration-design.md), [05](05-competitive-analysis.md), [06](06-strategy-and-roadmap.md), and [07](07-ideas-backlog.md). "Background" marks a source read for the set that no document cites.

## Pinned sources

Citations of the form `path:line` resolve against these commits.

| Source | Pin | Date |
|---|---|---|
| [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6) | `acbac9cb795094986cbab016bfd0352d980b17f6` on `main`, 13 commits after the v0.1.2 tag | committed 2026-09-29 02:18 UTC |
| [OpenShell v0.1.2](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2) | tag `v0.1.2` at `6648bd0` | release published 2026-09-28 |
| [cosai-oasis/ws4-odis](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144) | `148dc4187139a41325e3c6d6e7533d956bd33144` | 2026-09-08 |
| [NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw/tree/c97172ca1ae7cd63993b5ae04051146183d37fca) | `c97172ca1ae7cd63993b5ae04051146183d37fca` | committed 2026-09-29 02:37 UTC |
| [NVIDIA/NeMo-Relay](https://github.com/NVIDIA/NeMo-Relay/tree/db4c6c520d66f15acf28b21be179a6d576254a1b) | `db4c6c520d66f15acf28b21be179a6d576254a1b` | 2026-09-29 |
| [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent/tree/39faafb61688282a372ff2d59191581588e9a003) | `39faafb61688282a372ff2d59191581588e9a003` | 2026-09-28 |
| [backbay-labs/hush](https://github.com/backbay-labs/hush/tree/6ca599ca8322a7cae6050086718ed5f3417c97e1) (HushSpec) | `6ca599ca8322a7cae6050086718ed5f3417c97e1` | committed 2026-09-23 |
| [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema/tree/v1.9.0) | release `v1.9.0` | released 2026-08-03 |
| Chio (`bb-connor/arc`) | main `f5566d9a76` | 2026-09-03 |
| Chio draft PR #1160 | `f928453692` on `origin/integration/process-security-m4` | 2026-09-26 |
| Chio PR #1156 | `7059c71ca8` on `origin/codex/required-agent-integrations-20260909` | 2026-09-10 |

## NVIDIA primary sources

### Announcement, blogs, and product pages

| Source | Date | Status | Used in |
|---|---|---|---|
| [NVIDIA agent safety solution page](https://www.nvidia.com/en-us/solutions/ai/agent-safety) | undated; read 2026-09-28 | VERIFIED | 01 |
| [NVIDIA blog: AI security and the agent stack](https://blogs.nvidia.com/blog/ai-security-agent-stack) | 2026-09-21 | VERIFIED | background |
| [NVIDIA blog: Microsoft Build, Windows, local and cloud devices](https://blogs.nvidia.com/blog/microsoft-build-windows-local-cloud-devices) | 2026-06-02 | VERIFIED | background |
| [NVIDIA blog: Open Secure AI Alliance contributions](https://blogs.nvidia.com/blog/open-secure-ai-alliance-contributions) | 2026-08-04 | VERIFIED | 01, 05 |
| [NVIDIA blog: Open Secure AI Alliance launch post](https://blogs.nvidia.com/blog/open-secure-ai-alliance) | 2026-07-27; edited 2026-09-22 | VERIFIED | 01 |
| [NVIDIA developer blog figure: Agent Safety Platform reference (image)](https://developer-blogs.nvidia.com/wp-content/uploads/2026/09/NVIDIAAgentSafetyPlatform_1920x1080_Title_v05.webp) | 2026-09-28 | VERIFIED | background |
| [NVIDIA developer blog: Add runtime controls to AI agents with NVIDIA OpenShell](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell) | 2026-09-28 | VERIFIED | 01 |
| [NVIDIA developer blog: Advancing AI infrastructure for agentic AI with NVIDIA DOCA in-silicon security](https://developer.nvidia.com/blog/advancing-ai-infrastructure-for-agentic-ai-with-nvidia-doca-in-silicon-security) | 2026-06-01 | VERIFIED | background |
| [NVIDIA developer blog: Build a secure, always-on local AI agent with NVIDIA NemoClaw and OpenClaw](https://developer.nvidia.com/blog/build-a-secure-always-on-local-ai-agent-with-nvidia-nemoclaw-and-openclaw) | 2026-04-17 | VERIFIED | background |
| [NVIDIA developer blog: Build personal AI agents on Windows PCs with new tools from Microsoft and NVIDIA](https://developer.nvidia.com/blog/build-personal-ai-agents-on-windows-pcs-with-new-tools-from-microsoft-and-nvidia) | 2026-06-02 | VERIFIED | background |
| [NVIDIA developer blog: Building an adaptive agentic cybersecurity system with NVIDIA Nemotron](https://developer.nvidia.com/blog/building-an-adaptive-agentic-cybersecurity-system-with-nvidia-nemotron) | 2026-09-01 | VERIFIED | background |
| [NVIDIA developer blog: Four ways to deploy more secure AI agents](https://developer.nvidia.com/blog/four-ways-to-deploy-more-secure-ai-agents) | 2026-07-30 | VERIFIED | background |
| [NVIDIA developer blog: How to carry user identity across federated Kubernetes and AI platforms](https://developer.nvidia.com/blog/how-to-carry-user-identity-across-federated-kubernetes-and-ai-platforms) | 2026-09-03 | VERIFIED | background |
| [NVIDIA developer blog: How to govern autonomous agents in enterprise AI factories](https://developer.nvidia.com/blog/how-to-govern-autonomous-agents-in-enterprise-ai-factories) | 2026-06-29 | VERIFIED | background |
| [NVIDIA developer blog: NVIDIA verified agent skills provide capability governance for AI agents](https://developer.nvidia.com/blog/nvidia-verified-agent-skills-provide-capability-governance-for-ai-agents) | 2026-05-19 | VERIFIED | background |
| [NVIDIA developer blog: Open Agent Safety Platform, a reference for continuous in-silicon agent monitoring](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring) | 2026-09-28 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [NVIDIA developer blog: Route AI agent workloads across models with NVIDIA NeMo Switchyard](https://developer.nvidia.com/blog/route-ai-agent-workloads-across-models-with-nvidia-nemo-switchyard) | 2026-08-11 | VERIFIED | background |
| [NVIDIA developer blog: Run autonomous, self-evolving agents more safely with NVIDIA OpenShell](https://developer.nvidia.com/blog/run-autonomous-self-evolving-agents-more-safely-with-nvidia-openshell) | 2026-03-16 | VERIFIED | background |
| [NVIDIA developer blog: Six agent harness capabilities for higher model performance](https://developer.nvidia.com/blog/six-agent-harness-capabilities-for-higher-model-performance) | 2026-07-27 | VERIFIED | background |
| [NVIDIA developer blog: Where Security Fits in an AI Agent Stack](https://developer.nvidia.com/blog/where-security-fits-in-an-ai-agent-stack) | 2026-08-21 | VERIFIED | 01, 04, 05, 07 |
| [NVIDIA NeMo microservices documentation (archive)](https://archive.docs.nvidia.com/nemo/microservices/latest/index.html) | not documented | VERIFIED | background |
| [NVIDIA NemoClaw product page and FAQ](https://www.nvidia.com/en-us/ai/nemoclaw) | undated; read 2026-09-28 | VERIFIED | 01 |
| [NVIDIA OpenShell product page](https://www.nvidia.com/en-us/ai/openshell) | undated; read 2026-09-28 | VERIFIED | 01 |
| [NVIDIA partners page](https://www.nvidia.com/en-us/about-nvidia/partners) | not documented | VERIFIED | background |
| [NVIDIA data processing unit product page](https://www.nvidia.com/en-us/networking/products/data-processing-unit) | nv-update-date 2026-08-24 | VERIFIED | background |
| [NVIDIA DOCA product page](https://www.nvidia.com/en-us/networking/products/software/doca) | not documented | VERIFIED | background |
| [NVIDIA GTC 2026 session S81489: abstract and transcript](https://www.nvidia.com/assets/nvod/md/gtc26-s81489.md) | 2026-03-18 | VERIFIED | background |
| [NVIDIA GTC 2026 session S81489: A New Paradigm: Verifiable AI](https://www.nvidia.com/en-us/on-demand/session/gtc26-s81489) | uploadDate 2026-03-18 | VERIFIED | background |
| [NVIDIA Perspectives: OpenShell](https://perspectives.nvidia.com/nvidia-openshell) | last updated 2026-09-17 | VERIFIED | background |
| [NVIDIA press release: NVIDIA and Palantir, sovereign intelligence for supply chains](https://nvidianews.nvidia.com/news/nvidia-and-palantir-bring-sovereign-intelligence-to-critical-supply-chains) | not documented | VERIFIED | background |
| [NVIDIA press release: first quarter fiscal 2027 results](https://nvidianews.nvidia.com/news/nvidia-announces-financial-results-for-first-quarter-fiscal-2027) | 2026-05-20 | VERIFIED | background |
| [NVIDIA press release: second quarter fiscal 2027 results](https://nvidianews.nvidia.com/news/nvidia-announces-financial-results-for-second-quarter-fiscal-2027) | 2026-08-26 | VERIFIED | background |
| [NVIDIA press release: NVIDIA announces NemoClaw](https://nvidianews.nvidia.com/news/nvidia-announces-nemoclaw) | 2026-03-16 | VERIFIED | 01 |
| [NVIDIA press release: Agent Toolkit expands with PhysicsNeMo and CUDA-X libraries](https://nvidianews.nvidia.com/news/nvidia-expands-nvidia-agent-toolkit-with-nvidia-physicsnemo-and-cuda-x-libraries-to-transform-how-the-world-engineers-designs-and-builds) | 2026-07-26 | VERIFIED | background |
| [NVIDIA press release: Open Agent Safety Platform](https://nvidianews.nvidia.com/news/open-agent-safety-platform) | 2026-09-28 | VERIFIED | 01, 02, 03, 04, 05, 06, 07 |

### Secure Agent Workspace reference design

Every SAW page reads "Last updated on Jun 28, 2026".

| Source | Date | Status | Used in |
|---|---|---|---|
| [SAW: Abstract](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/abstract.html) | 2026-06-28 | VERIFIED | 01 |
| [SAW: Agent blueprint patterns](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/agent-blueprint-patterns.html) | 2026-06-28 | VERIFIED | background |
| [SAW: Azure reference implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/azure-reference-implementation.html) | 2026-06-28 | VERIFIED | 01, 03 |
| [SAW: Deployment tiers](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/deployment-tiers.html) | last updated 2026-06-28 | VERIFIED | 01, 02, 03, 05 |
| [SAW: Enterprise tool access model](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html) | last updated 2026-06-28 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [SAW: figure images](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/_images) | read 2026-09-28 | VERIFIED | background |
| [SAW: Notices](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/notices.html) | 2026-06-28 | VERIFIED | background |
| [SAW: OpenShift Virtualization reference implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html) | 2026-06-28 | VERIFIED | 01 |
| [SAW: Operating properties](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/operating-properties.html) | 2026-06-28 | VERIFIED | 01, 07 |
| [SAW: page inventory (objects.inv)](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/objects.inv) | read 2026-09-28 | VERIFIED | background |
| [SAW: Reference architecture](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/reference-architecture.html) | last updated 2026-06-28 | VERIFIED | 01, 05 |
| [SAW: Reference design index](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/index.html) | 2026-06-28 | VERIFIED | background |
| [SAW: Security and governance model](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html) | last updated 2026-06-28 | VERIFIED | 01, 03, 05, 06, 07 |
| [SAW: What is Secure Agent Workspace](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html) | last updated 2026-06-28 | VERIFIED | 01, 02, 03, 05, 06, 07 |
| [SAW: What it is not](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-it-is-not.html) | last updated 2026-06-28 | VERIFIED | 01, 05, 06, 07 |
| [SAW: Where it fits](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/where-it-fits.html) | 2026-06-28 | VERIFIED | background |

### BlueField, DOCA, and attestation

| Source | Date | Status | Used in |
|---|---|---|---|
| [DOCA 3.5.0: changes and new features](https://networking-docs.nvidia.com/doca/archive/3-5-0/changes-and-new-features) | September 2026; updated 2026-09-02 | VERIFIED | 01, 05, 06, 07 |
| [DOCA 3.5.0: DOCA Argus service guide](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide) | updated 2026-09-11 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [DOCA 3.5.0: DOCA services](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-services) | updated 2026-09-01 | VERIFIED | 01, 03, 05, 06, 07 |
| [DOCA 3.5.0: DOCA Telemetry Service guide](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-telemetry-service-guide) | undated; read 2026-09-28 | VERIFIED | 01 |
| [DOCA 3.5.0: general support](https://networking-docs.nvidia.com/doca/archive/3-5-0/general-support) | updated 2026-09-02 | VERIFIED | 01, 03, 05, 07 |
| [NRAS JSON Web Key Set](https://nras.attestation.nvidia.com/.well-known/jwks.json) | read 2026-09-28 (US time) | VERIFIED | 01, 04 |
| [NVIDIA attestation API reference: attestation info](https://docs.api.nvidia.com/attestation/reference/attestationinfo) | last updated 2026-08-06 | VERIFIED | background |
| [NVIDIA blog: BlueField-4 for AI factories](https://blogs.nvidia.com/blog/bluefield-4-ai-factory) | 2025-10-28 | VERIFIED | 01 |
| [NVIDIA BlueField-4 DPU datasheet](https://dam-cdn.nvd.orangelogic.com/AssetLink/whs8mhb340t412js4612g3356607hapf.pdf) | June 2026 | VERIFIED | 01, 03, 04 |
| [NVIDIA NRAS level-1 root certificate revocation list](http://crl.ndis.nvidia.com/crl-nras/nv-nras-l1-root.crl) | 2025-12-10 | VERIFIED | background |
| [NVIDIA developer blog: BlueField Astra for Vera Rubin NVL72](https://developer.nvidia.com/blog/redefining-secure-ai-infrastructure-with-nvidia-bluefield-astra-for-nvidia-vera-rubin-nvl72) | 2026-01-07 | VERIFIED | 01 |
| [NVIDIA developer blog: Building a zero-trust architecture for confidential AI factories](https://developer.nvidia.com/blog/building-a-zero-trust-architecture-for-confidential-ai-factories) | 2026-03-23 | VERIFIED | background |
| [NVIDIA developer blog: Inside the NVIDIA Rubin platform](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer) | 2026-01-05 | VERIFIED | 01 |
| [NVIDIA developer blog: BlueField-4 and network infrastructure for agentic AI factories](https://developer.nvidia.com/blog/nvidia-bluefield-4-powers-new-scale-in-network-infrastructure-for-agentic-ai-factories) | 2026-08-24 | VERIFIED | background |
| [NVIDIA developer blog: Vera Rubin POD, seven chips, five rack-scale systems, one AI supercomputer](https://developer.nvidia.com/blog/nvidia-vera-rubin-pod-seven-chips-five-rack-scale-systems-one-ai-supercomputer) | 2026-03-16 | VERIFIED | background |
| [NVIDIA developer blog: Scaling agentic AI factories through extreme co-design with NVIDIA BlueField](https://developer.nvidia.com/blog/scaling-agentic-ai-factories-through-extreme-co-design-with-nvidia-bluefield) | 2026-07-16 | VERIFIED | background |
| [NVIDIA device attestation documentation (DPUs and NICs), v6.0](https://networking-docs.nvidia.com/dpunicattestation) | 2026-08-31 | VERIFIED | 01, 03, 04, 05 |
| [NVIDIA Attestation documentation landing page](https://docs.nvidia.com/attestation) | not documented | VERIFIED | background |
| [NVIDIA Attestation docs: deployment guide](https://docs.nvidia.com/attestation/poc-to-production/latest/deployment_guide.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation docs: GPU claims](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Confidential Computing documentation index](https://docs.nvidia.com/confidential-computing/index.html) | not documented | VERIFIED | background |
| [NVIDIA Attestation docs: claims guide introduction](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/introduction.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation docs: NRAS introduction](https://docs.nvidia.com/attestation/cloud-services/latest/nras/nras_introduction.html) | last updated 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation docs: OCSP introduction](https://docs.nvidia.com/attestation/cloud-services/latest/ocsp/ocsp_introduction.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation docs: OCSP responses](https://docs.nvidia.com/attestation/cloud-services/latest/ocsp/ocsp_responses.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation docs: RIM API](https://docs.nvidia.com/attestation/cloud-services/latest/rim/rim_api.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation docs: Trust Outpost integration](https://docs.nvidia.com/attestation/poc-to-production/latest/integration-options/trust_outpost.html) | 2026-08-01 | VERIFIED | background |
| [NVIDIA Attestation SDK docs: Rust user guide](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-rust/user_guide.html) | 2026-06-10 | VERIFIED | background |
| [NVIDIA device attestation docs: BlueField-3 certificates](https://networking-docs.nvidia.com/dpunicattestation/bluefield-3-certificates) | 2026-08-31 | VERIFIED | background |
| [NVIDIA device attestation docs: CoRIM reference values](https://networking-docs.nvidia.com/dpunicattestation/concise-reference-integrity-manifest-corim) | 2026-08-31 | VERIFIED | background |
| [DOCA 3.5.0: DOCA App Shield](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-app-shield) | 2026-09-09 | VERIFIED | background |
| [BlueField BMC docs: SPDM attestation via Redfish](https://networking-docs.nvidia.com/bluefieldbmc/2601/dpu-bmc-spdm-attestation-via-redfish) | 2026-01-13 | VERIFIED | background |
| [DOCA 3.5.0: fTPM over OP-TEE](https://networking-docs.nvidia.com/doca/archive/3-5-0/ftpm-over-op-tee) | 2026-09-01 | VERIFIED | background |
| [DOCA SDK documentation](https://networking-docs.nvidia.com/doca/sdk) | 3.5.0 2026-09-10 | VERIFIED | background |
| [NVIDIA Vera CPU page](https://www.nvidia.com/en-us/data-center/vera-cpu) | undated | VERIFIED | background |
| [NVIDIA press release: Rubin platform](https://nvidianews.nvidia.com/news/rubin-platform-ai-supercomputer) | 2026-01-05 | VERIFIED | 01 |
| [NVIDIA press release: Vera BlueField-4 STX with in-silicon security](https://nvidianews.nvidia.com/news/nvidia-vera-bluefield-4-stx-brings-agentic-ai-storage-processing-with-in-silicon-security) | 2026-05-31 | VERIFIED | 01, 05 |
| [NVIDIA Remote Attestation Service (NRAS) release notes](https://docs.nvidia.com/attestation/cloud-services/latest/nras/nras_releases.html) | updated 2026-08-01 | VERIFIED | 01, 03, 04, 07 |
| [NVIDIA resource library: BlueField-4 DPU datasheet](https://resources.nvidia.com/en-us-accelerated-networking-resource-library/bluefield-4-dpu-datasheet) | not documented | VERIFIED | background |
| [NVIDIA RIM service: GH100 driver 550.90.07 reference integrity manifest](https://rim.attestation.nvidia.com/v1/rim/NV_GPU_DRIVER_GH100_550.90.07) | read 2026-09-29 | VERIFIED | background |
| [NVIDIA whitepaper: Hopper Confidential Computing (v1.0)](https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf) | July 2023 | VERIFIED | 01 |
| [NVIDIA whitepaper: Secure AI with Blackwell and Hopper GPUs (v1.3)](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf) | 2025-08-14 | VERIFIED | 01 |

### Software, blueprints, and models

| Source | Date | Status | Used in |
|---|---|---|---|
| [ai-dynamo/dynamo repository](https://github.com/ai-dynamo/dynamo) | v1.5.0 2026-09-21 | VERIFIED | background |
| [NeMo Relay docs: conditional middleware guardrails (at db4c6c5)](https://github.com/NVIDIA/NeMo-Relay/blob/db4c6c520d66f15acf28b21be179a6d576254a1b/docs/about-nemo-relay/concepts/conditional-middleware-guardrails.mdx) | commit of 2026-09-29 | VERIFIED | 06 |
| [NeMo Relay docs: daemon architecture (at db4c6c5)](https://github.com/NVIDIA/NeMo-Relay/blob/db4c6c520d66f15acf28b21be179a6d576254a1b/docs/daemon/architecture.mdx) | commit of 2026-09-29 | VERIFIED | 06 |
| [Dynamo docs: secure deployment guidelines](https://github.com/ai-dynamo/dynamo/blob/main/docs/fern/pages/developer-guide/security/secure-deployment-guidelines.md) | not documented | VERIFIED | 01 |
| [Hugging Face: nvidia/Nemotron-3.5-Content-Safety](https://huggingface.co/nvidia/Nemotron-3.5-Content-Safety) | not documented | VERIFIED | background |
| [Hugging Face dataset: nvidia/Nemotron-AIQ-Agentic-Safety-Dataset-1.0](https://huggingface.co/datasets/nvidia/Nemotron-AIQ-Agentic-Safety-Dataset-1.0) | not documented | VERIFIED | background |
| [Hugging Face: nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16](https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16) | not documented | VERIFIED | background |
| [Hugging Face: nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-NVFP4](https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-NVFP4) | not documented | VERIFIED | background |
| [NeMo Agent Toolkit docs: third-party plugins (v1.9.0)](https://github.com/NVIDIA/NeMo-Agent-Toolkit/blob/v1.9.0/docs/source/extend/third-party-plugins.md) | v1.9.0; read 2026-09-28 | VERIFIED | 07 |
| [NeMo Relay docs: CLI basic usage (at db4c6c5)](https://github.com/NVIDIA/NeMo-Relay/blob/db4c6c520d66f15acf28b21be179a6d576254a1b/docs/nemo-relay-cli/basic-usage.mdx) | commit of 2026-09-29 | VERIFIED | 05, 06, 07 |
| [NemoClaw #10140: quarantine command with a secret-free receipt](https://github.com/NVIDIA/NemoClaw/issues/10140) | 2026-08-24 | VERIFIED | 01, 07 |
| [NemoClaw #7937: Relay inside Hermes topology](https://github.com/NVIDIA/NemoClaw/issues/7937) | opened 2026-07-30; status of 2026-09-14 | VERIFIED | 01 |
| [NemoClaw #9833: comment deferring authenticated APF provenance](https://github.com/NVIDIA/NemoClaw/issues/9833) | 2026-08-25 | VERIFIED | 01, 07 |
| [NemoClaw docs: enterprise readiness](https://github.com/NVIDIA/NemoClaw/blob/main/docs/reference/enterprise-readiness.mdx) | main, read 2026-09-28 | VERIFIED | 03, 05, 06 |
| [NemoClaw docs: register an external component](https://github.com/NVIDIA/NemoClaw/blob/main/docs/deployment/register-external-component.mdx) | main at 2272c5c, 2026-09-28; read 2026-09-29 | VERIFIED | 01, 04, 05, 06 |
| [NemoClaw docs: set up a sub-agent](https://github.com/NVIDIA/NemoClaw/blob/main/docs/inference/set-up-sub-agent.mdx) | main, read 2026-09-28 | VERIFIED | 06 |
| [nv-morpheus/Morpheus repository](https://github.com/nv-morpheus/Morpheus) | not documented | VERIFIED | background |
| [NVIDIA AI Enterprise licensing guide: pricing](https://docs.nvidia.com/ai-enterprise/planning-resource/licensing-guide/latest/pricing.html) | last updated 2026-09-02 | VERIFIED | 06 |
| [NVIDIA build playbook: OpenShell overview](https://build.nvidia.com/playbooks/openshell/overview) | last updated 2026-07-27 | VERIFIED | background |
| [NVIDIA R595 trusted computing solutions release notes](https://docs.nvidia.com/595trd1-trusted-computing-solutions-release-notes.pdf) | April 2026 | VERIFIED | background |
| [NeMo Relay docs: overview](https://docs.nvidia.com/nemo/relay/about-nemo-relay/overview) | read 2026-09-29 | VERIFIED | background |
| [NVIDIA docs: agent skill trust pipeline](https://docs.nvidia.com/skills/agent-skill-trust-pipeline.md) | not documented | VERIFIED | background |
| [NVIDIA confidential computing deployment guide (TDX and SEV-SNP)](https://docs.nvidia.com/cc-deployment-guide-tdx-snp.pdf) | v7.1 2026-04-06 | VERIFIED | background |
| [NeMo Relay docs: middleware concepts](https://docs.nvidia.com/nemo/relay/about-nemo-relay/concepts/middleware) | read 2026-09-29 | VERIFIED | background |
| [NemoClaw user guide: configure runtime identity](https://docs.nvidia.com/nemoclaw/user-guide/openclaw/reference/configure-runtime-identity) | not documented | VERIFIED | background |
| [NemoClaw user guide: OpenClaw home](https://docs.nvidia.com/nemoclaw/user-guide/openclaw/home) | read 2026-09-29 | VERIFIED | background |
| [NVIDIA AI Enterprise documentation index](https://docs.nvidia.com/ai-enterprise/index.html) | read 2026-09-28 | VERIFIED | background |
| [NeMo Guardrails docs: llms.txt index](https://docs.nvidia.com/nemo/guardrails/latest/llms.txt) | not documented | VERIFIED | background |
| [NIM for LLMs docs: llms.txt index](https://docs.nvidia.com/nim/large-language-models/latest/llms.txt) | not documented | VERIFIED | background |
| [NIM for LLMs docs: model signature verification](https://docs.nvidia.com/nim/large-language-models/latest/reference/model-signature-verification.html) | not documented | VERIFIED | background |
| [NemoClaw documentation (latest)](https://docs.nvidia.com/nemoclaw/latest) | read 2026-09-28 | VERIFIED | background |
| [NIM for LLMs docs: NIM offerings](https://docs.nvidia.com/nim/large-language-models/latest/about-nim-llm/nim-offerings.html) | not documented | VERIFIED | background |
| [NVIDIA docs: skills](https://docs.nvidia.com/skills.md) | not documented | VERIFIED | background |
| [NIM for LLMs docs: tool calling and MCP](https://docs.nvidia.com/nim/large-language-models/latest/advanced-use-cases/tool-calling-and-mcp.html) | not documented | VERIFIED | background |
| [NVIDIA NIM for LLMs: API reference](https://docs.nvidia.com/nim/large-language-models/latest/reference/api-reference.html) | last updated 2026-09-24 | VERIFIED | 01, 06 |
| [NVIDIA-AI-Blueprints/aiq (AI-Q Blueprint)](https://github.com/NVIDIA-AI-Blueprints/aiq) | v2.2.1 2026-08-22 | VERIFIED | 01 |
| [NVIDIA-AI-Blueprints/Retail-Agentic-Commerce](https://github.com/NVIDIA-AI-Blueprints/Retail-Agentic-Commerce) | undated; read 2026-09-28 | VERIFIED | 07 |
| [NVIDIA-AI-Blueprints/safety-for-agentic-ai repository](https://github.com/NVIDIA-AI-Blueprints/safety-for-agentic-ai) | not documented | VERIFIED | background |
| [NVIDIA-NeMo/Guardrails repository](https://github.com/NVIDIA-NeMo/Guardrails) | v0.24.1 2026-09-16 | VERIFIED | 01 |
| [NVIDIA-NeMo/labs-OO-Agents (NOOA)](https://github.com/NVIDIA-NeMo/labs-OO-Agents) | v0.0.10 2026-09-04 | VERIFIED | 01 |
| [NVIDIA-NeMo/Switchyard repository](https://github.com/NVIDIA-NeMo/Switchyard) | v0.3.0 2026-09-22 | VERIFIED | background |
| [NVIDIA/AI-Factory-Operations-Agent repository](https://github.com/NVIDIA/AI-Factory-Operations-Agent) | not documented | VERIFIED | background |
| [NVIDIA/attestation-sdk repository](https://github.com/NVIDIA/attestation-sdk) | read 2026-09-28 | VERIFIED | 01, 04 |
| [NVIDIA/garak repository](https://github.com/NVIDIA/garak) | v0.17.0 2026-09-09 | VERIFIED | background |
| [NVIDIA/NeMo-Agent-Toolkit #1811](https://github.com/NVIDIA/NeMo-Agent-Toolkit/issues/1811) | not documented | VERIFIED | background |
| [NVIDIA/NeMo-Agent-Toolkit PR #2075 (closed unmerged)](https://github.com/NVIDIA/NeMo-Agent-Toolkit/pull/2075) | not documented | VERIFIED | background |
| [NVIDIA/NeMo-Agent-Toolkit repository](https://github.com/NVIDIA/NeMo-Agent-Toolkit) | v1.9.0 2026-09-10 | VERIFIED | 01 |
| [NVIDIA/NeMo-Relay #277: Relay and OpenShell boundary proposal](https://github.com/NVIDIA/NeMo-Relay/issues/277) | not documented | VERIFIED | background |
| [NVIDIA/NeMo-Relay PR #1154](https://github.com/NVIDIA/NeMo-Relay/pull/1154) | read 2026-09-29 | VERIFIED | background |
| [NVIDIA/NeMo-Relay release 0.9.0](https://github.com/NVIDIA/NeMo-Relay/releases/tag/0.9.0) | published 2026-09-17 | VERIFIED | background |
| [NVIDIA/NeMo-Relay repository](https://github.com/NVIDIA/NeMo-Relay) | v0.9.3 of 2026-09-28 | VERIFIED | 01, 05, 06 |
| [NVIDIA/NeMo-Relay-Plugins repository](https://github.com/NVIDIA/NeMo-Relay-Plugins) | created 2026-09-01 | VERIFIED | background |
| [NVIDIA/NemoClaw #10514: no second policy authority in NemoClaw](https://github.com/NVIDIA/NemoClaw/issues/10514) | not documented | VERIFIED | background |
| [NVIDIA/NemoClaw #11850](https://github.com/NVIDIA/NemoClaw/issues/11850) | 2026-09-15 | VERIFIED | background |
| [NVIDIA/NemoClaw #11944](https://github.com/NVIDIA/NemoClaw/issues/11944) | opened 2026-09-16; closed 2026-09-28 | VERIFIED | background |
| [NVIDIA/NemoClaw #8887: gateway-authored provider receipts](https://github.com/NVIDIA/NemoClaw/issues/8887) | opened 2026-08-12 | VERIFIED | background |
| [NVIDIA/NemoClaw at c97172c (pinned commit; docs/deployment/register-external-component.mdx, docs/reference/enterprise-readiness.mdx, package.json)](https://github.com/NVIDIA/NemoClaw/tree/c97172ca1ae7cd63993b5ae04051146183d37fca) | committed 2026-09-29 02:37 UTC | VERIFIED | 07 |
| [NVIDIA/NemoClaw PR #10305: external component contract](https://github.com/NVIDIA/NemoClaw/pull/10305) | not documented | VERIFIED | background |
| [NVIDIA/NemoClaw PR #11366: external component contract update](https://github.com/NVIDIA/NemoClaw/pull/11366) | not documented | VERIFIED | background |
| [NVIDIA/NemoClaw repository](https://github.com/NVIDIA/NemoClaw) | main at c97172c, committed 2026-09-29 02:37 UTC; read 2026-09-29 | VERIFIED | 01, 02, 06 |
| [NVIDIA/nemoclaw-community repository](https://github.com/NVIDIA/nemoclaw-community) | pushed 2026-09-23 | VERIFIED | background |
| [NemoClaw docs: commands reference](https://github.com/NVIDIA/NemoClaw/blob/main/docs/reference/commands.mdx) | not documented | VERIFIED | background |
| [NVIDIA/nvtrust repository](https://github.com/NVIDIA/nvtrust) | read 2026-09-28 | VERIFIED | 01 |
| [NVIDIA/OpenShell-Community (retired image catalog)](https://github.com/NVIDIA/OpenShell-Community) | 2026-09-23 | VERIFIED | background |
| [NVIDIA/SkillSpector repository](https://github.com/NVIDIA/SkillSpector) | v2.12.0 2026-09-23 | VERIFIED | background |

### Research notes, careers, programs, and forums

| Source | Date | Status | Used in |
|---|---|---|---|
| [OpenShell research notes index](https://nvidia.github.io/OpenShell-Research/dev-notes) | 2026-07-20; 2026-09-28 | VERIFIED | background |
| [NVIDIA careers (Workday): Principal Cyber Security Engineer, Agentic Identity and Security (JR2016696)](https://nvidia.wd5.myworkdayjobs.com/wday/cxs/nvidia/NVIDIAExternalCareerSite/job/US-CA-Santa-Clara/Principal-Cyber-Security-Engineer---Agentic-Identity-and-Security_JR2016696) | not documented | VERIFIED | background |
| [NVIDIA careers (Workday): Principal Software Engineer, Agent Policy Fabric (JR2019848)](https://nvidia.wd5.myworkdayjobs.com/wday/cxs/nvidia/NVIDIAExternalCareerSite/job/US-CA-Santa-Clara/Principal-Software-Engineer--Agent-Policy-Fabric_JR2019848) | not documented | VERIFIED | background |
| [NVIDIA careers (Workday): Senior Software Engineer, AI Agent Compute (JR2021516-1)](https://nvidia.wd5.myworkdayjobs.com/wday/cxs/nvidia/NVIDIAExternalCareerSite/job/US-CA-Remote/Senior-Software-Engineer--AI-Agent-Compute_JR2021516-1) | not documented | VERIFIED | background |
| [NVIDIA careers (Workday): Software Engineer, OpenShell (JR2020825)](https://nvidia.wd5.myworkdayjobs.com/wday/cxs/nvidia/NVIDIAExternalCareerSite/job/US-Remote/Software-Engineer--OpenShell_JR2020825) | not documented | VERIFIED | background |
| [NVIDIA careers (Workday): Staff Security Engineer, PAM and Agentic Identity (JR2024380)](https://nvidia.wd5.myworkdayjobs.com/wday/cxs/nvidia/NVIDIAExternalCareerSite/job/US-CA-Santa-Clara/Staff-Security-Engineer---PAM-and-Agentic-Identity_JR2024380) | not documented | VERIFIED | background |
| [NVIDIA careers: job 893394830937](https://jobs.nvidia.com/careers/job/893394830937) | not documented | VERIFIED | background |
| [NVIDIA careers: job 893396315492](https://jobs.nvidia.com/careers/job/893396315492) | not documented | VERIFIED | background |
| [NVIDIA careers: job 893396714460](https://jobs.nvidia.com/careers/job/893396714460) | not documented | VERIFIED | background |
| [NVIDIA careers: job 893397106477](https://jobs.nvidia.com/careers/job/893397106477) | not documented | VERIFIED | background |
| [NVIDIA careers: job 893397627179](https://jobs.nvidia.com/careers/job/893397627179) | not documented | VERIFIED | background |
| [NVIDIA careers API record for JR2019848](https://jobs.nvidia.com/api/apply/v2/jobs/893395763513?domain=nvidia.com) | not documented | VERIFIED | background |
| [NVIDIA careers: Principal Software Engineer, Agent Policy Fabric (JR2019848)](https://jobs.nvidia.com/careers/job/893395763513) | created 2026-06-12; posting start 2026-06-22 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [NVIDIA developer forums: search results for "openshell middleware"](https://forums.developer.nvidia.com/search.json?q=openshell%20middleware) | read 2026-09-29 | VERIFIED | 07 |
| [NVIDIA developer forums topic 376035: signed policy-decision attestation](https://forums.developer.nvidia.com/t/376035) | 2026-07-08 | VERIFIED | background |
| [NVIDIA developer forums topic 384549: OpenShell blog cross-post](https://forums.developer.nvidia.com/t/384549) | 2026-09-28 | VERIFIED | background |
| [NVIDIA Inception program page and FAQ](https://www.nvidia.com/en-us/startups) | undated; read 2026-09-28 | VERIFIED | 01, 05, 06, 07 |
| [NVIDIA terms of service](https://www.nvidia.com/en-eu/about-nvidia/terms-of-service) | undated | VERIFIED | 06 |
| [OpenShell research note: adversarial policy review for long-horizon agents](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-08-27-adversarial-policy-review-long-horizon-agents) | 2026-08-27 | VERIFIED | 01 |
| [OpenShell research note: learning formal methods for an agent policy prover](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover) | 2026-09-10 | VERIFIED | 01, 04, 06, 07 |
| [OpenShell research note: network redaction is not enough](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-26-network-redaction-is-not-enough) | 2026-09-26 | VERIFIED | 01 |

## OpenShell repository

### Repository and releases

| Source | Date | Status | Used in |
|---|---|---|---|
| [NVIDIA-dev/OpenShell-exporter (cited by #1055)](https://github.com/NVIDIA-dev/OpenShell-exporter) | not documented | Unavailable: HTTP 404 on 2026-09-29 | background |
| [NVIDIA/OpenShell at acbac9c (pinned commit)](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6) | committed 2026-09-29 02:18 UTC | VERIFIED | 01, 02, 03, 04, 05, 06, 07 |
| [NVIDIA/OpenShell releases](https://github.com/NVIDIA/OpenShell/releases) | v0.1.0 2026-09-25 to v0.1.2 2026-09-28; read 2026-09-29 | VERIFIED | 01, 06, 07 |
| [NVIDIA/OpenShell repository](https://github.com/NVIDIA/OpenShell) | created 2026-02-24; read 2026-09-29 | VERIFIED | 01, 06 |
| [NVIDIA/OpenShell repository metadata (GitHub API)](https://api.github.com/repos/NVIDIA/OpenShell) | read 2026-09-29 | VERIFIED | 07 |
| [OpenShell branch spike/maximal-policy-prover-subset: MAXIMUM_POLICY_ENVELOPE_SPIKE.md](https://raw.githubusercontent.com/NVIDIA/OpenShell/spike/maximal-policy-prover-subset/crates/openshell-prover/MAXIMUM_POLICY_ENVELOPE_SPIKE.md) | not documented | VERIFIED | background |
| [OpenShell release v0.1.0](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.0) | published 2026-09-25 | VERIFIED | 03 |
| [OpenShell release v0.1.2](https://github.com/NVIDIA/OpenShell/releases/tag/v0.1.2) | published 2026-09-28 | VERIFIED | 03 |

### Files at the pinned commit

Paths are relative to the OpenShell repository root at `acbac9c`. A path ending in a directory name cites the directory.

| File | Commit | Status | Used in |
|---|---|---|---|
| [`CONTRIBUTING.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/CONTRIBUTING.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 07 |
| [`Cargo.toml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/Cargo.toml) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`GOVERNANCE.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/GOVERNANCE.md) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`LICENSE`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/LICENSE) | acbac9c, 2026-09-29 | VERIFIED | 06 |
| [`MAINTAINERS.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/MAINTAINERS.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 05, 06, 07 |
| [`architecture/sandbox-limits.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/architecture/sandbox-limits.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 06, 07 |
| [`architecture/sandbox.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/architecture/sandbox.md) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`architecture/security-policy.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/architecture/security-policy.md) | acbac9c, 2026-09-29 | VERIFIED | background |
| [`crates`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/crates) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-core/src/policy.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-core/src/policy.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-core/src/policy_identity.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-core/src/policy_identity.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 06, 07 |
| [`crates/openshell-core/src/settings.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-core/src/settings.rs) | acbac9c, 2026-09-29 | VERIFIED | 04 |
| [`crates/openshell-gateway-interceptors/src/routes.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-gateway-interceptors/src/routes.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 06, 07 |
| [`crates/openshell-isolation-interface/src/contract.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-isolation-interface/src/contract.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-ocsf/src/builders/mod.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/builders/mod.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 06, 07 |
| [`crates/openshell-ocsf/src/events/mod.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/events/mod.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03, 04 |
| [`crates/openshell-ocsf/src/format/shorthand.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/format/shorthand.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-ocsf/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/lib.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03 |
| [`crates/openshell-ocsf/src/objects/metadata.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/objects/metadata.rs) | acbac9c, 2026-09-29 | VERIFIED | 03 |
| [`crates/openshell-ocsf/src/objects/process.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/objects/process.rs) | acbac9c, 2026-09-29 | VERIFIED | 03 |
| [`crates/openshell-prover-cli/src/main.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-prover-cli/src/main.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-prover/Cargo.toml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-prover/Cargo.toml) | acbac9c, 2026-09-29 | VERIFIED | 02 |
| [`crates/openshell-prover/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-prover/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-prover/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-prover/src/lib.rs) | acbac9c, 2026-09-29 | VERIFIED | 05 |
| [`crates/openshell-sandbox/src/sandbox/linux/seccomp.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-sandbox/src/sandbox/linux/seccomp.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 05, 06 |
| [`crates/openshell-server/src/auth/principal.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-server/src/auth/principal.rs) | acbac9c, 2026-09-29 | VERIFIED | 03 |
| [`crates/openshell-server/src/auth/sandbox_jwt.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-server/src/auth/sandbox_jwt.rs) | acbac9c, 2026-09-29 | VERIFIED | 05 |
| [`crates/openshell-server/src/grpc/policy.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-server/src/grpc/policy.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 05 |
| [`crates/openshell-server/src/multiplex.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-server/src/multiplex.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-supervisor-middleware/src/headers.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-middleware/src/headers.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 04 |
| [`crates/openshell-supervisor-middleware/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-middleware/src/lib.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 06, 07 |
| [`crates/openshell-supervisor-middleware/src/websocket.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-middleware/src/websocket.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 03 |
| [`crates/openshell-supervisor-network`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-supervisor-network/Cargo.toml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/Cargo.toml) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03 |
| [`crates/openshell-supervisor-network/data/sandbox-policy.rego`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/data/sandbox-policy.rego) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-supervisor-network/src/l7/middleware.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/src/l7/middleware.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04 |
| [`crates/openshell-supervisor-network/src/l7/mod.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/src/l7/mod.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-supervisor-network/src/l7/relay.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/src/l7/relay.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 06 |
| [`crates/openshell-supervisor-network/src/opa.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/src/opa.rs) | acbac9c, 2026-09-29 | VERIFIED | 03 |
| [`crates/openshell-supervisor-network/src/policy_local.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/src/policy_local.rs) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`crates/openshell-supervisor/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor/src/lib.rs) | acbac9c, 2026-09-29 | VERIFIED | 01, 04 |
| [`deploy/helm/openshell/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/deploy/helm/openshell/README.md) | acbac9c, 2026-09-29 | VERIFIED | 04, 07 |
| [`deploy/helm/openshell/templates/gateway-config.yaml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/deploy/helm/openshell/templates/gateway-config.yaml) | acbac9c, 2026-09-29 | VERIFIED | 04, 06, 07 |
| [`deploy/helm/openshell/values.yaml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/deploy/helm/openshell/values.yaml) | acbac9c, 2026-09-29 | VERIFIED | 07 |
| [`docs/about/architecture.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/about/architecture.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04 |
| [`docs/about/overview.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/about/overview.mdx) | acbac9c, 2026-09-29 | VERIFIED | 02 |
| [`docs/about/run-your-first-agent.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/about/run-your-first-agent.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`docs/about/support-matrix.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/about/support-matrix.mdx) | acbac9c, 2026-09-29 | VERIFIED | 06 |
| [`docs/extensibility/drivers.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/drivers.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 05 |
| [`docs/extensibility/gateway-interceptors.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/gateway-interceptors.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 06, 07 |
| [`docs/extensibility/isolation-backends.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/isolation-backends.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`docs/extensibility/overview.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/overview.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04 |
| [`docs/extensibility/supervisor-middleware/configure.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/supervisor-middleware/configure.mdx) | acbac9c, 2026-09-29 | VERIFIED | 04, 06, 07 |
| [`docs/extensibility/supervisor-middleware/index.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/supervisor-middleware/index.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04 |
| [`docs/extensibility/supervisor-middleware/operations.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/supervisor-middleware/operations.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 07 |
| [`docs/how-it-works/gateways/authentication.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/gateways/authentication.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 05 |
| [`docs/how-it-works/gateways/configuration.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/gateways/configuration.mdx) | acbac9c, 2026-09-29 | VERIFIED | 03 |
| [`docs/how-it-works/inference.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/inference.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03 |
| [`docs/how-it-works/policies/advisor.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/advisor.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03 |
| [`docs/how-it-works/policies/manage-policies.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/manage-policies.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 04 |
| [`docs/how-it-works/policies/network-rules.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/network-rules.mdx) | acbac9c, 2026-09-29 | VERIFIED | 04 |
| [`docs/how-it-works/policies/overview.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/overview.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`docs/how-it-works/policies/prover.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/prover.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 05, 06 |
| [`docs/how-it-works/policies/schema.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/schema.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03, 04, 05, 06, 07 |
| [`docs/how-it-works/providers/overview.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/providers/overview.mdx) | acbac9c, 2026-09-29 | VERIFIED | 03 |
| [`docs/how-it-works/providers/profiles.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/providers/profiles.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [`docs/how-it-works/sandboxes/overview.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/sandboxes/overview.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 04 |
| [`docs/how-it-works/sandboxes/runtimes.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/sandboxes/runtimes.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`docs/how-it-works/workspaces.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/workspaces.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03 |
| [`docs/kubernetes/openshift.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/kubernetes/openshift.mdx) | acbac9c, 2026-09-29 | VERIFIED | 04, 06 |
| [`docs/observability/accessing-logs.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/accessing-logs.mdx) | acbac9c, 2026-09-29 | VERIFIED | 03, 04, 05, 06 |
| [`docs/observability/logging.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/logging.mdx) | acbac9c, 2026-09-29 | VERIFIED | background |
| [`docs/observability/ocsf-json-export.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [`docs/sdk`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/docs/sdk) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`docs/security/best-practices.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/security/best-practices.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 05, 06 |
| [`docs/tutorials/microsoft-graph-provider-refresh.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/tutorials/microsoft-graph-provider-refresh.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`docs/upgrade/0-1-0.mdx`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/upgrade/0-1-0.mdx) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03, 06, 07 |
| [`examples/governance-interceptor`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/examples/governance-interceptor) | acbac9c, 2026-09-29 | VERIFIED | 01, 07 |
| [`examples/governance-interceptor/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/governance-interceptor/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [`examples/multi-agent-notepad/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/multi-agent-notepad/README.md) | acbac9c, 2026-09-29 | VERIFIED | 07 |
| [`examples/spiffe-token-exchange-demo/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/spiffe-token-exchange-demo/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`examples/spiffe-token-exchange-demo/k8s/token-issuer.js`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/spiffe-token-exchange-demo/k8s/token-issuer.js) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`examples/spiffe-token-grant-demo/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/spiffe-token-grant-demo/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`examples/supervisor-middleware-content-guard`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard) | acbac9c, 2026-09-29 | VERIFIED | 06, 07 |
| [`examples/supervisor-middleware-content-guard/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard/README.md) | acbac9c, 2026-09-29 | VERIFIED | 04, 06 |
| [`proto`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/proto) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`proto/compute_driver.proto`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/compute_driver.proto) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`proto/credential_driver.proto`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/credential_driver.proto) | acbac9c, 2026-09-29 | VERIFIED | 01, 07 |
| [`proto/gateway_interceptor.proto`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/gateway_interceptor.proto) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 06, 07 |
| [`proto/openshell.proto`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/openshell.proto) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [`proto/supervisor_middleware.proto`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/supervisor_middleware.proto) | acbac9c, 2026-09-29 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [`providers`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/providers) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`providers/claude-code.yaml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/providers/claude-code.yaml) | acbac9c, 2026-09-29 | VERIFIED | 04 |
| [`providers/github.yaml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/providers/github.yaml) | acbac9c, 2026-09-29 | VERIFIED | 06, 07 |
| [`rfc/0002-agent-driven-policy-management/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0002-agent-driven-policy-management/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04 |
| [`rfc/0009-supervisor-middleware/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0009-supervisor-middleware/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 05, 06, 07 |
| [`rfc/0010-gateway-interceptors/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0010-gateway-interceptors/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 06, 07 |
| [`rfc/0011-multi-player-design/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0011-multi-player-design/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 02, 03, 05, 06, 07 |
| [`rfc/0013-native-windows-mxc/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0013-native-windows-mxc/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01 |
| [`rfc/0014-release-stability/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0014-release-stability/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04, 07 |
| [`rfc/README.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/README.md) | acbac9c, 2026-09-29 | VERIFIED | 01, 04 |

### Files at the v0.1.2 tag

These files were read at tag `v0.1.2` (`6648bd0`) to check behavior seen in the local test.

| File | Commit | Status | Used in |
|---|---|---|---|
| [`architecture/sandbox-limits.md`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/architecture/sandbox-limits.md) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-core/src/middleware.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-core/src/middleware.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-policy-schema/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-policy-schema/src/lib.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-middleware-builtins/src/regex.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-middleware-builtins/src/regex.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-middleware/src/headers.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-middleware/src/headers.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-middleware/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-middleware/src/lib.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-middleware/src/websocket.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-middleware/src/websocket.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-network/src/l7/mcp.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/l7/mcp.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-network/src/l7/middleware.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/l7/middleware.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-network/src/l7/relay.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/l7/relay.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor-network/src/l7/rest.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor-network/src/l7/rest.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`crates/openshell-supervisor/src/lib.rs`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/crates/openshell-supervisor/src/lib.rs) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`docs/extensibility/gateway-interceptors.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/extensibility/gateway-interceptors.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`docs/extensibility/overview.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/extensibility/overview.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`docs/extensibility/supervisor-middleware/configure.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/extensibility/supervisor-middleware/configure.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`docs/extensibility/supervisor-middleware/index.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/extensibility/supervisor-middleware/index.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`docs/extensibility/supervisor-middleware/operations.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/extensibility/supervisor-middleware/operations.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`docs/how-it-works/policies/schema.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/how-it-works/policies/schema.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | 03 |
| [`docs/observability/ocsf-json-export.mdx`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/docs/observability/ocsf-json-export.mdx) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`examples/governance-interceptor/README.md`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/examples/governance-interceptor/README.md) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`examples/supervisor-middleware-content-guard/README.md`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/examples/supervisor-middleware-content-guard/README.md) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`proto/openshell.proto`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/proto/openshell.proto) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`proto/sandbox.proto`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/proto/sandbox.proto) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |
| [`proto/supervisor_middleware.proto`](https://github.com/NVIDIA/OpenShell/blob/v0.1.2/proto/supervisor_middleware.proto) | v0.1.2 (6648bd0), 2026-09-28 | VERIFIED | background |

### Issues, pull requests, and discussions

Issue states are as read on 2026-09-28 or 2026-09-29.

| Source | Date | Status | Used in |
|---|---|---|---|
| [OpenShell #1049: gateway relay for sandbox-to-sandbox traffic](https://github.com/NVIDIA/OpenShell/issues/1049) | opened 2026-04-29 | VERIFIED | 01, 07 |
| [OpenShell #1055: Enterprise Observability roadmap umbrella](https://github.com/NVIDIA/OpenShell/issues/1055) | opened 2026-04-29; body edited 2026-09-02 | VERIFIED | 01, 03, 05, 06, 07 |
| [OpenShell #1613: publish the gRPC API as a supported integration contract](https://github.com/NVIDIA/OpenShell/issues/1613) | closed not planned 2026-09-21 | VERIFIED | 07 |
| [OpenShell #1667: Entra Agent ID user_fic tokens](https://github.com/NVIDIA/OpenShell/issues/1667) | opened 2026-06-01; closed 2026-09-21 | VERIFIED | 01, 05 |
| [OpenShell #1733: external stateful authority above OpenShell](https://github.com/NVIDIA/OpenShell/issues/1733) | opened 2026-06-03; closed | VERIFIED | 01, 04, 06, 07 |
| [OpenShell #1736: dynamic identity sources for token exchange (actor_token gap)](https://github.com/NVIDIA/OpenShell/issues/1736) | opened 2026-06-03; closed 2026-09-21 | VERIFIED | 01 |
| [OpenShell #1754: Entra on-behalf-of token acquisition in the credential broker](https://github.com/NVIDIA/OpenShell/issues/1754) | closed 2026-09-21 | VERIFIED | 05 |
| [OpenShell #1756: scope attenuation for broker-issued downstream tokens](https://github.com/NVIDIA/OpenShell/issues/1756) | opened 2026-06-04; closed 2026-09-21 | VERIFIED | 01, 05, 07 |
| [OpenShell #1842: signed frozen policy bundles](https://github.com/NVIDIA/OpenShell/issues/1842) | closed 2026-06-30 | VERIFIED | 01, 05, 07 |
| [OpenShell #1987: user as sub and sandbox SPIFFE identity as azp](https://github.com/NVIDIA/OpenShell/issues/1987) | closed as completed 2026-08-24 | VERIFIED | 01, 03, 07 |
| [OpenShell #2025: spike on provable delegated authority for spawned agents](https://github.com/NVIDIA/OpenShell/issues/2025) | opened 2026-06-26 | VERIFIED | 01, 03, 05, 06, 07 |
| [OpenShell #2109: managed maximum policies](https://github.com/NVIDIA/OpenShell/issues/2109) | opened 2026-07-01 | VERIFIED | 01, 03, 05 |
| [OpenShell #2565: stabilize public API, SDK, and extension contracts for 0.1.0](https://github.com/NVIDIA/OpenShell/issues/2565) | opened 2026-07-30 | VERIFIED | 04, 06, 07 |
| [OpenShell #2637: provider-managed Cross-App Access (XAA) token flows](https://github.com/NVIDIA/OpenShell/issues/2637) | opened 2026-08-06; closed 2026-09-21 | VERIFIED | 01 |
| [OpenShell #2640: trace_id and span_id on OCSF events](https://github.com/NVIDIA/OpenShell/issues/2640) | opened 2026-08-06 | VERIFIED | 01, 04, 05, 06, 07 |
| [OpenShell discussion #2661: facts needed for restart-safe execution receipts](https://github.com/NVIDIA/OpenShell/discussions/2661) | created 2026-08-09 | VERIFIED | 01, 04, 06, 07 |
| [OpenShell #2684: run middleware inside sandboxes](https://github.com/NVIDIA/OpenShell/issues/2684) | 2026-08-10 | VERIFIED | 01 |
| [OpenShell #2708: token grants on Docker, Podman, and VM drivers](https://github.com/NVIDIA/OpenShell/issues/2708) | 2026-08-11 | VERIFIED | 01, 07 |
| [OpenShell #2745: atomic evidence bundle with digests and completeness state](https://github.com/NVIDIA/OpenShell/issues/2745) | opened 2026-08-14; closed 2026-09-21 | VERIFIED | 01, 03, 05, 06, 07 |
| [OpenShell #2762: evidence export (closed; maintainer comment on scope)](https://github.com/NVIDIA/OpenShell/issues/2762) | opened 2026-08-15; closed 2026-09-21 | VERIFIED | 01, 06, 07 |
| [OpenShell #2881: expiring and single-use approved grants](https://github.com/NVIDIA/OpenShell/issues/2881) | opened 2026-08-21 | VERIFIED | 01, 03, 05, 06, 07 |
| [OpenShell #2892: off-box OCSF export](https://github.com/NVIDIA/OpenShell/issues/2892) | opened 2026-08-22 | VERIFIED | 01 |
| [OpenShell #3017: audit of credential reads](https://github.com/NVIDIA/OpenShell/issues/3017) | opened 2026-08-29 | VERIFIED | 01 |
| [OpenShell discussion #3079: evidence independent of the acting components](https://github.com/NVIDIA/OpenShell/discussions/3079) | created 2026-09-01 | VERIFIED | 01, 04, 06, 07 |
| [OpenShell #3153: durable stop hold](https://github.com/NVIDIA/OpenShell/issues/3153) | opened 2026-09-03; labeled stale | VERIFIED | 01, 07 |
| [OpenShell #3224: external exporter with optional evidence processing](https://github.com/NVIDIA/OpenShell/issues/3224) | opened 2026-09-08 | VERIFIED | 05, 06, 07 |
| [OpenShell #3307: streaming replacement for the unary middleware request hook](https://github.com/NVIDIA/OpenShell/issues/3307) | opened 2026-09-14 | VERIFIED | 01, 04, 05, 06, 07 |
| [OpenShell #3782: non-blocking observe binding for middleware](https://github.com/NVIDIA/OpenShell/issues/3782) | opened 2026-09-28 | VERIFIED | 01, 04, 06, 07 |
| [OpenShell #3808: revalidate running subagents when ancestor authority changes](https://github.com/NVIDIA/OpenShell/issues/3808) | opened 2026-09-28 | VERIFIED | 01, 04, 05, 07 |
| [OpenShell #3817: sequence numbers and hash chain for sandbox events](https://github.com/NVIDIA/OpenShell/issues/3817) | opened 2026-09-29 | VERIFIED | 01, 04, 06, 07 |
| [OpenShell discussion #3818: external authority decision at the middleware](https://github.com/NVIDIA/OpenShell/discussions/3818) | created 2026-09-29 | VERIFIED | 01, 04, 06, 07 |
| [OpenShell #682: bind agents to Ed25519 passport identities](https://github.com/NVIDIA/OpenShell/issues/682) | closed 2026-05-30 | VERIFIED | 01, 05 |
| [OpenShell PR #2168: managed maximum admission (draft)](https://github.com/NVIDIA/OpenShell/pull/2168) | opened 2026-07-07; last author commit 2026-07-08 | VERIFIED | 01, 03, 06 |
| [OpenShell #1145](https://github.com/NVIDIA/OpenShell/issues/1145) | not documented | VERIFIED | background |
| [OpenShell #1755: generalize brokered credential delivery](https://github.com/NVIDIA/OpenShell/issues/1755) | opened 2026-06-04; closed 2026-09-21 | VERIFIED | background |
| [OpenShell #2143: sandbox-to-sandbox caller authentication](https://github.com/NVIDIA/OpenShell/issues/2143) | not documented | VERIFIED | background |
| [OpenShell #2722: secret-free provider mutation receipts from the gateway](https://github.com/NVIDIA/OpenShell/issues/2722) | opened 2026-08-12 | VERIFIED | background |
| [OpenShell #2911: structured gateway mutation audit events](https://github.com/NVIDIA/OpenShell/issues/2911) | opened 2026-08-24 | VERIFIED | background |
| [OpenShell #2912: authentication and authorization audit events](https://github.com/NVIDIA/OpenShell/issues/2912) | opened 2026-08-24 | VERIFIED | background |
| [OpenShell #3055: SDK helpers for event cursors](https://github.com/NVIDIA/OpenShell/issues/3055) | opened 2026-08-31 | VERIFIED | background |
| [OpenShell #3172: removal plan for managed inference routing](https://github.com/NVIDIA/OpenShell/issues/3172) | opened 2026-09-03; closed 2026-09-09 | VERIFIED | background |
| [OpenShell #3333: canonical authored policy representation for containment](https://github.com/NVIDIA/OpenShell/issues/3333) | not documented | VERIFIED | background |
| [OpenShell discussion #2626: standalone openshell-sandbox mode](https://github.com/NVIDIA/OpenShell/discussions/2626) | 2026-08-06 | VERIFIED | background |
| [OpenShell PR #2005: canonical policy and profile signing in the governance example](https://github.com/NVIDIA/OpenShell/pull/2005) | not documented | VERIFIED | background |
| [OpenShell PR #3104: gateway exporter spike](https://github.com/NVIDIA/OpenShell/pull/3104) | 2026-09-01 to 2026-09-09 | VERIFIED | background |
| [OpenShell PR #3209: resumable event cursors](https://github.com/NVIDIA/OpenShell/pull/3209) | merged 2026-09-22 | VERIFIED | background |
| [OpenShell PR #2772: delegated creator identity for token exchange](https://github.com/NVIDIA/OpenShell/pull/2772) | last updated 2026-09-16 | VERIFIED | 01, 03 |
| [OpenShell PR #1424: Microsoft Entra Agent ID provider](https://github.com/NVIDIA/OpenShell/pull/1424) | closed unmerged 2026-07-08 | VERIFIED | 01, 05 |
| [OpenShell PR #1784: SPIFFE token grants](https://github.com/NVIDIA/OpenShell/pull/1784) | merged 2026-06-10 | VERIFIED | 01, 07 |
| [OpenShell PR #1970: SPIFFE-backed RFC 8693 token exchange](https://github.com/NVIDIA/OpenShell/pull/1970) | merged 2026-08-24 | VERIFIED | 01 |
| [OpenShell PR #3195: remove managed inference routing](https://github.com/NVIDIA/OpenShell/pull/3195) | merged 2026-09-09 | VERIFIED | 01, 03, 07 |
| [OpenShell PR #3289: standalone policy prover boundary check](https://github.com/NVIDIA/OpenShell/pull/3289) | merged 2026-09-17 | VERIFIED | 01, 03, 05 |
| [OpenShell PR #3335: MCP revision 2026-07-28 inspection](https://github.com/NVIDIA/OpenShell/pull/3335) | merged 2026-09-28 | VERIFIED | 03, 07 |
| [OpenShell PR #3450: streaming request hook](https://github.com/NVIDIA/OpenShell/pull/3450) | created 2026-09-18 | VERIFIED | 04, 05, 06, 07 |

### Documentation site

Pages of the published OpenShell documentation at docs.nvidia.com/openshell. The same text lives under `docs/` in the repository.

| Source | Date | Status | Used in |
|---|---|---|---|
| [OpenShell docs site: about/architecture](https://docs.nvidia.com/openshell/about/architecture) | not documented | VERIFIED | background |
| [OpenShell docs site: about/installation](https://docs.nvidia.com/openshell/about/installation) | not documented | VERIFIED | background |
| [OpenShell docs site: about/overview](https://docs.nvidia.com/openshell/about/overview) | not documented | VERIFIED | background |
| [OpenShell docs site: about/run-your-first-agent](https://docs.nvidia.com/openshell/about/run-your-first-agent) | not documented | VERIFIED | background |
| [OpenShell docs site: about/support-matrix](https://docs.nvidia.com/openshell/about/support-matrix) | not documented | VERIFIED | background |
| [OpenShell docs site: dev/how-it-works/policies/schema.md](https://docs.nvidia.com/openshell/dev/how-it-works/policies/schema.md) | not documented | VERIFIED | background |
| [OpenShell docs site: dev/llms.txt](https://docs.nvidia.com/openshell/dev/llms.txt) | not documented | VERIFIED | background |
| [OpenShell docs site: extensibility/drivers](https://docs.nvidia.com/openshell/extensibility/drivers) | not documented | VERIFIED | background |
| [OpenShell docs site: extensibility/gateway-interceptors](https://docs.nvidia.com/openshell/extensibility/gateway-interceptors) | not documented | VERIFIED | background |
| [OpenShell docs site: extensibility/isolation-backends](https://docs.nvidia.com/openshell/extensibility/isolation-backends) | not documented | VERIFIED | background |
| [OpenShell docs site: extensibility/overview](https://docs.nvidia.com/openshell/extensibility/overview) | read 2026-09-28 | VERIFIED | background |
| [OpenShell docs site: extensibility/supervisor-middleware](https://docs.nvidia.com/openshell/extensibility/supervisor-middleware) | read 2026-09-28 | VERIFIED | background |
| [OpenShell docs site: extensibility/supervisor-middleware/configure](https://docs.nvidia.com/openshell/extensibility/supervisor-middleware/configure) | not documented | VERIFIED | background |
| [OpenShell docs site: extensibility/supervisor-middleware/operations](https://docs.nvidia.com/openshell/extensibility/supervisor-middleware/operations) | read 2026-09-28 | VERIFIED | background |
| [OpenShell docs site: how-it-works/gateways/authentication](https://docs.nvidia.com/openshell/how-it-works/gateways/authentication) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/gateways/configuration](https://docs.nvidia.com/openshell/how-it-works/gateways/configuration) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/gateways/overview](https://docs.nvidia.com/openshell/how-it-works/gateways/overview) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/inference](https://docs.nvidia.com/openshell/how-it-works/inference) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/advisor](https://docs.nvidia.com/openshell/how-it-works/policies/advisor) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/default-policy](https://docs.nvidia.com/openshell/how-it-works/policies/default-policy) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/manage-policies](https://docs.nvidia.com/openshell/how-it-works/policies/manage-policies) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/network-rules](https://docs.nvidia.com/openshell/how-it-works/policies/network-rules) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/overview](https://docs.nvidia.com/openshell/how-it-works/policies/overview) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/prover](https://docs.nvidia.com/openshell/how-it-works/policies/prover) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/policies/schema](https://docs.nvidia.com/openshell/how-it-works/policies/schema) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/providers/overview](https://docs.nvidia.com/openshell/how-it-works/providers/overview) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/providers/profiles](https://docs.nvidia.com/openshell/how-it-works/providers/profiles) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/sandboxes/overview](https://docs.nvidia.com/openshell/how-it-works/sandboxes/overview) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/sandboxes/runtimes](https://docs.nvidia.com/openshell/how-it-works/sandboxes/runtimes) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/sandboxes/templates](https://docs.nvidia.com/openshell/how-it-works/sandboxes/templates) | not documented | VERIFIED | background |
| [OpenShell docs site: how-it-works/workspaces](https://docs.nvidia.com/openshell/how-it-works/workspaces) | not documented | VERIFIED | background |
| [OpenShell docs site: kubernetes/access-control](https://docs.nvidia.com/openshell/kubernetes/access-control) | not documented | VERIFIED | background |
| [OpenShell docs site: kubernetes/high-availability](https://docs.nvidia.com/openshell/kubernetes/high-availability) | not documented | VERIFIED | background |
| [OpenShell docs site: kubernetes/openshift](https://docs.nvidia.com/openshell/kubernetes/openshift) | not documented | VERIFIED | background |
| [OpenShell docs site: kubernetes/setup](https://docs.nvidia.com/openshell/kubernetes/setup) | not documented | VERIFIED | background |
| [OpenShell docs site: latest/about/architecture](https://docs.nvidia.com/openshell/latest/about/architecture) | undated | VERIFIED | background |
| [OpenShell docs site: latest/extensibility/gateway-interceptors](https://docs.nvidia.com/openshell/latest/extensibility/gateway-interceptors) | not documented | VERIFIED | background |
| [OpenShell docs site: latest/extensibility/overview](https://docs.nvidia.com/openshell/latest/extensibility/overview) | not documented | VERIFIED | background |
| [OpenShell docs site: latest/extensibility/supervisor-middleware](https://docs.nvidia.com/openshell/latest/extensibility/supervisor-middleware) | not documented | VERIFIED | background |
| [OpenShell docs site: llms.txt](https://docs.nvidia.com/openshell/llms.txt) | not documented | VERIFIED | background |
| [OpenShell docs site: observability/accessing-logs](https://docs.nvidia.com/openshell/observability/accessing-logs) | not documented | VERIFIED | background |
| [OpenShell docs site: observability/logging](https://docs.nvidia.com/openshell/observability/logging) | not documented | VERIFIED | background |
| [OpenShell docs site: observability/ocsf-json-export](https://docs.nvidia.com/openshell/observability/ocsf-json-export) | read 2026-09-29 | VERIFIED | background |
| [OpenShell docs site: observability/telemetry](https://docs.nvidia.com/openshell/observability/telemetry) | not documented | VERIFIED | background |
| [OpenShell docs site: sdk/api-errors](https://docs.nvidia.com/openshell/sdk/api-errors) | not documented | VERIFIED | background |
| [OpenShell docs site: sdk/go](https://docs.nvidia.com/openshell/sdk/go) | not documented | VERIFIED | background |
| [OpenShell docs site: sdk/python](https://docs.nvidia.com/openshell/sdk/python) | not documented | VERIFIED | background |
| [OpenShell docs site: sdk/rust](https://docs.nvidia.com/openshell/sdk/rust) | not documented | VERIFIED | background |
| [OpenShell docs site: sdk/typescript](https://docs.nvidia.com/openshell/sdk/typescript) | not documented | VERIFIED | background |
| [OpenShell docs site: security/best-practices](https://docs.nvidia.com/openshell/security/best-practices) | not documented | VERIFIED | background |
| [OpenShell docs site: sitemap.xml](https://docs.nvidia.com/openshell/sitemap.xml) | not documented | VERIFIED | background |
| [OpenShell docs site: tutorials/github-push-access](https://docs.nvidia.com/openshell/tutorials/github-push-access) | not documented | VERIFIED | background |
| [OpenShell docs site: tutorials/microsoft-graph-provider-refresh](https://docs.nvidia.com/openshell/tutorials/microsoft-graph-provider-refresh) | not documented | VERIFIED | background |
| [OpenShell docs site: upgrade/0-1-0](https://docs.nvidia.com/openshell/upgrade/0-1-0) | not documented | VERIFIED | background |
| [OpenShell docs site: v0.0.116/about/how-it-works](https://docs.nvidia.com/openshell/v0.0.116/about/how-it-works) | not documented | VERIFIED | background |
| [OpenShell docs site: v0.0.116/about/supported-agents](https://docs.nvidia.com/openshell/v0.0.116/about/supported-agents) | not documented | VERIFIED | background |
| [OpenShell docs site: v0.0.116/get-started/tutorials/github-sandbox](https://docs.nvidia.com/openshell/v0.0.116/get-started/tutorials/github-sandbox) | not documented | VERIFIED | background |
| [OpenShell docs site: v0.0.116/sandboxes/inference-routing](https://docs.nvidia.com/openshell/v0.0.116/sandboxes/inference-routing) | not documented | VERIFIED | background |

## ODIS

### Specification and contract harness

Paths are relative to the ws4-odis repository root at `148dc41`.

| File | Commit | Status | Used in |
|---|---|---|---|
| [cosai-oasis/ws4-odis repository](https://github.com/cosai-oasis/ws4-odis) | created 2026-07-15 | VERIFIED | 01 |
| [cosai-oasis/ws4-odis at 148dc41 (pinned commit)](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144) | committed 2026-09-08 | VERIFIED | 01, 02, 03, 04, 05, 06, 07 |
| [`RFCs/ODIS.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md) | 148dc41, 2026-09-08 | VERIFIED | 01, 02, 03, 04, 05, 06, 07 |
| [`contract-harness`](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness) | 148dc41, 2026-09-08 | VERIFIED | 06 |
| [`contract-harness/CHANGELOG.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/CHANGELOG.md) | 148dc41, 2026-09-08 | VERIFIED | background |
| [`contract-harness/README.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/README.md) | 148dc41, 2026-09-08 | VERIFIED | 01, 04, 05, 06 |
| [`contract-harness/docs/odis-conformance.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/docs/odis-conformance.md) | 148dc41, 2026-09-08 | VERIFIED | 03, 05, 06, 07 |
| [`contract-harness/docs/run-modes.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/docs/run-modes.md) | 148dc41, 2026-09-08 | VERIFIED | background |
| [`contract-harness/examples/openshell-gated-agent/README.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/examples/openshell-gated-agent/README.md) | 148dc41, 2026-09-08 | VERIFIED | 07 |
| [`contract-harness/pyproject.toml`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/pyproject.toml) | 148dc41, 2026-09-08 | VERIFIED | 05 |
| [`contract-harness/schemas/odis.audit.event.v1.json`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/schemas/odis.audit.event.v1.json) | 148dc41, 2026-09-08 | VERIFIED | 01 |
| [`contract-harness/schemas/odis.bundle.v1.json`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/schemas/odis.bundle.v1.json) | 148dc41, 2026-09-08 | VERIFIED | 01, 03, 04, 05, 06, 07 |
| [`contract-harness/src/odis_harness/bundle/loader.py`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/src/odis_harness/bundle/loader.py) | 148dc41, 2026-09-08 | VERIFIED | 01 |
| [`contract-harness/src/odis_harness/contracts/constants.py`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/src/odis_harness/contracts/constants.py) | 148dc41, 2026-09-08 | VERIFIED | 01 |
| [`contract-harness/terraform/main.tf`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/terraform/main.tf) | 148dc41, 2026-09-08 | VERIFIED | 05 |
| [`contract-harness/vault-plugin`](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/vault-plugin) | 148dc41, 2026-09-08 | VERIFIED | background |
| [`contract-harness/vault-plugin/backend/path_mappings.go`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/vault-plugin/backend/path_mappings.go) | 148dc41, 2026-09-08 | VERIFIED | 01 |
| [`contract-harness/vault-plugin/internal/policydsl/attenuation_profile_v1.json`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/vault-plugin/internal/policydsl/attenuation_profile_v1.json) | 148dc41, 2026-09-08 | VERIFIED | background |
| [`contract-harness/vault-plugin/main.go`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/vault-plugin/main.go) | 148dc41, 2026-09-08 | VERIFIED | 01 |
| [`contract-harness/vault/README.md`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/vault/README.md) | 148dc41, 2026-09-08 | VERIFIED | background |

### Issues and pull requests

| Source | Date | Status | Used in |
|---|---|---|---|
| [ws4-odis #2](https://github.com/cosai-oasis/ws4-odis/issues/2) | not documented | VERIFIED | background |
| [ws4-odis #24: fail-closed obligations](https://github.com/cosai-oasis/ws4-odis/issues/24) | 2026-09-25 | VERIFIED | background |
| [ws4-odis pull request list](https://github.com/cosai-oasis/ws4-odis/pulls) | not documented | VERIFIED | background |
| [ws4-odis #15: Layer 1 issue by EQTY Lab (one of #15 to #20)](https://github.com/cosai-oasis/ws4-odis/issues/15) | not documented | VERIFIED | 01 |
| [ws4-odis #20: Layer 1 issue by EQTY Lab (one of #15 to #20)](https://github.com/cosai-oasis/ws4-odis/issues/20) | 2026-09-18 | VERIFIED | 01 |
| [ws4-odis #21: signed per-decision record proposal](https://github.com/cosai-oasis/ws4-odis/issues/21) | opened 2026-09-21 | VERIFIED | 01, 04, 05, 07 |
| [ws4-odis #22: digest contract proposal](https://github.com/cosai-oasis/ws4-odis/issues/22) | opened 2026-09-21 | VERIFIED | 01, 04, 07 |
| [ws4-odis issue list](https://github.com/cosai-oasis/ws4-odis/issues) | read 2026-09-28 | VERIFIED | 05, 07 |
| [ws4-odis PR #11: signed registration record proposal](https://github.com/cosai-oasis/ws4-odis/pull/11) | closed 2026-09-09 | VERIFIED | 07 |
| [ws4-odis PR #4: ODIS draft](https://github.com/cosai-oasis/ws4-odis/pull/4) | merged 2026-08-03 | VERIFIED | 01 |

### CoSAI governance and meeting records

Agendas and minutes are secondary records of what was said in meetings, so they carry REPORTED.

| Source | Date | Status | Used in |
|---|---|---|---|
| [CoSAI leadership page](https://www.coalitionforsecureai.org/leadership) | undated; read 2026-09-28 | VERIFIED | 01 |
| [CoSAI OASIS Open Project governance](https://github.com/cosai-oasis/oasis-open-project/blob/main/GOVERNANCE.md) | undated; read 2026-09-28 | VERIFIED | 01, 06 |
| [CoSAI onboarding (Contributor License Agreement)](https://github.com/cosai-oasis/cosai-tsc/blob/main/ONBOARDING.md) | undated; read 2026-09-28 | VERIFIED | 01, 04, 07 |
| [CoSAI post: working session on ODIS](https://www.coalitionforsecureai.org/cosai-hosts-working-session-on-open-delegation-identity-standard-odis) | 2026-09-01 | VERIFIED | 01 |
| [CoSAI TSC meeting minutes, 2026-07-14](https://github.com/cosai-oasis/cosai-tsc/blob/main/tsc-meeting-minutes/2026-07-14.md) | 2026-07-14 | REPORTED | 01, 04, 06 |
| [CoSAI TSC meeting minutes, 2026-07-21](https://github.com/cosai-oasis/cosai-tsc/blob/main/tsc-meeting-minutes/2026-07-21.md) | 2026-07-21 | REPORTED | 01 |
| [CoSAI Workstream 4 repository (Secure Design Patterns for Agentic Systems)](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems) | read 2026-09-29 | VERIFIED | 02 |
| [CoSAI WS4 draft agenda, 2026-07-02 meeting](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-07-02.md) | 2026-07-02 | REPORTED | 01 |
| [CoSAI WS4 draft agenda, 2026-07-30 meeting](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-07-30.md) | 2026-07-30 | REPORTED | 01, 05 |
| [CoSAI WS4 draft agenda, 2026-09-10 meeting](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-09-10.md) | 2026-09-10 | REPORTED | 01, 04 |
| [CoSAI TSC meeting minutes folder](https://github.com/cosai-oasis/cosai-tsc/tree/main/tsc-meeting-minutes) | 2026-07-14; 2026-07-21; 2026-07-28 | REPORTED | background |
| [CoSAI OASIS Open Project sponsors](https://github.com/cosai-oasis/oasis-open-project/blob/main/SPONSORS.md) | updated 2026-09-18 | VERIFIED | background |
| [CoSAI WS2 (defenders) #131](https://github.com/cosai-oasis/ws2-defenders/issues/131) | 2026-09-05 | VERIFIED | background |
| [CoSAI WS4 discussion #134](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/discussions/134) | 2026-07-06 | VERIFIED | background |
| [CoSAI WS4 draft agendas folder](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/tree/main/agenda_drafts/ws4) | 2026-06-25; 2026-07-02; 2026-07-30 | REPORTED | background |
| [CoSAI WS4 whitepaper: agentic identity and access control (source)](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/whitepapers/agentic-identity-and-access-control.md) | approved 2026-03-20 | VERIFIED | background |
| [cosai-tsc #62: governance path for ODIS](https://github.com/cosai-oasis/cosai-tsc/issues/62) | opened 2026-09-08; open on 2026-09-22 | VERIFIED | 01 |
| [CoSAI whitepaper: agentic identity and access control (v1.0)](https://www.coalitionforsecureai.org/wp-content/uploads/2026/04/agentic-identity-and-access-control.pdf) | v1.0 2026-03-20 | VERIFIED | background |

### Implementations and test vectors

| Source | Date | Status | Used in |
|---|---|---|---|
| [APS conformance suite: ODIS interop vectors pinned to ws4-odis 148dc41](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/main/interop/cosai-odis-148dc41) | undated; read 2026-09-28 | VERIFIED | 01, 04, 07 |
| [Highflame ZeroID: ODIS role-capability statement](https://github.com/highflame-ai/zeroid/blob/main/docs/odis/role-capability-statement.md) | merged 2026-09-04 | VERIFIED | 01, 05, 06, 07 |
| [highflame-ai/zeroid PR #317: ODIS role-capability statement](https://github.com/highflame-ai/zeroid/pull/317) | 2026-09-04 | VERIFIED | background |

## Standards bodies

### OCSF

| Source | Date | Status | Used in |
|---|---|---|---|
| [OCSF 1.3.0 schema browser: Authentication class](https://schema.ocsf.io/1.3.0/classes/authentication) | undated; read 2026-09-29 | VERIFIED | 02, 04, 06, 07 |
| [OCSF 1.3.0 schema browser: authorization class URL linked from chio-siem](https://schema.ocsf.io/1.3.0/classes/authorization) | read 2026-09-29 | Unavailable: HTTP 404 | 02 |
| [OCSF 1.3.0: events/iam/authentication.json (class 3002)](https://github.com/ocsf/ocsf-schema/blob/v1.3.0/events/iam/authentication.json) | released 2024-08-01 | VERIFIED | 03, 05 |
| [OCSF 1.3.0: events/iam/authorize_session.json (class 3003)](https://github.com/ocsf/ocsf-schema/blob/v1.3.0/events/iam/authorize_session.json) | not documented | VERIFIED | 02 |
| [OCSF 1.9.0 schema browser: delegation object](https://schema.ocsf.io/1.9.0/objects/delegation) | 2026-08-03 | VERIFIED | 05 |
| [OCSF issue #1640: delegation_activity and agent_activity classes](https://github.com/ocsf/ocsf-schema/issues/1640) | opened 2026-05-19 | VERIFIED | 04, 05, 07 |
| [OCSF PR #1665: delegation object](https://github.com/ocsf/ocsf-schema/pull/1665) | merged 2026-07-24 | VERIFIED | 04, 05, 06, 07 |
| [OCSF PR #1709: digital_signature value attribute](https://github.com/ocsf/ocsf-schema/pull/1709) | merged 2026-09-24; unreleased | VERIFIED | 03, 04, 05, 06, 07 |
| [OCSF 1.3.0 schema API: Authentication class](https://schema.ocsf.io/api/1.3.0/classes/authentication) | not documented | VERIFIED | background |
| [OCSF schema release 1.9.0](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0) | released 2026-08-03 | VERIFIED | 07 |
| [OCSF schema v1.9.0](https://github.com/ocsf/ocsf-schema/tree/v1.9.0) | released 2026-08-03 | VERIFIED | 01, 03, 04, 06 |
| [OCSF issue #1698](https://github.com/ocsf/ocsf-schema/issues/1698) | not documented | VERIFIED | background |
| [OCSF PR #1641](https://github.com/ocsf/ocsf-schema/pull/1641) | merged 2026-06-29 | VERIFIED | background |
| [OCSF PR #1661](https://github.com/ocsf/ocsf-schema/pull/1661) | merged 2026-07-17 | VERIFIED | background |
| [ocsf/ocsf-schema repository](https://github.com/ocsf/ocsf-schema) | 1.9.0 released 2026-08-03 | VERIFIED | 05 |

### IETF and RFC Editor

| Source | Date | Status | Used in |
|---|---|---|---|
| [datatracker lookup: draft-chio-protocol](https://datatracker.ietf.org/doc/draft-chio-protocol) | read 2026-09-29 | Unavailable: HTTP 404 on 2026-09-29 | 06 |
| [draft-aip-agent-identity-protocol-00 (text)](https://www.ietf.org/archive/id/draft-aip-agent-identity-protocol-00.txt) | not documented | VERIFIED | background |
| [draft-asor-wimse-agent-delegation-chain-01](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain) | not documented | VERIFIED | 05 |
| [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts) | 2026-09-04 | VERIFIED | background |
| [draft-gilda-wimse-agent-audit-record-01](https://datatracker.ietf.org/doc/draft-gilda-wimse-agent-audit-record) | 2026-09-27 | VERIFIED | 05, 07 |
| [draft-ietf-cose-merkle-tree-proofs (published as RFC 9942)](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs) | June 2026 | VERIFIED | background |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant) | 2026-05-21 | VERIFIED | background |
| [draft-ietf-oauth-identity-chaining](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining) | not documented | VERIFIED | background |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens) | 2026-07-30 | VERIFIED | background |
| [draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture) | not documented | VERIFIED | background |
| [draft-ietf-scitt-scrapi](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi) | not documented | VERIFIED | background |
| [draft-ietf-webbotauth-httpsig-protocol](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol) | not documented | VERIFIED | background |
| [draft-ietf-wimse-aims (AIMS)](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims) | 2026-09-15 | VERIFIED | 05, 06, 07 |
| [draft-ietf-wimse-aims-00 (text)](https://www.ietf.org/archive/id/draft-ietf-wimse-aims-00.txt) | 2026-09-15 | VERIFIED | 05 |
| [draft-mcgraw-httpapi-agent-budget-04](https://datatracker.ietf.org/doc/draft-mcgraw-httpapi-agent-budget) | 2026-09-10 | VERIFIED | 05, 07 |
| [draft-mih-agent-bilateral-attestation-02](https://datatracker.ietf.org/doc/draft-mih-agent-bilateral-attestation) | 2026-09-14 | VERIFIED | 05, 07 |
| [draft-mih-scitt-agent-action-capsule-05](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule) | not documented | VERIFIED | 05 |
| [draft-munoz-wimse-authorization-evidence-01](https://datatracker.ietf.org/doc/draft-munoz-wimse-authorization-evidence) | not documented | VERIFIED | 05 |
| [draft-nelson-agent-delegation-receipts-10](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts) | not documented | VERIFIED | 05 |
| [draft-niyikiza-oauth-attenuating-agent-tokens-01](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens) | not documented | VERIFIED | 05 |
| [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt) | not documented | VERIFIED | 05 |
| [draft-pidlisnyi-aps (Agent Passport System)](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps) | revision -04 of 2026-09-28 | VERIFIED | 01, 05, 06, 07 |
| [draft-sahu-agent-action-receipts-00](https://datatracker.ietf.org/doc/draft-sahu-agent-action-receipts) | not documented | VERIFIED | 05 |
| [IETF datatracker: drafts whose names contain "agent"](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=agent&type=draft) | drafts dated 2026-06-13 to 2026-09-27 | VERIFIED | 05 |
| [RFC 9711 (Entity Attestation Token)](https://www.rfc-editor.org/rfc/rfc9711.html) | not documented | VERIFIED | background |
| [RFC 9943 (SCITT architecture)](https://www.rfc-editor.org/rfc/rfc9943.html) | June 2026 | VERIFIED | 07 |

### Model Context Protocol

| Source | Date | Status | Used in |
|---|---|---|---|
| [MCP extension: Enterprise-Managed Authorization (stable)](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx) | stable 2026-06-17; stable since 2026-06-17 | VERIFIED | 05, 06, 07 |
| [MCP specification revision 2026-07-28: changelog](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx) | revision 2026-07-28 | VERIFIED | 04, 07 |
| [MCP specification revision 2025-11-25: lifecycle](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/lifecycle.mdx) | revision 2025-11-25 | VERIFIED | background |
| [MCP specification revision 2025-11-25: transports](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-11-25/basic/transports.mdx) | revision 2025-11-25 | VERIFIED | background |
| [MCP specification revision 2026-07-28: Streamable HTTP transport](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | revision 2026-07-28 | VERIFIED | background |

### OpenID Foundation

| Source | Date | Status | Used in |
|---|---|---|---|
| [OpenID AuthZEN Authorization API 1.0 (Final)](https://openid.net/specs/authorization-api-1_0-final.html) | 2026-01-11 | VERIFIED | 07 |
| [OpenID Foundation post: COAZ for APIs and AI agents](https://openid.net/getting-cozy-with-coaz-securing-apis-and-ai-agents-with-standardized-authorization) | 2026-07-31 | VERIFIED | 05, 06, 07 |
| [OpenID Foundation post: new AuthZEN working group drafts](https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts) | 2026-06-15 | VERIFIED | 05 |

### Linux Foundation, CNCF, and the Open Secure AI Alliance

| Source | Date | Status | Used in |
|---|---|---|---|
| [agentrust-io/ca2a (confidential agent-to-agent profile)](https://github.com/agentrust-io/ca2a) | pushed 2026-09-28 | VERIFIED | background |
| [agentrust-io/integrations PR #204](https://github.com/agentrust-io/integrations/pull/204) | merged 2026-09-22 | VERIFIED | background |
| [agentrust-io/integrations (TRACE adapters)](https://github.com/agentrust-io/integrations) | not documented | VERIFIED | background |
| [agentrust-io/integrations: OpenShell adapter](https://github.com/agentrust-io/integrations/tree/main/integrations/openshell) | commit 2fc8a09d 2026-09-28 | VERIFIED | background |
| [agentrust-io/trace-spec (TRACE)](https://github.com/agentrust-io/trace-spec) | pushed 2026-09-28 | VERIFIED | 05, 06 |
| [CNCF charter](https://github.com/cncf/foundation/blob/main/charter.md) | updated 2025-06-25 | VERIFIED | 06 |
| [cncf/sandbox #522: OpenShell Sandbox application](https://github.com/cncf/sandbox/issues/522) | opened 2026-09-08; vote passed 2026-09-26 | VERIFIED | 01, 06, 07 |
| [Linux Foundation blog: Open Secure AI Alliance joins the Linux Foundation](https://www.linuxfoundation.org/blog/open-secure-ai-alliance-joins-the-linux-foundation-to-build-a-shared-open-defense-stack-for-the-ai-era) | 2026-09-14 | VERIFIED | 01 |
| [Linux Foundation blog: Open Secure AI Alliance launch](https://www.linuxfoundation.org/blog/open-models-and-open-weights-are-foundational-to-secure-ai) | 2026-07-27 | VERIFIED | 01, 06 |
| [Linux Foundation press release on PR Newswire: TRACE](https://www.prnewswire.com/news-releases/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads-302858923.html) | 2026-08-25 | VERIFIED | 06 |
| [Linux Foundation press release: TRACE joins the Linux Foundation](https://www.linuxfoundation.org/press/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads) | 2026-08-25 | VERIFIED | 01, 05, 07 |
| [Linux Foundation trademark usage guidelines](https://www.linuxfoundation.org/legal/trademark-usage) | undated | VERIFIED | 06 |
| [Linux Foundation blog: proposing the SAFE working group](https://www.linuxfoundation.org/blog/proposing-the-safe-working-group-an-open-community-effort-to-improve-ai-security) | 2026-08-04 | VERIFIED | background |
| [Open Secure AI Alliance charter](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf) | effective 2026-09-01 | VERIFIED | 01, 04, 06, 07 |
| [OpenSecureAIAlliance/RFCs (SAFE RFC)](https://github.com/OpenSecureAIAlliance/RFCs) | last commit 2026-08-04; read 2026-09-29 | VERIFIED | 01, 04, 05, 06, 07 |
| [OpenSecureAIAlliance/RFCs: SAFE proposal text](https://github.com/OpenSecureAIAlliance/RFCs/blob/main/rfc-safe-proposal.md) | 2026-08-03 | VERIFIED | background |
| [Linux Foundation press release on PR Newswire: Open Secure AI Alliance joins the Linux Foundation](https://www.prnewswire.com/news-releases/open-secure-ai-alliance-joins-the-linux-foundation-to-build-a-shared-open-defense-stack-for-the-ai-era-302877844.html) | 2026-09-14 | VERIFIED | background |
| [PyPI: agentrust-trace-adapters](https://pypi.org/project/agentrust-trace-adapters) | 0.1.1 2026-09-26 | VERIFIED | background |
| [SAFE #13: approval-to-execution scope binding](https://github.com/OpenSecureAIAlliance/RFCs/issues/13) | not documented | VERIFIED | 01 |
| [SAFE #15: authority revalidation](https://github.com/OpenSecureAIAlliance/RFCs/issues/15) | not documented | VERIFIED | 01 |
| [SAFE #29: delegated-authority provenance](https://github.com/OpenSecureAIAlliance/RFCs/issues/29) | opened 2026-08-30 | VERIFIED | 01, 07 |
| [SAFE #37: Merkle transparency log](https://github.com/OpenSecureAIAlliance/RFCs/issues/37) | not documented | VERIFIED | 01 |
| [SAFE PR #18: anchored evidence](https://github.com/OpenSecureAIAlliance/RFCs/pull/18) | not documented | VERIFIED | 01 |
| [SAFE PR #27: chain-of-custody receipts](https://github.com/OpenSecureAIAlliance/RFCs/pull/27) | not documented | VERIFIED | 01 |
| [Open Secure AI Alliance website](https://secureaialliance.org/) | undated; read 2026-09-28 | VERIFIED | 01, 04 |
| [TRACE docs: OpenShell integration](https://github.com/agentrust-io/trace-spec/blob/main/docs/integration/openshell.md) | undated; read 2026-09-28 | VERIFIED | 01, 05, 07 |
| [TRACE docs: schema (at 1ec6fc7)](https://github.com/agentrust-io/trace-spec/blob/1ec6fc7d7a2b414419975567521f1a09acd86ea8/docs/schema.md) | commit of 2026-09-28 | VERIFIED | 07 |

### Other specifications and open projects

| Source | Date | Status | Used in |
|---|---|---|---|
| [A2A specification](https://github.com/a2aproject/A2A/blob/main/docs/specification.md) | undated; read 2026-09-28 | VERIFIED | 07 |
| [a2aproject/A2A repository](https://github.com/a2aproject/A2A) | not documented | VERIFIED | background |
| [AAIF Identity and Trust working group](https://aaif.io/working-groups/identity-trust) | read 2026-09-28 | VERIFIED | 05 |
| [AARM specification site](https://aarm.dev/) | not documented | VERIFIED | background |
| [Agentic Trust Framework site](https://agentictrustframework.ai/) | not documented | VERIFIED | background |
| [AP2 specification](https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/specification.md) | v0.2 of 2026-04-28 | VERIFIED | 05, 06, 07 |
| [AP2: agent authorization](https://github.com/google-agentic-commerce/AP2/blob/main/docs/ap2/agent_authorization.md) | v0.2 of 2026-04-28 | VERIFIED | 05, 06 |
| [cedar-policy/cedar repository](https://github.com/cedar-policy/cedar) | not documented | VERIFIED | background |
| [Cloud Security Alliance: agentic AI identity and access management](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach) | not documented | VERIFIED | background |
| [confidential-containers/guest-components: NVIDIA DPU attester](https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/attester/src/nvidia_dpu/mod.rs) | not documented | VERIFIED | background |
| [confidential-containers/trustee (CNCF Confidential Containers Trustee)](https://github.com/confidential-containers/trustee) | commit 57d2631b22 of 2026-09-18 | VERIFIED | 01, 04, 05, 06, 07 |
| [CSA Labs research note: frontier AI models hacking real systems](https://labs.cloudsecurityalliance.org/research/csa-research-note-frontier-ai-models-hacking-real-systems-ev) | not documented | REPORTED | background |
| [CSA Labs research note: NVIDIA Open Secure AI Alliance and NOOA](https://labs.cloudsecurityalliance.org/research/csa-research-note-nvidia-open-secure-ai-alliance-nooa-202607) | 2026-07-28 | REPORTED | background |
| [dogwood-policy/dogwood (Dogwood policy language)](https://github.com/dogwood-policy/dogwood) | created 2026-07-27 | VERIFIED | 05 |
| [eclipse-biscuit/biscuit repository](https://github.com/eclipse-biscuit/biscuit) | not documented | VERIFIED | background |
| [google-agentic-commerce/AP2 repository](https://github.com/google-agentic-commerce/AP2) | not documented | VERIFIED | background |
| [openagentidentityprotocol GitHub organization](https://github.com/openagentidentityprotocol) | not documented | VERIFIED | background |
| [in-toto attestation PR #549: Decision Receipt predicate](https://github.com/in-toto/attestation/pull/549) | closed 2026-04-27 | VERIFIED | 05 |
| [in-toto attestation: Simple Verification Result (SVR) predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md) | v1.2.0 of 2026-03-18 | VERIFIED | 05 |
| [in-toto/attestation repository](https://github.com/in-toto/attestation) | v1.2.0 2026-03-18 | VERIFIED | background |
| [kubernetes-sigs/agent-sandbox repository](https://github.com/kubernetes-sigs/agent-sandbox) | v1.0.0 of 2026-08-28 | VERIFIED | 05 |
| [kubernetes-sigs/agent-sandbox: roadmap.md (at 87a4695)](https://github.com/kubernetes-sigs/agent-sandbox/blob/87a4695e620f6057fef3f6b0c0251f2986b1c36f/roadmap.md) | commit of 2026-09-28 | VERIFIED | 07 |
| [openfga/openfga repository](https://github.com/openfga/openfga) | not documented | VERIFIED | background |
| [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026) | not documented | VERIFIED | background |
| [sigstore/rekor-tiles repository](https://github.com/sigstore/rekor-tiles) | v2.3.0 2026-06-10 | VERIFIED | background |
| [sigstore/rekor-tiles: client notes](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md) | undated; read 2026-09-28 | VERIFIED | 06, 07 |
| [ucan-wg/spec repository](https://github.com/ucan-wg/spec) | not documented | VERIFIED | background |
| [w3c-ccg/zcap-spec repository](https://github.com/w3c-ccg/zcap-spec) | not documented | VERIFIED | background |
| [xaa.dev (Cross App Access reference site)](https://xaa.dev/) | undated | VERIFIED | background |

### Law, regulation, and supervisory guidance

Third-party sites that republish legal text carry REPORTED.

| Source | Date | Status | Used in |
|---|---|---|---|
| [17 CFR 240.17a-4 (SEC Rule 17a-4)](https://www.law.cornell.edu/cfr/text/17/240.17a-4) | undated; read 2026-09-28 | VERIFIED | 06, 07 |
| [California SB 1047 bill status](https://leginfo.legislature.ca.gov/faces/billStatusClient.xhtml?bill_id=202320240SB1047) | veto of 2024-09-29 | VERIFIED | 06 |
| [Colorado SB 24-205 (signed act)](https://leg.colorado.gov/sites/default/files/2024a_205_signed.pdf) | not documented | VERIFIED | background |
| [Colorado SB25B-004 bill page](https://leg.colorado.gov/bills/sb25b-004) | signed 2025-08-28 | VERIFIED | background |
| [Commission Delegated Regulation (EU) 2024/1774 (DORA ICT risk RTS)](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R1774) | 2024-03-13 | VERIFIED | 06, 07 |
| [32 CFR 170.14 (CMMC)](https://www.law.cornell.edu/cfr/text/32/170.14) | not documented | VERIFIED | background |
| [15 CFR 762.6 (EAR recordkeeping)](https://www.law.cornell.edu/cfr/text/15/762.6) | not documented | VERIFIED | background |
| [EU AI Act Explorer: Annex III](https://artificialintelligenceact.eu/annex/3) | not documented | REPORTED | background |
| [EU AI Act Explorer: Annex IV](https://artificialintelligenceact.eu/annex/4) | not documented | REPORTED | background |
| [EU AI Act Explorer: Article 12](https://artificialintelligenceact.eu/article/12) | not documented | REPORTED | background |
| [EU AI Act Explorer: Article 19](https://artificialintelligenceact.eu/article/19) | not documented | REPORTED | background |
| [EU AI Act Explorer: Article 25](https://artificialintelligenceact.eu/article/25) | not documented | REPORTED | background |
| [EU AI Act Explorer: Article 26](https://artificialintelligenceact.eu/article/26) | not documented | REPORTED | background |
| [EU AI Act Explorer: implementation timeline](https://artificialintelligenceact.eu/implementation-timeline) | updated 2026-08-31 | REPORTED | background |
| [Regulation (EU) 2023/1230 (Machinery Regulation)](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32023R1230) | 2023-06-14; 2027-01-14 | VERIFIED | background |
| [European Commission: Machinery](https://single-market-economy.ec.europa.eu/sectors/mechanical-engineering/machinery_en) | undated; read 2026-09-29 | VERIFIED | 06, 07 |
| [European Commission: regulatory framework for AI](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) | updated 2026-08-03 | VERIFIED | background |
| [Federal Reserve SR 26-2](https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm) | 2026-04-17 | VERIFIED | 06 |
| [Federal Reserve speech by Governor Bowman, 2026-05-01](https://www.federalreserve.gov/newsevents/speech/bowman20260501a.htm) | 2026-05-01 | VERIFIED | background |
| [Federal Reserve SR 26-2 attachment](https://www.federalreserve.gov/supervisionreg/srletters/SR2602a1.pdf) | 2026-04-17 | VERIFIED | background |
| [FINRA 2026 annual regulatory oversight report](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report) | 2025-12-09 | VERIFIED | background |
| [FINRA 2026 oversight report: generative AI](https://www.finra.org/rules-guidance/guidance/reports/2026-finra-annual-regulatory-oversight-report/gen-ai) | not documented | VERIFIED | background |
| [ISMS.online: ISO/IEC 42001 Annex A controls (secondary source)](https://www.isms.online/iso-42001/annex-a-controls) | not documented | REPORTED | background |
| [NERC CIP-007-6](https://www.nerc.com/pa/Stand/Reliability%20Standards/CIP-007-6.pdf) | not documented | VERIFIED | background |
| [NIST CSRC: COSAIS project](https://csrc.nist.gov/projects/cosais) | not documented | VERIFIED | background |
| [NIST: AI agent standards initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) | 2026-02-17 | VERIFIED | background |
| [NIST: Center for AI Standards and Innovation (CAISI)](https://www.nist.gov/caisi) | not documented | VERIFIED | background |
| [NIST: CAISI request for information on securing AI agent systems](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems) | 2026-01-12 | VERIFIED | background |
| [NIST SP 800-171 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf) | updated 2021-01-28 | VERIFIED | background |
| [PCI Security Standards Council: AI principles for payment environments](https://blog.pcisecuritystandards.org/ai-principles-securing-the-use-of-ai-in-payment-environments) | 2025-09-11 | VERIFIED | background |
| [PCI Security Standards Council: security considerations for AI systems](https://blog.pcisecuritystandards.org/just-published-security-considerations-for-ai-systems) | 2026-09-15 | VERIFIED | background |
| [PCI Security Standards Council: PCI DSS v4.0.1 published](https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1) | 2024-06-11 | VERIFIED | 06 |
| [Regulation (EU) 2022/2554 (DORA)](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) | 2022-12-14 | VERIFIED | 06 |
| [Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng) | 2026-07-08; published in the Official Journal 2026-07-24 | VERIFIED | 06, 07 |
| [SEC Division of Examinations: 2026 examination priorities](https://www.sec.gov/files/2026-exam-priorities.pdf) | 2026-03-02; 2026-04-15 | VERIFIED | background |

## Partners and other vendors

A vendor's page is VERIFIED as the vendor's statement about its own products and plans. What it says about another party's product is REPORTED, and a post whose subject is another vendor's product carries REPORTED as a whole.

### Anthropic and OpenAI

| Source | Date | Status | Used in |
|---|---|---|---|
| [Anthropic (Claude blog): giving companies more control over their AI agents with NVIDIA](https://claude.com/blog/giving-companies-more-control-over-their-ai-agents-with-nvidia) | 2026-09-28 | VERIFIED | 01, 05 |
| [anthropics/claude-code #712: hooks feature request](https://github.com/anthropics/claude-code/issues/712) | 2025-04-05 | VERIFIED | background |
| [anthropics/sandbox-runtime repository](https://github.com/anthropics/sandbox-runtime) | v0.0.77 2026-09-18 | VERIFIED | background |
| [Claude blog: Claude Managed Agents updates](https://claude.com/blog/claude-managed-agents-updates) | not documented | VERIFIED | background |
| [Claude Code docs: sandboxing](https://code.claude.com/docs/en/sandboxing) | not documented | VERIFIED | background |
| [Claude Code docs: hooks](https://code.claude.com/docs/en/hooks) | undated | VERIFIED | 05 |
| [Claude Code docs: MCP](https://code.claude.com/docs/en/mcp) | undated | VERIFIED | background |
| [Claude Code docs: monitoring usage](https://code.claude.com/docs/en/monitoring-usage) | not documented | VERIFIED | background |
| [Claude Code docs: sandbox environments](https://code.claude.com/docs/en/sandbox-environments) | not documented | VERIFIED | background |
| [Claude Managed Agents docs: cloud sandboxes reference (beta)](https://platform.claude.com/docs/en/managed-agents/cloud-sandboxes-reference) | not documented | VERIFIED | background |
| [Claude Managed Agents docs: events and streaming (beta)](https://platform.claude.com/docs/en/managed-agents/events-and-streaming) | not documented | VERIFIED | background |
| [Claude Managed Agents docs: overview (beta)](https://platform.claude.com/docs/en/managed-agents/overview) | not documented | VERIFIED | background |
| [Claude Managed Agents docs: MCP connector (beta)](https://platform.claude.com/docs/en/managed-agents/mcp-connector) | read 2026-09-29 | VERIFIED | background |
| [Claude Managed Agents docs: multiagent orchestration (beta)](https://platform.claude.com/docs/en/managed-agents/multiagent-orchestration) | beta, undated; read 2026-09-29 | VERIFIED | 05, 06 |
| [Claude Managed Agents docs: permission policies (beta)](https://platform.claude.com/docs/en/managed-agents/permission-policies) | beta, undated; read 2026-09-29 | VERIFIED | 05, 06 |
| [Claude Developer Platform release notes](https://platform.claude.com/docs/en/release-notes/overview) | not documented | VERIFIED | background |
| [Claude Managed Agents docs: self-hosted sandbox security (beta)](https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes-security) | beta, undated | VERIFIED | 05 |
| [Claude Managed Agents docs: self-hosted sandboxes (beta)](https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes) | beta, undated; read 2026-09-29 | VERIFIED | 01, 05, 06, 07 |
| [Claude Managed Agents docs: session budgets (beta)](https://platform.claude.com/docs/en/managed-agents/budgets) | beta, undated; read 2026-09-29 | VERIFIED | 05, 07 |
| [Claude Managed Agents docs: vaults (beta)](https://platform.claude.com/docs/en/managed-agents/vaults) | beta, undated; read 2026-09-29 | VERIFIED | 05, 07 |
| [OpenAI Codex docs: agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security) | not documented | VERIFIED | background |
| [OpenAI Codex docs: sandboxing auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review) | not documented | VERIFIED | background |
| [OpenAI Codex docs: configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) | not documented | VERIFIED | background |
| [OpenAI Codex docs: sandboxing](https://learn.chatgpt.com/docs/sandboxing) | not documented | VERIFIED | background |
| [OpenAI Codex docs: hooks](https://learn.chatgpt.com/docs/hooks) | undated | VERIFIED | 05 |
| [OpenAI Codex docs: managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration) | not documented | VERIFIED | background |
| [OpenAI developer docs: Codex configuration reference (redirects to learn.chatgpt.com)](https://developers.openai.com/codex/config-reference) | undated | VERIFIED | background |
| [openai/codex repository (codex-rs/agent-identity)](https://github.com/openai/codex) | main, read 2026-09-29 | VERIFIED | 05 |

### Identity, security, and governance vendors

| Source | Date | Status | Used in |
|---|---|---|---|
| [Aembit blog: Aembit and CrowdStrike](https://aembit.io/blog/aembit-crowdstrike-more-judgment-behind-every-ai-agent-yes) | not documented | VERIFIED | background |
| [agntcy/identity repository](https://github.com/agntcy/identity) | not documented | VERIFIED | background |
| [Armis blog: protecting NVIDIA AI factories](https://www.armis.com/blog/safeguarding-ai-at-scale-how-armis-protects-critical-nvidia-ai-factories) | not documented | Unavailable: HTTP 403 to automated retrieval | background |
| [Astrix Security homepage](https://astrix.security/) | not documented | VERIFIED | background |
| [Auth0 docs: on-behalf-of token exchange](https://auth0.com/docs/secure/call-apis-on-users-behalf/on-behalf-of-token-exchange) | read 2026-09-28 | VERIFIED | 05 |
| [Auth0 for AI Agents: asynchronous authorization](https://auth0.com/ai/docs/intro/asynchronous-authorization) | read 2026-09-28 | VERIFIED | 05 |
| [Check Point blog: AI factory security with NVIDIA](https://blog.checkpoint.com/ai-security/check-point-lays-the-groundwork-for-the-future-of-ai-factory-security-with-nvidia) | 2026-05-31 | VERIFIED | background |
| [Cisco blog: beyond intelligence, trust as the benchmark in AI](https://blogs.cisco.com/news/beyond-intelligence-how-trust-is-the-benchmark-that-matters-in-ai) | 2026-09-28 | VERIFIED | 01, 05, 06, 07 |
| [Cisco blog: DefenseClaw](https://blogs.cisco.com/ai/cisco-announces-defenseclaw) | 2026-03-23 | VERIFIED | 05 |
| [Cisco blog: intent to acquire Astrix Security](https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security) | 2026-05-04; updated 2026-06-29 | VERIFIED | 05 |
| [Cisco DefenseClaw docs: SANDBOX.md](https://github.com/cisco-ai-defense/defenseclaw/blob/main/docs/SANDBOX.md) | undated; read 2026-09-28 | VERIFIED | 01 |
| [cisco-ai-defense/defenseclaw repository](https://github.com/cisco-ai-defense/defenseclaw) | commit f8dc95ab 2026-09-27 | VERIFIED | background |
| [Cloudflare blog: signed agents](https://blog.cloudflare.com/signed-agents) | not documented | VERIFIED | background |
| [CrowdStrike blog: Agentic Identity Provider](https://www.crowdstrike.com/en-us/blog/crowdstrike-announces-agentic-identity-provider) | 2026-09-02 | VERIFIED | 01, 05, 07 |
| [CrowdStrike blog: CrowdStrike and NVIDIA extend security across the AI stack](https://www.crowdstrike.com/en-us/blog/crowdstrike-nvidia-extend-security-across-ai-stack) | 2026-09-28 | VERIFIED | 01, 05 |
| [CrowdStrike blog: Continuous Identity for AI agents](https://www.crowdstrike.com/en-us/blog/crowdstrike-announces-continuous-identity-for-ai-agents) | 2026-06-15 | VERIFIED | background |
| [CrowdStrike blog: enterprise-grade security for the AI factory with NVIDIA](https://www.crowdstrike.com/en-us/blog/crowdstrike-nvidia-bring-enterprise-grade-security-to-the-ai-factory) | 2026-06-01 | VERIFIED | background |
| [CrowdStrike press release: secure-by-design AI blueprint for AI agents with NVIDIA](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-nvidia-unveil-secure-by-design-ai-blueprint-for-ai-agents) | 2026-03-16 | VERIFIED | background |
| [CrowdStrike blog: Claude integration brings audit data into Falcon](https://www.crowdstrike.com/en-us/blog/new-claude-integration-brings-audit-data-into-the-falcon-platform) | not documented | VERIFIED | background |
| [cyberark/agent-guard repository](https://github.com/cyberark/agent-guard) | last push 2025-09-15 | VERIFIED | background |
| [cyberark/agentwatch repository](https://github.com/cyberark/agentwatch) | last push 2025-05-14 | VERIFIED | background |
| [CyberArk: secure AI agents page](https://www.cyberark.com/products/secure-ai-agents) | read 2026-09-28 | VERIFIED | 05 |
| [Cyera research: NemoClaw, one website visit to hijack your AI agent](https://www.cyera.com/research/nemoclaw-one-website-visit-to-hijack-your-ai-agent) | 2026-08-25 | REPORTED | 01 |
| [Descope homepage](https://www.descope.com/) | not documented | VERIFIED | background |
| [Endstop blog: NVIDIA OpenShell and the machine layer](https://endstop.systems/blog/nvidia-openshell-machine-layer) | undated; read 2026-09-28 | REPORTED | 01 |
| [EQTY Lab verifiable compute site](https://vcomp.eqtylab.io/) | read 2026-09-29 | VERIFIED | background |
| [EQTY Lab blog: Blackwell announcement](https://www.eqtylab.io/blog/blackwell-announcement) | 2025-07-10 | VERIFIED | background |
| [EQTY Lab blog: Confidential Computing Consortium announcement](https://www.eqtylab.io/blog/ccc-announcement) | 2025-08-19 | VERIFIED | background |
| [EQTY Lab blog: joins FINOS](https://www.eqtylab.io/blog/eqty-lab-joins-finos) | 2025-09-02 | VERIFIED | background |
| [EQTY Lab blog: introducing AI Guardian](https://www.eqtylab.io/blog/introducing-ai-guardian) | 2025-04-27 | VERIFIED | background |
| [EQTY Lab blog: introducing Verifiable Runtime](https://www.eqtylab.io/blog/introducing-verifiable-runtime) | 2026-03-18 | VERIFIED | 01, 05, 06, 07 |
| [EQTY Lab: Verifiable Runtime page (earlier URL)](https://www.eqtylab.io/introducing-verifiable-runtime) | not documented | Unavailable: HTTP 404 on 2026-09-29 | background |
| [EQTY Lab blog: verifiable compute and HALA](https://www.eqtylab.io/blog/verifiable-compute-and-hala) | 2024-12-17 | VERIFIED | background |
| [EQTY Lab blog: verifiable compute press release](https://www.eqtylab.io/blog/verifiable-compute-press-release) | 2024-12-18 | VERIFIED | background |
| [EQTY Lab blog: verifiable knowledge, the third pillar of trust](https://www.eqtylab.io/blog/verifiable-knowledge-the-third-pillar-of-trust-for-the-agentic-ai) | 2026-06-01 | VERIFIED | 01, 04, 05 |
| [EQTY Lab blog: white paper on sovereign AI for mission-critical infrastructure](https://www.eqtylab.io/blog/white-paper-sovereign-ai-for-mission-critical-infrastructure) | 2026-03-18 | VERIFIED | background |
| [EQTY Lab GitHub organization](https://github.com/eqtylab) | read 2026-09-29 | VERIFIED | 05, 06 |
| [EQTY Lab white paper: sovereign AI](https://a.storyblok.com/f/257174/x/78e17cc37d/eqty-sovereign-ai-whitepaper.pdf) | March 2026 | VERIFIED | 05 |
| [eqtylab/container_example repository](https://github.com/eqtylab/container_example) | HEAD 5f0cb20c03 2026-09-23 | VERIFIED | background |
| [eqtylab/cupcake repository](https://github.com/eqtylab/cupcake) | release 2025-12-10; HEAD 27b94b84f6 2026-03-02 | VERIFIED | background |
| [eqtylab/deployment repository](https://github.com/eqtylab/deployment) | dated 2026-09-24; dated 2026-08-07 | VERIFIED | background |
| [eqtylab/deployment: gateway-stack README](https://github.com/eqtylab/deployment/blob/main/charts/gateway-stack/README.md) | repository state 2026-09-22 to 2026-09-28 | VERIFIED | 05 |
| [eqtylab/deployment: plugin runtime bootstrap docs](https://github.com/eqtylab/deployment/blob/main/charts/gateway-stack/docs/plugin-runtime-bootstrap.md) | 2026-09-24 | VERIFIED | 05 |
| [eqtylab/deployment: releases](https://github.com/eqtylab/deployment/tree/main/releases) | 2026-05-19 to 2026-09-24 | VERIFIED | 05 |
| [eqtylab/eqty-lineage repository](https://github.com/eqtylab/eqty-lineage) | HEAD d1e4475371 2026-09-28; 0.1.0 2026-09-15; 0.1.1 2026-09-16 | VERIFIED | background |
| [eqtylab/eqty-lineage: NeMo Relay recorder plugin](https://github.com/eqtylab/eqty-lineage/tree/main/packages/eqty-lineage-nemo-relay) | 0.1.0 of 2026-09-15 | VERIFIED | 05 |
| [eqtylab/eqty-skills repository](https://github.com/eqtylab/eqty-skills) | created 2026-09-25; 2026-09-28 | VERIFIED | background |
| [eqtylab/integrity repository](https://github.com/eqtylab/integrity) | repository state 2026-09-22 to 2026-09-28 | VERIFIED | 05 |
| [eqtylab/integrity-py repository](https://github.com/eqtylab/integrity-py) | HEAD fa6e7fd57b 2026-09-25 | VERIFIED | background |
| [eqtylab/mcp-guardian repository](https://github.com/eqtylab/mcp-guardian) | HEAD 54395bfe65 2025-04-10 | VERIFIED | background |
| [F5 blog: secure-by-design storage for agentic AI](https://www.f5.com/company/blog/secure-by-design-storage-agentic-ai-runtime-visibility-traffic-control) | 2026-05-31 | VERIFIED | background |
| [Fortinet press release: securing enterprise AI at scale](https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2026/fortinet-deepens-integration-to-uniquely-secure-enterprise-ai-at-scale-with-nvidia) | not documented | VERIFIED | background |
| [HashiCorp blog: Vault Agentic IAM is generally available](https://www.hashicorp.com/en/blog/hashicorp-vault-agentic-iam-is-now-generally-available) | 2026-09-01 | VERIFIED | 01, 05, 06 |
| [HashiCorp Vault docs: audit devices](https://developer.hashicorp.com/vault/docs/audit) | read 2026-09-28 | VERIFIED | 05 |
| [HashiCorp Vault docs: SPIFFE auth method](https://developer.hashicorp.com/vault/docs/auth/spiffe) | not documented | VERIFIED | background |
| [HashiCorp Vault docs: Agentic IAM](https://developer.hashicorp.com/vault/ai/iam) | last_modified 2026-09-01 | VERIFIED | background |
| [HashiCorp Vault docs: Agentic IAM OAuth profiles](https://developer.hashicorp.com/vault/ai/iam/concepts/oauth-profiles) | last_modified 2026-09-01 | VERIFIED | background |
| [HashiCorp Vault docs: IBM Verify provider for Agentic IAM](https://developer.hashicorp.com/vault/docs/ai/iam/providers/verify) | last_modified 2026-09-01 | VERIFIED | background |
| [HashiCorp Vault docs: Rich Authorization Requests](https://developer.hashicorp.com/vault/ai/iam/concepts/rar) | not documented | VERIFIED | background |
| [hashicorp/vault: audit/entry_formatter.go](https://github.com/hashicorp/vault/blob/main/audit/entry_formatter.go) | read 2026-09-29 | VERIFIED | background |
| [hashicorp/web-unified-docs (Vault release notes)](https://github.com/hashicorp/web-unified-docs) | commit d3a810df 2026-09-28 | VERIFIED | background |
| [HashiCorp blog feed](https://www.hashicorp.com/blog/feed.xml) | updated 2026-09-28 | VERIFIED | background |
| [IBM community blog: IBM Agent Identity public preview](https://community.ibm.com/community/user/blogs/dinesh-jain/2026/09/01/ibm-agent-identity-public-preview) | 2026-09-01 | VERIFIED | 05 |
| [IBM newsroom: building trust into the next generation of AI agents](https://newsroom.ibm.com/blog-building-trust-into-the-next-generation-of-ai-agents) | 2026-09-28 | VERIFIED | 01, 05, 06 |
| [IBM solution page: agentic AI identity management](https://www.ibm.com/solutions/agentic-ai-identity-management) | modified 2026-09-28 per page metadata | VERIFIED | 01, 05 |
| [IBM Agent Identity documentation: overview](https://www.ibm.com/docs/en/agent-identity?topic=overview) | undated | VERIFIED | background |
| [IBM Think: securing the agentic enterprise starts with identity](https://www.ibm.com/think/perspectives/securing-the-agentic-enterprise-starts-with-identity) | 2026-09-09 | VERIFIED | background |
| [Keycard blog: Keycard for multi-agent apps](https://www.keycard.ai/blog/announcing-keycard-for-multi-agent-apps) | 2026-05-13 | VERIFIED | 05 |
| [Keycard homepage](https://www.keycard.ai/) | undated | VERIFIED | 05, 06 |
| [Microsoft blog index](https://blogs.microsoft.com/) | read 2026-09-29 | VERIFIED | background |
| [Microsoft blog: Build 2026](https://blogs.microsoft.com/blog/2026/06/02/microsoft-build-2026-be-yourself-at-work) | 2026-06-02 | VERIFIED | background |
| [Microsoft Learn: Entra agent blueprints](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-blueprint) | not documented | VERIFIED | background |
| [Microsoft Learn: Entra Agent ID documentation](https://learn.microsoft.com/en-us/entra/agent-id) | not documented | VERIFIED | background |
| [Microsoft Learn: agent on-behalf-of OAuth flow](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-on-behalf-of-oauth-flow) | not documented | VERIFIED | background |
| [Microsoft Learn: What is Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id) | 2026-06-15 | VERIFIED | 05 |
| [Microsoft Learn: What's new in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id) | 2026-05-01 | VERIFIED | 07 |
| [Microsoft open source blog: introducing the Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents) | 2026-04-02 | VERIFIED | 05, 06, 07 |
| [Microsoft Security blog: Agent 365 generally available](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations) | 2026-05-01 | VERIFIED | 01, 05, 06, 07 |
| [microsoft/agent-governance-toolkit repository (AGT; includes docs/compliance/owasp-llm-top10-mapping.md)](https://github.com/microsoft/agent-governance-toolkit) | commit c07577d of 2026-09-28 | VERIFIED | 05, 06, 07 |
| [microsoft/agent-governance-toolkit: OpenShell skill integration](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agentmesh-integrations/openshell-skill) | 2026-08-03 | VERIFIED | background |
| [microsoft/vscode: terminal sandbox MXC runtime](https://github.com/microsoft/vscode/blob/main/src/vs/platform/sandbox/common/terminalSandboxMxcRuntime.ts) | not documented | VERIFIED | background |
| [Microsoft Security blog index](https://www.microsoft.com/en-us/security/blog) | read 2026-09-29 | VERIFIED | background |
| [Microsoft Security blog: what's new, September 2026](https://www.microsoft.com/en-us/security/blog/2026/09/24/whats-new-in-microsoft-security-september-2026) | 2026-09-24 | VERIFIED | background |
| [Natoma blog: Natoma and Snowflake](https://natoma.ai/blog/natoma-snowflake) | not documented | VERIFIED | background |
| [Okta developer guide: AI agent token exchange](https://developer.okta.com/docs/guides/ai-agent-token-exchange/authserver/main) | read 2026-09-28 | VERIFIED | 05 |
| [Okta help: Cross App Access](https://help.okta.com/oie/en-us/content/topics/apps/apps-cross-app-access.htm) | not documented | VERIFIED | background |
| [Palo Alto Networks blog: reinventing security for the agentic NVIDIA AI factory](https://www.paloaltonetworks.com/blog/2026/06/reinventing-security-for-the-agentic-nvidia-ai-factory) | 2026-06-01 | VERIFIED | 05 |
| [Palo Alto Networks blog: securing AI agents at scale with NVIDIA](https://www.paloaltonetworks.com/blog/2026/09/securing-ai-agents-at-scale-with-nvidia) | 2026-09-28 | VERIFIED | 01, 05, 06 |
| [Palo Alto Networks press release: Idira](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-introduces-idira--the-next-generation-identity-security-platform-built-for-the-ai-enterprise) | 2026-05-12 | VERIFIED | 05 |
| [Ping Identity press release: identity control plane for the agentic enterprise](https://press.pingidentity.com/2026-05-27-Ping-Identity-Redefines-the-Identity-Control-Plane-for-the-Agentic-Enterprise) | not documented | VERIFIED | background |
| [PyPI: eqty-sdk](https://pypi.org/project/eqty-sdk) | 2.4.2 2026-09-17 | VERIFIED | background |
| [rossoctl/rossoctl repository](https://github.com/rossoctl/rossoctl) | not documented | VERIFIED | background |
| [Scalekit blog: delegated agent access](https://www.scalekit.com/blog/delegated-agent-access) | not documented | VERIFIED | background |
| [Scalekit blog: joins Okta Cross App Access](https://www.scalekit.com/blog/scalekit-joins-okta-cross-app) | not documented | VERIFIED | background |
| [SGNL homepage](https://sgnl.ai/) | not documented | VERIFIED | background |
| [Strata: agentic identity](https://www.strata.io/agentic-identity) | not documented | VERIFIED | background |
| [Teleport blog: Cisco partnership](https://goteleport.com/blog/cisco-teleport-partnership) | not documented | VERIFIED | background |
| [Tigera blog: NVIDIA OpenShell secures the agent, who governs the fleet](https://www.tigera.io/blog/nvidia-openshell-secures-the-agent-who-governs-the-fleet) | 2026-07-15 | REPORTED | 01, 05, 06, 07 |
| [Tigera blog: why we built Lynx](https://www.tigera.io/blog/why-we-built-lynx-bringing-control-to-the-age-of-ai-agents) | 2026-06-17 | VERIFIED | 05 |
| [Token Security homepage](https://www.token.security/) | not documented | VERIFIED | background |
| [Trend Micro research: security at the speed of AI agents with NVIDIA](https://www.trendaisecurity.com/en-us/resources-insights/research/driving-security-at-the-speed-of-ai-agents-with-nvidia-doca) | 2026-06-01 | VERIFIED | background |
| [Xage press release: zero trust for agentic AI with Vera BlueField-4 STX](https://xage.com/press/xage-security-supercharges-its-just-announced-zero-trust-for-agentic-ai-solution-with-nvidia-vera-bluefield-4-stx-security-innovations) | 2026-06-01 | VERIFIED | 01, 05, 06, 07 |
| [Zscaler blog: DOCA Argus telemetry streaming](https://www.zscaler.com/blogs/partner/agentless-runtime-signals-ai-factory-streaming-nvidia-doca-argus-telemetry-zscaler) | 2026-03-18 | VERIFIED | background |

### Platforms, clouds, and runtimes

| Source | Date | Status | Used in |
|---|---|---|---|
| [Accenture newsroom: AI choice and control with open-weight models](https://newsroom.accenture.com/blogs/2026/accenture-helps-organizations-unlock-greater-ai-choice-and-control-with-open-weight-models) | not documented | VERIFIED | background |
| [Amazon Bedrock AgentCore docs: Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html) | not documented | VERIFIED | background |
| [Amazon Bedrock AgentCore docs: key features and benefits](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/key-features-and-benefits.html) | read 2026-09-28 | VERIFIED | 05 |
| [AWS Lambda docs: MicroVMs for Claude Managed Agents](https://docs.aws.amazon.com/lambda/latest/dg/microvms-integrations-claude-managed-agents.html) | not documented | VERIFIED | background |
| [Amazon Bedrock AgentCore docs: Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html) | read 2026-09-28 | VERIFIED | 05, 06 |
| [Amazon Bedrock AgentCore docs: session-based temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-session-based-temporal.html) | undated; read 2026-09-28 | VERIFIED | 05, 06 |
| [Amazon Bedrock AgentCore docs: temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html) | read 2026-09-28 | VERIFIED | 05 |
| [Arm newsroom: trusted compute foundation for agentic AI](https://newsroom.arm.com/blog/trusted-compute-foundation-agentic-ai) | 2026-09-28 | VERIFIED | background |
| [Azure blog index](https://azure.microsoft.com/en-us/blog) | read 2026-09-29 | VERIFIED | background |
| [Azure/kars repository](https://github.com/Azure/kars) | read 2026-09-29 | VERIFIED | 01, 05, 06 |
| [Baseten blog: announcing Carbon](https://www.baseten.co/blog/announcing-carbon) | not documented | VERIFIED | background |
| [Canonical blog: Charmed OpenShell alpha](https://canonical.com/blog/charmed-openshell-alpha-release) | 2026-09-28 | VERIFIED | 01 |
| [Canonical blog: NVIDIA OpenShell on Ubuntu](https://canonical.com/blog/nvidia-openshell-ubuntu-announcement) | 2026-06-01 | VERIFIED | background |
| [canonical/openshell-driver-lxd](https://github.com/canonical/openshell-driver-lxd) | commit of 2026-09-29 | VERIFIED | 01 |
| [Citi Ventures: agents-as-a-service evolution](https://www.citi.com/ventures/perspectives/opinion/agents-as-a-service-evolution.html) | not documented | VERIFIED | background |
| [Cloudflare Sandbox docs: Claude Managed Agents tutorial](https://developers.cloudflare.com/sandbox/tutorials/claude-managed-agents) | not documented | VERIFIED | background |
| [Cloudflare Sandbox docs: security concepts](https://developers.cloudflare.com/sandbox/concepts/security) | not documented | VERIFIED | background |
| [Cloudflare docs: Web Bot Auth](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth) | not documented | VERIFIED | background |
| [Cloudflare Sandbox docs: outbound traffic](https://developers.cloudflare.com/sandbox/guides/outbound-traffic) | 2026-09-28 | VERIFIED | 05 |
| [Daytona docs: isolation](https://www.daytona.io/docs/en/isolation.md) | not documented | VERIFIED | background |
| [daytonaio/daytona repository (maintenance notice)](https://github.com/daytonaio/daytona) | 2026-06-23 | VERIFIED | 05 |
| [Dell blog: a new security model for AI agents](https://www.dell.com/en-us/blog/a-new-era-of-ai-agents-demands-a-new-security-model) | not documented | VERIFIED | background |
| [Docker docs: Docker Sandboxes and AI Governance](https://docs.docker.com/ai/sandboxes) | release 0.45.0 of 2026-09-21 | VERIFIED | 05 |
| [docker/mcp-gateway repository](https://github.com/docker/mcp-gateway) | commit a34df45d of 2026-09-16 | VERIFIED | 05, 07 |
| [E2B docs: bring your own egress proxy](https://docs.e2b.dev/network/byop) | SDK 2.41.0 of 2026-08-24 | VERIFIED | 05, 06, 07 |
| [E2B docs: changelog](https://docs.e2b.dev/changelog) | not documented | VERIFIED | background |
| [E2B docs: internet access](https://docs.e2b.dev/network/internet-access) | not documented | VERIFIED | background |
| [E2B docs: OpenAI Agents API](https://docs.e2b.dev/agents/openai-agents-api) | not documented | VERIFIED | background |
| [E2B docs: workload identity](https://docs.e2b.dev/iam/workload-identity) | SDK 2.39.0 of 2026-08-17 | VERIFIED | 05 |
| [E2B security page](https://e2b.dev/security) | not documented | VERIFIED | background |
| [firecracker-microvm/firecracker releases](https://github.com/firecracker-microvm/firecracker/releases) | not documented | VERIFIED | background |
| [Gecko Robotics news: NVIDIA OpenShell](https://www.geckorobotics.com/news/nvidia-openshell) | not documented | VERIFIED | background |
| [GitHub docs: managing personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) | undated | VERIFIED | 05 |
| [Google Cloud docs: Agent Identity](https://docs.cloud.google.com/agent-builder/agent-engine/agent-identity) | updated 2026-09-28 | VERIFIED | 05, 06 |
| [Google Cloud docs: Gemini Enterprise agent runtime identity](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-identity) | not documented | VERIFIED | background |
| [Google Cloud docs: Gemini Enterprise agent identity overview](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/agent-identity-overview) | not documented | VERIFIED | background |
| [Google Cloud docs: GKE Agent Sandbox](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/machine-learning/agent-sandbox) | last updated 2026-09-24 | VERIFIED | 07 |
| [Google Patents: US12530480B2 (NVIDIA)](https://patents.google.com/patent/US12530480B2/en) | not documented | VERIFIED | background |
| [google/gvisor: runtime monitoring guide](https://github.com/google/gvisor/blob/master/g3doc/user_guide/runtime_monitoring.md) | not documented | VERIFIED | background |
| [hermes-agent: agent/relay_runtime.py (at 39faafb)](https://github.com/NousResearch/hermes-agent/blob/39faafb61688282a372ff2d59191581588e9a003/agent/relay_runtime.py) | commit of 2026-09-28 | VERIFIED | 05, 06 |
| [HPE newsroom: secure, governed agentic AI with NVIDIA](https://www.hpe.com/us/en/newsroom/blog-post/2026/09/hpe-and-nvidia-bring-secure-governed-agentic-ai-into-enterprise-production.html) | 2026-09-28 | Unavailable: could not be retrieved on 2026-09-28 | background |
| [JPMorganChase technology blog: securing agentic AI](https://www.jpmorganchase.com/about/technology/blog/securing-agentic-ai) | 2026-03-23 | VERIFIED | 01, 05, 06, 07 |
| [kata-containers: how to use the Kata agent policy](https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-use-the-kata-agent-policy.md) | not documented | VERIFIED | background |
| [MicrosoftDocs/azure-ai-docs: Foundry hosted agents](https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/foundry/agents/concepts/hosted-agents.md) | not documented | VERIFIED | background |
| [MicrosoftDocs/azure-ai-docs: Foundry agents overview](https://github.com/MicrosoftDocs/azure-ai-docs/blob/main/articles/foundry/agents/overview.md) | not documented | VERIFIED | background |
| [MicrosoftDocs/azure-docs: Container Apps sessions](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/container-apps/sessions.md) | not documented | VERIFIED | background |
| [MicrosoftDocs/entra-docs: Agent ID docs](https://github.com/MicrosoftDocs/entra-docs/tree/main/docs/agent-id) | 2026-04-28; 2026-04-29 | VERIFIED | background |
| [Modal docs: audit logs](https://modal.com/docs/guide/audit-logs) | not documented | VERIFIED | background |
| [Modal docs: security](https://modal.com/docs/guide/security) | not documented | VERIFIED | background |
| [Modal docs: OIDC integration](https://modal.com/docs/guide/oidc-integration) | not documented | VERIFIED | background |
| [Modal docs: sandbox networking](https://modal.com/docs/guide/sandbox-networking) | not documented | VERIFIED | background |
| [Modal docs: sandbox sidecars](https://modal.com/docs/guide/sandbox-sidecars) | undated | VERIFIED | 05 |
| [Modal docs: VM sandboxes](https://modal.com/docs/guide/vm-sandboxes) | not documented | VERIFIED | background |
| [NousResearch/hermes-agent repository](https://github.com/NousResearch/hermes-agent) | 2026-09-28 | VERIFIED | background |
| [npm registry API: last-month downloads](https://api.npmjs.org/downloads/point/last-month) | not documented | VERIFIED | background |
| [openclaw/openclaw: MXC extension](https://github.com/openclaw/openclaw/tree/main/extensions/mxc) | not documented | VERIFIED | background |
| [OpenHands SDK docs: security architecture](https://docs.openhands.dev/sdk/arch/security) | not documented | VERIFIED | background |
| [OpenHands docs: sandboxes overview](https://docs.openhands.dev/openhands/usage/sandboxes/overview) | not documented | VERIFIED | background |
| [openshell-slack-admin-bridge README (at 8229bc1)](https://github.com/slack-samples/openshell-slack-admin-bridge/blob/8229bc151edc96f384ae5ac0fd5f1c3001d8f2cc/README.md) | commit of 2026-09-24 | VERIFIED | 07 |
| [Automation Anywhere press release: EnterpriseClaw with Cisco, NVIDIA, Okta, and OpenAI](https://www.prnewswire.com/news-releases/automation-anywhere-collaborates-with-cisco-nvidia-okta-and-openai-launching-enterpriseclaw-to-run-next-generation-ai-agents-inside-enterprise-systems-302775670.html) | not documented | VERIFIED | background |
| [pypistats API](https://pypistats.org/api/packages) | not documented | VERIFIED | background |
| [pypistats: openshell package recent downloads](https://pypistats.org/api/packages/openshell/recent) | undated; read 2026-09-29 | VERIFIED | 06, 07 |
| [Red Hat blog: Claude self-hosted sandboxes on OpenShell on Red Hat AI](https://www.redhat.com/en/blog/bringing-claude-self-hosted-sandboxes-to-openshell-on-red-hat-ai) | 2026-05-20 | VERIFIED | background |
| [Red Hat blog: introducing Asago](https://www.redhat.com/en/blog/introducing-asago-open-source-ai-safety-and-governance-orchestration) | not documented | VERIFIED | background |
| [Red Hat blog: securing the systems around AI agents](https://www.redhat.com/en/blog/securing-ai-agents-requires-securing-systems-around-them) | not documented | VERIFIED | background |
| [Red Hat blog: secure agent onboarding](https://www.redhat.com/en/blog/why-red-hat-is-building-secure-agent-onboarding) | not documented | VERIFIED | background |
| [Red Hat validated pattern: architecture-alignment.md (at 31364b1)](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/blob/31364b10d81e61057b50cdf22c0cdab403fb5f0a/docs/architecture-alignment.md) | 2026-09-27 | VERIFIED | 03, 05, 06, 07 |
| [Red Hat press release: Asago community](https://redhat.com/en/about/press-releases/red-hat-launches-asago-community-automate-ai-safety-and-governance-policy-production) | 2026-08-04 | VERIFIED | background |
| [Salesforce blog: admin control at the runtime layer with OpenShell and Slack](https://www.salesforce.com/blog/extending-admin-control-to-the-runtime-layer-with-nvidia-openshell-and-slack) | not documented | VERIFIED | background |
| [SAP News: SAP and NVIDIA OpenShell for auditable AI agents](https://news.sap.com/2026/09/sap-nvidia-openshell-auditable-ai-agents-enterprise-systems) | 2026-09-28 | VERIFIED | 01, 05 |
| [ServiceNow press release: agentic AI governance with NVIDIA](https://newsroom.servicenow.com/press-releases/details/2026/ServiceNow-extends-agentic-AI-governance-from-desktops-to-data-centers-with-NVIDIA/default.aspx) | 2026-05-05 | REPORTED | 01, 05 |
| [slack-samples/openshell-slack-admin-bridge](https://github.com/slack-samples/openshell-slack-admin-bridge) | created 2026-09-10; commit 8229bc1 of 2026-09-24 | VERIFIED | 01, 05, 06 |
| [Supermicro press release: shipping Vera Rubin NVL72 racks](https://www.supermicro.com/en/pressreleases/supermicro-now-shipping-nvidia-vera-rubin-nvl72-racks) | 2026-09-23 | VERIFIED | 01 |
| [Supermicro: support for the Open Agent Safety Platform](https://learn-more.supermicro.com/data-center-stories/supermicro-supports-nvidia-open-agent-safety-platform) | not documented | VERIFIED | background |
| [SUSE blog: we gave our agents autonomy, here's how we kept control](https://www.suse.com/c/we-gave-our-agents-autonomy-heres-how-we-kept-control) | not documented | VERIFIED | background |
| [validatedpatterns-sandbox/secure-agent-workspace (Red Hat validated pattern)](https://github.com/validatedpatterns-sandbox/secure-agent-workspace) | commit of 2026-09-27 | VERIFIED | 01 |
| [vercel/sandbox repository](https://github.com/vercel/sandbox) | not documented | VERIFIED | background |

## Press and analysis

### Incident reports and research

Reports by the organizations involved are primary for their own accounts.

| Source | Date | Status | Used in |
|---|---|---|---|
| [Anthropic research: alignment assessment of cybersecurity incidents](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents) | 2026-09-09 | VERIFIED | 01, 07 |
| [Anthropic: investigating incidents in cybersecurity evaluations](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals) | 2026-07-30 | VERIFIED | 01, 05, 06, 07 |
| [Hugging Face blog: agent intrusion technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline) | 2026-07-27 | VERIFIED | 01 |
| [Hugging Face blog: security incident, July 2026](https://huggingface.co/blog/security-incident-july-2026) | not documented | VERIFIED | background |
| [METR: OpenAI and Hugging Face incident investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation) | 2026-08-26 | VERIFIED | 01 |
| [OpenAI misalignment report: encouraging deception in compaction summaries](https://alignment.openai.com/misalignment-reports/encouraging-deception-in-compaction-summaries) | not documented | VERIFIED | background |
| [OpenAI misalignment report: exposing a GitHub token in a public repository](https://alignment.openai.com/misalignment-reports/exposing-a-github-token-in-a-public-repository) | not documented | VERIFIED | background |
| [OpenAI misalignment reports index](https://alignment.openai.com/misalignment-reports) | not documented | VERIFIED | background |
| [OpenAI misalignment report: unauthorized Artifactory writes](https://alignment.openai.com/misalignment-reports/unauthorized-artifactory-writes-and-cross-sample-communication) | not documented | VERIFIED | background |
| [OpenAI misalignment report: an agent used DNS to reach an external chatbot](https://alignment.openai.com/misalignment-reports/an-agent-used-dns-to-reach-an-external-chatbot) | 2026-09-25 | VERIFIED | 01 |

### Press coverage

| Source | Date | Status | Used in |
|---|---|---|---|
| [Business Insider: NVIDIA launches Open Agent Safety Platform](https://www.businessinsider.com/nvidia-launches-open-agent-safety-platform-ai-going-rogue-2026-9) | not documented | REPORTED | background |
| [Calcalist: report on a Meta incident in an evaluation environment](https://www.calcalistech.com/ctechnews/article/jbl2ysnq5) | 2026-08-06 | REPORTED | 01 |
| [CNBC: NVIDIA release coverage, 2026-09-28](https://www.cnbc.com/2026/09/28/nvidia-releases.html) | not documented | REPORTED | background |
| [CSO Online: NVIDIA releases Open Agent Safety Platform](https://www.csoonline.com/article/4227843/nvidia-releases-open-agent-safety-platform-to-monitor-and-govern-agentic-ai.html) | 2026-09-28 | REPORTED | 01, 05, 07 |
| [CSO Online: OpenAI pauses training after an agent bypasses network restrictions](https://www.csoonline.com/article/4227777/openai-pauses-ai-model-training-after-another-agent-bypasses-network-restrictions.html) | not documented | REPORTED | background |
| [Data Science Dojo: AI containment crisis 2026](https://datasciencedojo.com/blog/ai-containment-crisis-2026) | 2026-09-20 | REPORTED | 01 |
| [Forkast: the Open Secure AI Alliance's 37 members](https://forkast.news/nvidias-open-secure-ai-alliance-has-37-members-the-four-that-arent-there-tell-the-real-story) | 2026-07-28 | REPORTED | background |
| [Fortune: OpenAI training pause after a second sandbox escape](https://fortune.com/2026/09/26/openai-ai-agents-secure-sandbox-escape-training-pause-second-time-hugging-face-hack) | not documented | REPORTED | background |
| [Fortune: OpenAI says AI models escaped control](https://fortune.com/2026/07/21/openai-says-ai-models-escaped-control-hacked-hugging-face) | not documented | REPORTED | background |
| [FourWeekMBA: NVIDIA Open Agent Safety Platform (first version)](https://fourweekmba.com/ai-nvidia-open-agent-safety-platform-openshell-sentry) | 2026-09-28 | REPORTED | background |
| [FourWeekMBA: NVIDIA Open Agent Safety Platform, OpenShell and Sentry](https://fourweekmba.com/ai-nvidia-open-agent-safety-platform-openshell-sentry-2) | 2026-09-28 | REPORTED | 01 |
| [Hacker News discussion thread on the platform announcement](https://news.ycombinator.com/item?id=49879883) | 2026-09-28 | REPORTED | 01 |
| [Hacker News thread 47427027](https://news.ycombinator.com/item?id=47427027) | not documented | REPORTED | background |
| [Hacker News thread 49713261](https://news.ycombinator.com/item?id=49713261) | not documented | REPORTED | background |
| [Help Net Security: NVIDIA Open Agent Safety Platform](https://www.helpnetsecurity.com/2026/09/28/nvidia-open-agent-safety-platform) | 2026-09-28 | REPORTED | background |
| [Nextgov: AI breakout at OpenAI](https://www.nextgov.com/artificial-intelligence/2026/09/AI-breakout-openai-complex/415826) | not documented | REPORTED | background |
| [Pulse 2.0: IBM supports the Open Agent Safety Platform](https://pulse2.com/ibm-supports-nvidia-open-agent-safety-platform-with-identity-storage-and-hybrid-cloud-integrations) | not documented | REPORTED | background |
| [Remote Rocketship: copy of the NVIDIA Agent Policy Fabric job post](https://www.remoterocketship.com/us/company/nvidia/jobs/principal-software-engineer-agent-policy-fabric-united-states-remote) | not documented | REPORTED | background |
| [SecurityWeek: NVIDIA unveils AI agent safety platform](https://www.securityweek.com/nvidia-unveils-ai-agent-safety-platform-with-hardware-based-watchdog) | 2026-09-28 | REPORTED | background |
| [ServeTheHome: BlueField-4 at Hot Chips 2026](https://www.servethehome.com/nvidia-bluefield-4-processor-at-hot-chips-2026) | 2026-08-25 | REPORTED | background |
| [SiliconANGLE: NVIDIA launches NemoClaw](https://siliconangle.com/2026/03/16/nvidia-launches-nemoclaw-agent-toolkit-enhance-ai-agents) | 2026-03-16 | REPORTED | background |
| [StorageReview: HPE expands AI factory portfolio](https://www.storagereview.com/news/hpe-expands-ai-factory-portfolio-for-agentic-ai-deployments) | 2026-06-16 | REPORTED | background |
| [StorageReview: NVIDIA Open Agent Safety Platform](https://www.storagereview.com/news/nvidia-open-agent-safety-platform-openshell-sentry-bluefield-4) | 2026-09-28 | REPORTED | background |
| [Techstrong.ai: the Open Secure AI Alliance needs one open home](https://techstrong.ai/articles/nvidias-open-secure-ai-alliance-needs-one-open-home) | 2026-07-27 | REPORTED | background |
| [The Hacker News: NVIDIA forms 37-member Open Secure AI Alliance](https://thehackernews.com/2026/07/nvidia-forms-37-member-open-secure-ai.html) | 2026-07-27 | REPORTED | 01 |
| [The New Stack: NVIDIA OpenShell and Sentry](https://thenewstack.io/nvidia-openshell-sentry-agents) | 2026-09-28 | REPORTED | 01, 03, 04, 06, 07 |
| [TIME: OpenAI and the Hugging Face attack](https://time.com/article/2026/07/24/openai-hugging-face-attack) | not documented | REPORTED | background |
| [VentureBeat: NVIDIA's Open Agent Safety Platform bets agents can't police themselves](https://venturebeat.com/infrastructure/nvidias-open-agent-safety-platform-bets-agents-cant-police-themselves-so-the-infrastructure-has-to) | 2026-09-28 | REPORTED | 05 |

### Commentary

| Source | Date | Status | Used in |
|---|---|---|---|
| [Christian Posta blog: do we even need agent identity](https://blog.christianposta.com/do-we-even-need-agent-identity) | not documented | REPORTED | background |
| [Christian Posta blog: on-behalf-of for AI agents](https://blog.christianposta.com/explaining-on-behalf-of-for-ai-agents) | not documented | REPORTED | background |
| [Christian Posta blog: exploring AAuth](https://blog.christianposta.com/exploring-aauth-agent-auth-identity-and-access-management-for-ai-agents) | not documented | REPORTED | background |
| [CyberUnit: AI sandbox escapes at three labs](https://cyberunit.com/insights/ai-sandbox-escapes-three-labs-meta-anthropic-openai) | not documented | REPORTED | background |
| [David Kaya blog: NVIDIA OpenShell](https://davidkaya.com/blog/nvidia-openshell-the-sandbox-ai-agents-have-been-missing) | not documented | REPORTED | background |
| [Substack essay: the container was always there](https://suthakamal.substack.com/p/the-container-was-always-there) | not documented | REPORTED | background |

## Chio repository documents

Paths are relative to the repository root. Links use `../../../` from this directory. Files on unmerged branches are given as text, because they do not exist on `main`.

### Release, claim boundary, and formal evidence

| File | Commit | Status | Used in |
|---|---|---|---|
| [`docs/formal/CURRENT_STATE.md`](../../../docs/formal/CURRENT_STATE.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/reference/CLAIM_REGISTRY.md`](../../../docs/reference/CLAIM_REGISTRY.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`docs/release/CHIO_WEB3_READINESS_AUDIT.md`](../../../docs/release/CHIO_WEB3_READINESS_AUDIT.md) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`docs/release/QUALIFICATION.md`](../../../docs/release/QUALIFICATION.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`docs/release/RELEASE_CANDIDATE.md`](../../../docs/release/RELEASE_CANDIDATE.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`docs/release/RISK_REGISTER.md`](../../../docs/release/RISK_REGISTER.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 06, 07 |
| [`docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json`](../../../docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`formal/assumptions.toml`](../../../formal/assumptions.toml) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`formal/diff-tests/src/generators.rs`](../../../formal/diff-tests/src/generators.rs) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`formal/lean4/Chio/Chio.lean`](../../../formal/lean4/Chio/Chio.lean) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`formal/lean4/Chio/Chio/Capability/Delegation.lean`](../../../formal/lean4/Chio/Chio/Capability/Delegation.lean) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`formal/lean4/Chio/Chio/Core/Capability.lean`](../../../formal/lean4/Chio/Chio/Core/Capability.lean) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`formal/lean4/Chio/Chio/Proofs/AttenuationWitness.lean`](../../../formal/lean4/Chio/Chio/Proofs/AttenuationWitness.lean) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`formal/lean4/Chio/Chio/Proofs/SiblingSumBudget.lean`](../../../formal/lean4/Chio/Chio/Proofs/SiblingSumBudget.lean) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`formal/proof-manifest.toml`](../../../formal/proof-manifest.toml) | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`formal/theorem-inventory.json`](../../../formal/theorem-inventory.json) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`releases.toml`](../../../releases.toml) | f5566d9a76, 2026-09-03 | Read at main | 03, 05, 06 |
| [`xtask/src/qualify.rs`](../../../xtask/src/qualify.rs) | f5566d9a76, 2026-09-03 | Read at main | 02, 06, 07 |

### Specifications and schemas

| File | Commit | Status | Used in |
|---|---|---|---|
| [`spec/CHIO_BILATERAL_COSIGN_INVOCATION.md`](../../../spec/CHIO_BILATERAL_COSIGN_INVOCATION.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06, 07 |
| [`spec/PROTOCOL.md`](../../../spec/PROTOCOL.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`spec/SECURITY.md`](../../../spec/SECURITY.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`spec/audit-log/export-schema.v1.json`](../../../spec/audit-log/export-schema.v1.json) | f5566d9a76, 2026-09-03 | Read at main | 02, 05, 06, 07 |
| [`spec/ietf/draft-chio-protocol-00.md`](../../../spec/ietf/draft-chio-protocol-00.md) | f5566d9a76, 2026-09-03 | Read at main | 05, 07 |
| [`spec/registries/claim-registry.v1.json`](../../../spec/registries/claim-registry.v1.json) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`spec/schemas/chio-runtime/v1`](../../../spec/schemas/chio-runtime/v1) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`spec/schemas/chio-runtime/v1/sandbox-attestation.schema.json`](../../../spec/schemas/chio-runtime/v1/sandbox-attestation.schema.json) | f5566d9a76, 2026-09-03 | Read at main | 03 |
| [`spec/schemas/chio-wire/v1/agent/active-response-governed-intent.schema.json`](../../../spec/schemas/chio-wire/v1/agent/active-response-governed-intent.schema.json) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`spec/schemas/chio-wire/v1/capability/token.schema.json`](../../../spec/schemas/chio-wire/v1/capability/token.schema.json) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`spec/schemas/chio-wire/v1/receipt/record.schema.json`](../../../spec/schemas/chio-wire/v1/receipt/record.schema.json) | f5566d9a76, 2026-09-03 | Read at main | background |

### Positioning, guides, and integration documents

| File | Commit | Status | Used in |
|---|---|---|---|
| [`AGENTS.md`](../../../AGENTS.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 05, 06, 07 |
| [`README.md`](../../../README.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 04, 05, 06, 07 |
| [`compliance/hitrust/operational-samples.md`](../../../compliance/hitrust/operational-samples.md) | f5566d9a76, 2026-09-03 | Read at main | 05, 06, 07 |
| [`deploy`](../../../deploy) | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`deploy/README.md`](../../../deploy/README.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 04 |
| [`deploy/cognition-market/kubernetes.yaml.template`](../../../deploy/cognition-market/kubernetes.yaml.template) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`deploy/healthcare-design-partner/chio-siem-overrides.yaml`](../../../deploy/healthcare-design-partner/chio-siem-overrides.yaml) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`deploy/sbom`](../../../deploy/sbom) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`docs/README.md`](../../../docs/README.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/assets/hero-mobile.svg`](../../../docs/assets/hero-mobile.svg) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/assets/hero.svg`](../../../docs/assets/hero.svg) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/assets/pillars-mobile.svg`](../../../docs/assets/pillars-mobile.svg) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/assets/pillars.svg`](../../../docs/assets/pillars.svg) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/assets/subhead-mobile.svg`](../../../docs/assets/subhead-mobile.svg) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/assets/subhead.svg`](../../../docs/assets/subhead.svg) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/compliance`](../../../docs/compliance) | f5566d9a76, 2026-09-03 | Read at main | 06, 07 |
| [`docs/compliance/colorado-sb-24-205.md`](../../../docs/compliance/colorado-sb-24-205.md) | f5566d9a76, 2026-09-03 | Read at main | background |
| [`docs/compliance/eu-ai-act-article-19.md`](../../../docs/compliance/eu-ai-act-article-19.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/compliance/iso-42001.md`](../../../docs/compliance/iso-42001.md) | f5566d9a76, 2026-09-03 | Read at main | background |
| [`docs/compliance/nist-ai-rmf.md`](../../../docs/compliance/nist-ai-rmf.md) | f5566d9a76, 2026-09-03 | Read at main | background |
| [`docs/compliance/owasp-llm-top-10.md`](../../../docs/compliance/owasp-llm-top-10.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/compliance/pci-dss-v4.md`](../../../docs/compliance/pci-dss-v4.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/conformance.md`](../../../docs/conformance.md) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`docs/distribution/apn-blog/aws-bedrock-mcp-listing.md`](../../../docs/distribution/apn-blog/aws-bedrock-mcp-listing.md) | f5566d9a76, 2026-09-03 | Read at main | 05, 06, 07 |
| [`docs/guards/13-CODE-EXECUTION-GUARDS.md`](../../../docs/guards/13-CODE-EXECUTION-GUARDS.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/guides/MIGRATING-FROM-MCP.md`](../../../docs/guides/MIGRATING-FROM-MCP.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/install/PUBLISHING.md`](../../../docs/install/PUBLISHING.md) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`docs/install/README.md`](../../../docs/install/README.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`docs/integrations/HERMES.md`](../../../docs/integrations/HERMES.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06, 07 |
| [`docs/integrations/otel.md`](../../../docs/integrations/otel.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/integrations/providers.md`](../../../docs/integrations/providers.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/market/README.md`](../../../docs/market/README.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/operator-runbook/phi-policy.md`](../../../docs/operator-runbook/phi-policy.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/reference/AGENT_PASSPORT_GUIDE.md`](../../../docs/reference/AGENT_PASSPORT_GUIDE.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`docs/reference/COMPETITIVE_LANDSCAPE.md`](../../../docs/reference/COMPETITIVE_LANDSCAPE.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 05, 06, 07 |
| [`docs/reference/DID_CHIO_METHOD.md`](../../../docs/reference/DID_CHIO_METHOD.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 06, 07 |
| [`docs/reference/DPOP_INTEGRATION_GUIDE.md`](../../../docs/reference/DPOP_INTEGRATION_GUIDE.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/reference/IDENTITY_FEDERATION_GUIDE.md`](../../../docs/reference/IDENTITY_FEDERATION_GUIDE.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/reference/POLICY_ANALYSIS.md`](../../../docs/reference/POLICY_ANALYSIS.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`docs/reference/SIEM_INTEGRATION_GUIDE.md`](../../../docs/reference/SIEM_INTEGRATION_GUIDE.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/reference/WORKLOAD_IDENTITY_RUNBOOK.md`](../../../docs/reference/WORKLOAD_IDENTITY_RUNBOOK.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`docs/sdk/PLATFORM.md`](../../../docs/sdk/PLATFORM.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/sdk/PYTHON.md`](../../../docs/sdk/PYTHON.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/sdk/TYPESCRIPT.md`](../../../docs/sdk/TYPESCRIPT.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/security/threat-coverage.md`](../../../docs/security/threat-coverage.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/standards/CHIO_AGENT_WEB_PROTOCOL_TAXONOMY.md`](../../../docs/standards/CHIO_AGENT_WEB_PROTOCOL_TAXONOMY.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`docs/start-here/VISION.md`](../../../docs/start-here/VISION.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |

### ADRs, designs, and papers

| File | Commit | Status | Used in |
|---|---|---|---|
| [`docs/adr/ADR-0007-dpop-binding-format.md`](../../../docs/adr/ADR-0007-dpop-binding-format.md) | f5566d9a76, 2026-09-03 | Read at main | 04 |
| [`docs/adr/ADR-0011-boundary-taxonomy-product-wording.md`](../../../docs/adr/ADR-0011-boundary-taxonomy-product-wording.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`docs/adr/ADR-0014-iroh-federation-transport.md`](../../../docs/adr/ADR-0014-iroh-federation-transport.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06, 07 |
| [`docs/adr/ADR-0017-cognition-market-finding-artifacts.md`](../../../docs/adr/ADR-0017-cognition-market-finding-artifacts.md) | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`docs/adr/README.md`](../../../docs/adr/README.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/papers/agentic-tool-safety/sections/06-threat-model.tex`](../../../docs/papers/agentic-tool-safety/sections/06-threat-model.tex) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/papers/bilateral-receipt-admission/sections/09-limitations.tex`](../../../docs/papers/bilateral-receipt-admission/sections/09-limitations.tex) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/papers/delegated-emergency-authority/sections/04-grammar.tex`](../../../docs/papers/delegated-emergency-authority/sections/04-grammar.tex) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/papers/programmable-sovereignty/CLAIM_LEDGER.md`](../../../docs/papers/programmable-sovereignty/CLAIM_LEDGER.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 05, 06, 07 |
| [`docs/papers/reversible-action/theorems.lean`](../../../docs/papers/reversible-action/theorems.lean) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/papers/sensor-grounded-admission`](../../../docs/papers/sensor-grounded-admission) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/papers/sensor-grounded-admission/README.md`](../../../docs/papers/sensor-grounded-admission/README.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/papers/sensor-grounded-admission/lean/STATUS.md`](../../../docs/papers/sensor-grounded-admission/lean/STATUS.md) | f5566d9a76, 2026-09-03 | Read at main | 04 |
| [`docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean`](../../../docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 07 |
| [`docs/papers/sensor-grounded-admission/research/tee-attestation-delta.md`](../../../docs/papers/sensor-grounded-admission/research/tee-attestation-delta.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`docs/papers/sensor-grounded-admission/sections/01-introduction.tex`](../../../docs/papers/sensor-grounded-admission/sections/01-introduction.tex) | f5566d9a76, 2026-09-03 | Read at main | 03 |
| [`docs/papers/sensor-grounded-admission/sections/03-substrate.tex`](../../../docs/papers/sensor-grounded-admission/sections/03-substrate.tex) | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04 |
| [`docs/papers/sensor-grounded-admission/sections/10-conclusion.tex`](../../../docs/papers/sensor-grounded-admission/sections/10-conclusion.tex) | f5566d9a76, 2026-09-03 | Read at main | 02, 04 |
| [`docs/protocols/COMPLIANCE-ROADMAP.md`](../../../docs/protocols/COMPLIANCE-ROADMAP.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md`](../../../docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md`](../../../docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`docs/protocols/STRUCTURAL-SECURITY-FIXES.md`](../../../docs/protocols/STRUCTURAL-SECURITY-FIXES.md) | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`docs/superpowers/specs/2026-07-09-enterprise-hardening-design.md`](../../../docs/superpowers/specs/2026-07-09-enterprise-hardening-design.md) | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`docs/superpowers/specs/2026-07-09-security-folder-design.md`](../../../docs/superpowers/specs/2026-07-09-security-folder-design.md) | f5566d9a76, 2026-09-03 | Read at main | 02, 04 |

### Code and configuration

Code citations are grouped by crate. The Files column lists the paths cited inside each crate.

| Crate or path | Files | Commit | Status | Used in |
|---|---|---|---|---|
| [`crates/core/chio-core-types`](../../../crates/core/chio-core-types) | `Cargo.toml`, `src/canonical.rs`, `src/capability/attenuation.rs`, `src/capability/caveat.rs`, `src/capability/features.rs`, `src/capability/governance.rs`, `src/capability/runtime_attestation.rs`, `src/capability/scope.rs`, `src/capability/threshold_approval.rs`, `src/capability/token.rs`, `src/capability/trust_policy.rs`, `src/capability/workload_identity.rs`, `src/crypto.rs`, `src/delegation_receipt.rs`, `src/pq.rs`, `src/receipt/authoritative_spend.rs`, `src/receipt/body.rs`, `src/receipt/decision.rs`, `src/receipt/economics.rs`, `src/receipt/governance.rs`, `src/receipt/kinds.rs`, `src/receipt/lineage.rs`, `src/receipt/metadata.rs`, `src/runtime_attestation.rs`, `src/session/auth.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/economy/chio-anchor`](../../../crates/economy/chio-anchor) | `src/witness/rekor.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/economy/chio-appraisal`](../../../crates/economy/chio-appraisal) | `src/appraisal.rs`, `src/types.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 04 |
| [`crates/economy/chio-credit`](../../../crates/economy/chio-credit) | `src/clearing` | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`crates/economy/chio-metering`](../../../crates/economy/chio-metering) | `src/cost.rs` | f5566d9a76, 2026-09-03 | Read at main | 03 |
| [`crates/economy/chio-settle`](../../../crates/economy/chio-settle) | `Cargo.toml` | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`crates/economy/chio-web3`](../../../crates/economy/chio-web3) | `Cargo.toml` | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`crates/guards/chio-data-guards`](../../../crates/guards/chio-data-guards) | `src/warehouse_cost_guard.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/guards/chio-external-guards`](../../../crates/guards/chio-external-guards) | `README.md`, `src/external/endpoint_security.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`crates/guards/chio-guards`](../../../crates/guards/chio-guards) | `src/mcp_tool.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/guards/chio-policy`](../../../crates/guards/chio-policy) | `src/analyze/mod.rs`, `src/analyze/refine.rs`, `src/compiler/rules.rs`, `src/compiler/scope.rs`, `src/evaluate/engine.rs`, `src/models/extensions.rs`, `src/models/rules.rs`, `src/validate.rs`, `src/version.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/guards/chio-wasm-guards`](../../../crates/guards/chio-wasm-guards) | the crate directory | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/kernel/chio-kernel`](../../../crates/kernel/chio-kernel) | `ARCHITECTURE.md`, `Cargo.toml`, `src/approval.rs`, `src/boot.rs`, `src/budget_store/model.rs`, `src/capability_lineage.rs`, `src/checkpoint.rs`, `src/custody.rs`, `src/dpop.rs`, `src/evidence_export.rs`, `src/governed_active_response.rs`, `src/governed_approval_replay.rs`, `src/kernel/admission_coordinator/terminal.rs`, `src/kernel/construction.rs`, `src/kernel/delegation.rs`, `src/kernel/dispatch.rs`, `src/kernel/governed_validation.rs`, `src/kernel/kernel_struct.rs`, `src/kernel/mod.rs`, `src/kernel/responses/receipt_persistence.rs`, `src/kernel/tests/approval_flow.rs`, `src/kernel/tests/support_monetary.rs`, `src/kernel/validation.rs`, `src/kernel/validation/revocation_trace.rs`, `src/operator_report/constants.rs`, `src/otel.rs`, `src/payment.rs`, `src/post_invocation.rs`, `src/receipt_store.rs`, `src/receipt_support/coupling.rs`, `src/receipt_support/receipt_metadata.rs`, `src/request_matching.rs`, `src/runtime.rs`, `tests/passkey_capability_dispatch.rs`, `tests/pq_key_load_after_self_quote.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/kernel/chio-kernel-browser`](../../../crates/kernel/chio-kernel-browser) | `README.md` | f5566d9a76, 2026-09-03 | Read at main | background |
| [`crates/kernel/chio-kernel-core`](../../../crates/kernel/chio-kernel-core) | `README.md`, `src/budget_split.rs`, `src/capability_verify.rs`, `src/lib.rs`, `src/revocation_view.rs`, `src/scope.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 07 |
| [`crates/kernel/chio-kernel-mobile`](../../../crates/kernel/chio-kernel-mobile) | `src/lib.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/kernel/chio-runtime`](../../../crates/kernel/chio-runtime) | `src/lib.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/kernel/chio-runtime-core`](../../../crates/kernel/chio-runtime-core) | `benches/fixtures/treaty_admission_fixture.rs`, `src/admission.rs`, `src/admission_hook/swarm_authority.rs`, `src/store/sqlite/health_summaries.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 07 |
| [`crates/kernel/chio-runtime-harness`](../../../crates/kernel/chio-runtime-harness) | `src/kernel.rs` | f5566d9a76, 2026-09-03 | Read at main | 04, 05, 06, 07 |
| [`crates/kernel/chio-swarm-authority`](../../../crates/kernel/chio-swarm-authority) | `ARCHITECTURE.md`, `src/types.rs`, `src/verifier.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`crates/observability/chio-lineage`](../../../crates/observability/chio-lineage) | `schemas/lineage-graph.v1.json`, `src/anchor.rs`, `src/schema.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 06 |
| [`crates/observability/chio-otel-receipt-exporter`](../../../crates/observability/chio-otel-receipt-exporter) | `README.md` | f5566d9a76, 2026-09-03 | Read at main | background |
| [`crates/observability/chio-siem`](../../../crates/observability/chio-siem) | `(crate)`, `ARCHITECTURE.md`, `README.md`, `src/alerting.rs`, `src/exporters/mod.rs`, `src/exporters/ocsf_exporter.rs`, `src/ocsf.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/platform/chio-agent-web-interop`](../../../crates/platform/chio-agent-web-interop) | `README.md`, `src/protocols.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`crates/platform/chio-config`](../../../crates/platform/chio-config) | `src/schema.rs` | f5566d9a76, 2026-09-03 | Read at main | 03 |
| [`crates/platform/chio-control-plane`](../../../crates/platform/chio-control-plane) | `src/attestation`, `src/attestation.rs`, `src/attestation/model.rs`, `src/attestation/verification.rs`, `src/durable_admission.rs`, `src/evidence_export/verification.rs`, `src/issuance/scope.rs`, `src/lib.rs`, `src/policy/types.rs`, `src/policy/util.rs`, `src/scim_lifecycle.rs`, `src/trust_control/config_and_public.rs`, `src/trust_control/finding_hosted_profile.rs`, `src/trust_control/passport_handlers.rs`, `src/trust_control/service_runtime/budget.rs`, `src/trust_control/service_types/requests.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/platform/chio-finding-worker`](../../../crates/platform/chio-finding-worker) | `src/executor.rs`, `src/lib.rs`, `src/protocol.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`crates/platform/chio-http-core`](../../../crates/platform/chio-http-core) | `src/authority.rs`, `src/emergency.rs`, `src/routes.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/platform/chio-transaction-passport`](../../../crates/platform/chio-transaction-passport) | `src/runtime_security.rs`, `src/runtime_security/artifacts.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 07 |
| [`crates/platform/chio-workflow`](../../../crates/platform/chio-workflow) | `src/authority.rs`, `src/grant.rs`, `src/receipt.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`crates/platform/chio-workflow-preflight`](../../../crates/platform/chio-workflow-preflight) | `src/lib.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/products/chio-api-protect`](../../../crates/products/chio-api-protect) | `README.md`, `src/proxy/approval.rs`, `src/proxy/http.rs`, `src/proxy/mediated.rs`, `src/proxy/router.rs`, `src/proxy/sidecar.rs`, `src/proxy/tests.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/products/chio-cli`](../../../crates/products/chio-cli) | `Cargo.toml`, `src/cli/dispatch/finding/verified_fix_repository_sandbox.rs`, `src/cli/dispatch/proof.rs`, `src/cli/mcp/ide.rs`, `src/cli/mcp/wrap.rs`, `src/cli/runtime.rs`, `src/cli/types.rs`, `src/cli/types/receipt.rs`, `src/cli/types/runtime.rs`, `src/guard`, `src/policies/code_agent.yaml` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 06 |
| [`crates/products/chio-proof-room`](../../../crates/products/chio-proof-room) | `src/source_verifier.rs` | f5566d9a76, 2026-09-03 | Read at main | 03 |
| [`crates/products/chio-wall`](../../../crates/products/chio-wall) | `src/commands.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/protocol/chio-anthropic-tools-adapter`](../../../crates/protocol/chio-anthropic-tools-adapter) | `README.md`, `src/transport.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/protocol/chio-egress-contract`](../../../crates/protocol/chio-egress-contract) | `README.md`, `src/lib.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`crates/protocol/chio-envoy-ext-authz`](../../../crates/protocol/chio-envoy-ext-authz) | `README.md`, `src/lib.rs`, `src/response.rs`, `src/service.rs`, `src/translate.rs`, `tests/translate.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 05, 06, 07 |
| [`crates/protocol/chio-mcp-adapter`](../../../crates/protocol/chio-mcp-adapter) | `Cargo.toml`, `src/transport/stdio.rs`, `src/transport/utils.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`crates/protocol/chio-mcp-edge`](../../../crates/protocol/chio-mcp-edge) | `src/runtime.rs`, `src/runtime/jsonrpc.rs`, `src/runtime/requests.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 06, 07 |
| [`crates/protocol/chio-mcp-remote`](../../../crates/protocol/chio-mcp-remote) | `src/remote_mcp/http_service.rs`, `src/remote_mcp/http_service_auth.rs`, `src/remote_mcp/oauth/bearer_auth.rs`, `src/remote_mcp/oauth/local_server.rs`, `src/remote_mcp/session_core.rs`, `src/remote_mcp/session_core/factory.rs`, `src/remote_mcp/session_identity.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 04, 06, 07 |
| [`crates/protocol/chio-openai-adapter`](../../../crates/protocol/chio-openai-adapter) | `(crate)`, `src/transport.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/protocol/chio-tool-call-fabric`](../../../crates/protocol/chio-tool-call-fabric) | `src/adapter.rs`, `src/error.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/protocol/chio-tower`](../../../crates/protocol/chio-tower) | `src/service.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 04 |
| [`crates/sdk/chio-cpp-kernel-ffi`](../../../crates/sdk/chio-cpp-kernel-ffi) | the crate directory | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/tooling/chio-conformance`](../../../crates/tooling/chio-conformance) | `tests/b4_bilateral_dsse_pae_conformance.rs`, `tests/frost_quorum.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/trust/chio-attest-verify`](../../../crates/trust/chio-attest-verify) | `Cargo.toml`, `src/lib.rs`, `src/quote.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`crates/trust/chio-credentials`](../../../crates/trust/chio-credentials) | `src/passport.rs` | f5566d9a76, 2026-09-03 | Read at main | 03 |
| [`crates/trust/chio-custody-hw`](../../../crates/trust/chio-custody-hw) | `src/capability.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/trust/chio-did`](../../../crates/trust/chio-did) | `(crate)`, `src/lib.rs` | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/trust/chio-federation`](../../../crates/trust/chio-federation) | `src/bilateral_dsse/builder.rs`, `src/bilateral_dsse/types.rs`, `src/treaty.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 05 |
| [`crates/trust/chio-federation-transport-iroh`](../../../crates/trust/chio-federation-transport-iroh) | the crate directory | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`crates/trust/chio-governance`](../../../crates/trust/chio-governance) | `src/lease.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03 |
| [`crates/trust/chio-revocation-oracle`](../../../crates/trust/chio-revocation-oracle) | `ARCHITECTURE.md`, `src/api.rs`, `tests/swarm_revocation_e2e.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 03, 07 |
| [`crates/trust/chio-selective-disclosure`](../../../crates/trust/chio-selective-disclosure) | the crate directory | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`crates/trust/chio-signing-remote`](../../../crates/trust/chio-signing-remote) | `src/lib.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 04, 05, 06, 07 |
| [`crates/trust/chio-tee`](../../../crates/trust/chio-tee) | `src/lib.rs`, `src/mode.rs`, `src/runner.rs` | f5566d9a76, 2026-09-03 | Read at main | 02, 07 |
| [`.github/workflows/audit-log-schema-lint.yml`](../../../.github/workflows/audit-log-schema-lint.yml) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`.github/workflows/cognition-market-hosted.yml`](../../../.github/workflows/cognition-market-hosted.yml) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`Cargo.toml`](../../../Cargo.toml) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 06, 07 |
| [`LICENSE`](../../../LICENSE) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`crates/protocol`](../../../crates/protocol) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02, 06 |
| [`examples/chio-3vendor`](../../../examples/chio-3vendor) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 07 |
| [`examples/istio-ext-authz/00-chio-sidecar-deployment.yaml`](../../../examples/istio-ext-authz/00-chio-sidecar-deployment.yaml) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`integrations/mcp-adapter/registry/server.json`](../../../integrations/mcp-adapter/registry/server.json) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`integrations/mcp-adapter/tests/agentcore_gateway_consumer.rs`](../../../integrations/mcp-adapter/tests/agentcore_gateway_consumer.rs) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02, 05, 06 |
| [`scripts/check-chio-treaty-bound-provenance.sh`](../../../scripts/check-chio-treaty-bound-provenance.sh) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`scripts/check-chio-treaty-buyer-hero-loop.sh`](../../../scripts/check-chio-treaty-buyer-hero-loop.sh) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`sdks/k8s`](../../../sdks/k8s) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`sdks/k8s/controller/config/manager/manager.yaml`](../../../sdks/k8s/controller/config/manager/manager.yaml) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 06 |
| [`sdks/k8s/controller/internal/chio/types.go`](../../../sdks/k8s/controller/internal/chio/types.go) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`sdks/k8s/webhooks`](../../../sdks/k8s/webhooks) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`sdks/k8s/webhooks/capability.go`](../../../sdks/k8s/webhooks/capability.go) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02, 04, 07 |
| [`sdks/k8s/webhooks/config.go`](../../../sdks/k8s/webhooks/config.go) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`sdks/k8s/webhooks/server.go`](../../../sdks/k8s/webhooks/server.go) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02, 04 |
| [`sdks/python/chio-code-agent/src/chio_code_agent/tools.py`](../../../sdks/python/chio-code-agent/src/chio_code_agent/tools.py) | the path itself | f5566d9a76, 2026-09-03 | Read at main | background |
| [`sdks/python/chio-hermes`](../../../sdks/python/chio-hermes) | the path itself | f5566d9a76, 2026-09-03 | Read at main | background |
| [`sdks/python/chio-hermes/README.md`](../../../sdks/python/chio-hermes/README.md) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`sdks/python/chio-hermes/src/chio_hermes/hooks.py`](../../../sdks/python/chio-hermes/src/chio_hermes/hooks.py) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02, 04, 06, 07 |
| [`sdks/python/chio-langchain`](../../../sdks/python/chio-langchain) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`sdks/python/chio-sdk-python/src/chio_sdk/client.py`](../../../sdks/python/chio-sdk-python/src/chio_sdk/client.py) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 04 |
| [`sdks/typescript/chio-ts/src/invariants/receipt.ts`](../../../sdks/typescript/chio-ts/src/invariants/receipt.ts) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |
| [`tests/bindings/vectors`](../../../tests/bindings/vectors) | the path itself | f5566d9a76, 2026-09-03 | Read at main | 02 |

### Files on unmerged branches

| File | Branch and commit | Status | Used in |
|---|---|---|---|
| `docs/integrations/acceptance/20260909/PROGRAM.md` | PR #1156, `7059c71ca8` (2026-09-10) | Read on branch | 02 |
| `docs/strategy/chio-direction/19-priority-agent-integrations.md` | PR #1156, `7059c71ca8` (2026-09-10) | Read on branch | 02, 07 |
| `crates/kernel/chio-kernel/src/kernel/signing_authority.rs` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 07 |
| `crates/security/chio-active-response-authority` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 03 |
| `crates/security/chio-cage` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 03 |
| `crates/security/chio-cage/README.md` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 02, 05, 06, 07 |
| `crates/security/chio-quarantine` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 03 |
| `crates/security/chio-secret-broker` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 03 |
| `crates/security/chio-secret-broker/README.md` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 02 |
| `crates/security/chio-secret-broker/src/generic_https.rs` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 05, 06 |
| `crates/security/chio-secret-broker/src/generic_https/rustls_transport.rs` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 05, 06 |
| `docs/reviews/2026-09-15-pr-portfolio.md` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 06 |
| `docs/security/active-defense-rollout.md` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 02, 05 |
| `docs/security/launch-status.md` | PR #1160, `f928453692` (2026-09-26) | Read on branch | 02 |

### Releases and sibling repositories

| Source | Date | Status | Used in |
|---|---|---|---|
| [backbay-labs/chio prerelease: Agentic OS application runtime preview](https://github.com/backbay-labs/chio/releases/tag/agentic-os-2026-09-10-9ffca8d6) | 2026-09-10 | VERIFIED | 02 |
| [backbay-labs/chio release v0.1.0](https://github.com/backbay-labs/chio/releases/tag/v0.1.0) | 2026-09-09 | VERIFIED | 02, 03 |
| [backbay-labs/chio-bridge PR #1](https://github.com/backbay-labs/chio-bridge/pull/1) | not documented | VERIFIED | 06 |
| [backbay-labs/chio-claude-code-plugin PR #1](https://github.com/backbay-labs/chio-claude-code-plugin/pull/1) | not documented | VERIFIED | 06 |
| [backbay-labs/chio-claude-code-plugin repository](https://github.com/backbay-labs/chio-claude-code-plugin) | pushed 2026-09-10 | VERIFIED | background |
| [backbay-labs/chio-codex-plugin PR #1](https://github.com/backbay-labs/chio-codex-plugin/pull/1) | not documented | VERIFIED | 06 |
| [backbay-labs/chio-cursor-plugin PR #1](https://github.com/backbay-labs/chio-cursor-plugin/pull/1) | not documented | VERIFIED | 06 |
| [backbay-labs/chio-open-claw-plugin PR #1](https://github.com/backbay-labs/chio-open-claw-plugin/pull/1) | not documented | VERIFIED | 06 |
| [backbay-labs/chio-pi-plugin PR #1](https://github.com/backbay-labs/chio-pi-plugin/pull/1) | not documented | VERIFIED | 06 |
| [backbay-labs/hush at 6ca599c (pinned commit)](https://github.com/backbay-labs/hush/tree/6ca599ca8322a7cae6050086718ed5f3417c97e1) | committed 2026-09-23 | VERIFIED | 02 |
| [backbay-labs/hush release v1.0.0 (HushSpec)](https://github.com/backbay-labs/hush/releases/tag/v1.0.0) | 2026-09-23 | VERIFIED | 02, 07 |
| [bb-connor/arc prerelease: Chio enterprise evidence verifier c5a9a75e1](https://github.com/bb-connor/arc/releases/tag/security-evidence-verifier-c5a9a75e1) | 2026-07-26 | VERIFIED | 02 |
| [bb-connor/arc release v0.1.0](https://github.com/bb-connor/arc/releases/tag/v0.1.0) | 2026-04-22 | VERIFIED | 02, 03 |
| [chio-claude-code-plugin: hooks/pretooluse.mjs (at 65ac839)](https://github.com/backbay-labs/chio-claude-code-plugin/blob/65ac8390c57a5292c055fba50caa1aafbd915848/hooks/pretooluse.mjs) | pushed 2026-09-10 | VERIFIED | 05, 07 |
| [chio-claude-code-plugin: scripts/sandbox.mjs (at 65ac839)](https://github.com/backbay-labs/chio-claude-code-plugin/blob/65ac8390c57a5292c055fba50caa1aafbd915848/scripts/sandbox.mjs) | not documented | VERIFIED | 06 |
| [chio-pi-plugin: src/protected-cli.ts (at cd3dbf9)](https://github.com/backbay-labs/chio-pi-plugin/blob/cd3dbf90974687d30f23f989173bd8c155b016d3/src/protected-cli.ts) | not documented | VERIFIED | 06 |
| [HushSpec `LICENSE`](https://github.com/backbay-labs/hush/blob/6ca599ca8322a7cae6050086718ed5f3417c97e1/LICENSE) | committed 2026-09-23 | VERIFIED | 02 |
| [HushSpec `spec/versioning.md`](https://github.com/backbay-labs/hush/blob/6ca599ca8322a7cae6050086718ed5f3417c97e1/spec/versioning.md) | committed 2026-09-23 | VERIFIED | 02 |
| [HushSpec `spec/registries/rule-blocks.yaml`](https://github.com/backbay-labs/hush/blob/6ca599ca8322a7cae6050086718ed5f3417c97e1/spec/registries/rule-blocks.yaml) | committed 2026-09-23 | VERIFIED | 02 |

## Local test of OpenShell v0.1.2

Documents [01](01-nvidia-stack.md), [04](04-integration-design.md), [06](06-strategy-and-roadmap.md), and [07](07-ideas-backlog.md) label behavior seen in this test "VERIFIED, local test" (01 writes "VERIFIED (local test)"). The scripts, policies, prototype code, and retained results are published in [spike/](spike/README.md), which also explains how to run them again.

### Setup

| Component | Version or setting |
|---|---|
| Host | One aarch64 host with 12 cores. Only the Docker driver was run; the host had no Podman, no `/dev/kvm`, and no Kubernetes cluster. |
| Date | 2026-09-29 |
| OpenShell | v0.1.2 (tag `6648bd0`, release published 2026-09-28): gateway with the Docker driver and supervisor image `ghcr.io/nvidia/openshell/supervisor:0.1.2` |
| Gateway configuration | [`spike/gateway/gateway.toml`](spike/gateway/gateway.toml): two supervisor middleware registrations over plaintext gRPC with `allow_insecure_transport`, each with a 500 ms timeout |
| Chio prototype middleware | [`spike/middleware/chio_mw.py`](spike/middleware/chio_mw.py), Python, using the Chio Python SDK in [`sdks/python/chio-py`](../../../sdks/python/chio-py) for canonical JSON |
| Chio MCP edge | `chio mcp serve-http` from a chio-cli 0.1.0 binary built on 2026-09-05; it accepts MCP revision 2025-11-25 only. It wrapped [`spike/edge/wrapped_server.py`](spike/edge/wrapped_server.py) under [`spike/edge/policy.yaml`](spike/edge/policy.yaml). |
| NVIDIA middleware example | Rust content-guard example from OpenShell [`examples/supervisor-middleware-content-guard`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard), registered as `content-guard-example` |
| Built-in middleware | `openshell/regex` |
| Clients inside the sandbox | Claude Code 2.1.284 and Codex 0.158.0 from npm; Python probes [`spike/client/probe.py`](spike/client/probe.py) and [`spike/client/probe2.py`](spike/client/probe2.py) |

### Published artifacts

| File | Contents | Recorded (UTC) | Used in |
|---|---|---|---|
| [`spike/results/ocsf.jsonl`](spike/results/ocsf.jsonl) | 58 OCSF 1.8.0 events from sandbox `chio-spike-1` during an MCP probe sequence | 2026-09-29 05:20:55 to 05:20:56 | 04 |
| [`spike/results/bench2.jsonl`](spike/results/bench2.jsonl) | Latency matrix for five policy variants at 1,000 bytes, 64 KiB, and 1 MiB; the no-middleware variant ran first and last | 2026-09-29 08:09:35 to 08:10:53 | 04 |
| [`spike/results/bench.jsonl`](spike/results/bench.jsonl) | An earlier latency run whose lines record neither the middleware variant nor a time | not recorded | background |
| [`spike/results/q5_events.txt`](spike/results/q5_events.txt) | Policy revisions 14 to 19 submitted while requests ran | 2026-09-29 08:19:15 to 08:20:25 | background |
| [`spike/results/q5_policy_list.json`](spike/results/q5_policy_list.json) | All 19 policy revisions of sandbox `chio-spike-2` with created and loaded times | 2026-09-29 08:09:05 to 08:20:05 | 04 |
| [`spike/results/q7_restart_events.txt`](spike/results/q7_restart_events.txt) | Middleware kill, restart, and end of the request loop | 2026-09-29 07:58:25 to 07:58:52 | 04 |

### Logs not published

These logs from the same runs were not published. Findings that rest only on them are labeled "VERIFIED, local test" without a link.

| Log | What it recorded |
|---|---|
| `mw.jsonl`, `mw2.jsonl` | Every middleware request evaluation and response preflight: header names, `request_id`, `originating_process` presence (absent in all 3,934 request evaluations and 5,321 response preflights), the `policy_ref` value per request, and time spent inside the middleware |
| `receipts2.jsonl` | Receipts the prototype signed, including allow receipts for five requests that timed out and never reached the upstream |
| `q1_hdr_baseline.jsonl`, `q1_toksize_guarded.jsonl`, `q1_toksize_baseline.jsonl` | Header names seen upstream, and requests carrying 1, 10, and 40-link capability tokens (the 40-link token was 20,776 bytes) |
| `q2_sweep_rest_guarded.jsonl`, `q2_sweep_mcp_default.jsonl`, `q2_sweep_mcp_big.jsonl`, `q2_mcp_probe_v2.jsonl` | Request body size sweeps up to and past 4 MiB, and MCP probes with argument checks |
| `q5_loop.jsonl` | The request loop that ran while `q5_switch.sh` switched policies |
| `q7_restart.jsonl`, `q7_crash.jsonl`, `q7_conc120.jsonl` | Fail-closed runs: middleware kill and restart, a crash mid-request, and 120 concurrent requests against a 400 ms service |
| `capture.jsonl`, `codex_exec.out`, `lenient.jsonl` | Codex requests captured by `spike/edge/capture_proxy.py` in front of the Chio edge, the Codex error output, and a log cited for MCP revision handling |
| `gateway-mwdown.log` | Gateway start with the Chio middleware unreachable |

Supervisor Docker log lines and a wire capture of Claude Code's requests were not retained.
