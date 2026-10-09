# iroh-blobs 0.103.0 to 0.103.1 source delta audit

The complete twelve-file published delta was reviewed for safe-to-deploy. The
existing 0.103.0 exemption is unchanged; this is a delta audit, not a full
baseline certification. No exemption is added.

Registry archive SHA-256:

- Base: 5be50b0e2d0a9ba65cee4e0dfb708b3704e02ad12bd4c14c6307e94245943126
- Target: a3148ad01585eb6b7cfb641e4100564f4f56db644f4cbed8c10ab2478663161f

Exact source revisions are e82cbdcbdac9a78033174aad55e3199b2cf4c0dc and
7a4c53a45ecd2bbbb5dd86b3639271004ae89d39. The registry has no public yank
message; attributing the yank to the patch's security defect is an inference.

The [provider repair](https://github.com/n0-computer/iroh-blobs/pull/270) selects
the request type's own EventMask permission. Disabled default/read-only Push
refuses before store import. Get is unchanged. Custom policies must explicitly
configure get-many and observe; Chio's default provider settings are unchanged.

Other production changes log provider/store errors and replace checked 32-byte
hash conversion with equivalent safe array iteration. All constructors preserve
the multiple-of-32 invariant. No unsafe code, public API, runtime dependency,
feature, allocation or MSRV change is introduced. The byte-identical build script
requires cfg_aliases 0.2.2 and emits the existing wasm-browser alias. Example
permission opt-ins, all test changes, and the complete development lock delta
were reviewed; the latter is not copied into Chio.

Consumer locks keep Iroh 1.0.1 and gossip 0.101.0, changing only blobs 0.103.1 and
cfg_aliases 0.2.2. The latter has genuine Mozilla 0.2.1 to 0.2.2 delta coverage
through reviewed Cargo Vet imports.

Runtime qualification remains required: pair negative Push tests with healthy
Push/Get controls and a mutation restoring get-only dispatch. Upstream standalone
tests use Iroh 1.0.0, so Chio transport checks remain separate.

[Observe mode](https://github.com/n0-computer/iroh-blobs/pull/271) is an allowed
metadata subscription outside this patch. Provider concurrency/lifetime bounds
remain a separate inherited acceptance for callers mounting the public blob
helper. The shipped CLI mounts the bounded pheromone lane. This audit does not
claim complete provider isolation or lane-e resource qualification.
