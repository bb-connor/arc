# Required integrations: source handoff

Observed 2026-10-08 UTC. Source identity confidence is high; no agent/model calls,
installs or runtime qualification were executed. The user's required scope is
specified in [FIRST-CLASS-INTEGRATIONS](../FIRST-CLASS-INTEGRATIONS.md).
The [observation record](required-harness-source-observation.json) retains live
public responses, exact commits, archive/lock and selected file hashes.

The published [Megastart archive](https://www.chio.computer/examples/megastart.zip)
already prepares Claude Code, Codex, Pi and Hermes through their actual restricted
launchers. Its Herdr plugin operates the application-owned mission. These are
the adoption paths to extend. Mini-swe was overrepresented because an earlier
sealed-coding proposal reused its concrete runner/capture/recovery code, not
because it was a demonstrated user preference or necessary kernel architecture.
Existing implementation detail is not a product-priority argument.

## Concrete owner and evidence matrix

| Consumer | Inspected public source and existing entrypoints | Source behavior and remaining acceptance |
| --- | --- | --- |
| Claude Code | Public main `65ac8390c57a5292c055fba50caa1aafbd915848`: `.claude-plugin/plugin.json`, `hooks/pretooluse.mjs`, `scripts/{restricted,sandbox,gateway-http}.mjs`. [RC5](https://github.com/backbay-labs/chio-claude-code-plugin/blob/65e3f6639b7cc3fa6e6090304e1ef7b9f8da2047/acceptance/2026-10-05/rc5/REPORT.md) adds `src/control/service.ts`, `src/workflow/` and `src/bridge-internals/` controls. | Hooks and native Mods alone do not confine ordinary Bash/files. The separate restricted launcher owns the selected protected path. RC5 records `productionQualified:false`; scoped host fixtures are not session/recovery/cold-install qualification. Adapt these existing controls and launcher to the selected native owners; preserve request identity and action binding. |
| Codex | Public main `deefb3a85001ee47a22fcfbb43ab6749c4944004`: `.codex-plugin/plugin.json`, `hooks.json`, `src/hooks/`, `src/cli/{restricted,sandbox,modelRelay}.ts`; [restricted contract](https://github.com/backbay-labs/chio-codex-plugin/blob/deefb3a85001ee47a22fcfbb43ab6749c4944004/RESTRICTED.md). | Actual hook failure/omission tests permit native effects. Restricted mode uses fixed Chio MCP tools, disables alternate host facilities and retains parent-owned relay/gateway/journal/credentials. Native `apply_patch` remains listed under a read-only effect boundary. Historical macOS work/recovery evidence is scoped to Codex 0.153.4 and its exact tuple; new native profiles need fresh I01-I08. |
| Pi | Public main `4214a5a8ddec776a5ff9ec78007442683fd8df03`: `src/{extension,session,protected-cli,tool-registry,pi-governance,run-limits,linux-sandbox,linux-guest,durable,continuation}.ts`, `src/coding-resource/participant.ts`; [feature crosswalk](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/ROADMAP-IMPLEMENTATION.md). | Public source 0.2.0/Pi 1.0.2 differs from frozen 0.1.0/Pi 0.85.1 evidence. Native extension/session/coding-resource/Durable entrypoints are concrete reuse surfaces; delegation interfaces do not yet launch children. New component, stock-host and confinement results are not live-provider/live-kernel qualification. Linux arm64 outer-container fixtures do not qualify native x64 or normal Docker defaults. |
| Hermes | Public Chio `6753edbc365f5ea820224b96a59940feedbfca94`, `sdks/python/chio-hermes/`; `src/chio_hermes/{restricted.py,gateway_transport.py,gateway_runner.mjs,model_relay.py,host_supervisor.py,hooks.py,plugin.py,handlers.py}`; [source README](https://github.com/backbay-labs/chio/blob/6753edbc365f5ea820224b96a59940feedbfca94/sdks/python/chio-hermes/README.md). | Use the existing `chio-hermes-restricted` CLI/package. Later restricted 0.1.2 source exists at PROGRAM-MAP F; a legacy default-checkout hook package is not equivalent. Restricted launch keeps Hermes 0.20.5 at `175054c14b54404663d8614a178280cffe6062eb`, fixed tools and separately held relay/resource custody. Historical installed useful-work/recovery results retain unresolved overall acceptance/publication. One-shot execution does not establish interactive PTY support. |
| Herdr/Megastart | Archive `herdr/{herdr-plugin.toml,CONTRACT.md,src/client.rs,src/main.rs,src/ui.rs}` and `src/{operator.rs,authority.rs,agents/launcher.rs,agents/connections.rs,agents/hermes.rs,agents/mission.rs}`. Plugin id `chio.megastart`, version 0.1.0, minimum Herdr 0.9.0. | An application client, not a fifth inference runtime. Existing v1 state/events/action routes retain app ownership. Closing the pane preserves the detached mission; gaps re-read state and lost mutation replies are not retried automatically. The client manifest declares macOS/Linux, while native mission setup requires Apple Silicon macOS. Neither declaration establishes the new platform/harness matrix. |

The local Codex and Pi root checkouts lag their public mains. Always select exact
owner source and compatible built artifacts, rather than treating a local branch
name as the current integration contract. Current candidate source may be more
capable than the packaged example, but silently updating example pins invalidates
the evidence associated with those bytes.

## Published example pins

Fresh archive: 335069 bytes, 59 members, SHA-256
`9dcbecec5bf9681c301ffd0bf7a2eeea685ec8b8b5911ac180692f66cf292050`.
The observation records both Cargo locks and selected source hashes.

- `Cargo.toml` pins public Chio `6753edbc365f5ea820224b96a59940feedbfca94`.
- `src/agents/connections.rs` pins Claude plugin `65ac8390c57a5292c055fba50caa1aafbd915848`
  (0.3.1-rc.1), Codex plugin `deefb3a85001ee47a22fcfbb43ab6749c4944004`
  (0.3.0), and Pi plugin `cd3dbf90974687d30f23f989173bd8c155b016d3` (0.1.0).
- Claude host is 2.1.267, Codex host is 0.153.4 darwin-arm64, and the Hermes
  source pin above is 0.20.5. `connections.rs` and `hermes.rs` bind their concrete
  host/launcher/bridge digests and isolated build dependencies.
- `src/agents/launcher.rs` selects Claude `scripts/restricted.mjs`, Codex
  `restricted`, Pi `dist/protected-cli.js`, or installed `chio-hermes-restricted`.
  Herdr consumes the resulting application state; it does not replace the agents.

The archive is publicly retrievable. In the bounded current availability check,
the three plugin repositories' GitHub release/tag lists were empty; the inspected
npm package names and PyPI `chio-hermes` returned 404. Public source, a checked-in
version, source installation and registry distribution are distinct. These are
timestamped observations, not permanent availability claims or instructions to
publish new packages during this specification work.

## Implementation consequences

Extend the actual plugin, session, launcher, resource and Herdr owners above.
Retain each harness's workflow and user-facing controls, while using qualified
native owners for authority, credentials, effects, resource accounting and
original-operation recovery. Ordinary plugin/native UI surfaces can expose useful
diagnostics while explicitly remaining unprotected; they cannot qualify a
protected release through labeling.

H01-H08 require installed work, denied alternatives, lifecycle, same-harness and
mixed-harness composition, and independent Herdr compatibility. A same-process Pi
fixture is not cross-harness recovery; a mixed Megastart recording does not pass
every host's I01-I08. Target passports, recursive delegation, swarm and accepted
work features additionally consume their actual owner/capability gates. Missing
native ports or owner contracts remain explicit delivery work, never replacement
by mini-swe, mock evidence or a new platform-private authority.
