# Changelog

Fork of [`schwarztim/sec-ligolo-ng-mcp`](https://github.com/schwarztim/sec-ligolo-ng-mcp)
(MIT). Versions below are this fork's; `1.0.0` is the upstream initial release it
started from.

## 3.0.0 — 2026-11-11

### Security (breaking)

- **`ligolo_route_add` now gates the routed network, not only `target`.** The
  whole `network` must fit inside a single `LIGOLO_SCOPE` entry, and `target`
  must lie inside that network; otherwise the call is refused with
  `checkpoint-denied`, `exit_code: 3`, before anything is sent. Previously one
  in-scope host authorized a route of any width — with
  `LIGOLO_SCOPE=10.10.10.5`, `0.0.0.0/0` passed the gate. Migration: route the
  ranges you are authorized for, or list the wider range in `LIGOLO_SCOPE`
  deliberately.

### Changed

- IPv6 scope entries are range-matched (`fd00::/64` covers `fd00::1`); they
  used to match only the exact string, so IPv6 routes could never pass the
  new network check.
- IPv4 octets with leading zeros (`010.0.0.1`) are rejected by the scope
  matcher: other parsers read them as octal, so the gate could disagree with
  the tool that later uses the address.

### Fixed

- `ligolo_teardown` and `ligolo_tunnel_stop` refuse a call without `agentId`
  before touching the proxy. Teardown used to delete the interface's routes,
  then fail on `DELETE /api/v1/tunnel/` and leave the agent's listeners in
  place — half a cleanup.
- CI: `npm test` runs `node --test test/*.test.mjs`; `node --test test/`
  failed on Node 22/24, which treat arguments as globs.

## 2.0.0 — 2026-11-11

### Removed (breaking)

- **Framework mode is gone; `LIGOLO_SCOPE` is the only authorization.** The
  server no longer looks for an external scope-check script, reads another
  tool's assessment file, per-assessment flag or active-assessment marker, or
  appends to an external command log. The two old framework environment
  variables are ignored. Migration: set `LIGOLO_SCOPE` to the hosts/CIDRs you
  are authorized to reach; the gate (target in scope + `confirmed: true`,
  exit 3/4/5) is unchanged.
- Proxy logs always go to `<workspace>/ligolo[<n>].log` (previously the
  assessment's state tree when one was active).
- Tool texts no longer refer to `state/decisions.md`, `state/hosts.md` or
  `state/cleanup-pending.md`; the listener `cleanup` hint reads "Track for
  cleanup: …".

### Fixed

- **`LIGOLO_PASSWORD` / `LIGOLO_USER` now win over `.ligolo-mcp-credentials`**
  for every instance, as the README always said. The credentials file used to
  win once an instance was running, so a password changed in the environment
  was silently ignored. Without the environment variables, each instance still
  uses its own credentials file.
- **`ligolo_teardown` now removes IPv6 routes.** It skipped every destination
  containing `:`, so an IPv6 route added through the MCP survived teardown. It
  now skips only ligolo's own `fe80::/64` link-local routes, which the proxy
  adds on each tunnel start (two of them after a restart, seen in the lab).

### Documentation

- README and USAGE rewritten around `LIGOLO_SCOPE` as the authorization: the
  server is self-contained and needs no external framework. USAGE gains the
  double-pivot lesson from the lab (one interface per agent, never start a
  second tunnel on a running agent). Stale details fixed
  (`ligolo-proxy.log` and the pid file no longer exist; logs are
  `<workspace>/ligolo[<n>].log`), credential precedence spelled out, including
  the `401` after changing a password on an existing config.

## 1.5.0 — 2026-11-11

### Added

- **Observer WebUI (`LIGOLO_WEBUI=1`).** Agents drive the pivot through the MCP;
  a human watches it live in ligolo's own WebUI, served on the same loopback API
  listener. Seeds `web.enableui: true`, `corsallowedorigin` and a separate
  `web.users` entry (`LIGOLO_WEBUI_USER`, default `operator`). `ligolo_proxy_start`
  and `ligolo_proxy_status` return `webui: {enabled, url, login, note}`.
  Refused, before anything is written, on a non-loopback listener, without
  `LIGOLO_WEBUI_PASSWORD`, or when the human user equals `LIGOLO_USER`. The
  human password is never generated, returned, or written to
  `.ligolo-mcp-credentials`. Verified live against proxy 0.9.1.
- **Origin of proxy state.** A per-instance ledger
  (`.ligolo-mcp-ledger.json`) records what this server created. Route,
  interface and listener lists carry `origin: "mcp" | "external"`;
  `ligolo_agents_list` carries `tunnel_origin`; `ligolo_proxy_status` reports
  `outside_mcp` (external state, and MCP-made state removed elsewhere).

### Fixed

- **Read-only mode only hid the mutating tools.** With `LIGOLO_MCP_READ_ONLY=1`
  they were missing from `tools/list`, but a client calling `ligolo_route_add`
  by name still ran the gate and reached the proxy API. Dispatch now accepts
  only registered tools and answers `not available: this server runs read-only`.
- **`apiPort` on `ligolo_proxy_start` was read but never declared**, so the
  unknown-argument check rejected every call that passed it.
- **No second proxy over one that already answers.** If the planned API port
  was served by a proxy this server did not start, `ligolo_proxy_start` spawned
  another one that could not bind, got its readiness "pong" from the other
  process, and recorded the doomed child's pid as a managed instance. It now
  reports the running proxy (`managed: false`, nothing spawned), and refuses
  with a clear message when the port answers with an HTTP error.
- **A recycled pid is no longer treated as our proxy.** A manifest entry whose
  pid had been reused by an unrelated process counted as live, and
  `ligolo_proxy_stop` would SIGTERM that process. On Linux the entry must match
  the proxy's `-config <path>` in `/proc/<pid>/cmdline`.
- **`LIGOLO_API` defaults to `LIGOLO_API_LISTEN`.** Setting only the listen
  address started the proxy there while status and unmanaged calls probed :8080.
- **A TUN device left by an earlier proxy gets an actionable error.** With
  `CAP_NET_ADMIN`, kernel TUNs outlive the proxy, and a fresh config then failed
  with `TUNSETIFF failed … device or resource busy`. The error now names the
  leftover device and how to remove it. Seen against proxy 0.9.1.

- **Found in a Docker double-pivot lab** (proxy 0.9.1 in a container,
  operator → pivot1 → listener → pivot2 → target):
  - `ligolo_tunnel_start` on an agent whose tunnel is already running on
    another interface is refused, and a repeat on the same interface is an
    `already_running` no-op. ligolo leaves the new TUN orphaned: after the next
    stop, the device stays held (`tun.New device or resource busy`) until the
    proxy restarts. Reproduced deliberately, twice.
  - That `busy` error now explains the cause and the way out (fresh interface
    name, or restart the proxy).
  - Interface names Linux rejects (over 15 bytes, whitespace, `/`) are refused
    by `ligolo_interface_create` and `ligolo_tunnel_start` before the proxy
    registers them. The proxy accepts any string and leaves a pending interface
    (`TUNSETIFF … invalid argument`).
  - For a proxy this server did not start, `apiUrl` and `webui.url` reported
    the planned listen address (`:8080`) instead of `LIGOLO_API`, sending the
    human to the wrong port.

### Changed

- `ligolo_listener_delete` on a listener that is already gone returns
  `already_absent: true` instead of an error, matching `ligolo_route_delete`.
- An existing config with the UI off is refused under `LIGOLO_WEBUI=1` until
  `rewriteConfig: true` (backup kept) or a manual edit.

## 1.4.0 — 2026-11-08

Field report from a five-host, four-hop pivot driven entirely through this
server (a docker double-pivot lab).
Every item below is a failure the run actually hit.

### Fixed

- **Unknown arguments are rejected instead of silently dropped.** A call with
  `listenAddr`/`redirectAddr` (this tool's real names are
  `localAddress`/`remoteAddress`) used to pass its `agentId`/`target` checks,
  send an empty listener address to the proxy, and come back as
  `HTTP 500: invalid listener addr: missing port in address` — a caller's typo
  reported as a server fault. Dispatch now validates the argument names against
  the tool's declared schema, lists the accepted ones, and suggests the nearest
  declared name for a plain typo (`localAdress` → `did you mean localAddress?`).
- **`ligolo_route_add` validates the CIDR before calling the API.**
  `{"network":"not-a-cidr"}` used to reach the proxy and return
  `POST /api/v1/routes -> HTTP 500: interface ligolo not found`, which named a
  different problem entirely and spent the scope gate on an impossible request.
  Now: `network "not-a-cidr" is not a CIDR — expected <address>/<prefix>`.
- **An already-present route is a success.** Routes outlive
  `ligolo_tunnel_stop`/`tunnel_start`, so the natural retry after a tunnel
  restart hit `HTTP 500: route <cidr> already exists` with `isError: true`.
  It now returns `already_present: true`, `scope_checked: true`, and the message
  `route <cidr> already present on <iface>`.
- **`ligolo_listener_add` reports every bad argument at once** and checks that
  `localAddress`/`remoteAddress` actually look like `host:port`. Previously a
  caller learned `target` was missing, fixed it, then learned `agentId` was bad,
  one round trip per problem.
- **`ligolo_interface_create` no longer claims to have created a device.** The
  call only registers the interface in the proxy's config; the reply now carries
  `registered: true`, `os_created: "unknown"` and a `hint` naming
  `ip -d link show <iface>` plus the `ip tuntap add` fallback. Previously
  `"message": "Interface ligolo created."` was returned on a host where no
  kernel device existed, and the gap only surfaced later at `tunnel_start`.

### Added

- **`ligolo_proxy_start {reuse: true}`** returns the instance already running
  instead of starting the next one. Without it, a retry (or a call after a
  timeout) silently started `ligolo2` on the next port with a new workspace and
  selfcert, leaving the caller with two proxies and two fingerprints.

### Tests

- `test/mcp.test.mjs`: the fake proxy now rejects duplicate routes like the real
  one, plus five cases for the behaviour above (unknown argument + typo
  suggestion, non-CIDR network, already-present route, aggregated listener
  arguments, registry-vs-device wording). 42 tests, all passing.

## 1.3.1 — 2026-11-07

### Security

- Dependency refresh: `@modelcontextprotocol/sdk` 1.25.3 → 1.32.2, which brings
  patched `express` 5.3.0, `hono` 4.13.17, `@hono/node-server` 2.1.6, `zod`
  4.6.7, `ajv` 8.20.0, `fast-uri` 3.1.9, `qs` 6.17.1, `path-to-regexp` 8.4.2 and
  `body-parser` 2.4.0. `npm audit` goes from **10 advisories (1 critical, 7
  high)** to **0**. Also `@types/node` 22.20.5.
- The upstream repository this fork came from has seven open Dependabot PRs, all
  transitive bumps inside the old SDK range (fast-uri, hono, @hono/node-server,
  path-to-regexp, ajv, qs, and SDK 1.25.3 → 1.26.0). Upgrading the one root
  dependency supersedes all seven; there is nothing to cherry-pick.
- `.github/dependabot.yml` (grouped, weekly npm / monthly actions) and a
  `.github/workflows/test.yml` gate so the next bump arrives with a test run
  rather than sitting unmerged.

## 1.3.0 — 2026-11-07

### Added

- **Standalone mode.** `LIGOLO_SCOPE` (comma-separated hosts/CIDRs) authorizes
  reachability-changing calls without any framework: target must be inside the
  list and the call must pass `confirmed: true`. Read-only tools need nothing.
  Previously every mutating tool refused unless an external framework checkout
  and an assessment were present, which made the server unusable outside it.
- The gate now has two explicit modes with stable exit codes: 3 = target outside
  `LIGOLO_SCOPE`, 5 = checkpoint not confirmed, 4 = no authorization source /
  assessment did not opt in.

### Changed

- **Framework mode requires the assessment to opt in**: `scope.yaml` must carry
  `ligolo:
  mcp: true`, asked at assessment setup and **off by default** (the
  same defaulting rule as the Burp MCP block). Without it, mutating tools refuse
  and name the console wrapper as the fallback.
- There is no `--force`, `LIGOLO_GATE=off`, or equivalent: the gate either has an
  authorization source or refuses.

## 1.2.0 — 2026-11-07

### Added

- **Multiple proxy instances.** `ligolo_proxy_start` with no instance starts
  `ligolo`, the next one starts `ligolo2`, and `{"instance": "ligolo3"}` names
  one explicitly. Each instance gets its own API and agent ports (first free
  after the configured ones), workspace (`<workspace>/ligolo<N>/`) with its own
  config, selfcert cache and credentials, pid, log, and manifest entry in
  `<workspace>/.ligolo-mcp-instances.json`.
- Every tool accepts an optional `instance` argument (default `ligolo`), because
  agent ids, routes and listeners are per-proxy.
- `ligolo_proxy_start` accepts `apiPort` alongside `port`.
- `ligolo_proxy_status` with no argument lists every live instance with API URL
  and log path; an externally started proxy is reported with `managed: false`
  plus a note, rather than as a stopped instance that is answering requests.

### Changed

- **Proxy logs moved into the assessment's state tree**:
  `assessments/<name>/state/ligolo.log`, then `ligolo2.log`, `ligolo3.log` per
  instance. Previously a single `<workspace>/ligolo-proxy.log`, which put
  engagement evidence in a scratch directory and made a second proxy overwrite
  the first's log. With no active assessment the file falls back to
  `<workspace>/ligolo[<n>].log`.
- `ligolo_proxy_stop` is per instance and prunes the manifest entry; dead
  entries are also pruned on the next start or status.

### Fixed

- `seedConfig` returned the seeded workspace's password only via a mutated
  config; it now returns it explicitly, so starting a second instance cannot
  authenticate with the first instance's credential.

## 1.1.0 — 2026-11-07

**Compatibility:** requires ligolo-ng proxy **0.9.x** (tested 0.9.1 and 0.9.2,
with the matching agent). The proxy's REST API is labelled experimental
upstream, so an upgrade may break these tools — see the warning at the top of
the README before bumping ligolo-ng.

Everything is now a call against the ligolo proxy's authenticated REST control
plane (`POST /api/auth` → JWT, then `/api/v1/…`). All 19 tool names are kept;
the internals are rewritten.

### Added

- Reachability-changing tools (`ligolo_tunnel_start`, `ligolo_route_add`,
  `ligolo_listener_add`) run
  an external scope-check script plus the per-assessment opt-in
  in-process before any HTTP request, and refuse with
  `{"error":"checkpoint-denied","action_taken":false}` when it denies.
- `log_command.sh` audit trail for every call (tool, arguments, target).
- `ligolo_teardown`: listeners → routes → tunnel → interface, tolerating routes
  the tunnel already removed.
- `ligolo_proxy_start` seeds a headless loopback-API config
  (`web.enabled: true`, `web.enableui: false`, empty `logfile`), generates a
  password when `LIGOLO_PASSWORD` is unset, and writes it to
  `.ligolo-mcp-credentials` (mode 0600).
- `LIGOLO_MCP_READ_ONLY=1`: registers only the 9 read-only tools.
- Assessment resolution for the (now removed) framework mode, with the same
  marker and 12h TTL; expired/invalid markers were treated as no assessment.
- Real agent interface/address data (`GET /api/v1/agents`), replacing the
  `ifconfig` console scrape.
- `port` parameter on `ligolo_proxy_start` to override the agent-facing port for
  one instance; `rewriteConfig` to re-seed an existing config (original kept as
  `.bak`).
- JSON error payloads for every failure, so a refused pivot is distinguishable
  from a transport error.

### Changed

- `ligolo_proxy_start` always selfcert, always headless, always API-enabled. It
  no longer takes `selfcert`, `apiPort`, `enableApi` or `daemonMode`.
- `ligolo_agent_command` pins `-accept-fingerprint` by default, reading the
  SHA-256 from the proxy's cached selfcert; `-ignore-cert` moved behind
  `debugIgnoreCert: true` with a warning.
- `ligolo_teardown` replaces the console `kill` for reversing a pivot.
- Proxy lifecycle is a local child process (pid file + `/ping` readiness)
  instead of `ssh <host> nohup ligolo-proxy`.

### Removed

- `ligolo_send_command` (console passthrough — nothing to send over the API).
- The per-call `ssh` transport, log greps, and `pgrep`-based status.

### Fixed

- `ligolo_listener_add` sends `AgentID` + `Network`; without both, the proxy
  answers only `{"error":"input error"}`.
- `ligolo_agents_list` returns real agents instead of grepping
  `/tmp/ligolo-proxy.log`.
- Route deletion happens before tunnel stop, so it no longer fails with
  `no such process`.
- `ligolo_proxy_start` uses the real binary name (`proxy`).

### Docs

- `USAGE.md` — the operational path: prerequisites, registration for both
  clients, an eight-step pivot with real request/response payloads, reverse
  shell via `listener_add`, agent-localhost `240.0.0.0/4`, double pivot,
  read-only mode, teardown discipline, what to do without the gate, how to read
  `checkpoint-denied` vs `failed`, and raw-API calls by hand.

### Tests

22 tests over real MCP stdio against a stub proxy API: gate denial leaves the
API untouched, confirmed calls carry the expected payloads, teardown ordering,
fingerprint equality, credential seeding, port override, and marker resolution
with its TTL.
