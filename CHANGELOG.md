# Changelog

Fork of [`schwarztim/sec-ligolo-ng-mcp`](https://github.com/schwarztim/sec-ligolo-ng-mcp)
(MIT). Versions below are this fork's; `1.0.0` is the upstream initial release it
started from.

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
  Previously every mutating tool refused unless a BITORIA checkout and an
  assessment were present, which made the server unusable outside that framework.
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
  `scripts/common/scope_check.py <target> --assessment <A> --technique lateral --checkpoint`
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
- Assessment resolution via `state/assessment-scope.json`, mirroring the
  framework's own marker and 12h TTL; expired/invalid markers are treated as no
  assessment.
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
