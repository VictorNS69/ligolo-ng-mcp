# Changelog

Fork of [`schwarztim/sec-ligolo-ng-mcp`](https://github.com/schwarztim/sec-ligolo-ng-mcp)
(MIT). Versions below are this fork's; `1.0.0` is the upstream initial release it
started from.

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

### Tests

22 tests over real MCP stdio against a stub proxy API: gate denial leaves the
API untouched, confirmed calls carry the expected payloads, teardown ordering,
fingerprint equality, credential seeding, port override, and marker resolution
with its TTL.
