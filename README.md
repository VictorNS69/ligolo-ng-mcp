# Ligolo-ng MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[ligolo-ng](https://github.com/nicocha30/ligolo-ng) — pivoting and lateral
movement in authorized security assessments.

Every tool is a call against the ligolo **proxy's authenticated REST control
plane**. No SSH, no tmux, no scraping the readline console.

```
MCP client ──stdio──> ligolo-ng-mcp ──HTTP /api/v1──> ligolo proxy ──TLS──> agent
                                              │
                                              └─ scope_check.py (lateral checkpoint)
                                              └─ log_command.sh (audit trail)
```

## Why this fork

The upstream repository this fork started from (schwarztim/sec-ligolo-ng-mcp) declared
19 tools and implemented three log greps. Measured against proxy 0.9.1:

| Tool | Original behaviour |
|---|---|
| `ligolo_proxy_start` | `ssh kali "nohup ligolo-proxy …"` — wrong binary name (upstream ships `proxy`) |
| `ligolo_session_select` | returned the prose "Session selection requires interactive access" |
| `ligolo_tunnel_start` / `_stop` | returned "run in the ligolo-ng console: tunnel_start" |
| `ligolo_listener_add` / `_list` / `_delete` | returned the command for a human to type |
| `ligolo_agent_info` | told the caller to run `ifconfig` |
| `ligolo_send_command` | suggested `screen -r` |
| `ligolo_agents_list` | `grep` over `/tmp/ligolo-proxy.log` |

The architecture could not work even after fixing typos: the proxy console is a
readline TUI, its `session`/`autoroute` steps are interactive overlays, and each
tool call was a fresh `ssh` process, so console state was lost between calls.

The tool *surface* was sound, though, so this fork keeps all 19 names and
replaces the internals: the proxy has shipped an authenticated REST API since
v0.8 (`POST /api/auth` → JWT, then `/api/v1/…`) that expresses the same
operations without a terminal. Two tools changed meaning, and two gained
required parameters — see [Breaking changes](#breaking-changes).

## Requirements

- Node.js 20+
- a ligolo-ng release (proxy **and** agent) — this fork is tested against
  **proxy 0.9.1/0.9.2**. Nothing is vendored: point `LIGOLO_NG_DIR` at the
  directory holding `proxy`, or set `LIGOLO_PROXY_BIN`.
- privileges to create a TUN interface for the proxy (the agent needs none)
- to use the checkpoint gate: a BITORIA checkout (`scripts/common/scope_check.py`)

## Install

```bash
git clone git@github.com:VictorNS69/ligolo-ng-mcp.git
cd ligolo-ng-mcp
npm install
npm run build
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LIGOLO_NG_DIR` | — | directory holding `proxy` / `agent` (`…/linux/proxy` also probed) |
| `LIGOLO_PROXY_BIN` | — | explicit path to the proxy binary |
| `LIGOLO_API` | `http://127.0.0.1:8080` | proxy REST API base URL |
| `LIGOLO_USER` | `ligolo` | API user (proxy config `web.users`) |
| `LIGOLO_PASSWORD` | — | API password; if unset, `ligolo_proxy_start` generates one |
| `LIGOLO_TOKEN` | — | pre-minted JWT instead of user/password |
| `LIGOLO_INTERFACE` | `ligolo` | default TUN interface name |
| `LIGOLO_PROXY_ADDR` | `0.0.0.0:11601` | agent-facing listen address |
| `LIGOLO_API_LISTEN` | `127.0.0.1:8080` | API listen address written into a seeded config |
| `LIGOLO_PROXY_CONFIG` | `./ligolo-ng.yaml` | proxy config; keep it in a workspace, not a repo root |
| `LIGOLO_SELFCERT_DIR` / `LIGOLO_SELFCERT_DOMAIN` | `./ligolo-selfcerts` / `ligolo` | where `-selfcert` caches its cert (fingerprint source) |
| `LIGOLO_ASSESSMENT` | — | assessment name/path for the gate; falls back to `state/assessment-scope.json` |
| `LIGOLO_BITORIA_ROOT` | auto-detected | framework checkout owning `scripts/common/scope_check.py` |
| `LIGOLO_MCP_READ_ONLY` | off | `1` registers only the 9 read-only tools |

Generated credentials land in `.ligolo-mcp-credentials` (mode 0600) next to the
proxy config, so registering the server never needs a secret in its config.

### Registering it

```json
{
  "mcpServers": {
    "ligolo": {
      "command": "node",
      "args": ["/path/to/ligolo-ng-mcp/dist/index.js"],
      "env": {
        "LIGOLO_NG_DIR": "/opt/ligolo-ng",
        "LIGOLO_API": "http://127.0.0.1:8080",
        "LIGOLO_PROXY_CONFIG": "/path/to/workspace/ligolo-ng.yaml"
      }
    }
  }
}
```

## The lateral-movement gate

`ligolo_tunnel_start`, `ligolo_route_add` and `ligolo_listener_add` make
something newly reachable, so each one runs
`scripts/common/scope_check.py <target> --assessment <A> --technique lateral --checkpoint`
**before** the HTTP request leaves the process:

- exit 0 → the call proceeds, and is appended to `<assessment>/logs/commands.log`
- exit 5 → returns `{"error": "checkpoint-denied", "action_taken": false}` and
  nothing is sent to the proxy. Record the pivot in `state/decisions.md`, get
  human approval, then re-call with `target` + `confirmed: true`

`target` is the in-scope host the action makes reachable. For a route wider than
`/32` it is required explicitly — "visible in `ifconfig`" is not authorization.

Cleanup tools (`*_delete`, `ligolo_teardown`, `ligolo_tunnel_stop`) are logged
but not checkpointed: reversing a pivot is not a new reachability transition.

## Tools

Read-only (always registered):

| Tool | What it does |
|---|---|
| `ligolo_proxy_status` | API liveness (`/ping`), pid, binary, config and log paths |
| `ligolo_agents_list` | agents with name, session id, tunnel state, and full NIC/address list |
| `ligolo_session_select` | resolve one agent id (compatibility name; there is no persistent selection) |
| `ligolo_agent_info` | one agent's interfaces (or all, if no id given) — replaces `ifconfig` |
| `ligolo_interface_list` | TUN interfaces with routed destinations and active state |
| `ligolo_route_list` | flattened routes per interface |
| `ligolo_listener_list` | listeners: agent, listen addr, redirect addr, network, online |
| `ligolo_certificate_fingerprint` | SHA-256 of the cached selfcert, in `-accept-fingerprint` form |
| `ligolo_agent_command` | agent command line, fingerprint-pinned by default |

Mutating (hidden with `LIGOLO_MCP_READ_ONLY=1`):

| Tool | Gate |
|---|---|
| `ligolo_proxy_start` | starts the proxy headless with a seeded loopback-API config |
| `ligolo_proxy_stop` | SIGTERM via pid file |
| `ligolo_interface_create` | none (local TUN only) |
| `ligolo_tunnel_start` | **lateral checkpoint** — creates the interface first if unregistered |
| `ligolo_tunnel_stop` | none (cleanup) |
| `ligolo_route_add` | **lateral checkpoint** |
| `ligolo_route_delete` | none (cleanup) |
| `ligolo_listener_add` | **lateral checkpoint** — also a resident artifact, log it in `cleanup-pending.md` |
| `ligolo_listener_delete` | none (cleanup) |
| `ligolo_teardown` | none (cleanup) — listeners → routes → tunnel → interface |

## Breaking changes

- `ligolo_send_command` is **removed**. It existed to type into the console;
  against the API there is nothing to send. `ligolo_teardown` replaces it.
- `ligolo_session_select` no longer selects anything. It resolves an agent id
  and returns its record; every other tool takes `agentId` explicitly.
- `ligolo_tunnel_start` now requires `agentId`; `ligolo_tunnel_stop`,
  `ligolo_listener_add` and `ligolo_listener_delete` gained `agentId`.
- `ligolo_listener_add` gained `network` (default `tcp`) — the proxy rejects the
  request without it (`{"error":"input error"}`).
- `ligolo_route_add` requires `target` for anything wider than `/32`.
- Reachability-changing tools return `{"error":"checkpoint-denied"}` when no
  assessment is active. That is intentional, not a misconfiguration.
- `ligolo_agent_command` pins the fingerprint and no longer defaults to
  `-ignore-cert`; `debugIgnoreCert: true` restores the old behaviour with a warning.

## Testing

```bash
npm test          # 19 tests: gate, teardown ordering, payload shapes, pinning
```

The suite drives the built server over real MCP stdio against a stub proxy API,
so it needs no ligolo binary and no root. A live smoke test against a real proxy
plus a local agent is worth running before an engagement:

1. `ligolo_proxy_start` → note `fingerprint`
2. run the agent on the foothold with `-connect <operator>:11601 -accept-fingerprint <fp>`
3. `ligolo_agents_list` → `ligolo_tunnel_start` (`target`, `confirmed`) → `ligolo_route_add`
4. scan through the TUN, then `ligolo_teardown` and delete the agent binary

## Security notes

- The API is a control plane for offensive tooling: bind it to loopback and
  keep `web.secret`/`web.users` in the proxy config, not in shell history.
- The proxy reads `Authorization` **raw**; a `Bearer ` prefix returns 401.
- `-ignore-cert` is debug-only. The fingerprint comes from the proxy's own
  cached selfcert, so no console round-trip is needed to pin it.
- Nothing here uploads, deletes, or cleans up the agent binary on a client
  host — that stays an explicit step, logged at upload time.

## License

MIT. Original work © 2025 schwarztim; fork © 2026 Víctor Nieves.
Authorized testing only.
