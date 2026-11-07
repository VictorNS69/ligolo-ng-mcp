# Ligolo-ng MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[ligolo-ng](https://github.com/nicocha30/ligolo-ng) — pivoting and lateral
movement in authorized security assessments.

Every tool is a call against the ligolo **proxy's authenticated REST control
plane**. No SSH, no tmux, no scraping the readline console.

```
MCP client ──stdio──> ligolo-ng-mcp ──HTTP /api/v1──> ligolo proxy ──TLS──> agent
                            │
                            ├─ scripts/common/scope_check.py  (lateral checkpoint, before any HTTP call)
                            └─ scripts/common/log_command.sh  (audit trail per call)
```

Contents: [Why this fork](#why-this-fork) · [Requirements](#requirements) ·
[Install](#install) · [Configuration](#configuration) · [Typical
flow](#typical-flow) · [The lateral-movement gate](#the-lateral-movement-gate) ·
[Tools](#tools) · [HTTP endpoints used](#http-endpoints-used) ·
[Breaking changes](#breaking-changes) · [Troubleshooting](#troubleshooting) ·
[Development](#development) · [Security notes](#security-notes)

## Why this fork

The repository this fork started from (`schwarztim/sec-ligolo-ng-mcp`) declared
19 tools and implemented three log greps. Built and driven over MCP stdio
against proxy 0.9.1, measured behaviour was:

| Tool | Original behaviour |
|---|---|
| `ligolo_proxy_start` | `ssh kali "nohup ligolo-proxy …"` — wrong binary name (upstream ships `proxy`) |
| `ligolo_session_select` | returned the prose "Session selection requires interactive access" |
| `ligolo_tunnel_start` / `_stop` | returned "run in the ligolo-ng console: tunnel_start" |
| `ligolo_listener_add` / `_list` / `_delete` | returned the command for a human to type |
| `ligolo_agent_info` | told the caller to run `ifconfig` |
| `ligolo_send_command` | suggested `screen -r` |
| `ligolo_agents_list` | `grep` over `/tmp/ligolo-proxy.log` |

Of 19 tools, 4 reached a shell and all 4 failed; 6 returned prose; the rest
grepped a log file that only exists if the proxy was started by the same tool.
The architecture could not work even after fixing typos: the console is a
readline TUI whose `session`/`autoroute` steps are interactive overlays, and
every tool call was a fresh `ssh` process, so console state was lost between
calls.

The tool *surface* was sound, so this fork keeps all 19 names and replaces the
internals: the proxy has shipped an authenticated REST API since v0.8
(`POST /api/auth` → JWT, then `/api/v1/…`) that expresses the same operations
without a terminal. Two tools changed meaning (`ligolo_send_command` removed,
`ligolo_session_select` repurposed) and several gained required parameters —
the full list is in [Breaking changes](#breaking-changes). See
[CHANGELOG.md](CHANGELOG.md) for the 1.0.0 → 1.1.0 delta.

## Requirements

- Node.js 20+ (`fetch`, `AbortSignal.timeout`, `X509Certificate.fingerprint256`)
- a ligolo-ng release (proxy **and** agent) — tested against **proxy
  0.9.1/0.9.2**. Nothing is vendored: point `LIGOLO_NG_DIR` at the directory
  holding `proxy`, or set `LIGOLO_PROXY_BIN`.
- privileges to create a TUN interface for the proxy (the agent needs none —
  it uses a userland gVisor stack)
- to use the checkpoint gate: a framework checkout providing
  `scripts/common/scope_check.py` (BITORIA). Without it the mutating tools
  refuse to run — by design.

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
| `LIGOLO_PROXY_BIN` | — | explicit path to the proxy binary (wins over `LIGOLO_NG_DIR`) |
| `LIGOLO_API` | `http://127.0.0.1:8080` | proxy REST API base URL |
| `LIGOLO_USER` | `ligolo` | API user (must match `web.users` in the proxy config) |
| `LIGOLO_PASSWORD` | — | API password; if unset, `ligolo_proxy_start` generates one |
| `LIGOLO_TOKEN` | — | pre-minted JWT instead of user/password |
| `LIGOLO_INTERFACE` | `ligolo` | default TUN interface name for tunnel/route/teardown |
| `LIGOLO_PROXY_ADDR` | `0.0.0.0:11601` | agent-facing listen address |
| `LIGOLO_API_LISTEN` | `127.0.0.1:8080` | API listen address written into a **newly seeded** config |
| `LIGOLO_PROXY_CONFIG` | `./ligolo-ng.yaml` | proxy config path; keep it in a workspace, not a repo root |
| `LIGOLO_SELFCERT_DIR` / `LIGOLO_SELFCERT_DOMAIN` | `./ligolo-selfcerts` / `ligolo` | where `-selfcert` caches its cert (fingerprint source) |
| `LIGOLO_ASSESSMENT` | — | assessment name/path for the gate; when unset, the active-assessment marker is used |
| `LIGOLO_BITORIA_ROOT` | auto-detected | framework checkout owning `scripts/common/scope_check.py` (walks up from cwd) |
| `LIGOLO_MCP_READ_ONLY` | off | `1` registers only the 9 read-only tools |

Precedence: an explicit environment value wins; otherwise
`.ligolo-mcp-credentials` (written next to the proxy config) supplies
`user`/`password`. Credentials generated by `ligolo_proxy_start` land in that
file with mode `0600`, so registering the server never requires a secret in the
client's config.

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
        "LIGOLO_PROXY_CONFIG": "/path/to/workspace/ligolo/ligolo-ng.yaml"
      }
    }
  }
}
```

`LIGOLO_PROXY_CONFIG` must point outside the checkout: the proxy writes
`ligolo-ng.yaml`, `ligolo-selfcerts/`, `ligolo-proxy.log` and
`.ligolo-mcp-proxy.pid` beside it (all covered by `.gitignore` if you do run it
from a clone).

## Typical flow

1. `ligolo_proxy_start` (optionally `{ "port": "443", "rewriteConfig": true }`)
   → returns `{ running, pid, apiUrl, fingerprint }`. The config is seeded
   headless: `web.enabled: true`, `web.enableui: false`, loopback API.
2. `ligolo_certificate_fingerprint` → `[0-9A-F]{64}`. This is the value the
   agent pins; no console round-trip.
3. `ligolo_agent_command` `{ "proxyIp": "<operator-ip>" }` → fingerprint-pinned
   `agent`/`agent.exe` command line. The port in that command is the proxy's
   configured listen port, including a `port` override from step 1 — one source
   of truth, so the agent cannot be pointed at a port the proxy is not on.
   Upload the agent to the foothold (log it in `cleanup-pending.md` at upload
   time) and run it.
4. `ligolo_agents_list` → `agent_id` + the agent's interfaces and addresses
   (this is the `ifconfig` step, as JSON).
5. `ligolo_tunnel_start` `{ "agentId": "1", "tun": "ligolo", "target":
   "10.10.10.5", "confirmed": true }` → registers the interface if needed and
   starts the tunnel. First attempt without `confirmed` returns
   `checkpoint-denied` — that is the gate, not a bug.
6. `ligolo_route_add` `{ "network": "10.10.10.0/24", "target": "10.10.10.5",
   "confirmed": true }` → route appears on the TUN; scan normally (SYN or
   connect both work; no SOCKS tax).
7. `ligolo_listener_add` for reverse callbacks / payload serving.
8. `ligolo_teardown` `{ "agentId": "1", "deleteInterface": true }` → listeners,
   routes, tunnel, interface. Then delete the agent binary on the foothold and
   resolve the `cleanup-pending.md` entries.

## The lateral-movement gate

`ligolo_tunnel_start`, `ligolo_route_add` and `ligolo_listener_add` make
something newly reachable, so each runs

```
scripts/common/scope_check.py <target> --assessment <A> --technique lateral --checkpoint
```

**before** the HTTP request leaves the process:

| Outcome | What happens |
|---|---|
| exit 0 | the call proceeds and is appended to `<assessment>/logs/commands.log` |
| exit 5 | `{"error":"checkpoint-denied","action_taken":false,"exit_code":5}` and **nothing** is sent to the proxy |
| exit 4 / other | `{"error":"checkpoint-denied", …}` — no assessment, no framework root, or a bad target |

Recovery for exit 5: record the pivot (foothold, destination, mechanism, ports)
in `state/decisions.md`, obtain human approval, then re-call with `target` +
`confirmed: true`.

`target` is the in-scope host the action makes reachable. For a route wider than
`/32` it is required explicitly — "visible in `ifconfig`" is not authorization.
Cleanup tools (`*_delete`, `ligolo_teardown`, `ligolo_tunnel_stop`) are logged
but not checkpointed: reversing a pivot is not a new reachability transition.

With no `LIGOLO_ASSESSMENT`, the server reads `state/assessment-scope.json` —
the same marker (and the same 12h TTL) the framework's filesystem guard uses. An
**expired or invalid marker counts as no assessment**: a leftover file refuses
the pivot instead of authorizing it.

## Tools

Read-only (always registered, 9):

| Tool | Parameters | What it does |
|---|---|---|
| `ligolo_proxy_status` | — | API liveness (`/ping`), pid, binary, config and log paths |
| `ligolo_agents_list` | — | agents with name, session id, tunnel state, full NIC/address list |
| `ligolo_session_select` | `sessionId` | resolve one agent id and return its record (compatibility name; there is no persistent selection) |
| `ligolo_agent_info` | `sessionId?` | one agent's interfaces (all agents if omitted) — replaces `ifconfig` |
| `ligolo_interface_list` | — | TUN interfaces with routed destinations and active state |
| `ligolo_route_list` | — | flattened routes per interface |
| `ligolo_listener_list` | — | listeners: agent, listen addr, redirect addr, network, online |
| `ligolo_certificate_fingerprint` | — | SHA-256 of the cached selfcert, in `-accept-fingerprint` form |
| `ligolo_agent_command` | `proxyIp`, `port?`, `fingerprint?`, `retry?`, `useWs?`, `debugIgnoreCert?` | agent command line, fingerprint-pinned by default |

Mutating (10, hidden with `LIGOLO_MCP_READ_ONLY=1`):

| Tool | Parameters | Gate |
|---|---|---|
| `ligolo_proxy_start` | `port?`, `rewriteConfig?` | none — starts the proxy headless with a seeded loopback-API config |
| `ligolo_proxy_stop` | — | none — SIGTERM via pid file |
| `ligolo_interface_create` | `name?` | none (local TUN only) |
| `ligolo_tunnel_start` | `agentId`, `target`, `tun?`, `confirmed?` | **lateral checkpoint**; registers the interface first if missing |
| `ligolo_tunnel_stop` | `agentId` | none (cleanup) |
| `ligolo_route_add` | `network`, `target?` (required unless `/32`), `interface?`, `confirmed?` | **lateral checkpoint** |
| `ligolo_route_delete` | `network`, `interface?` | none (cleanup) |
| `ligolo_listener_add` | `localAddress`, `remoteAddress`, `agentId`, `target`, `network?`, `confirmed?` | **lateral checkpoint**; also a resident artifact — record it in `cleanup-pending.md` |
| `ligolo_listener_delete` | `listenerId`, `agentId` | none (cleanup) |
| `ligolo_teardown` | `agentId`, `interface?`, `deleteInterface?` | none (cleanup) — listeners → routes → tunnel → interface |

Every response is JSON. Failures are JSON too:
`{"error": "checkpoint-denied" | "failed", "tool", "message"}` plus
`isError: true`, so a refused pivot is distinguishable from a transport problem
without parsing prose.

## HTTP endpoints used

Useful when debugging without the MCP layer (or for a non-MCP client). The proxy
reads `Authorization` **raw** — no `Bearer ` prefix:

```bash
TOK=$(curl -s -X POST http://127.0.0.1:8080/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"ligolo","password":"…"}' | jq -r .token)
curl -s -H "Authorization: $TOK" http://127.0.0.1:8080/api/v1/agents
```

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth` | username/password → JWT (1h TTL; the server refreshes automatically) |
| `GET` | `/api/v1/ping` | liveness |
| `GET` | `/api/v1/agents` | agents, session ids, interface/address list, tunnel state |
| `GET`/`POST`/`DELETE` | `/api/v1/interfaces` | TUN interfaces (`{Interface}`) |
| `POST`/`DELETE` | `/api/v1/routes` | routes (`{Interface, Route: [cidr…]}` / `{Interface, Route: cidr}`) |
| `GET`/`POST`/`DELETE` | `/api/v1/listeners` | listeners (`{AgentID, ListenerAddr, RedirectAddr, Network}`) |
| `POST`/`DELETE` | `/api/v1/tunnel/<agentId>` | start/stop a tunnel (`{Interface}`) |

## Breaking changes

Versus upstream 1.0.0:

- `ligolo_send_command` is **removed** — it existed to type into the console;
  against the API there is nothing to send. `ligolo_teardown` replaces it.
- `ligolo_session_select` no longer selects anything: it resolves an agent id
  and returns its record, and every other tool takes `agentId` explicitly.
- Required parameters added: `agentId` on `ligolo_tunnel_start` /
  `_stop` / `ligolo_listener_add` / `ligolo_listener_delete`; `target` on
  `ligolo_tunnel_start` / `ligolo_listener_add`, and on `ligolo_route_add` for
  any range wider than `/32`.
- `ligolo_listener_add` gained `network` (default `tcp`) — the proxy rejects the
  request without it (`{"error":"input error"}`).
- `ligolo_proxy_start` lost `selfcert`, `apiPort`, `enableApi` and `daemonMode`:
  it is always selfcert, always headless, always API-enabled. It gained `port`
  (agent-facing port override) and `rewriteConfig`.
- Reachability-changing tools return `{"error":"checkpoint-denied"}` when no
  assessment is active. Intentional, not a misconfiguration.
- `ligolo_agent_command` pins the fingerprint and no longer defaults to
  `-ignore-cert`; `debugIgnoreCert: true` restores the old behaviour with a warning.
- Errors are JSON (`isError: true`) instead of English prose.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `proxy binary not found` | set `LIGOLO_NG_DIR` to the release dir (holding `proxy`) or `LIGOLO_PROXY_BIN` |
| `HTTP 401 (proxy API rejects the token — check LIGOLO_USER/LIGOLO_PASSWORD)` | wrong credentials, or a `Bearer ` prefix was hand-rolled into the header; the proxy wants the raw JWT |
| `no active assessment (…) — mutating ligolo calls are refused` | set `LIGOLO_ASSESSMENT`, or run `pentest assessment activate <name>`; an expired marker does **not** authorize |
| `checkpoint-denied … exit 5` | the checkpoint is real: record the pivot in `state/decisions.md`, get approval, re-call with `target` + `confirmed: true` |
| `agent N not connected (known ids: …)` | the agent died or reconnected with a new id; re-run `ligolo_agents_list` (agents reconnect with `-reconnect`, default on) |
| `POST /api/v1/routes -> HTTP 500: interface ligolo not found` | register the interface first (`ligolo_interface_create`, or just `ligolo_tunnel_start`, which does it) |
| `DELETE /api/v1/routes -> HTTP 500: no such process` | the tunnel was stopped before its routes; teardown now deletes routes first and treats an already-gone route as success |
| `selfcert cache not found at …/ligolo_cert` | the proxy was started without `-selfcert`; start it via `ligolo_proxy_start` or set `LIGOLO_SELFCERT_DIR`/`_DOMAIN` |
| `a proxy process (pid N) is running but …/ping does not answer` | something else holds the pid file or the proxy died mid-start; `ligolo_proxy_stop`, then check `ligolo-proxy.log` |
| TUN creation fails / `operation not permitted` | the proxy needs TUN privileges; grant `CAP_NET_ADMIN` or run it as a user allowed to create TUN devices |
| `report: running: true` but no agents appear | agent cannot reach the operator port — check `LIGOLO_PROXY_ADDR`, egress, and that the agent used the pinned fingerprint |

Logs: `<config dir>/ligolo-proxy.log` (proxy stdout/stderr) and
`<assessment>/logs/commands.log` (every MCP call, via `log_command.sh`).

## Development

```bash
npm run build     # tsc -> dist/
npm run dev       # tsc --watch
npm test          # build, then 22 tests over real MCP stdio against a stub API
```

The suite needs no ligolo binary, no root and no network: it spawns
`dist/index.js`, speaks JSON-RPC over stdin/stdout, and asserts what actually
leaves the process — the HTTP bodies sent to the proxy, that a denied call sends
**nothing**, teardown ordering, fingerprint equality with the certificate, the
0600 credential file, and marker-based assessment resolution with its TTL.

Source layout: `src/index.ts` (MCP surface + handlers), `src/ligolo.ts` (API
client, checkpoint gate, fingerprint, assessment resolution),
`src/proxy.ts` (proxy lifecycle, config seeding, port override).

## Security notes

- The API is a control plane for offensive tooling: bind it to loopback
  (`LIGOLO_API_LISTEN=127.0.0.1:8080`, the default), and keep `web.secret` /
  `web.users` in the proxy config rather than shell history. The upstream WebUI
  warns the API is experimental and wants a reverse proxy if ever exposed.
- `LIGOLO_PROXY_ADDR` defaults to `0.0.0.0:11601` — the agent-facing listener.
  Narrow it to the operator address the foothold can actually reach when the
  host is multi-homed.
- `-ignore-cert` is debug-only. The pinned value is the SHA-256 of the proxy's
  own cached selfcert, so pinning costs nothing.
- The default selfcert domain is `ligolo`, a known IoC — pass
  `-selfcert-domain <innocuous>` (proxy flag) when TLS-inspecting targets exist.
- Nothing here uploads, deletes or cleans up the agent binary on a client host —
  that stays an explicit, logged step.
- See [SECURITY.md](SECURITY.md) for authorized-use scope and reporting.

## What this server does not do

- It does not create the agent binary, upload it, or clean it up on the target.
- It does not decide scope: `scope_check.py` does, and it refuses rather than
  guesses.
- It does not implement relay chains (multi-hop agent chaining). The supported
  double pivot is the `listener_add` relay described in the framework doctrine.
- It does not talk to the WebUI.

## License

MIT. Original work © 2025 schwarztim; fork © 2026 Víctor Nieves — both notices
kept in [LICENSE](LICENSE). Authorized testing only.
