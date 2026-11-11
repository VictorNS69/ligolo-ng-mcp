# Ligolo-ng MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[ligolo-ng](https://github.com/nicocha30/ligolo-ng) — pivoting and lateral
movement in authorized security assessments.

Every tool is a call against the ligolo **proxy's authenticated REST control
plane**. No SSH, no tmux, no scraping the readline console.

It is self-contained: Node.js and a ligolo-ng release are all it needs. You
declare what you are authorized to reach in `LIGOLO_SCOPE`, and every call that
makes something newly reachable must name a target inside it and carry an
explicit `confirmed: true`.

```
MCP client ──stdio──> ligolo-ng-mcp ──HTTP /api/v1──> ligolo proxy ──TLS──> agent
                            │
                            └─ lateral-movement gate: target ∈ LIGOLO_SCOPE + confirmed
                               (checked before any HTTP request leaves the process)
```

> [!WARNING]
> **Version compatibility — read before upgrading ligolo-ng.**
> This server is tested against **ligolo-ng proxy 0.9.1 and 0.9.2** (Linux
> amd64 release binaries, with the matching agent). It depends on the proxy's
> REST API, which upstream itself labels **experimental**: a newer ligolo-ng
> release can rename or remove an endpoint, change a payload field, or alter
> auth without any compatibility promise — and that breaks these tools, not
> ligolo itself.
>
> - **Pin the ligolo-ng release** per engagement (keep the 0.9.x `proxy` and
>   `agent` from the same release together). A new proxy with an old agent, or
>   a new proxy under this MCP, is untested.
> - **Check before blaming the MCP:** `proxy -version` should print
>   `Ligolo-ng 0.9.x`. `npm test` is a stub-API suite — it validates this
>   server, **not** upstream drift, so a green run does not prove a new proxy
>   still works.
> - **Symptoms of upstream drift:** `ligolo_proxy_status` reports the proxy
>   running but `/api/v1/ping` fails; `404 page not found` on `/api/v1/…`;
>   `401` for credentials that work in the WebUI; `{"error":"input error"}` on
>   listener creation; `interface … not found` for an interface the UI shows.
> - **If it drifted:** the endpoints and payloads this server assumes are
>   listed in [HTTP endpoints used](#http-endpoints-used); the client methods
>   live in `src/ligolo.ts`. Fix there, add a test, then run the live smoke
>   test — that is the only check that exercises a real proxy.

**Operational walkthrough with request/response examples: [USAGE.md](USAGE.md).**

Contents: [Why this fork](#why-this-fork) · [Requirements](#requirements) ·
[Install](#install) · [Quick start](#quick-start) · [Configuration](#configuration) · [Typical
flow](#typical-flow) · [Usage](USAGE.md) · [Logs](#logs) ·
[Multiple instances](#multiple-instances) · [Observer WebUI](#observer-webui) ·
[The lateral-movement gate](#the-lateral-movement-gate) · [Tools](#tools) ·
[HTTP endpoints used](#http-endpoints-used) · [Breaking
changes](#breaking-changes) · [Troubleshooting](#troubleshooting) ·
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
- a ligolo-ng release (proxy **and** agent) — see the compatibility warning
  above; tested against proxy 0.9.1/0.9.2 only. Nothing is vendored: point
  `LIGOLO_NG_DIR` at the directory holding `proxy`, or set `LIGOLO_PROXY_BIN`.
- privileges to create a TUN interface for the proxy (the agent needs none —
  it uses a userland gVisor stack)

Nothing else: no Python, no shell wrappers, no external framework.

## Install

```bash
git clone git@github.com:VictorNS69/ligolo-ng-mcp.git
cd ligolo-ng-mcp
npm install
npm run build
```

## Quick start

```bash
export LIGOLO_NG_DIR=/opt/ligolo-ng                       # release binaries
export LIGOLO_PROXY_CONFIG=$HOME/.ligolo/ligolo-ng.yaml   # workspace, outside the checkout
export LIGOLO_SCOPE="10.10.10.0/24"                       # what you may pivot to
node dist/index.js                                        # or register it in any MCP client
```

Without `LIGOLO_SCOPE` the server still runs, but only read-only tools succeed:
mutating tools refuse until you say what you are authorized to reach.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `LIGOLO_NG_DIR` | — | directory holding `proxy` / `agent` (`…/linux/proxy` also probed) |
| `LIGOLO_PROXY_BIN` | — | explicit path to the proxy binary (wins over `LIGOLO_NG_DIR`) |
| `LIGOLO_API` | derived from `LIGOLO_API_LISTEN` (`http://127.0.0.1:8080`) | proxy REST API base URL |
| `LIGOLO_USER` | `ligolo` | API user (must match `web.users` in the proxy config) |
| `LIGOLO_PASSWORD` | — | API password; if unset, `ligolo_proxy_start` generates one (see precedence below) |
| `LIGOLO_TOKEN` | — | pre-minted JWT instead of user/password |
| `LIGOLO_INTERFACE` | `ligolo` | default TUN interface name for tunnel/route/teardown |
| `LIGOLO_PROXY_ADDR` | `0.0.0.0:11601` | agent-facing listen address |
| `LIGOLO_API_LISTEN` | `127.0.0.1:8080` | API listen address written into a **newly seeded** config |
| `LIGOLO_PROXY_CONFIG` | `./ligolo-ng.yaml` | proxy config path; keep it in a workspace, not a repo root |
| `LIGOLO_SELFCERT_DIR` / `LIGOLO_SELFCERT_DOMAIN` | `./ligolo-selfcerts` / `ligolo` | where `-selfcert` caches its cert (fingerprint source) |
| `LIGOLO_MCP_READ_ONLY` | off | `1` registers only the 9 read-only tools |
| `LIGOLO_WEBUI` | off | `1` also serves the proxy's WebUI on the (loopback) API listener for a **human observer** — see [Observer WebUI](#observer-webui) |
| `LIGOLO_WEBUI_USER` | `operator` | the human's `web.users` entry; must differ from `LIGOLO_USER` |
| `LIGOLO_WEBUI_PASSWORD` | — | the human's password; **required** with `LIGOLO_WEBUI=1`, never generated, never returned |
| `LIGOLO_SCOPE` | — | **authorization**: comma-separated hosts/CIDRs this server may pivot to (see [The lateral-movement gate](#the-lateral-movement-gate)) |

**Credential precedence.** `LIGOLO_USER` / `LIGOLO_PASSWORD`, when set, win
for every instance. When they are unset, each instance uses its own
`.ligolo-mcp-credentials` (written next to its proxy config, mode `0600`): that
is where `ligolo_proxy_start` stores a password it generated, so registering the
server never requires a secret in the client's config.

The password is only written into `web.users` when a config is **seeded**. If you
set or change `LIGOLO_PASSWORD` after a config exists, the proxy still holds the
old (hashed) one and the API answers `401`: re-seed with `ligolo_proxy_start
{"rewriteConfig": true}` (the original is kept as `.bak`), or update `web.users`
yourself.

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

Add `"LIGOLO_SCOPE"` (and optionally `"LIGOLO_PASSWORD"`) to `env` the same way.

`LIGOLO_PROXY_CONFIG` must point outside the checkout: the proxy and this server
write `ligolo-ng.yaml`, `ligolo-selfcerts/`, `ligolo.log`,
`.ligolo-mcp-credentials`, `.ligolo-mcp-instances.json` and
`.ligolo-mcp-ledger.json` beside it.

## Typical flow

The condensed version — [USAGE.md](USAGE.md) has the same path with real
request/response payloads, plus reverse shells, agent-localhost, double pivot,
read-only mode and teardown discipline.

1. `ligolo_proxy_start` (optionally `{ "port": "443", "rewriteConfig": true }`)
   → returns `{ running, pid, apiUrl, fingerprint, webui }`. The config is seeded
   headless: `web.enabled: true`, `web.enableui: false` (unless
   `LIGOLO_WEBUI=1`), loopback API.
2. `ligolo_certificate_fingerprint` → `[0-9A-F]{64}`. This is the value the
   agent pins; no console round-trip.
3. `ligolo_agent_command` `{ "proxyIp": "<operator-ip>" }` → fingerprint-pinned
   `agent`/`agent.exe` command line. The port in that command is the proxy's
   configured listen port, including a `port` override from step 1 — one source
   of truth, so the agent cannot be pointed at a port the proxy is not on.
   Upload the agent to the foothold (note it for cleanup the moment it lands)
   and run it.
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
   routes, tunnel, interface. Then delete the agent binary on the foothold — the
   API cannot do that for you.

## Logs

The proxy's stdout/stderr go to the workspace (`dirname(LIGOLO_PROXY_CONFIG)`):

| Instance | Log file |
|---|---|
| first (`ligolo`) | `<workspace>/ligolo.log` |
| second (`ligolo2`) | `<workspace>/ligolo2.log` |
| third (`ligolo3`) | `<workspace>/ligolo3.log` |

Appended across restarts of the same instance, so the file accumulates the
proxy's whole history. `ligolo_proxy_start` returns the resolved `logPath` and
`ligolo_proxy_status` returns it per instance, so nothing has to be guessed. The
MCP server's own diagnostics are a separate stream: they go to **stderr**
(captured by the MCP client).

Note the proxy also writes `<workspace>/ligolo-ng.yaml`, `ligolo-selfcerts/`
(the fingerprint source) and a log for gin's HTTP layer only if `web.logfile` is
set — this server seeds it empty.

## Multiple instances

Two proxies are legitimate: a second engagement in one session, a port already
held by something else, or a segment that must not share routes with the first.
Instance 1 is `ligolo`; each further instance is `ligolo2`, `ligolo3`, …

```
ligolo_proxy_start                       → ligolo   api :8080  agent :11601  ligolo.log
ligolo_proxy_start                       → ligolo2  api :8081  agent :11602  ligolo2.log
ligolo_proxy_start {"instance":"ligolo3"} → ligolo3  api :8082  agent :11603  ligolo3.log
```

Each instance gets its own API/agent ports (first free after the configured
ones), its own workspace under `<workspace>/ligolo<N>/` (config, selfcert,
credentials — so each has its own fingerprint), its own pid and log, and its own
entry in `<workspace>/.ligolo-mcp-instances.json`. **Agent ids are per-proxy**, so
every other tool takes an optional `instance` argument and defaults to `ligolo`:

```json
{"tool": "ligolo_agents_list", "arguments": {"instance": "ligolo2"}}
{"tool": "ligolo_route_add", "arguments": {"instance": "ligolo2", "network": "10.9.9.0/24",
                                            "target": "10.9.9.9", "confirmed": true}}
```

`ligolo_proxy_status` with no argument lists every live instance with its API
URL and log path. Stopping is per instance (`ligolo_proxy_stop {"instance":
"ligolo2"}`); a dead instance's manifest entry is pruned on the next start or
status. If a proxy was started outside this server (by hand, in a container, …),
status reports it as `managed: false` with the URL it talks to (`LIGOLO_API`),
and the log path stays wherever that process put it.

## Observer WebUI

The intended split: **autonomous agents drive the pivot through this MCP; a
human watches it in the browser.** ligolo-ng (0.8+) serves its WebUI on the same
listener as the REST API, so turning it on costs no extra port:

```json
"env": {
  "LIGOLO_WEBUI": "1",
  "LIGOLO_WEBUI_PASSWORD": "<the human's password>"
}
```

`ligolo_proxy_start` then seeds `web.enableui: true`, sets `corsallowedorigin` to
the listener, and adds a second `web.users` entry (`operator` by default) next to
the MCP's own. It answers with:

```json
"webui": {
  "enabled": true,
  "url": "http://127.0.0.1:8080/",
  "login": { "api_url": "http://127.0.0.1:8080", "user": "operator" },
  "note": "Observer UI for a human operator. It is NOT read-only: …"
}
```

Open the URL, enter that API URL, the user and your password. The UI polls the
proxy every 2 s, so agents, tunnels, routes and listeners the MCP creates appear
live. From another machine use `ssh -L 8080:127.0.0.1:8080 <operator-host>`;
each instance (`ligolo2`, …) has its own UI on its own API port.

What the server enforces, and why:

| Rule | Reason |
|---|---|
| Off by default | the UI is a second control path |
| Loopback listener only (`127.0.0.0/8`, `::1`, `localhost`) | the upstream API is experimental and unhardened |
| `LIGOLO_WEBUI_PASSWORD` required, never generated | every channel this server could hand a generated password over (tool output, the creds file, stderr) is one the agent reads |
| Separate user from `LIGOLO_USER` | the agent's credential is never given to the human; revoke either independently |
| Human password never in tool output or `.ligolo-mcp-credentials` | tool output is the agent's context. It is in `ligolo-ng.yaml` only until the proxy's first load re-hashes it to argon2id |
| Existing config with the UI off is not silently changed | `rewriteConfig: true` (backup to `.bak`) or edit it yourself |

### Changes made in the UI

**The WebUI is not read-only.** ligolo has no read-only role, so a route, tunnel
or listener created there **bypasses the lateral checkpoint**.
That is acceptable for an authorized human operator — the gate exists to bound
the agents — but the agents must not be confused by it. The server therefore
keeps a ledger of what it created (`<workspace>/.ligolo-mcp-ledger.json`, reset
when a config is freshly seeded) and labels everything it reads:

- `ligolo_route_list`, `ligolo_interface_list`, `ligolo_listener_list`: every
  entry has `origin: "mcp" | "external"` (`"proxy"` for ligolo's own IPv6
  link-local routes); `removed_outside_mcp` lists MCP-made resources that are
  gone.
- `ligolo_agents_list`: `tunnel_origin` per running tunnel, and
  `tunnels_stopped_outside_mcp` for an MCP tunnel stopped while its agent stayed
  connected (a disconnected agent is not reported).
- `ligolo_proxy_status`: `outside_mcp` with the full `external` /
  `removed_outside_mcp` picture per instance.

`external` means *not created through this MCP* — the WebUI, the console, or
state the proxy restored from an existing config. ligolo does not record which
user made a change, so this is attribution by elimination, not an audit trail.
A removed entry keeps being reported until the MCP deletes or recreates it;
`ligolo_route_delete` and `ligolo_listener_delete` are idempotent, so they clear
it.

### The limit: agents with a shell

If the autonomous agent has a **shell on the operator host as the same OS user**
that runs the proxy, the gate is a convention, not a control — with or without
the WebUI. It can read `.ligolo-mcp-credentials` (or the MCP's own config) and
call the API directly. For a guarantee, run the proxy and this server as a
dedicated OS user, and give the agent only the MCP connection, not read access to
the workspace or the MCP client's config.

## The lateral-movement gate

`ligolo_tunnel_start`, `ligolo_route_add` and `ligolo_listener_add` make
something newly reachable, so each passes a gate **before** the HTTP request
leaves the process. Set `LIGOLO_SCOPE` to the hosts/CIDRs you are authorized to
reach:

```bash
export LIGOLO_SCOPE="10.10.10.0/24,172.16.5.9"
```

A reachability-changing call then needs a `target` inside that list **and**
`confirmed: true`:

| Outcome | What happens |
|---|---|
| target in scope + `confirmed: true` | the call proceeds |
| target outside `LIGOLO_SCOPE` | `{"error":"checkpoint-denied","exit_code":3,"action_taken":false}`; **nothing** is sent to the proxy |
| route `network` not contained in one `LIGOLO_SCOPE` entry, or `target` outside that `network` | `checkpoint-denied`, `exit_code: 3`; **nothing** is sent to the proxy |
| target in scope, no `confirmed` | `checkpoint-denied`, `exit_code: 5` — a human approves the pivot, then the call is repeated with `confirmed: true` |
| `LIGOLO_SCOPE` unset | `checkpoint-denied`, `exit_code: 4` — no authorization configured |

`target` is the in-scope host the action makes reachable. For a route wider than
`/32` it is required explicitly — "visible in `ifconfig`" is not authorization.
A route makes its whole range reachable, so its `network` must also fit entirely
inside a single `LIGOLO_SCOPE` entry and `target` must lie inside it: with
`LIGOLO_SCOPE=10.10.10.5`, `10.10.10.5/32` is allowed and `0.0.0.0/0` is not.
IPv4 and IPv6 ranges are bit-compared; hostnames match exactly
(case-insensitively), and octets with leading zeros (`010.0.0.1`) are refused. Cleanup tools
(`*_delete`, `ligolo_teardown`, `ligolo_tunnel_stop`) are not gated: reversing a
pivot is not a new reachability transition.

Read-only tools (`agents_list`, `interface_list`, `route_list`, `listener_list`,
fingerprints, `proxy_status`) work with or without `LIGOLO_SCOPE`. There is
deliberately no `--force`, `LIGOLO_GATE=off`, or "trust me" flag: a gate that can
be switched off is not a gate.

## Tools

Every tool accepts an optional `instance` (default `ligolo`) — see
[Multiple instances](#multiple-instances).

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
| `ligolo_proxy_start` | `port?`, `apiPort?`, `rewriteConfig?`, `reuse?` | none — starts the proxy headless with a seeded loopback-API config |
| `ligolo_proxy_stop` | — | none — SIGTERM to the instance's recorded (and verified) pid |
| `ligolo_interface_create` | `name?` | none (local TUN only) |
| `ligolo_tunnel_start` | `agentId`, `target`, `tun?`, `confirmed?` | **lateral checkpoint**; registers the interface first if missing; refuses to move an already running tunnel (ligolo would orphan the TUN) |
| `ligolo_tunnel_stop` | `agentId` | none (cleanup) |
| `ligolo_route_add` | `network`, `target?` (required unless `/32`), `interface?`, `confirmed?` | **lateral checkpoint**; `network` must be contained in `LIGOLO_SCOPE` and hold `target` |
| `ligolo_route_delete` | `network`, `interface?` | none (cleanup) |
| `ligolo_listener_add` | `localAddress`, `remoteAddress`, `agentId`, `target`, `network?`, `confirmed?` | **lateral checkpoint**; also a resident artifact on the agent's host — track it for cleanup |
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

- 3.0.0: `ligolo_route_add` refuses a route whose `network` is not contained in
  a single `LIGOLO_SCOPE` entry, or whose `target` lies outside that network
  (exit 3). One in-scope host no longer authorizes a route of any width.
- 2.0.0: the external-framework integration is removed; `LIGOLO_SCOPE` is the
  only authorization and the old framework variables (`LIGOLO_ASSESSMENT` and
  the framework-root path) are ignored. Logs always go to
  `<workspace>/ligolo[<n>].log`.
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
  authorization is configured. Intentional, not a misconfiguration.
- `ligolo_agent_command` pins the fingerprint and no longer defaults to
  `-ignore-cert`; `debugIgnoreCert: true` restores the old behaviour with a warning.
- Errors are JSON (`isError: true`) instead of English prose.
- 1.3.0: mutating tools are authorized by `LIGOLO_SCOPE` (previously they
  refused without an external scope checker).
- 1.2.0: proxy logs moved from `<workspace>/ligolo-proxy.log` to
  `<workspace>/ligolo.log` + the per-instance numbering above; every tool
  gained the optional `instance` argument; `ligolo_proxy_start` gained `apiPort`
  and `ligolo_proxy_status` returns a list instead of a single state when called
  with no `instance`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `proxy binary not found` | set `LIGOLO_NG_DIR` to the release dir (holding `proxy`) or `LIGOLO_PROXY_BIN` |
| `HTTP 401 (proxy API rejects the token — check LIGOLO_USER/LIGOLO_PASSWORD)` | wrong credentials, or a `Bearer ` prefix was hand-rolled into the header; the proxy wants the raw JWT |
| `HTTP 401` right after changing `LIGOLO_PASSWORD` | the proxy config still holds the old password: `ligolo_proxy_start {"rewriteConfig": true}` or update `web.users` (see [Configuration](#configuration)) |
| `checkpoint-denied … exit 5` | the checkpoint is real: get a human to approve the pivot, then re-call with `target` + `confirmed: true` |
| `checkpoint-denied … exit 4` "no authorization source configured" | set `LIGOLO_SCOPE` to the hosts/CIDRs you are authorized to reach |
| `checkpoint-denied … exit 3` "not inside LIGOLO_SCOPE" | the target is outside the authorization list; extend `LIGOLO_SCOPE` deliberately |
| `checkpoint-denied … exit 3` "route … is not contained in LIGOLO_SCOPE" | the route is wider than what is authorized; route a narrower network inside one scope entry (e.g. the `/24` you were given, not a `/16` or `0.0.0.0/0`) |
| `agent N not connected (known ids: …)` | the agent died or reconnected with a new id; re-run `ligolo_agents_list` (agents reconnect with `-reconnect`, default on) |
| `POST /api/v1/routes -> HTTP 500: interface ligolo not found` | register the interface first (`ligolo_interface_create`, or just `ligolo_tunnel_start`, which does it) |
| `DELETE /api/v1/routes -> HTTP 500: no such process` | the tunnel was stopped before its routes; teardown now deletes routes first and treats an already-gone route as success |
| `selfcert cache not found at …/ligolo_cert` | the proxy was started without `-selfcert`; start it via `ligolo_proxy_start` or set `LIGOLO_SELFCERT_DIR`/`_DOMAIN` |
| `proxy did not answer …/api/v1/ping within 20s` | the proxy died mid-start or cannot bind; check `logPath` (`<workspace>/ligolo.log`) |
| `tun.New device or resource busy` on `ligolo_tunnel_start` | the proxy still holds that TUN (ligolo 0.9.x orphans it when a running tunnel is started elsewhere); use a fresh interface name, or restart the proxy |
| TUN creation fails / `operation not permitted` | the proxy needs TUN privileges; grant `CAP_NET_ADMIN` or run it as a user allowed to create TUN devices |
| `report: running: true` but no agents appear | agent cannot reach the operator port — check `LIGOLO_PROXY_ADDR`, egress, and that the agent used the pinned fingerprint |

Logs: `<workspace>/ligolo[<n>].log` (proxy stdout/stderr) and the MCP server's
stderr (captured by the MCP client).

## Development

```bash
npm run build     # tsc -> dist/
npm run dev       # tsc --watch
npm test          # build, then 58 tests over real MCP stdio against a stub API
```

The suite needs no ligolo binary, no root and no network: it spawns
`dist/index.js`, speaks JSON-RPC over stdin/stdout, and asserts what actually
leaves the process — the HTTP bodies sent to the proxy, that a denied call sends
**nothing**, teardown ordering, fingerprint equality with the certificate, the
0600 credential file and credential precedence.

Source layout: `src/index.ts` (MCP surface + handlers), `src/ligolo.ts` (API
client, checkpoint gate, fingerprint), `src/proxy.ts` (proxy lifecycle, config
seeding, port override), `src/ledger.ts` (what the MCP created, for `origin`).

## Security notes

- The API is a control plane for offensive tooling: bind it to loopback
  (`LIGOLO_API_LISTEN=127.0.0.1:8080`, the default), and keep `web.secret` /
  `web.users` in the proxy config rather than shell history. The upstream WebUI
  warns the API is experimental and wants a reverse proxy if ever exposed.
- `LIGOLO_WEBUI=1` is refused on a non-loopback listener. The UI can change
  proxy state outside the gate; see [Observer WebUI](#observer-webui), including
  the same-OS-user limit that applies whether or not it is on.
- `LIGOLO_PROXY_ADDR` defaults to `0.0.0.0:11601` — the agent-facing listener.
  Narrow it to the operator address the foothold can actually reach when the
  host is multi-homed.
- `-ignore-cert` is debug-only. The pinned value is the SHA-256 of the proxy's
  own cached selfcert, so pinning costs nothing.
- The default selfcert domain is `ligolo`, a known IoC — pass
  `-selfcert-domain <innocuous>` (proxy flag) when TLS-inspecting targets exist.
- Nothing here uploads, deletes or cleans up the agent binary on a client host —
  that stays an explicit step.
- See [SECURITY.md](SECURITY.md) for authorized-use scope and reporting.

## What this server does not do

- It does not create the agent binary, upload it, or clean it up on the target.
- It does not decide scope: you do, in `LIGOLO_SCOPE`, and it refuses rather
  than guesses.
- Relay chains (multi-hop agent chaining) have no dedicated tool, but they work
  with one `listener_add` relay per hop — see the [USAGE.md](USAGE.md) §Double
  pivot walk-through (a hop-3 agent connects to hop-2's relay, and so on).
- It does not drive the WebUI. With `LIGOLO_WEBUI=1` it only turns the proxy's
  own UI on for a human, and reports what was changed there as `external`.

## License

MIT. Original work © 2025 schwarztim; fork © 2026 Víctor Nieves — both notices
kept in [LICENSE](LICENSE). Authorized testing only.
