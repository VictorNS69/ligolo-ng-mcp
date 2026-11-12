# Security policy

## Scope of use

This server drives [ligolo-ng](https://github.com/nicocha30/ligolo-ng), a
tunneling tool. It is intended **only** for authorized security assessments —
a signed engagement, a bug-bounty program's published scope, or your own lab.
Nothing here grants authorization, and the gate exists precisely because
"reachable" is not "in scope":

- `ligolo_tunnel_start`, `ligolo_route_add` and `ligolo_listener_add` refuse to
  run unless the named target is inside `LIGOLO_SCOPE` **and** the call carries
  `confirmed: true` (exit 3 / 4 / 5). `ligolo_route_add` additionally requires
  the whole routed network to fit inside a single scope entry.
- With no authorization source at all, mutating tools fail closed rather than
  guessing; there is no mode in which the gate can be switched off, and no
  external file is consulted.
- `LIGOLO_MCP_READ_ONLY=1` exposes only the 9 read-only tools.

## Threat model

- **The proxy's REST API is a control plane.** It manages TUN interfaces,
  routes, listeners and tunnels on the host. Bind it to loopback
  (`LIGOLO_API_LISTEN=127.0.0.1:8080`, the default) and treat credentials like
  root on that host. The upstream WebUI describes the API as experimental and
  expects a reverse proxy if it is ever exposed.
- **Credentials** are held in the proxy config (`web.users`, argon2id hashes)
  and, if generated, in `.ligolo-mcp-credentials` (mode 0600) beside it. The
  server never logs a password or a token.
- **The agent-facing listener** (`LIGOLO_PROXY_ADDR`, default
  `0.0.0.0:11601`) is reachable by anything that can route to the operator
  host. Narrow it on multi-homed hosts.
- **TLS**: the agent should pin `-accept-fingerprint <sha256>`; `-ignore-cert`
  accepts any MITM and is exposed only behind an explicit debug flag.
- **Local side effects**: the proxy creates/deletes TUN interfaces and routes,
  and listeners create forwarding sockets on client hosts. Each instance's
  manifest (`<workspace>/.ligolo-mcp-instances.json`, 0600) records pids, ports
  and paths but never a password; credentials stay in the per-instance
  `.ligolo-mcp-credentials` (0600). Cleanup is explicit
  (`ligolo_teardown`), and the agent binary on the foothold is never removed by
  this server.

## Supported versions

| Version | Supported |
|---|---|
| 1.3.x | yes |
| 1.2.x | security fixes only |
| 1.1.x | security fixes only |
| 1.0.x (upstream scaffold) | no — its tools could not move a packet |

Tested against ligolo-ng proxy 0.9.1 and 0.9.2.

## Reporting

Open a private security advisory on this repository, or email the maintainer
(Víctor Nieves) at the address in the git commits. Please do not open a public
issue for a vulnerability. Include the version, the tool call, and the smallest
reproduction you can manage; a `LIGOLO_SCOPE` bypass or an ungated mutating path
is the highest-severity class here.
