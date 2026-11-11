#!/usr/bin/env node

// Ligolo-ng MCP server.
//
// Every tool is a call against the ligolo proxy's authenticated REST
// control plane. Nothing here shells out to `ssh`, greps a log, or types
// into the readline console — the previous implementation did all three
// and therefore could not move a packet (see README §Why this fork).
//
// Reachability-changing tools (tunnel start, route add, listener add)
// run the framework's lateral-movement hard checkpoint first and refuse
// to touch the API when it denies. See src/ligolo.ts.
//
// LIGOLO_MCP_READ_ONLY=1 registers only the read-only half; every failure
// comes back as JSON with isError, so a refused checkpoint is never
// confused with a broken proxy.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

import {
  assertScope,
  certFingerprint,
  Config,
  GateError,
  LigoloApi,
  loadConfig,
  logCommand,
  requireAgent,
  AgentRecord,
  ListenerRecord,
} from "./ligolo.js";
import { computeDrift, keys, Kind, Ledger, liveResources } from "./ledger.js";
import { configForInstance, instanceStatus, listInstances, startProxy, stopProxy } from "./proxy.js";

const cfg: Config = loadConfig();

/**
 * Per-call instance scope.
 *
 * A single proxy is the normal case, so `instance` is optional everywhere and
 * defaults to "ligolo". When two proxies run (two engagements in one session, a
 * port already held, a segment that must not share routes), each tool call
 * names its instance and gets that proxy's API URL, credentials and cert dir —
 * agent ids are per-proxy, so mixing them up would route a tunnel through the
 * wrong proxy.
 */
function ctx(args: Args): { c: Config; api: LigoloApi; instance: string } {
  const instance = str(args, "instance");
  const c = configForInstance(cfg, instance);
  return { c, api: new LigoloApi(c), instance: instance === "" ? "ligolo" : instance };
}

type Args = Record<string, unknown>;

function str(args: Args, key: string, fallback = ""): string {
  const v = args[key];
  return typeof v === "string" && v.trim() !== "" ? v.trim() : fallback;
}

function bool(args: Args, key: string, fallback = false): boolean {
  const v = args[key];
  return typeof v === "boolean" ? v : fallback;
}

function num(args: Args, key: string): number | null {
  const v = args[key];
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return Number(v.trim());
  return null;
}

/** A gated mutation: checkpoint first, then act, then record. */
function gate(target: string, confirmed: boolean, summary: string): void {
  assertScope(cfg, target, confirmed);
  logCommand(cfg, summary);
}

function log(summary: string): void {
  logCommand(cfg, summary);
}

/**
 * Record what an MCP mutation made (or removed) in the instance's ledger.
 *
 * Runs only after the API call succeeded, and never fails the tool: the pivot
 * already happened, and reporting it as an error would invite a retry that
 * duplicates it. The worst case of a lost write is a resource later shown as
 * origin "external" — visible, not silent.
 */
function track(c: Config, fn: (ledger: Ledger) => void): void {
  try {
    fn(Ledger.load(c.proxyConfig));
  } catch (err) {
    console.error(`ligolo-ng-mcp: ledger update failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Ledger entries of one kind that are no longer live (removed in the WebUI/console, or by a restart). */
function removedOutside(ledger: Ledger, kind: Kind, liveKeys: Iterable<string>): Payload[] {
  const live = new Set(liveKeys);
  return ledger
    .entries()
    .filter((e) => e.kind === kind && !live.has(e.key))
    .map((e) => ({ kind: e.kind, key: e.key, created_at: e.createdAt }));
}

/** Everything on this proxy the MCP did not make, and everything it made that is gone. */
async function outsideMcp(c: Config, api: LigoloApi): Promise<Payload> {
  try {
    const [interfaces, agents, listeners] = await Promise.all([api.interfaces(), api.agents(), api.listeners()]);
    const drift = computeDrift(Ledger.load(c.proxyConfig), liveResources(interfaces, agents, listeners), agents);
    return {
      changed: drift.external.length + drift.removed_outside_mcp.length > 0,
      external: drift.external.map((r) => ({ kind: r.kind, ...r.detail })),
      removed_outside_mcp: drift.removed_outside_mcp.map((e) => ({ kind: e.kind, key: e.key, created_at: e.createdAt })),
      meaning:
        "external = live on the proxy but not created through this MCP (WebUI, console, or restored from an " +
        "existing config). removed_outside_mcp = created through this MCP, no longer present. ligolo does not " +
        "record who made a change; treat external state as the operator's, and do not delete it unasked.",
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

const TARGET = {
  type: "string",
  description:
    "In-scope host/address behind the pivot that this action makes reachable. Required by the lateral-movement " +
    "hard checkpoint (scope_check.py); visible-but-unlisted networks are still out of scope.",
} as const;

const CONFIRMED = {
  type: "boolean",
  description:
    "Set true only after a human approved this pivot and it is recorded in state/decisions.md. Never set it " +
    "speculatively: scope_check.py exits 5 until the checkpoint is genuinely cleared.",
  default: false,
} as const;

const AGENT_ID = {
  type: "string",
  description: "Agent id from ligolo_agents_list (e.g. \"1\"). The console's \"selected session\" does not exist here.",
} as const;

const INSTANCE = {
  type: "string",
  description:
    "Which proxy instance (\"ligolo\" by default, \"ligolo2\" for a second one). Agent ids, routes and listeners " +
    "are per-proxy, so pass this whenever more than one proxy is running; ligolo_proxy_status lists them.",
} as const;

const readTools: Tool[] = [
  {
    name: "ligolo_proxy_status",
    description:
      "Check the ligolo proxy: API liveness (GET /api/v1/ping), pid, binary, config and log paths, whether the " +
      "observer WebUI is on (webui), and `outside_mcp`: proxy state not created through this server (WebUI or " +
      "console changes) plus MCP-made state that has disappeared. Read-only.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_agents_list",
    description:
      "List connected agents: name, session id, remote address, tunnel state and the full agent-side interface list " +
      "with addresses (this replaces the console's `ifconfig`), and tunnel_origin for running tunnels. Read-only.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_session_select",
    description:
      "Resolve one agent by id and return its record. Kept for compatibility with the old tool surface: there is no " +
      "persistent session selection over the API — pass agentId to the tunnel/listener tools instead. Read-only.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE, sessionId: { type: "number", description: "Agent id from ligolo_agents_list" } },
      required: ["sessionId"],
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_agent_info",
    description:
      "Agent-side network detail: interfaces, flags, MTU and addresses. Optionally narrow to one agent id. Read-only.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE, sessionId: { type: "number", description: "Optional agent id" } },
      required: [],
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_interface_list",
    description: "Configured TUN interfaces with their routed destinations and active state. Each entry carries origin: \"mcp\" (made by this server) or \"external\" (WebUI, console, restored config). Read-only.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_route_list",
    description: "Routes per interface, flattened, with active state. Each entry carries origin: \"mcp\" (made by this server) or \"external\" (WebUI, console, restored config). Read-only.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_listener_list",
    description: "Active listeners/redirectors across agents (agent, listen addr, redirect addr, network, online). Each entry carries origin: \"mcp\" (made by this server) or \"external\" (WebUI, console, restored config). Read-only.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_certificate_fingerprint",
    description:
      "SHA-256 fingerprint of the proxy's cached selfcert, in the exact form `-accept-fingerprint` wants. Read-only, " +
      "no console needed. Errors if the proxy has not been started with -selfcert yet.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_agent_command",
    description:
      "Generate the agent command for a foothold. Fingerprint-pinned by default (pass fingerprint or call " +
      "ligolo_certificate_fingerprint); -ignore-cert only behind debugIgnoreCert.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        proxyIp: { type: "string", description: "Address the foothold reaches the operator on" },
        port: { type: "string", description: "Proxy listen port", default: "11601" },
        fingerprint: { type: "string", description: "SHA-256 from ligolo_certificate_fingerprint" },
        retry: { type: "boolean", description: "Add -retry", default: true },
        useWs: { type: "boolean", description: "WebSocket transport (-ws)", default: false },
        debugIgnoreCert: {
          type: "boolean",
          description: "Emit -ignore-cert instead of a pinned fingerprint. Debug only: accepts any MITM.",
          default: false,
        },
      },
      required: ["proxyIp"],
    },
    annotations: { readOnlyHint: true },
  },
];

const writeTools: Tool[] = [
  {
    name: "ligolo_proxy_start",
    description:
      "Start the proxy locally (headless, -selfcert, API enabled) with a config seeded for loopback API use, then " +
      "wait for /api/v1/ping. Existing config is only rewritten with rewriteConfig: true (original kept as .bak). " +
      "With LIGOLO_WEBUI=1 the proxy also serves its WebUI on the same loopback listener for a human observer " +
      "(webui.url); that login is the human's, never this server's.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        port: {
          type: "string",
          description:
            "Agent-facing listen port for this proxy instance, overriding LIGOLO_PROXY_ADDR's port (1-65535). " +
            "Use it when the default 11601 is already taken or an egress rule pins a port.",
          default: "11601",
        },
        apiPort: {
          type: "string",
          description:
            "API (and WebUI) listen port for this instance, overriding LIGOLO_API_LISTEN's port (1-65535). The " +
            "host stays the configured one, loopback by default.",
        },
        rewriteConfig: {
          type: "boolean",
          description: "Rewrite an existing ligolo-ng.yaml that lacks web.enabled/web.users (backup written first)",
          default: false,
        },
        reuse: {
          type: "boolean",
          description:
            "Return the instance that is already running instead of starting another. Without it, a retried " +
            "call (or a call after a timeout) starts the next instance, with a new port, workspace and " +
            "selfcert, leaving the caller with two proxies and two fingerprints.",
          default: false,
        },
      },
      required: [],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "ligolo_proxy_stop",
    description: "Stop the proxy process started by ligolo_proxy_start (SIGTERM to its recorded, verified pid). Does not touch agents.",
    inputSchema: { type: "object" as const, properties: { instance: INSTANCE }, required: [] },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "ligolo_interface_create",
    description:
      "Register (and, with privileges, create) a TUN interface on the operator host. Local-only: no target is " +
      "contacted, so no checkpoint is required.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE, name: { type: "string", description: "Interface name", default: "ligolo" } },
      required: [],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "ligolo_tunnel_start",
    description:
      "Start an agent's TUN tunnel on an interface (creates the interface first if unregistered). GATED: runs the " +
      "lateral hard checkpoint for `target` before any API call.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        agentId: AGENT_ID,
        tun: { type: "string", description: "TUN interface name", default: "ligolo" },
        target: TARGET,
        confirmed: CONFIRMED,
      },
      required: ["agentId", "target"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "ligolo_tunnel_stop",
    description: "Stop an agent's tunnel (cleanup, not a new reachability transition). Logged, not checkpointed.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE, agentId: AGENT_ID },
      required: ["agentId"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "ligolo_route_add",
    description:
      "Route a CIDR through an interface. GATED. For anything wider than /32 pass `target` explicitly — the " +
      "representative in-scope host the checkpoint is evaluated against.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        network: { type: "string", description: "CIDR to route (e.g. 10.10.10.0/24)" },
        interface: { type: "string", description: "TUN interface name", default: "ligolo" },
        target: TARGET,
        confirmed: CONFIRMED,
      },
      required: ["network"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "ligolo_route_delete",
    description: "Remove a route from an interface (cleanup). Logged, not checkpointed.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        network: { type: "string", description: "CIDR to remove" },
        interface: { type: "string", description: "TUN interface name", default: "ligolo" },
      },
      required: ["network"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "ligolo_listener_add",
    description:
      "Add a listener on the agent that relays back to the operator (reverse shell catch, payload serving). GATED: " +
      "a listener is a resident artifact on a client host and must also be recorded in state/cleanup-pending.md.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        localAddress: { type: "string", description: "Listen address on the agent (e.g. 0.0.0.0:4444)" },
        remoteAddress: { type: "string", description: "Operator-side target (e.g. 127.0.0.1:443)" },
        network: { type: "string", description: "tcp, tcp4, tcp6, udp, udp4, udp6", default: "tcp" },
        agentId: AGENT_ID,
        target: TARGET,
        confirmed: CONFIRMED,
      },
      required: ["localAddress", "remoteAddress", "agentId", "target"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "ligolo_listener_delete",
    description:
      "Delete a listener by id on an agent (cleanup). Logged, not checkpointed. A listener that is already gone " +
      "(e.g. removed in the WebUI) is reported as already_absent, not as an error.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        listenerId: { type: "number", description: "ListenerID from ligolo_listener_list" },
        agentId: AGENT_ID,
      },
      required: ["listenerId", "agentId"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "ligolo_teardown",
    description:
      "Reverse a pivot through the API: stop the agent's tunnel, delete its listeners, and optionally delete the " +
      "interface and its routes. The uploaded agent binary itself is still a foothold-side cleanup item.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instance: INSTANCE,
        agentId: AGENT_ID,
        interface: { type: "string", description: "TUN interface to remove when deleteInterface is true", default: "ligolo" },
        deleteInterface: { type: "boolean", description: "Also delete the interface and its routes", default: false },
      },
      required: ["agentId"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
];

/** Single source for the version reported over MCP and in the startup banner. */
const VERSION = "1.5.1";

const tools: Tool[] = cfg.readOnly ? readTools : [...readTools, ...writeTools];

/** Declared argument names per tool, used to reject unknown keys.
 *
 * An unknown key used to be dropped silently: `ligolo_listener_add` called with
 * `listenAddr`/`redirectAddr` (real names: `localAddress`/`remoteAddress`)
 * forwarded an empty listener address to the proxy and came back as
 * `HTTP 500: invalid listener addr: missing port in address` — a caller-side typo
 * reported as a server fault, after the agent/target checks had already run and
 * made the call look validated. Reject the call instead, naming the near miss.
 */
const ARG_NAMES: ReadonlyMap<string, ReadonlySet<string>> = new Map(
  tools.map((t) => {
    const props = (t.inputSchema as { properties?: Record<string, unknown> }).properties ?? {};
    return [t.name, new Set(Object.keys(props))] as const;
  }),
);

function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0 || n === 0) return Math.max(m, n);
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = new Array<number>(n + 1);
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

/** Closest declared name within a small edit distance, so a typo gets a suggestion. */
function nearestName(wanted: string, candidates: ReadonlySet<string>): string | null {
  const lower = wanted.toLowerCase();
  let best: { name: string; d: number } | null = null;
  for (const name of candidates) {
    const d = editDistance(lower, name.toLowerCase());
    if (best === null || d < best.d) best = { name, d };
  }
  if (best === null) return null;
  const threshold = Math.max(2, Math.floor(wanted.length / 3));
  return best.d <= threshold ? best.name : null;
}

function rejectUnknownArgs(name: string, args: Args): void {
  const known = ARG_NAMES.get(name);
  if (known === undefined) return;
  const unknown = Object.keys(args ?? {}).filter((k) => !known.has(k));
  if (unknown.length === 0) return;
  const named = unknown.map((k) => {
    const near = nearestName(k, known);
    return near === null ? k : `${k} (did you mean ${near}?)`;
  });
  throw new Error(
    `unknown argument(s) for ${name}: ${named.join(", ")}. Accepted: ${[...known].join(", ")}`,
  );
}

/**
 * A name Linux accepts for a TUN device: 1-15 bytes (IFNAMSIZ - 1), no
 * whitespace or '/', not "." / "..". The proxy registers any string in its
 * config and only fails at device creation ("TUNSETIFF failed … invalid
 * argument"), leaving a pending interface behind — seen in the lab with a
 * WebUI-created "test desde ui".
 */
function assertInterfaceName(name: string): void {
  const problems: string[] = [];
  if (Buffer.byteLength(name, "utf8") > 15) problems.push("longer than 15 bytes");
  if (/[\s/]/.test(name)) problems.push("contains whitespace or '/'");
  if (name === "." || name === "..") problems.push("is '.' or '..'");
  if (problems.length > 0) {
    throw new Error(
      `interface name "${name}" is not a valid Linux interface name (${problems.join(", ")}). ` +
        "Use up to 15 characters without spaces, e.g. ligolo2. Nothing was sent to the proxy.",
    );
  }
}

/** IPv4/IPv6 CIDR with a mandatory, in-range prefix length. */
function isCidr(value: string): boolean {
  const parts = value.split("/");
  if (parts.length !== 2) return false;
  const [addr, prefix] = parts;
  if (prefix === "" || !/^\d{1,3}$/.test(prefix)) return false;
  const bits = Number(prefix);
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (v4 !== null) {
    return v4.slice(1).every((o) => Number(o) <= 255) && bits >= 0 && bits <= 32;
  }
  if (addr.includes(":")) {
    return /^[0-9a-fA-F:.]+$/.test(addr) && bits >= 0 && bits <= 128;
  }
  return false;
}

type Payload = Record<string, unknown>;

async function handleProxyStart(args: Args): Promise<Payload> {
  if (bool(args, "reuse", false)) {
    const wanted = str(args, "instance");
    const existing = await instanceStatus(cfg, wanted).catch(() => null);
    if (existing !== null && existing.running) {
      let fingerprint: string | null = null;
      let fingerprintError: string | null = null;
      try {
        fingerprint = certFingerprint(configForInstance(cfg, existing.instance));
      } catch (err) {
        fingerprintError = err instanceof Error ? err.message : String(err);
      }
      log(`ligolo_proxy_start reuse=true instance=${existing.instance} pid=${existing.pid ?? "none"}`);
      return {
        ...existing,
        reused: true,
        fingerprint,
        fingerprint_error: fingerprintError,
        scope_checked: false,
      };
    }
  }
  const state = await startProxy(cfg, {
    instance: str(args, "instance"),
    port: str(args, "port"),
    apiPort: str(args, "apiPort"),
    rewriteConfig: bool(args, "rewriteConfig", false),
  });
  log(
    `ligolo_proxy_start instance=${state.instance} api=${state.apiUrl} ` +
      `binary=${state.binary ?? "<missing>"} log=${state.logPath}`,
  );
  let fingerprint: string | null = null;
  let fingerprintError: string | null = null;
  try {
    fingerprint = certFingerprint(configForInstance(cfg, state.instance));
  } catch (err) {
    fingerprintError = err instanceof Error ? err.message : String(err);
  }
  return { ...state, fingerprint, fingerprint_error: fingerprintError, scope_checked: false };
}

async function handleAgents(args: Args): Promise<Payload> {
  const { c, api, instance } = ctx(args);
  const agents = await api.agents();
  const ledger = Ledger.load(c.proxyConfig);
  const running = Object.values(agents ?? {}).filter((a) => a.Running);
  // A tunnel the MCP started whose agent is still connected but no longer
  // running was stopped elsewhere; a disconnected agent is not reported.
  const connected = Object.values(agents ?? {}).map((a) => a.SessionID);
  const stopped = removedOutside(ledger, "tunnel", running.map((a) => a.SessionID)).filter((e) =>
    connected.includes(String(e.key)),
  );
  return {
    scope_checked: false,
    instance,
    count: Object.keys(agents ?? {}).length,
    ...(stopped.length > 0 ? { tunnels_stopped_outside_mcp: stopped } : {}),
    agents: Object.entries(agents ?? {}).map(([id, a]) => ({
      agent_id: id,
      name: a.Name,
      session_id: a.SessionID,
      remote_addr: a.RemoteAddr,
      tunnel_interface: a.Interface,
      tunnel_running: a.Running,
      tunnel_origin: a.Running ? ledger.origin("tunnel", keys.tunnel(a.SessionID)) : null,
      interfaces: (a.Network ?? []).map((n) => ({ name: n.Name, mtu: n.MTU, addresses: n.Addresses ?? [] })),
    })),
  };
}

function agentDetail(id: string, agent: AgentRecord, instance: string): Payload {
  return {
    scope_checked: false,
    instance,
    agent_id: id,
    name: agent.Name,
    session_id: agent.SessionID,
    remote_addr: agent.RemoteAddr,
    tunnel_interface: agent.Interface,
    tunnel_running: agent.Running,
    listeners: agent.Listeners ?? [],
    interfaces: (agent.Network ?? []).map((n) => ({
      name: n.Name,
      index: n.Index,
      mtu: n.MTU,
      hardware_addr: n.HardwareAddr,
      flags: n.Flags,
      addresses: n.Addresses ?? [],
    })),
  };
}

async function handleTunnelStart(args: Args): Promise<Payload> {
  const { c, api, instance } = ctx(args);
  const agentId = str(args, "agentId");
  const tun = str(args, "tun", c.interfaceName);
  const target = str(args, "target");
  if (target === "") throw new Error("target is required: the in-scope host this tunnel makes reachable");
  assertInterfaceName(tun);
  const agent = await requireAgent(api, agentId);
  // ligolo 0.9.1: starting a tunnel on an agent that already runs one opens
  // the new TUN but leaves it orphaned — after the next tunnel_stop that
  // device stays held by the proxy ("tun.New device or resource busy") until
  // the proxy restarts. Reproduced twice in the double-pivot lab. Never move a
  // running tunnel implicitly; a repeat on the same interface is a no-op.
  if (agent.Running) {
    if (agent.Interface === tun) {
      return {
        scope_checked: false,
        instance,
        agent_id: agentId,
        agent_name: agent.Name,
        interface: tun,
        already_running: true,
        message: `agent ${agentId} already runs its tunnel on ${tun} — nothing changed.`,
      };
    }
    throw new Error(
      `agent ${agentId} already runs a tunnel on ${agent.Interface || "an interface"}; starting another on ${tun} ` +
        "would leave a TUN orphaned and held by the proxy (ligolo 0.9.x). Stop it first with ligolo_tunnel_stop, " +
        `then start it on ${tun}. Routes stay on their interface, so move them with ligolo_route_delete/route_add. ` +
        "Nothing was sent to the proxy.",
    );
  }
  gate(
    target,
    bool(args, "confirmed", false),
    `ligolo_tunnel_start instance=${instance} agent=${agentId} (${agent.Name}) tun=${tun} target=${target}`,
  );
  const interfaces = await api.interfaces();
  let interfaceCreated = false;
  if (!(tun in (interfaces ?? {}))) {
    await api.createInterface(tun);
    interfaceCreated = true;
  }
  const started = await api.startTunnel(agentId, tun);
  track(c, (l) => {
    if (interfaceCreated) l.record("interface", keys.interface(tun));
    l.record("tunnel", keys.tunnel(agent.SessionID));
  });
  return {
    scope_checked: true,
    instance,
    agent_id: agentId,
    agent_name: agent.Name,
    interface: tun,
    interface_created: interfaceCreated,
    message: started.message,
    routed: (await api.interfaces())?.[tun]?.Routes ?? [],
    next:
      "Route the segment onto the interface (ligolo_route_add) if it is not already listed, then scan through the " +
      "tun. Every newly reachable in-scope host belongs in state/hosts.md.",
  };
}

async function handleRouteAdd(args: Args): Promise<Payload> {
  const { c, api, instance } = ctx(args);
  const network = str(args, "network");
  if (network === "") throw new Error("network is required (a CIDR)");
  if (!isCidr(network)) {
    throw new Error(
      `network "${network}" is not a CIDR — expected <address>/<prefix> (e.g. 20.20.20.0/24, 10.10.10.2/32). ` +
        "Unvalidated it reached the proxy as a route and came back as an unrelated HTTP 500 " +
        "(\"interface not found\"), which reads like a server fault instead of a bad argument.",
    );
  }
  const iface = str(args, "interface", c.interfaceName);
  const explicitTarget = str(args, "target");
  const target = explicitTarget !== "" ? explicitTarget : network.endsWith("/32") ? network.slice(0, -3) : "";
  if (target === "") {
    throw new Error(
      "target is required for a range wider than /32 — name one in-scope host inside it, so the checkpoint is " +
        "evaluated against something real (visible != authorized).",
    );
  }
  gate(target, bool(args, "confirmed", false), `ligolo_route_add instance=${instance} ${network} dev ${iface} target=${target}`);
  let applied: { message: string };
  try {
    applied = await api.addRoutes(iface, [network]);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // Routes outlive tunnel_stop/tunnel_start, so the natural retry after a
    // tunnel restart hits "already exists" while the desired end state is
    // exactly what is in place. That is success, not failure.
    if (/already exists|already present/i.test(message)) {
      return {
        scope_checked: true,
        instance,
        network,
        interface: iface,
        already_present: true,
        origin: Ledger.load(c.proxyConfig).origin("route", keys.route(iface, network)),
        message: `route ${network} already present on ${iface}`,
        note: "No change made; the segment is already routed through this interface.",
      };
    }
    throw err;
  }
  track(c, (l) => l.record("route", keys.route(iface, network)));
  return {
    scope_checked: true,
    instance,
    network,
    interface: iface,
    message: applied.message,
    note: "If the interface was not yet created, the route is stored and applied at tunnel start.",
  };
}

async function handleListenerAdd(args: Args): Promise<Payload> {
  const { c, api, instance } = ctx(args);
  const local = str(args, "localAddress");
  const remote = str(args, "remoteAddress");
  const agentId = str(args, "agentId");
  const network = str(args, "network", "tcp");
  const target = str(args, "target");
  // Report every missing/invalid argument at once: failing on the first one made
  // a caller spend a round trip per problem (target, then agentId, then addr).
  const missing: string[] = [];
  if (agentId === "") missing.push("agentId (from ligolo_agents_list)");
  if (local === "") missing.push("localAddress (agent-side listen address, host:port)");
  if (remote === "") missing.push("remoteAddress (operator-side redirect address, host:port)");
  if (target === "") missing.push("target (the foothold/segment host the listener sits on)");
  const malformed: string[] = [];
  for (const [field, value] of [["localAddress", local], ["remoteAddress", remote]] as const) {
    if (value !== "" && !/^[^\s:]+:\d{1,5}$/.test(value)) {
      malformed.push(`${field} "${value}" is not host:port`);
    }
  }
  if (missing.length > 0 || malformed.length > 0) {
    throw new Error(
      "ligolo_listener_add needs valid arguments: " +
        [...missing, ...malformed].join("; ") +
        ". Nothing was sent to the proxy.",
    );
  }
  const agent = await requireAgent(api, agentId);
  gate(
    target,
    bool(args, "confirmed", false),
    `ligolo_listener_add instance=${instance} agent=${agentId} addr=${local} to=${remote} network=${network} target=${target}`,
  );
  const created = await api.createListener(agentId, local, remote, network);
  const listeners = (await api.listeners()) ?? [];
  const mine = listeners.filter((l: ListenerRecord) => String(l.AgentID) === agentId && l.ListenerAddr === local);
  if (mine[0] !== undefined) {
    const made = mine[0];
    track(c, (l) => l.record("listener", keys.listener(made), { listenerId: made.ListenerID, agentId: made.AgentID }));
  }
  return {
    scope_checked: true,
    instance,
    agent_id: agentId,
    agent_name: agent.Name,
    message: created.message,
    listener: mine[0] ?? null,
    cleanup:
      `Record in state/cleanup-pending.md: listener ${local} -> ${remote} (${network}) on agent ${agentId}; ` +
      `revert with ligolo_listener_delete {listenerId: ${mine[0]?.ListenerID ?? "<id>"}, agentId: "${agentId}"}.`,
  };
}

async function handleTeardown(args: Args): Promise<Payload> {
  const { c, api, instance } = ctx(args);
  const agentId = str(args, "agentId");
  const iface = str(args, "interface", c.interfaceName);
  const deleteInterface = bool(args, "deleteInterface", false);
  log(`ligolo_teardown instance=${instance} agent=${agentId} interface=${iface} delete_interface=${deleteInterface}`);
  const steps: Payload[] = [];
  const attempt = async (label: string, fn: () => Promise<unknown>): Promise<void> => {
    try {
      const result = await fn();
      steps.push({ step: label, ok: true, result });
    } catch (err) {
      steps.push({ step: label, ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  };
  const agentsBefore = await api.agents().catch(() => null);
  const listeners = (await api.listeners().catch(() => [])) ?? [];
  for (const listener of listeners.filter((l) => String(l.AgentID) === agentId)) {
    await attempt(`delete listener ${listener.ListenerID}`, async () => {
      const done = await api.deleteListener(agentId, listener.ListenerID);
      track(c, (l) => l.forget("listener", keys.listener(listener)));
      return done;
    });
  }
  // Routes are deleted while the TUN still exists: stopping the tunnel tears
  // the interface down underneath us and the proxy then answers 500
  // ("no such process") for every route it can no longer find. A route that
  // is already gone counts as cleaned up, not as a failure.
  const interfaces = await api.interfaces().catch(() => ({}) as Record<string, unknown>);
  const record = (interfaces ?? {})[iface] as { Routes?: { Destination: string }[] } | undefined;
  // Skip only ligolo's own IPv6 link-local routes (fe80::/64, added on every
  // tunnel start — two of them after a restart, as seen in the lab). Skipping
  // every address with a ':' also left any IPv6 route the operator added in
  // place after teardown.
  const routes = (record?.Routes ?? []).filter((r) => !/^fe80:/i.test(r.Destination));
  for (const route of routes) {
    await attempt(`delete route ${route.Destination}`, async () => {
      const done = await api.deleteRoute(iface, route.Destination).catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        if (/no such process|does not exist|not found/i.test(message)) return { message: "already gone" };
        throw err;
      });
      track(c, (l) => l.forget("route", keys.route(iface, route.Destination)));
      return done;
    });
  }
  await attempt("stop tunnel", async () => {
    const done = await api.stopTunnel(agentId);
    const session = agentsBefore?.[agentId]?.SessionID;
    if (session !== undefined) track(c, (l) => l.forget("tunnel", keys.tunnel(session)));
    return done;
  });
  if (deleteInterface) {
    await attempt(`delete interface ${iface}`, async () => {
      const done = await api.deleteInterface(iface);
      track(c, (l) => {
        l.forget("interface", keys.interface(iface));
        l.forgetWhere((e) => e.kind === "route" && e.key.startsWith(`${iface} `));
      });
      return done;
    });
  }
  return {
    scope_checked: false,
    instance,
    agent_id: agentId,
    steps,
    note:
      "Resolve state/cleanup-pending.md entries for this pivot (uploaded agent binary, listeners) and delete the " +
      "agent binary on the foothold; the API cannot unlink files on the client.",
  };
}

const REGISTERED: ReadonlySet<string> = new Set(tools.map((t) => t.name));

async function handleToolCall(name: string, args: Args): Promise<Payload> {
  // Read-only mode used to only *hide* the mutating tools from tools/list: a
  // client calling one by name still reached the gate and the proxy API. Only
  // a registered tool may run.
  if (!REGISTERED.has(name)) {
    if (cfg.readOnly && writeTools.some((t) => t.name === name)) {
      throw new Error(`${name} is not available: this server runs read-only (LIGOLO_MCP_READ_ONLY). Nothing was sent.`);
    }
    throw new Error(`unknown tool: ${name}`);
  }
  rejectUnknownArgs(name, args);
  switch (name) {
    case "ligolo_proxy_start":
      return handleProxyStart(args);
    case "ligolo_proxy_stop": {
      const wanted = str(args, "instance");
      const state = await stopProxy(cfg, wanted);
      log(`ligolo_proxy_stop instance=${state.instance} pid=${state.stoppedPid ?? "none"} running=${state.running}`);
      return { ...state, scope_checked: false };
    }
    case "ligolo_proxy_status": {
      const wanted = str(args, "instance");
      const compatibility =
        "requires ligolo-ng proxy 0.9.x (tested 0.9.1, 0.9.2); the proxy API is experimental upstream";
      const withDrift = async (state: Awaited<ReturnType<typeof instanceStatus>>): Promise<Payload> => {
        if (!state.running) return state as unknown as Payload;
        const c = state.managed === true ? configForInstance(cfg, state.instance) : cfg;
        return { ...state, outside_mcp: await outsideMcp(c, new LigoloApi(c)) };
      };
      if (wanted !== "") {
        return { ...(await withDrift(await instanceStatus(cfg, wanted))), scope_checked: false, compatibility };
      }
      const { entries, logDir } = listInstances(cfg);
      if (entries.length === 0) {
        return { ...(await withDrift(await instanceStatus(cfg))), scope_checked: false, compatibility, instances: [] };
      }
      const states = await Promise.all(entries.map(async (e) => withDrift(await instanceStatus(cfg, e.name))));
      return {
        running: states.some((s) => s.running === true),
        count: states.length,
        instances: states,
        log_dir: logDir,
        apiUrl: states[0].apiUrl,
        binary: cfg.proxyBin,
        scope_checked: false,
        compatibility,
      };
    }
    case "ligolo_agents_list":
      return handleAgents(args);
    case "ligolo_session_select": {
      const { api, instance } = ctx(args);
      const id = num(args, "sessionId");
      if (id === null) throw new Error("sessionId is required (an agent id from ligolo_agents_list)");
      return agentDetail(String(id), await requireAgent(api, String(id)), instance);
    }
    case "ligolo_agent_info": {
      const { api, instance } = ctx(args);
      const id = num(args, "sessionId");
      if (id === null) return handleAgents(args);
      return agentDetail(String(id), await requireAgent(api, String(id)), instance);
    }
    case "ligolo_interface_create": {
      const { c, api, instance } = ctx(args);
      const iface = str(args, "name", c.interfaceName);
      assertInterfaceName(iface);
      log(`ligolo_interface_create instance=${instance} ${iface}`);
      const created = await api.createInterface(iface);
      track(c, (l) => l.record("interface", keys.interface(iface)));
      return {
        scope_checked: false,
        instance,
        interface: iface,
        registered: true,
        // The API call only adds the interface to the proxy's own config. Whether
        // a kernel tun device exists is a separate fact, and reporting the two as
        // one "created" claim sent an operator straight into a confusing
        // tunnel_start failure on hosts where the device was never made.
        os_created: "unknown",
        message: created.message,
        hint:
          `"${created.message}" means the proxy accepted the interface in its config — it is not proof of a ` +
          `kernel device. Check with \`ip -d link show ${iface}\`: the proxy creates it at tunnel_start when the ` +
          `binary holds CAP_NET_ADMIN, otherwise create it once with ` +
          `\`sudo ip tuntap add user $USER mode tun ${iface} && sudo ip link set ${iface} up\`.`,
        interfaces: await api.interfaces(),
      };
    }
    case "ligolo_interface_list": {
      const { c, api, instance } = ctx(args);
      const interfaces = await api.interfaces();
      const ledger = Ledger.load(c.proxyConfig);
      const removed = removedOutside(ledger, "interface", Object.keys(interfaces ?? {}));
      return {
        scope_checked: false,
        instance,
        ...(removed.length > 0 ? { removed_outside_mcp: removed } : {}),
        interfaces: Object.entries(interfaces ?? {}).map(([name, rec]) => ({
          name,
          active: rec.Active,
          origin: ledger.origin("interface", keys.interface(name)),
          routes: (rec.Routes ?? []).map((r) => ({
            ...r,
            origin: /^fe80:/i.test(r.Destination) ? "proxy" : ledger.origin("route", keys.route(name, r.Destination)),
          })),
        })),
      };
    }
    case "ligolo_tunnel_start":
      return handleTunnelStart(args);
    case "ligolo_tunnel_stop": {
      const { c, api, instance } = ctx(args);
      const agentId = str(args, "agentId");
      log(`ligolo_tunnel_stop instance=${instance} agent=${agentId}`);
      const session = (await api.agents().catch(() => null))?.[agentId]?.SessionID;
      const stopped = await api.stopTunnel(agentId);
      if (session !== undefined) track(c, (l) => l.forget("tunnel", keys.tunnel(session)));
      return { scope_checked: false, instance, agent_id: agentId, message: stopped.message };
    }
    case "ligolo_route_add":
      return handleRouteAdd(args);
    case "ligolo_route_delete": {
      const { c, api, instance } = ctx(args);
      const network = str(args, "network");
      const iface = str(args, "interface", c.interfaceName);
      log(`ligolo_route_delete instance=${instance} ${network} dev ${iface}`);
      const removed = await api.deleteRoute(iface, network);
      track(c, (l) => l.forget("route", keys.route(iface, network)));
      return { scope_checked: false, instance, network, interface: iface, message: removed.message };
    }
    case "ligolo_route_list": {
      const { c, api, instance } = ctx(args);
      const interfaces = await api.interfaces();
      const ledger = Ledger.load(c.proxyConfig);
      const routes = Object.entries(interfaces ?? {}).flatMap(([name, rec]) =>
        (rec.Routes ?? []).map((r) => ({
          interface: name,
          destination: r.Destination,
          active: r.Active,
          origin: /^fe80:/i.test(r.Destination) ? "proxy" : ledger.origin("route", keys.route(name, r.Destination)),
        })),
      );
      const removed = removedOutside(
        ledger,
        "route",
        routes.map((r) => keys.route(r.interface, r.destination)),
      );
      return {
        scope_checked: false,
        instance,
        count: routes.length,
        routes,
        ...(removed.length > 0 ? { removed_outside_mcp: removed } : {}),
      };
    }
    case "ligolo_listener_add":
      return handleListenerAdd(args);
    case "ligolo_listener_list": {
      const { c, api, instance } = ctx(args);
      const listeners = (await api.listeners()) ?? [];
      const ledger = Ledger.load(c.proxyConfig);
      const removed = removedOutside(ledger, "listener", listeners.map((l) => keys.listener(l)));
      return {
        scope_checked: false,
        instance,
        count: listeners.length,
        listeners: listeners.map((l) => ({ ...l, origin: ledger.origin("listener", keys.listener(l)) })),
        ...(removed.length > 0 ? { removed_outside_mcp: removed } : {}),
      };
    }
    case "ligolo_listener_delete": {
      const { c, api, instance } = ctx(args);
      const listenerId = num(args, "listenerId");
      const agentId = str(args, "agentId");
      if (listenerId === null) throw new Error("listenerId is required (from ligolo_listener_list)");
      if (agentId === "") throw new Error("agentId is required — listeners are addressed per agent");
      log(`ligolo_listener_delete instance=${instance} agent=${agentId} listener=${listenerId}`);
      const forgetIt = (): void =>
        track(c, (l) =>
          l.forgetWhere((e) => e.kind === "listener" && e.listenerId === listenerId && e.agentId === Number(agentId)),
        );
      let deleted: { message: string };
      try {
        deleted = await api.deleteListener(agentId, listenerId);
      } catch (err) {
        // Already removed (typically from the WebUI): the desired end state, so
        // cleanup stays idempotent — the same rule deleteRoute follows.
        const still = ((await api.listeners().catch(() => null)) ?? null)?.some(
          (l) => l.ListenerID === listenerId && String(l.AgentID) === agentId,
        );
        if (still !== false) throw err;
        forgetIt();
        return {
          scope_checked: false,
          instance,
          agent_id: agentId,
          listener_id: listenerId,
          already_absent: true,
          message: `listener ${listenerId} on agent ${agentId} was already absent — nothing to remove.`,
        };
      }
      forgetIt();
      return { scope_checked: false, instance, agent_id: agentId, listener_id: listenerId, message: deleted.message };
    }
    case "ligolo_certificate_fingerprint": {
      const { c, instance } = ctx(args);
      const fingerprint = certFingerprint(c);
      return {
        scope_checked: false,
        instance,
        fingerprint,
        path: `${c.selfcertDir}/${c.selfcertDomain}_cert`,
        usage: `agent -connect <operator>:${c.proxyAddr.split(":").pop()} -accept-fingerprint ${fingerprint}`,
      };
    }
    case "ligolo_agent_command": {
      const { c, instance } = ctx(args);
      const proxyIp = str(args, "proxyIp");
      const port = str(args, "port", c.proxyAddr.split(":").pop() ?? "11601");
      const retry = bool(args, "retry", true);
      const useWs = bool(args, "useWs", false);
      const debugIgnore = bool(args, "debugIgnoreCert", false);
      let fingerprint = str(args, "fingerprint");
      if (fingerprint === "" && !debugIgnore) fingerprint = certFingerprint(c);
      const flags: string[] = [];
      if (fingerprint !== "") flags.push(`-accept-fingerprint ${fingerprint}`);
      else if (debugIgnore) flags.push("-ignore-cert");
      if (useWs) flags.push("-ws");
      if (retry) flags.push("-retry");
      const linux = `./agent -connect ${proxyIp}:${port} ${flags.join(" ")}`.trim();
      const windows = `agent.exe -connect ${proxyIp}:${port} ${flags.join(" ")}`.trim();
      return {
        scope_checked: false,
        instance,
        linux,
        windows,
        pinned: fingerprint !== "" && !debugIgnore,
        warning: debugIgnore
          ? "-ignore-cert accepts any MITM between foothold and operator. Debug only; re-issue without debugIgnoreCert."
          : null,
        cleanup: "Log the uploaded agent binary in state/cleanup-pending.md the moment it lands on the foothold.",
      };
    }
    case "ligolo_teardown":
      return handleTeardown(args);
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

async function main(): Promise<void> {
  const server = new Server({ name: "ligolo-ng-mcp", version: VERSION }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs } = request.params;
    const args = (rawArgs ?? {}) as Args;
    try {
      const payload = await handleToolCall(name, args);
      return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
    } catch (err) {
      const gateRefusal = err instanceof GateError;
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                error: gateRefusal ? "checkpoint-denied" : "failed",
                tool: name,
                message,
                ...(gateRefusal ? { exit_code: err.code, action_taken: false } : {}),
              },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }
  });

  await server.connect(new StdioServerTransport());
  // stdout is the MCP stream; diagnostics go to stderr only.
  console.error(
    `ligolo-ng-mcp ${VERSION} ready — api=${cfg.apiUrl} ` +
      `assessment=${cfg.assessment || "<unset>"}(${cfg.assessmentSource}) ` +
      `read_only=${cfg.readOnly} tools=${tools.length} framework=${cfg.bitoriaRoot ?? "<not found>"} ` +
      `webui=${cfg.webUi ? `on(user=${cfg.webUiUser})` : "off"} ` +
      `logs=${cfg.assessment === "" ? "<workspace>/ligolo[<n>].log" : `assessments/${cfg.assessment}/state/ligolo[<n>].log`}`,
  );
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
