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
import { applyPortOverride, proxyStatus, startProxy, stopProxy } from "./proxy.js";

const cfg: Config = loadConfig();
const api = new LigoloApi(cfg);

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

const readTools: Tool[] = [
  {
    name: "ligolo_proxy_status",
    description:
      "Check the ligolo proxy: API liveness (GET /api/v1/ping), pid, binary, config and log paths. Read-only.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_agents_list",
    description:
      "List connected agents: name, session id, remote address, tunnel state and the full agent-side interface list " +
      "with addresses (this replaces the console's `ifconfig`). Read-only.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_session_select",
    description:
      "Resolve one agent by id and return its record. Kept for compatibility with the old tool surface: there is no " +
      "persistent session selection over the API — pass agentId to the tunnel/listener tools instead. Read-only.",
    inputSchema: {
      type: "object" as const,
      properties: { sessionId: { type: "number", description: "Agent id from ligolo_agents_list" } },
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
      properties: { sessionId: { type: "number", description: "Optional agent id" } },
      required: [],
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_interface_list",
    description: "Configured TUN interfaces with their routed destinations and active state. Read-only.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_route_list",
    description: "Routes per interface, flattened, with active state. Read-only.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_listener_list",
    description: "Active listeners/redirectors across agents (agent, listen addr, redirect addr, network, online). Read-only.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
    annotations: { readOnlyHint: true },
  },
  {
    name: "ligolo_certificate_fingerprint",
    description:
      "SHA-256 fingerprint of the proxy's cached selfcert, in the exact form `-accept-fingerprint` wants. Read-only, " +
      "no console needed. Errors if the proxy has not been started with -selfcert yet.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
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
      "wait for /api/v1/ping. Existing config is only rewritten with rewriteConfig: true (original kept as .bak).",
    inputSchema: {
      type: "object" as const,
      properties: {
        port: {
          type: "string",
          description:
            "Agent-facing listen port for this proxy instance, overriding LIGOLO_PROXY_ADDR's port (1-65535). " +
            "Use it when the default 11601 is already taken or an egress rule pins a port.",
          default: "11601",
        },
        rewriteConfig: {
          type: "boolean",
          description: "Rewrite an existing ligolo-ng.yaml that lacks web.enabled/web.users (backup written first)",
          default: false,
        },
      },
      required: [],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "ligolo_proxy_stop",
    description: "Stop the proxy process started by ligolo_proxy_start (SIGTERM via its pid file). Does not touch agents.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
  {
    name: "ligolo_interface_create",
    description:
      "Register (and, with privileges, create) a TUN interface on the operator host. Local-only: no target is " +
      "contacted, so no checkpoint is required.",
    inputSchema: {
      type: "object" as const,
      properties: { name: { type: "string", description: "Interface name", default: "ligolo" } },
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
      properties: { agentId: AGENT_ID },
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
    description: "Delete a listener by id on an agent (cleanup). Logged, not checkpointed.",
    inputSchema: {
      type: "object" as const,
      properties: {
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
        agentId: AGENT_ID,
        interface: { type: "string", description: "TUN interface to remove when deleteInterface is true", default: "ligolo" },
        deleteInterface: { type: "boolean", description: "Also delete the interface and its routes", default: false },
      },
      required: ["agentId"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
];

const tools: Tool[] = cfg.readOnly ? readTools : [...readTools, ...writeTools];

type Payload = Record<string, unknown>;

async function handleProxyStart(args: Args): Promise<Payload> {
  applyPortOverride(cfg, str(args, "port"));
  const state = await startProxy(cfg, bool(args, "rewriteConfig", false));
  log(`ligolo_proxy_start api=${state.apiUrl} binary=${state.binary ?? "<missing>"}`);
  let fingerprint: string | null = null;
  let fingerprintError: string | null = null;
  try {
    fingerprint = certFingerprint(cfg);
  } catch (err) {
    fingerprintError = err instanceof Error ? err.message : String(err);
  }
  return { ...state, fingerprint, fingerprint_error: fingerprintError, scope_checked: false };
}

async function handleAgents(): Promise<Payload> {
  const agents = await api.agents();
  return {
    scope_checked: false,
    count: Object.keys(agents ?? {}).length,
    agents: Object.entries(agents ?? {}).map(([id, a]) => ({
      agent_id: id,
      name: a.Name,
      session_id: a.SessionID,
      remote_addr: a.RemoteAddr,
      tunnel_interface: a.Interface,
      tunnel_running: a.Running,
      interfaces: (a.Network ?? []).map((n) => ({ name: n.Name, mtu: n.MTU, addresses: n.Addresses ?? [] })),
    })),
  };
}

function agentDetail(id: string, agent: AgentRecord): Payload {
  return {
    scope_checked: false,
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
  const agentId = str(args, "agentId");
  const tun = str(args, "tun", cfg.interfaceName);
  const target = str(args, "target");
  if (target === "") throw new Error("target is required: the in-scope host this tunnel makes reachable");
  const agent = await requireAgent(api, agentId);
  gate(
    target,
    bool(args, "confirmed", false),
    `ligolo_tunnel_start agent=${agentId} (${agent.Name}) tun=${tun} target=${target}`,
  );
  const interfaces = await api.interfaces();
  let interfaceCreated = false;
  if (!(tun in (interfaces ?? {}))) {
    await api.createInterface(tun);
    interfaceCreated = true;
  }
  const started = await api.startTunnel(agentId, tun);
  return {
    scope_checked: true,
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
  const network = str(args, "network");
  if (network === "") throw new Error("network is required (a CIDR)");
  const iface = str(args, "interface", cfg.interfaceName);
  const explicitTarget = str(args, "target");
  const target = explicitTarget !== "" ? explicitTarget : network.endsWith("/32") ? network.slice(0, -3) : "";
  if (target === "") {
    throw new Error(
      "target is required for a range wider than /32 — name one in-scope host inside it, so the checkpoint is " +
        "evaluated against something real (visible != authorized).",
    );
  }
  gate(target, bool(args, "confirmed", false), `ligolo_route_add ${network} dev ${iface} target=${target}`);
  const applied = await api.addRoutes(iface, [network]);
  return {
    scope_checked: true,
    network,
    interface: iface,
    message: applied.message,
    note: "If the interface was not yet created, the route is stored and applied at tunnel start.",
  };
}

async function handleListenerAdd(args: Args): Promise<Payload> {
  const local = str(args, "localAddress");
  const remote = str(args, "remoteAddress");
  const agentId = str(args, "agentId");
  const network = str(args, "network", "tcp");
  const target = str(args, "target");
  if (target === "") throw new Error("target is required: the foothold/segment host the listener sits on");
  const agent = await requireAgent(api, agentId);
  gate(
    target,
    bool(args, "confirmed", false),
    `ligolo_listener_add agent=${agentId} addr=${local} to=${remote} network=${network} target=${target}`,
  );
  const created = await api.createListener(agentId, local, remote, network);
  const listeners = (await api.listeners()) ?? [];
  const mine = listeners.filter((l: ListenerRecord) => String(l.AgentID) === agentId && l.ListenerAddr === local);
  return {
    scope_checked: true,
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
  const agentId = str(args, "agentId");
  const iface = str(args, "interface", cfg.interfaceName);
  const deleteInterface = bool(args, "deleteInterface", false);
  log(`ligolo_teardown agent=${agentId} interface=${iface} delete_interface=${deleteInterface}`);
  const steps: Payload[] = [];
  const attempt = async (label: string, fn: () => Promise<unknown>): Promise<void> => {
    try {
      const result = await fn();
      steps.push({ step: label, ok: true, result });
    } catch (err) {
      steps.push({ step: label, ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  };
  const listeners = (await api.listeners().catch(() => [])) ?? [];
  for (const listener of listeners.filter((l) => String(l.AgentID) === agentId)) {
    await attempt(`delete listener ${listener.ListenerID}`, () => api.deleteListener(agentId, listener.ListenerID));
  }
  // Routes are deleted while the TUN still exists: stopping the tunnel tears
  // the interface down underneath us and the proxy then answers 500
  // ("no such process") for every route it can no longer find. A route that
  // is already gone counts as cleaned up, not as a failure.
  const interfaces = await api.interfaces().catch(() => ({}) as Record<string, unknown>);
  const record = (interfaces ?? {})[iface] as { Routes?: { Destination: string }[] } | undefined;
  const routes = (record?.Routes ?? []).filter((r) => !r.Destination.includes(":"));
  for (const route of routes) {
    await attempt(`delete route ${route.Destination}`, () =>
      api.deleteRoute(iface, route.Destination).catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        if (/no such process|does not exist|not found/i.test(message)) return { message: "already gone" };
        throw err;
      }),
    );
  }
  await attempt("stop tunnel", () => api.stopTunnel(agentId));
  if (deleteInterface) {
    await attempt(`delete interface ${iface}`, () => api.deleteInterface(iface));
  }
  return {
    scope_checked: false,
    agent_id: agentId,
    steps,
    note:
      "Resolve state/cleanup-pending.md entries for this pivot (uploaded agent binary, listeners) and delete the " +
      "agent binary on the foothold; the API cannot unlink files on the client.",
  };
}

async function handleToolCall(name: string, args: Args): Promise<Payload> {
  switch (name) {
    case "ligolo_proxy_start":
      return handleProxyStart(args);
    case "ligolo_proxy_stop": {
      const state = await stopProxy(cfg);
      log(`ligolo_proxy_stop pid=${state.stoppedPid ?? "none"} running=${state.running}`);
      return { ...state, scope_checked: false };
    }
    case "ligolo_proxy_status":
      return {
        ...(await proxyStatus(cfg)),
        scope_checked: false,
        // Surfaced in-band because the doc warning is not read mid-run: if the
        // proxy answers /ping but a later call 404s, this is the first place to
        // look — the tested range is a claim about a specific release pair.
        compatibility: "requires ligolo-ng proxy 0.9.x (tested 0.9.1, 0.9.2); the proxy API is experimental upstream",
      };
    case "ligolo_agents_list":
      return handleAgents();
    case "ligolo_session_select": {
      const id = num(args, "sessionId");
      if (id === null) throw new Error("sessionId is required (an agent id from ligolo_agents_list)");
      return agentDetail(String(id), await requireAgent(api, String(id)));
    }
    case "ligolo_agent_info": {
      const id = num(args, "sessionId");
      if (id === null) return handleAgents();
      return agentDetail(String(id), await requireAgent(api, String(id)));
    }
    case "ligolo_interface_create": {
      const iface = str(args, "name", cfg.interfaceName);
      log(`ligolo_interface_create ${iface}`);
      const created = await api.createInterface(iface);
      return { scope_checked: false, interface: iface, message: created.message, interfaces: await api.interfaces() };
    }
    case "ligolo_interface_list": {
      const interfaces = await api.interfaces();
      return {
        scope_checked: false,
        interfaces: Object.entries(interfaces ?? {}).map(([name, rec]) => ({
          name,
          active: rec.Active,
          routes: rec.Routes ?? [],
        })),
      };
    }
    case "ligolo_tunnel_start":
      return handleTunnelStart(args);
    case "ligolo_tunnel_stop": {
      const agentId = str(args, "agentId");
      log(`ligolo_tunnel_stop agent=${agentId}`);
      const stopped = await api.stopTunnel(agentId);
      return { scope_checked: false, agent_id: agentId, message: stopped.message };
    }
    case "ligolo_route_add":
      return handleRouteAdd(args);
    case "ligolo_route_delete": {
      const network = str(args, "network");
      const iface = str(args, "interface", cfg.interfaceName);
      log(`ligolo_route_delete ${network} dev ${iface}`);
      const removed = await api.deleteRoute(iface, network);
      return { scope_checked: false, network, interface: iface, message: removed.message };
    }
    case "ligolo_route_list": {
      const interfaces = await api.interfaces();
      const routes = Object.entries(interfaces ?? {}).flatMap(([name, rec]) =>
        (rec.Routes ?? []).map((r) => ({ interface: name, destination: r.Destination, active: r.Active })),
      );
      return { scope_checked: false, count: routes.length, routes };
    }
    case "ligolo_listener_add":
      return handleListenerAdd(args);
    case "ligolo_listener_list": {
      const listeners = (await api.listeners()) ?? [];
      return { scope_checked: false, count: listeners.length, listeners };
    }
    case "ligolo_listener_delete": {
      const listenerId = num(args, "listenerId");
      const agentId = str(args, "agentId");
      if (listenerId === null) throw new Error("listenerId is required (from ligolo_listener_list)");
      if (agentId === "") throw new Error("agentId is required — listeners are addressed per agent");
      log(`ligolo_listener_delete agent=${agentId} listener=${listenerId}`);
      const deleted = await api.deleteListener(agentId, listenerId);
      return { scope_checked: false, agent_id: agentId, listener_id: listenerId, message: deleted.message };
    }
    case "ligolo_certificate_fingerprint": {
      const fingerprint = certFingerprint(cfg);
      return {
        scope_checked: false,
        fingerprint,
        path: `${cfg.selfcertDir}/${cfg.selfcertDomain}_cert`,
        usage: `agent -connect <operator>:${cfg.proxyAddr.split(":").pop()} -accept-fingerprint ${fingerprint}`,
      };
    }
    case "ligolo_agent_command": {
      const proxyIp = str(args, "proxyIp");
      const port = str(args, "port", cfg.proxyAddr.split(":").pop() ?? "11601");
      const retry = bool(args, "retry", true);
      const useWs = bool(args, "useWs", false);
      const debugIgnore = bool(args, "debugIgnoreCert", false);
      let fingerprint = str(args, "fingerprint");
      if (fingerprint === "" && !debugIgnore) fingerprint = certFingerprint(cfg);
      const flags: string[] = [];
      if (fingerprint !== "") flags.push(`-accept-fingerprint ${fingerprint}`);
      else if (debugIgnore) flags.push("-ignore-cert");
      if (useWs) flags.push("-ws");
      if (retry) flags.push("-retry");
      const linux = `./agent -connect ${proxyIp}:${port} ${flags.join(" ")}`.trim();
      const windows = `agent.exe -connect ${proxyIp}:${port} ${flags.join(" ")}`.trim();
      return {
        scope_checked: false,
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
  const server = new Server({ name: "ligolo-ng-mcp", version: "1.1.0" }, { capabilities: { tools: {} } });

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
    `ligolo-ng-mcp 1.1.0 ready — api=${cfg.apiUrl} ` +
      `assessment=${cfg.assessment || "<unset>"}(${cfg.assessmentSource}) ` +
      `read_only=${cfg.readOnly} tools=${tools.length} framework=${cfg.bitoriaRoot ?? "<not found>"}`,
  );
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
