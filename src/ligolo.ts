// Ligolo-ng MCP — control-plane client.
//
// Why the REST API and not the proxy console: ligolo's console is a
// readline TUI, and two of its steps (session selection, autoroute CIDR
// pick) are interactive overlays. A tool driving that console has to
// scrape a pty and guess at arrow-key state. The proxy has shipped an
// authenticated REST control plane since v0.8 — `POST /api/auth` -> JWT,
// then `/api/v1/…` — which expresses the same operations as explicit
// calls with an explicit agent id. Every tool in this fork goes through
// it; nothing here greps a log or types into a terminal.
//
// One behaviour is non-negotiable: every reachability-changing call
// (route add, tunnel start, listener add) passes the lateral-movement gate
// *before* an HTTP request leaves the process — its target (and, for a
// route, the whole routed network) must be inside LIGOLO_SCOPE and the call
// must carry `confirmed: true`. Denied = nothing
// happened, and the error says why.

import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface Config {
  /** Proxy REST API base URL, e.g. http://127.0.0.1:8080 */
  apiUrl: string;
  /** API credentials (argon2id hashes live in the proxy config; these are plaintext for /api/auth). */
  user: string;
  password: string;
  /**
   * True when LIGOLO_USER / LIGOLO_PASSWORD came from the environment. An
   * explicit environment value wins over `.ligolo-mcp-credentials` for every
   * instance; without it, each instance uses its own credentials file.
   */
  userFromEnv: boolean;
  passwordFromEnv: boolean;
  /** Pre-minted JWT instead of user/password (optional). */
  token: string;
  /** Default TUN interface name used by tunnel/route tools. */
  interfaceName: string;
  /** Directory holding the selfcert cache (`<domain>_cert`), used for fingerprint pinning. */
  selfcertDir: string;
  selfcertDomain: string;
  /** Proxy binary + its config file + listen addresses. */
  proxyBin: string | null;
  proxyConfig: string;
  proxyAddr: string;
  apiListen: string;
  /** 0600 file holding {user,password} for the API, written by proxy_start when it seeds a config. */
  credsPath: string;
  /** When true, mutating tools are not registered at all. */
  readOnly: boolean;
  /**
   * Authorization: hosts/CIDRs this server may pivot to (LIGOLO_SCOPE). Empty
   * makes mutating tools refuse — the server still works read-only.
   */
  scope: string[];
  /**
   * Observer WebUI (`LIGOLO_WEBUI=1`): the proxy also serves its browser UI on
   * the API listener, for a *human* to watch what the agents do. Off by default.
   * The human gets their own `web.users` entry so the agent's credential is
   * never handed out, and the human's password is never written anywhere this
   * server reads back or returns.
   */
  webUi: boolean;
  webUiUser: string;
  webUiPassword: string;
}

function envStr(env: NodeJS.ProcessEnv, key: string, fallback: string): string {
  const v = env[key];
  return v === undefined || v === "" ? fallback : v;
}

/** `LIGOLO_NG_DIR/proxy`, `LIGOLO_NG_DIR/linux/proxy`, `proxy` on PATH — in that order. */
export function resolveProxyBin(env: NodeJS.ProcessEnv = process.env): string | null {
  const explicit = env.LIGOLO_PROXY_BIN;
  if (explicit && existsSync(explicit)) return explicit;
  const dir = env.LIGOLO_NG_DIR;
  if (dir) {
    for (const cand of [join(dir, "proxy"), join(dir, "linux", "proxy")]) {
      if (existsSync(cand)) return cand;
    }
  }
  const which = spawnSync("sh", ["-c", "command -v proxy"], { encoding: "utf8" });
  const found = which.status === 0 ? which.stdout.trim() : "";
  return found === "" ? null : found;
}

/** {user,password} written next to the proxy config by proxy_start (mode 0600). */
export function readCreds(path: string): { user?: string; password?: string } {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as { user?: string; password?: string };
  } catch {
    return {};
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()): Config {
  const proxyConfig = resolve(cwd, envStr(env, "LIGOLO_PROXY_CONFIG", "ligolo-ng.yaml"));
  const selfcertDir = resolve(dirname(proxyConfig), envStr(env, "LIGOLO_SELFCERT_DIR", "ligolo-selfcerts"));
  const credsPath = join(dirname(proxyConfig), ".ligolo-mcp-credentials");
  const creds = readCreds(credsPath);
  const apiListen = envStr(env, "LIGOLO_API_LISTEN", "127.0.0.1:8080");
  // Without an explicit LIGOLO_API, talk to where the proxy is told to listen.
  // A fixed :8080 default meant LIGOLO_API_LISTEN=127.0.0.1:9090 alone started
  // the proxy on 9090 while status and every unmanaged call probed 8080.
  const listenHostPart = listenHost(apiListen);
  const reachableHost = /^(0\.0\.0\.0|::|)$/.test(listenHostPart) ? "127.0.0.1" : listenHostPart;
  const defaultApi = `http://${reachableHost.includes(":") ? `[${reachableHost}]` : reachableHost}:${apiListen.slice(apiListen.lastIndexOf(":") + 1)}`;
  return {
    apiUrl: envStr(env, "LIGOLO_API", defaultApi).replace(/\/+$/, ""),
    user: envStr(env, "LIGOLO_USER", creds.user ?? "ligolo"),
    password: envStr(env, "LIGOLO_PASSWORD", creds.password ?? ""),
    userFromEnv: envStr(env, "LIGOLO_USER", "") !== "",
    passwordFromEnv: envStr(env, "LIGOLO_PASSWORD", "") !== "",
    token: envStr(env, "LIGOLO_TOKEN", ""),
    interfaceName: envStr(env, "LIGOLO_INTERFACE", "ligolo"),
    selfcertDir,
    selfcertDomain: envStr(env, "LIGOLO_SELFCERT_DOMAIN", "ligolo"),
    proxyBin: resolveProxyBin(env),
    proxyConfig,
    proxyAddr: envStr(env, "LIGOLO_PROXY_ADDR", "0.0.0.0:11601"),
    apiListen,
    credsPath,
    readOnly: /^(1|true|yes|on)$/i.test(envStr(env, "LIGOLO_MCP_READ_ONLY", "")),
    scope: envStr(env, "LIGOLO_SCOPE", "")
      .split(",")
      .map((v) => v.trim())
      .filter((v) => v !== ""),
    webUi: /^(1|true|yes|on)$/i.test(envStr(env, "LIGOLO_WEBUI", "")),
    webUiUser: envStr(env, "LIGOLO_WEBUI_USER", "operator"),
    webUiPassword: envStr(env, "LIGOLO_WEBUI_PASSWORD", ""),
  };
}

/** Host part of a `host:port` listen address, brackets stripped. */
export function listenHost(addr: string): string {
  const bare = addr.replace(/^https?:\/\//, "");
  const host = bare.includes(":") ? bare.slice(0, bare.lastIndexOf(":")) : bare;
  return host.replace(/^\[|\]$/g, "");
}

/** True for 127.0.0.0/8, ::1 and localhost — the only places the WebUI may listen. */
export function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  return h === "localhost" || h === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/** A gate refusal is a first-class outcome, not a generic failure. */
export class GateError extends Error {
  constructor(message: string, readonly code: number) {
    super(message);
    this.name = "GateError";
  }
}

/** An address as an integer of its family, so v4 and v6 share one comparison path. */
interface Ip {
  v: 4 | 6;
  value: bigint;
}

const BITS = { 4: 32, 6: 128 } as const;

function parseIpv4(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    // No leading zeros: "010" is 10 here but 8 to inet_aton-style parsers, and
    // the gate must not disagree with the tools that later use the address.
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) + BigInt(octet);
  }
  return value;
}

function parseIpv6(ip: string): bigint | null {
  let addr = ip.toLowerCase();
  if (addr.includes("%")) return null; // zone ids are not routable scope
  // A trailing dotted quad (::ffff:10.0.0.1) counts as two groups.
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(addr);
  if (tail !== null) {
    const v4 = parseIpv4(tail[2]);
    if (v4 === null) return null;
    addr = `${tail[1]}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const groups = (h: string): string[] => (h === "" ? [] : h.split(":"));
  const head = groups(halves[0]);
  const rest = halves.length === 2 ? groups(halves[1]) : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  let value = 0n;
  for (const g of all) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    value = (value << 16n) + BigInt(parseInt(g, 16));
  }
  return value;
}

function parseIp(raw: string): Ip | null {
  const ip = raw.trim().replace(/^\[|\]$/g, "");
  const v4 = parseIpv4(ip);
  if (v4 !== null) return { v: 4, value: v4 };
  if (!ip.includes(":")) return null;
  const v6 = parseIpv6(ip);
  return v6 === null ? null : { v: 6, value: v6 };
}

/** A parsed CIDR (a bare address is its own /32 or /128); null if malformed. */
interface Net {
  v: 4 | 6;
  base: bigint;
  bits: number;
}

function parseNet(raw: string): Net | null {
  const [addr, bitsRaw, extra] = raw.trim().split("/");
  if (extra !== undefined) return null;
  const ip = parseIp(addr);
  if (ip === null) return null;
  const max = BITS[ip.v];
  let bits: number = max;
  if (bitsRaw !== undefined) {
    if (!/^\d{1,3}$/.test(bitsRaw)) return null;
    bits = Number(bitsRaw);
    if (bits > max) return null;
  }
  return { v: ip.v, base: ip.value & mask(ip.v, bits), bits };
}

function mask(v: 4 | 6, bits: number): bigint {
  const max = BigInt(BITS[v]);
  const all = (1n << max) - 1n;
  return bits === 0 ? 0n : (all >> (max - BigInt(bits))) << (max - BigInt(bits));
}

/** True when `inner` lies entirely inside `outer` (same family, no wider, same prefix bits). */
function netContains(outer: Net, inner: Net): boolean {
  return outer.v === inner.v && outer.bits <= inner.bits && (inner.base & mask(outer.v, outer.bits)) === outer.base;
}

/**
 * Host/CIDR membership for a single target. IPv4 and IPv6 ranges are
 * bit-compared; a non-address entry (a hostname) matches only itself,
 * case-insensitively. A malformed entry matches nothing — never everything.
 */
export function targetInScope(scope: string[], target: string): boolean {
  const host = target.replace(/^\[|\]$/g, "").split("/")[0].trim();
  const ip = parseIp(host);
  for (const raw of scope) {
    const entry = raw.trim();
    if (entry === "") continue;
    if (entry.toLowerCase() === host.toLowerCase()) return true;
    if (ip === null) continue;
    const net = parseNet(entry);
    if (net !== null && netContains(net, { v: ip.v, base: ip.value, bits: BITS[ip.v] })) return true;
  }
  return false;
}

/** True when the whole of `network` (a CIDR) lies inside a single LIGOLO_SCOPE entry. */
export function networkInScope(scope: string[], network: string): boolean {
  const net = parseNet(network);
  if (net === null) return false;
  return scope.some((raw) => {
    const entry = parseNet(raw);
    return entry !== null && netContains(entry, net);
  });
}

/** True when `target` (an address) lies inside `network` (a CIDR). */
export function targetInNetwork(network: string, target: string): boolean {
  const net = parseNet(network);
  const ip = parseIp(target.split("/")[0]);
  if (net === null || ip === null) return false;
  return netContains(net, { v: ip.v, base: ip.value, bits: BITS[ip.v] });
}

/**
 * The lateral-movement gate.
 *
 * `LIGOLO_SCOPE` lists the hosts/CIDRs you are authorized to reach; every
 * reachability-changing call must name a target inside it *and* pass
 * `confirmed: true` (the human approval). Unset → refuse and say so.
 *
 * There is deliberately no `--force`/`LIGOLO_GATE=off`: a gate that can be
 * switched off is not a gate.
 */
export function assertScope(cfg: Config, target: string, confirmed: boolean): void {
  if (cfg.scope.length === 0) {
    throw new GateError(
      "no authorization source configured: set LIGOLO_SCOPE to the hosts/CIDRs you are authorized to reach " +
        "(comma-separated). Read-only tools work either way.",
      4,
    );
  }
  if (!targetInScope(cfg.scope, target)) {
    throw new GateError(
      `${target} is not inside LIGOLO_SCOPE (${cfg.scope.join(", ")}). ` +
        "Only the listed hosts/CIDRs are authorized; extend the list deliberately or name an authorized target.",
      3,
    );
  }
  if (!confirmed) {
    throw new GateError(
      `${target} is inside LIGOLO_SCOPE, but this is a hard checkpoint: re-call with confirmed: true after a ` +
        "human has approved the pivot.",
      5,
    );
  }
}

/**
 * The gate for a route: a route makes a whole range reachable, so a single
 * in-scope host must not authorize a wider one. The routed network has to fit
 * inside one LIGOLO_SCOPE entry, and `target` has to lie inside the network —
 * then the usual target check and human confirmation apply.
 */
export function assertRouteScope(cfg: Config, network: string, target: string, confirmed: boolean): void {
  if (cfg.scope.length > 0 && !networkInScope(cfg.scope, network)) {
    throw new GateError(
      `route ${network} is not contained in LIGOLO_SCOPE (${cfg.scope.join(", ")}). ` +
        "A route makes the whole range reachable, so every address in it must be authorized: route a narrower " +
        "network that fits inside one scope entry, or extend the list deliberately.",
      3,
    );
  }
  if (cfg.scope.length > 0 && !targetInNetwork(network, target)) {
    throw new GateError(
      `target ${target} is not inside the routed network ${network}. Name an in-scope host that this route ` +
        "actually makes reachable.",
      3,
    );
  }
  assertScope(cfg, target, confirmed);
}

/** Colon-free uppercase SHA-256 of the proxy's cached selfcert — exactly what `-accept-fingerprint` takes. */
export function certFingerprint(cfg: Config): string {
  const path = join(cfg.selfcertDir, `${cfg.selfcertDomain}_cert`);
  if (!existsSync(path)) {
    throw new Error(
      `selfcert cache not found at ${path}. Start the proxy with -selfcert (ligolo_proxy_start does), ` +
        "or set LIGOLO_SELFCERT_DIR / LIGOLO_SELFCERT_DOMAIN to match where it caches.",
    );
  }
  const cert = new X509Certificate(readFileSync(path));
  return cert.fingerprint256.replace(/:/g, "").toUpperCase();
}

export interface AgentNetworkInterface {
  Index: number;
  MTU: number;
  Name: string;
  HardwareAddr: string;
  Flags: number;
  Addresses: string[] | null;
}

export interface AgentRecord {
  Name: string;
  Network: AgentNetworkInterface[] | null;
  SessionID: string;
  RemoteAddr: string;
  Interface: string;
  Running: boolean;
  Listeners: unknown[] | null;
}

export interface ListenerRecord {
  ListenerID: number;
  AgentID: number;
  Agent: string;
  RemoteAddr: string;
  SessionID: string;
  Network: string;
  ListenerAddr: string;
  RedirectAddr: string;
  Online: boolean;
}

export interface InterfaceRecord {
  Routes: { Destination: string; Active: boolean }[] | null;
  Active: boolean;
}

export type Agents = Record<string, AgentRecord>;

function decodeExpiry(jwt: string): number {
  const parts = jwt.split(".");
  if (parts.length !== 3) return 0;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { exp?: number };
    return typeof claims.exp === "number" ? claims.exp : 0;
  } catch {
    return 0;
  }
}

export class LigoloApi {
  private tokenValue = "";
  private tokenExpiry = 0;

  constructor(private readonly cfg: Config) {
    if (cfg.token !== "") {
      this.tokenValue = cfg.token;
      this.tokenExpiry = decodeExpiry(cfg.token);
    }
  }

  get baseUrl(): string {
    return this.cfg.apiUrl;
  }

  private async http(method: string, path: string, body?: unknown, token?: string): Promise<unknown> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    // The proxy reads this header raw — a "Bearer " prefix makes every
    // authenticated call 401. (Verified against proxy 0.9.1.)
    if (token !== undefined && token !== "") headers.Authorization = token;
    const res = await fetch(`${this.cfg.apiUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text();
    let parsed: unknown = text;
    try {
      parsed = text === "" ? null : JSON.parse(text);
    } catch {
      /* keep raw text */
    }
    if (!res.ok) {
      const hint = res.status === 401 ? " (proxy API rejects the token — check LIGOLO_USER/LIGOLO_PASSWORD)" : "";
      const msg =
        typeof parsed === "object" && parsed !== null && "error" in parsed
          ? String((parsed as { error: unknown }).error)
          : text.slice(0, 300);
      throw new Error(`${method} ${path} -> HTTP ${res.status}${hint}: ${msg}`);
    }
    return parsed;
  }

  /**
   * Credentials are minted by `proxy_start` *after* this server has loaded its
   * config, so a process started first holds an empty password forever — the
   * proxy runs, `proxy_status` answers, and every API call fails with "no API
   * credentials" even though `.ligolo-mcp-credentials` exists on disk. Re-read
   * that file on demand rather than trusting the startup snapshot.
   */
  private refreshCredsFromDisk(): void {
    if (this.cfg.token !== "" || this.cfg.password !== "") return;
    const path = this.cfg.credsPath ?? "";
    if (path === "" || !existsSync(path)) return;
    const fresh = readCreds(path);
    if (fresh.password) {
      this.cfg.password = fresh.password;
      if (fresh.user) this.cfg.user = fresh.user;
    }
  }

  private async authToken(force = false): Promise<string> {
    if (!force && this.tokenValue !== "" && (this.tokenExpiry === 0 || this.tokenExpiry - 30 > Date.now() / 1000)) {
      return this.tokenValue;
    }
    this.refreshCredsFromDisk();
    if (this.cfg.password === "" && this.cfg.token === "") {
      throw new Error(
        "no API credentials: set LIGOLO_PASSWORD (and LIGOLO_USER) or LIGOLO_TOKEN. " +
          "The proxy config's web.users holds the argon2id hash; /api/auth needs the plaintext.",
      );
    }
    const res = (await this.http("POST", "/api/auth", {
      username: this.cfg.user,
      password: this.cfg.password,
    })) as { token?: string };
    if (!res || typeof res.token !== "string") throw new Error("/api/auth returned no token");
    this.tokenValue = res.token;
    this.tokenExpiry = decodeExpiry(res.token);
    return this.tokenValue;
  }

  /** Authenticated call with a single transparent retry when the 1h JWT expired. */
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const token = await this.authToken();
    try {
      return (await this.http(method, path, body, token)) as T;
    } catch (err) {
      if (err instanceof Error && /HTTP 401/.test(err.message)) {
        const fresh = await this.authToken(true);
        return (await this.http(method, path, body, fresh)) as T;
      }
      throw err;
    }
  }

  ping(): Promise<{ message: string }> {
    return this.call("GET", "/api/v1/ping");
  }

  agents(): Promise<Agents> {
    return this.call("GET", "/api/v1/agents");
  }

  interfaces(): Promise<Record<string, InterfaceRecord>> {
    return this.call("GET", "/api/v1/interfaces");
  }

  listeners(): Promise<ListenerRecord[] | null> {
    return this.call("GET", "/api/v1/listeners");
  }

  /**
   * With CAP_NET_ADMIN the proxy creates a real kernel TUN, and that device
   * outlives the proxy. A later proxy with a fresh config then fails with
   * "Tuntap IOCTL TUNSETIFF failed [0], errno device or resource busy", which
   * names neither the cause nor the fix. (Seen against proxy 0.9.1.)
   */
  async createInterface(name: string): Promise<{ message: string }> {
    try {
      return await this.call("POST", "/api/v1/interfaces", { Interface: name });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/TUNSETIFF/i.test(msg) && /busy/i.test(msg)) {
        throw new Error(
          `${msg} — a TUN device named ${name} already exists on this host, usually left by an earlier proxy ` +
            `(kernel TUNs outlive the process). Check with \`ip -d link show ${name}\`; remove it with ` +
            `\`sudo ip link delete ${name}\`, or pick another interface name. Teardown with deleteInterface: true ` +
            "removes it while the proxy that knows it is still running.",
        );
      }
      throw err;
    }
  }

  deleteInterface(name: string): Promise<{ message: string }> {
    return this.call("DELETE", "/api/v1/interfaces", { Interface: name });
  }

  addRoutes(iface: string, routes: string[]): Promise<{ message: string }> {
    return this.call("POST", "/api/v1/routes", { Interface: iface, Route: routes });
  }

  /**
   * Removing a route that is already gone (its interface was deleted first, or
   * the tunnel was stopped) comes back as HTTP 500 "no such process" — the
   * desired end state, reported as a failure. Cleanup must be idempotent, so
   * treat that specific case as success and say so.
   */
  async deleteRoute(iface: string, route: string): Promise<{ message: string }> {
    try {
      return await this.call("DELETE", "/api/v1/routes", { Interface: iface, Route: route });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/HTTP 500/.test(msg) && /no such process/i.test(msg)) {
        return { message: `Route ${route} on ${iface} was already absent — nothing to remove.` };
      }
      throw err;
    }
  }

  /**
   * "tun.New device or resource busy" means the proxy itself still holds the
   * device — typically a tunnel orphaned when a running tunnel was started on
   * another interface (ligolo 0.9.x). Only a proxy restart releases it.
   */
  async startTunnel(agentId: string, iface: string): Promise<{ message: string }> {
    try {
      return await this.call("POST", `/api/v1/tunnel/${encodeURIComponent(agentId)}`, { Interface: iface });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/tun\.New/i.test(msg) && /busy/i.test(msg)) {
        throw new Error(
          `${msg} — the proxy still holds ${iface}, usually from a tunnel orphaned when a running tunnel was ` +
            "started on another interface. Only a proxy restart frees it: use a fresh interface name now " +
            "(and move its routes there), or restart the proxy when convenient.",
        );
      }
      throw err;
    }
  }

  stopTunnel(agentId: string): Promise<{ message: string }> {
    return this.call("DELETE", `/api/v1/tunnel/${encodeURIComponent(agentId)}`, { Interface: this.cfg.interfaceName });
  }

  createListener(agentId: string, listenerAddr: string, redirectAddr: string, network: string): Promise<{ message: string }> {
    return this.call("POST", "/api/v1/listeners", {
      AgentID: Number(agentId),
      ListenerAddr: listenerAddr,
      RedirectAddr: redirectAddr,
      Network: network,
    });
  }

  deleteListener(agentId: string, listenerId: number): Promise<{ message: string }> {
    return this.call("DELETE", "/api/v1/listeners", { AgentID: Number(agentId), ListenerID: listenerId });
  }
}

/** Resolve one agent by id, with the failure mode a caller can act on. */
export async function requireAgent(api: LigoloApi, agentId: string): Promise<AgentRecord> {
  const agents = await api.agents();
  const agent = agents?.[agentId];
  if (!agent) {
    const known = Object.keys(agents ?? {});
    throw new Error(
      `agent ${agentId} not connected (known ids: ${known.length === 0 ? "none" : known.join(", ")}). ` +
        "Check ligolo_agents_list, and that the agent on the foothold is still running with -reconnect.",
    );
  }
  return agent;
}
