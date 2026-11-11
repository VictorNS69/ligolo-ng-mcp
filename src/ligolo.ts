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
// Two behaviours are non-negotiable, because this server is meant to run
// inside a governed assessment framework (BITORIA):
//
//   1. Every reachability-changing call (route add, tunnel start,
//      listener add) passes `scripts/common/scope_check.py --technique
//      lateral --checkpoint` *before* an HTTP request leaves the
//      process. Denied = nothing happened, and the error says why.
//   2. Every call is recorded through `scripts/common/log_command.sh`,
//      so the assessment's commands.log stays a complete audit trail.
//
// A ligolo MCP that skips those two is unusable for real engagement
// work regardless of how tidy its tool surface is.

import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

export interface Config {
  /** Proxy REST API base URL, e.g. http://127.0.0.1:8080 */
  apiUrl: string;
  /** API credentials (argon2id hashes live in the proxy config; these are plaintext for /api/auth). */
  user: string;
  password: string;
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
  /** Assessment folder name/path — required for anything gated. */
  assessment: string;
  /** How `assessment` was resolved: env | marker | none | expired | invalid. */
  assessmentSource: string;
  /** Human-readable reason, quoted back when a gate denies for lack of an assessment. */
  assessmentDetail: string;
  /** 0600 file holding {user,password} for the API, written by proxy_start when it seeds a config. */
  credsPath: string;
  /** Repo root that owns scripts/common/scope_check.py, or null if not found. */
  bitoriaRoot: string | null;
  /** When true, mutating tools are not registered at all. */
  readOnly: boolean;
  /**
   * Standalone authorization: hosts/CIDRs this server may pivot to when no
   * BITORIA assessment is in play. Empty means "no standalone authorization",
   * which makes mutating tools refuse — the server still works read-only.
   */
  standaloneScope: string[];
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

/**
 * Walk up from `start` looking for the framework root that owns
 * scripts/common/scope_check.py. Lets the server be launched from any
 * cwd without hardcoding a machine-specific path.
 */
export function findBitoriaRoot(start: string): string | null {
  let dir = resolve(start);
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, "scripts", "common", "scope_check.py"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export interface AssessmentResolution {
  name: string;
  source: "env" | "marker" | "none" | "expired" | "invalid";
  detail: string;
}

/**
 * Which assessment this session belongs to.
 *
 * Mirrors `orchestrator/assessment_scope.py` exactly — same marker file,
 * same 12h TTL, same "a marker naming a missing folder is invalid" rule —
 * so the tool that gates on it agrees with the filesystem guard instead of
 * inventing a second notion of "active assessment". Env wins when set
 * (`LIGOLO_ASSESSMENT`), which is what a per-assessment dispatch uses.
 */
export function resolveAssessment(
  root: string | null,
  envValue: string,
  now: number = Date.now(),
  ttlHours = 12,
): AssessmentResolution {
  if (envValue !== "") return { name: envValue, source: "env", detail: "LIGOLO_ASSESSMENT" };
  if (root === null) return { name: "", source: "none", detail: "framework root unknown" };
  const marker = join(root, "state", "assessment-scope.json");
  if (!existsSync(marker)) return { name: "", source: "none", detail: "no active assessment marker" };
  let data: { assessment?: unknown; updated_at?: unknown };
  try {
    data = JSON.parse(readFileSync(marker, "utf8")) as typeof data;
  } catch (err) {
    return { name: "", source: "invalid", detail: `marker unreadable (${String(err)})` };
  }
  const name = typeof data.assessment === "string" ? data.assessment.trim() : "";
  if (name === "") return { name: "", source: "invalid", detail: "marker names no assessment" };
  if (!existsSync(join(root, "assessments", name))) {
    return { name, source: "invalid", detail: `${join(root, "assessments", name)} no longer exists` };
  }
  const stamp = typeof data.updated_at === "string" ? Date.parse(data.updated_at) : Number.NaN;
  if (!Number.isNaN(stamp)) {
    const ageHours = (now - stamp) / 3_600_000;
    if (ageHours > ttlHours) {
      return {
        name,
        source: "expired",
        detail: `marker is ${ageHours.toFixed(1)}h old (TTL ${ttlHours}h) — re-activate with \`pentest assessment activate ${name}\``,
      };
    }
  }
  return { name, source: "marker", detail: "active assessment marker" };
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
  const root = env.LIGOLO_BITORIA_ROOT ? resolve(env.LIGOLO_BITORIA_ROOT) : findBitoriaRoot(cwd);
  const credsPath = join(dirname(proxyConfig), ".ligolo-mcp-credentials");
  const creds = readCreds(credsPath);
  const assessment = resolveAssessment(root, envStr(env, "LIGOLO_ASSESSMENT", ""));
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
    token: envStr(env, "LIGOLO_TOKEN", ""),
    interfaceName: envStr(env, "LIGOLO_INTERFACE", "ligolo"),
    selfcertDir,
    selfcertDomain: envStr(env, "LIGOLO_SELFCERT_DOMAIN", "ligolo"),
    proxyBin: resolveProxyBin(env),
    proxyConfig,
    proxyAddr: envStr(env, "LIGOLO_PROXY_ADDR", "0.0.0.0:11601"),
    apiListen,
    // An expired or invalid marker names an assessment, but it does not
    // *authorize* one: the filesystem guard treats it as development mode, and
    // so must the gate. Keep the name out of `assessment` so a stale marker
    // cannot silently clear a lateral-movement checkpoint.
    assessment: assessment.source === "expired" || assessment.source === "invalid" ? "" : assessment.name,
    assessmentSource: assessment.source,
    assessmentDetail: assessment.detail,
    credsPath,
    bitoriaRoot: root,
    readOnly: /^(1|true|yes|on)$/i.test(envStr(env, "LIGOLO_MCP_READ_ONLY", "")),
    standaloneScope: envStr(env, "LIGOLO_SCOPE", "")
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

/**
 * Run the framework's lateral-movement hard checkpoint for `target`.
 *
 * scope_check.py exits 5 while a human approval is outstanding, so a
 * denial here is information ("record the pivot in state/decisions.md
 * and re-call with confirmed: true"), not a bug to retry blindly.
 */
/**
 * True/false when the assessment's scope.yaml declares `ligolo.mcp`, null when
 * the file exists but says nothing about it. Bit-for-bit the same defaulting
 * rule the assessment interview uses: absent means **off**.
 */
export function assessmentMcpFlag(cfg: Config): boolean | null {
  if (cfg.assessment === "" || cfg.bitoriaRoot === null) return null;
  const dir = cfg.assessment.includes("/") || isAbsolute(cfg.assessment)
    ? resolve(cfg.assessment)
    : join(cfg.bitoriaRoot, "assessments", cfg.assessment);
  const file = join(dir, "scope.yaml");
  if (!existsSync(file)) return null;
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  let inLigolo = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      inLigolo = /^ligolo:\s*$/i.test(trimmed);
      continue;
    }
    if (!inLigolo) continue;
    const match = /^mcp:\s*(true|false)\b/i.exec(trimmed);
    if (match) return match[1].toLowerCase() === "true";
  }
  return null;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8) + octet;
  }
  return value >>> 0;
}

/** Host/CIDR membership. IPv4 ranges bit-compared; anything else exact-match. */
export function targetInScope(scope: string[], target: string): boolean {
  const host = target.replace(/^\[|\]$/g, "").split("/")[0].trim();
  const hostInt = ipv4ToInt(host);
  for (const raw of scope) {
    const entry = raw.trim();
    if (entry === "") continue;
    if (entry.toLowerCase() === host.toLowerCase()) return true;
    const [net, bitsRaw] = entry.split("/");
    if (bitsRaw === undefined) continue;
    const bits = Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue;
    const netInt = ipv4ToInt(net);
    if (netInt === null || hostInt === null) continue;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((hostInt & mask) === (netInt & mask)) return true;
  }
  return false;
}

/**
 * The one gate, two modes.
 *
 * **Framework mode** (an assessment is active and the framework is present):
 * `scope_check.py` runs the lateral hard checkpoint, exactly as a wrapper would,
 * and the assessment's `ligolo.mcp` flag must be `true`. That flag is asked at
 * assessment setup and is **off by default** — the MCP server is optional, so an
 * engagement that never opted in keeps using the console wrapper.
 *
 * **Standalone mode** (no framework, no assessment): `LIGOLO_SCOPE` lists the
 * hosts/CIDRs you are authorized to reach, and every reachability-changing call
 * must name a target inside it *and* pass `confirmed: true`. This exists because
 * the server must be usable outside BITORIA; refusing every pivot without a
 * framework would make it a read-only viewer for anyone else.
 *
 * Neither mode configured → refuse and say so. There is deliberately no
 * `--force`/`LIGOLO_GATE=off`: a gate that can be switched off is not a gate.
 */
export function assertScope(cfg: Config, target: string, confirmed: boolean): void {
  const frameworkMode = cfg.assessment !== "" && cfg.bitoriaRoot !== null;

  if (frameworkMode) {
    const flag = assessmentMcpFlag(cfg);
    if (flag !== true) {
      throw new GateError(
        `the ligolo MCP server is not enabled for assessment ${cfg.assessment}` +
          (flag === null ? " (scope.yaml has no `ligolo:` block)" : " (`ligolo.mcp: false`)") +
          ". It is off by default: either enable it with `ligolo:\n  mcp: true` in scope.yaml and re-run, " +
          "or drive the pivot through scripts/pivoting/ligolo_console.sh instead.",
        4,
      );
    }
    const script = join(cfg.bitoriaRoot as string, "scripts", "common", "scope_check.py");
    const args = [script, target, "--assessment", cfg.assessment, "--technique", "lateral", "--checkpoint"];
    if (confirmed) args.push("--confirmed");
    const run = spawnSync("python3", args, { encoding: "utf8" });
    if (run.status !== 0) {
      const detail = `${run.stdout ?? ""}${run.stderr ?? ""}`.trim();
      throw new GateError(
        `scope/checkpoint denied for ${target} (exit ${run.status}). ` +
          "Record the pivot (foothold, destination, mechanism, ports) in state/decisions.md, get human " +
          "approval, then re-call with target + confirmed: true." +
          (detail === "" ? "" : `\n${detail}`),
        run.status ?? 1,
      );
    }
    return;
  }

  if (cfg.standaloneScope.length > 0) {
    if (!targetInScope(cfg.standaloneScope, target)) {
      throw new GateError(
        `${target} is not inside LIGOLO_SCOPE (${cfg.standaloneScope.join(", ")}). ` +
          "Standalone mode authorizes only the listed hosts/CIDRs; extend the list deliberately or name an " +
          "authorized target.",
        3,
      );
    }
    if (!confirmed) {
      throw new GateError(
        `${target} is inside LIGOLO_SCOPE, but this is a hard checkpoint: re-call with confirmed: true after a ` +
          "human has approved the pivot and it is written down (state/decisions.md when a framework is present).",
        5,
      );
    }
    return;
  }

  throw new GateError(
    "no authorization source configured. Either activate a BITORIA assessment (with `ligolo.mcp: true`) and " +
      "set LIGOLO_ASSESSMENT / LIGOLO_BITORIA_ROOT, or set LIGOLO_SCOPE to the hosts/CIDRs you are authorized " +
      "to reach (comma-separated). Read-only tools work either way.",
    4,
  );
}

export function logCommand(cfg: Config, summary: string): void {
  if (cfg.assessment === "" || cfg.bitoriaRoot === null) return;
  const script = join(cfg.bitoriaRoot, "scripts", "common", "log_command.sh");
  if (!existsSync(script)) return;
  spawnSync("bash", [script, "--assessment", cfg.assessment, "--tool", "ligolo_mcp", "--cmd", summary], {
    encoding: "utf8",
  });
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
