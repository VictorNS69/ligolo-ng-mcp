// Ligolo-ng MCP — proxy lifecycle (start / stop / status), multi-instance.
//
// Formerly this was `ssh kali "nohup ligolo-proxy …"`: a wrong binary
// name (`ligolo-proxy` does not exist — upstream ships `proxy`), a
// remote-host assumption, and a `pgrep` that cannot tell "my proxy" from
// "somebody else's". Here each proxy is a local child process with its
// own pid file, config, credentials and log.
//
// Instances: a single agent-facing proxy is the normal case, but two are
// legitimate (a second engagement in the same session, a port already
// held by another tool, a segment that must not share routes with the
// first). An instance is therefore a first-class record — name, index,
// ports, workspace, log — kept in a manifest beside the workspace so a
// second server process (or a later session) can see it.
//
// Logs go to `<assessment>/state/ligolo.log`, and `ligolo2.log`,
// `ligolo3.log`, … for the second and later instances: engagement
// evidence belongs in the assessment's state tree, not in a workspace
// scratch dir. With no active assessment they fall back to
// `<workspace>/ligolo[<n>].log`, because there is no state tree to own
// them.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { Config, LigoloApi, readCreds } from "./ligolo.js";

/** One running (or configured) proxy instance. */
export interface InstanceEntry {
  name: string;
  index: number;
  pid: number;
  apiUrl: string;
  proxyAddr: string;
  configPath: string;
  credsPath: string;
  selfcertDir: string;
  workspace: string;
  /** `<assessment>/state/ligolo[<n>].log`, or the workspace fallback. */
  logPath: string;
  assessment: string;
  startedAt: string;
}

export interface ProxyState {
  running: boolean;
  pid: number | null;
  instance: string;
  index: number;
  apiUrl: string;
  binary: string | null;
  configPath: string;
  logPath: string;
  assessment: string;
  /** true when this server owns the process; false for an externally started proxy. */
  managed?: boolean;
  note?: string;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** `<n>` = "" for the first instance, "2", "3", … — so names and files sort readably. */
export function suffixForIndex(index: number): string {
  return index <= 1 ? "" : String(index);
}

export function nameForIndex(index: number): string {
  return `ligolo${suffixForIndex(index)}`;
}

/**
 * Where this session's assessment keeps its state tree, or null when none is
 * active. `LIGOLO_ASSESSMENT` may be a bare folder name (resolved under
 * `<framework>/assessments/`) or a path.
 */
export function assessmentStateDir(cfg: Config): string | null {
  if (cfg.assessment === "") return null;
  const candidates: string[] = [];
  if (cfg.assessment.includes("/") || isAbsolute(cfg.assessment)) {
    candidates.push(cfg.assessment);
  } else if (cfg.bitoriaRoot !== null) {
    candidates.push(join(cfg.bitoriaRoot, "assessments", cfg.assessment));
  }
  for (const dir of candidates) {
    const target = join(resolve(dir), "state");
    if (existsSync(dirname(target)) || existsSync(target)) return target;
  }
  return null;
}

/** Log file for an instance: assessment state tree first, workspace fallback. */
export function logFileFor(cfg: Config, index: number): string {
  const state = assessmentStateDir(cfg);
  const base = state ?? dirname(cfg.proxyConfig);
  return join(base, `ligolo${suffixForIndex(index)}.log`);
}

function manifestPath(cfg: Config): string {
  return join(dirname(cfg.proxyConfig), ".ligolo-mcp-instances.json");
}

export function readManifest(cfg: Config): Record<string, InstanceEntry> {
  const file = manifestPath(cfg);
  if (!existsSync(file)) return {};
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, InstanceEntry>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeManifest(cfg: Config, entries: Record<string, InstanceEntry>): void {
  const file = manifestPath(cfg);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(entries, null, 2)}\n`, { mode: 0o600 });
}

/** Instances whose pid is still alive; entries for dead processes are dropped. */
export function liveInstances(cfg: Config): InstanceEntry[] {
  const all = readManifest(cfg);
  const live = Object.values(all).filter((e) => Number.isInteger(e.pid) && alive(e.pid));
  if (live.length !== Object.keys(all).length) {
    writeManifest(cfg, Object.fromEntries(live.map((e) => [e.name, e])));
  }
  return live.sort((a, b) => a.index - b.index);
}

function portOf(addr: string): number {
  const tail = addr.slice(addr.lastIndexOf(":") + 1);
  const port = Number(tail);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : 0;
}

function nextFreePort(addr: string, taken: Set<number>): string {
  const host = addr.includes(":") ? addr.slice(0, addr.lastIndexOf(":")) : addr;
  let port = portOf(addr);
  if (port === 0) return addr;
  while (taken.has(port)) port += 1;
  return `${host}:${port}`;
}

export interface InstanceSpec {
  name: string;
  index: number;
  workspace: string;
  configPath: string;
  credsPath: string;
  selfcertDir: string;
  apiUrl: string;
  proxyAddr: string;
  logPath: string;
}

/**
 * Work out which instance a start request refers to, without side effects.
 *
 * - an explicit `instance` name reuses that index (creating it if new),
 * - otherwise the first index with no *live* instance,
 * - index 1 keeps the config/creds paths from the environment so existing
 *   registrations and the credential file keep working; later instances get
 *   their own sub-workspace and shifted ports (one per live instance).
 */
export function planInstance(
  cfg: Config,
  opts: { instance?: string; port?: string; apiPort?: string } = {},
): InstanceSpec {
  const live = liveInstances(cfg);
  const usedAgentPorts = new Set(live.map((e) => portOf(e.proxyAddr)));
  const usedApiPorts = new Set(live.map((e) => portOf(e.apiUrl.replace(/^https?:\/\//, ""))));

  let index: number;
  if (opts.instance !== undefined && opts.instance !== "") {
    const match = /^ligolo(\d*)$/.exec(opts.instance);
    if (match === null) {
      throw new Error(`invalid instance name '${opts.instance}': expected "ligolo", "ligolo2", …`);
    }
    index = match[1] === "" ? 1 : Number(match[1]);
    if (index < 1) throw new Error(`invalid instance name '${opts.instance}'`);
    const existing = live.find((e) => e.index === index);
    if (existing) throw new Error(`instance ${existing.name} is already running (pid ${existing.pid})`);
  } else {
    index = 1;
    while (live.some((e) => e.index === index)) index += 1;
  }

  const first = index === 1;
  const workspaceBase = dirname(cfg.proxyConfig);
  const workspace = first ? workspaceBase : join(workspaceBase, nameForIndex(index));
  const proxyAddr =
    opts.port !== undefined && opts.port !== ""
      ? withPort(cfg.proxyAddr, opts.port)
      : first
        ? cfg.proxyAddr
        : nextFreePort(cfg.proxyAddr, usedAgentPorts);
  const apiListen =
    opts.apiPort !== undefined && opts.apiPort !== ""
      ? withPort(cfg.apiListen, opts.apiPort)
      : first
        ? cfg.apiListen
        : nextFreePort(cfg.apiListen, usedApiPorts);

  return {
    name: nameForIndex(index),
    index,
    workspace,
    configPath: first ? cfg.proxyConfig : join(workspace, "ligolo-ng.yaml"),
    credsPath: first ? cfg.credsPath : join(workspace, ".ligolo-mcp-credentials"),
    selfcertDir: first ? cfg.selfcertDir : join(workspace, "ligolo-selfcerts"),
    apiUrl: `http://${apiListen}`,
    proxyAddr,
    logPath: logFileFor(cfg, index),
  };
}

function withPort(addr: string, port: string): string {
  const trimmed = port.trim();
  if (!/^\d{1,5}$/.test(trimmed) || Number(trimmed) > 65535 || Number(trimmed) < 1) {
    throw new Error(`invalid port '${port}': expected 1-65535`);
  }
  const host = addr.includes(":") ? addr.slice(0, addr.lastIndexOf(":")) : addr;
  return `${host}:${Number(trimmed)}`;
}

/**
 * Per-call agent-facing port override on the *default* config. Kept for the
 * single-instance path: `ligolo_proxy_start {port}` with no `instance`.
 */
export function applyPortOverride(cfg: Config, port: string): void {
  if (port.trim() === "") return;
  cfg.proxyAddr = withPort(cfg.proxyAddr, port);
}

/** A Config scoped to one instance: same assessment/gate, that instance's ports and files. */
export function instanceConfig(cfg: Config, entry: InstanceEntry): Config {
  const creds = readCreds(entry.credsPath);
  return {
    ...cfg,
    apiUrl: entry.apiUrl,
    proxyAddr: entry.proxyAddr,
    proxyConfig: entry.configPath,
    credsPath: entry.credsPath,
    selfcertDir: entry.selfcertDir,
    password: creds.password ?? cfg.password,
    user: creds.user ?? cfg.user,
  };
}

/** Config for a named instance; falls back to the environment's default config when unknown. */
export function configForInstance(cfg: Config, name?: string): Config {
  if (name === undefined || name === "" || name === "ligolo") {
    const live = liveInstances(cfg).find((e) => e.index === 1);
    return live ? instanceConfig(cfg, live) : cfg;
  }
  const entry = liveInstances(cfg).find((e) => e.name === name);
  if (!entry) {
    const known = liveInstances(cfg).map((e) => e.name);
    throw new Error(
      `unknown or stopped instance '${name}' (running: ${known.length === 0 ? "none" : known.join(", ")}). ` +
        "Start it with ligolo_proxy_start, or omit `instance` for the default one.",
    );
  }
  return instanceConfig(cfg, entry);
}

/**
 * Write the minimum config that makes the proxy headless and API-only:
 *
 *  - web.enabled / web.enableui: the REST API is what we drive; the browser
 *    UI and its first-run prompt are not wanted.
 *  - web.logfile: "" — otherwise every start drops a gin `ui.log` in the
 *    working directory.
 *  - web.users: a plaintext password here is what /api/auth needs; the proxy
 *    re-hashes it to argon2id and rewrites the file on first load.
 *
 * An existing config is never rewritten silently: `rewrite` must be explicit,
 * and the original is backed up first.
 */
export function seedConfig(
  cfg: Config,
  spec: InstanceSpec,
  rewrite: boolean,
): { created: boolean; backup: string | null; path: string; password: string } {
  const path = spec.configPath;
  mkdirSync(dirname(path), { recursive: true });
  const existingCreds = readCreds(spec.credsPath);
  const password =
    cfg.password !== "" ? cfg.password : (existingCreds.password ?? randomBytes(24).toString("hex"));

  if (existsSync(path) && !rewrite) {
    const existing = readFileSync(path, "utf8");
    if (!/^\s*enabled:\s*true/m.test(existing) || !/^\s*users:/m.test(existing)) {
      throw new Error(
        `${path} exists but does not enable the web/API surface or define web.users. ` +
          "Re-call ligolo_proxy_start with rewriteConfig: true (the original is backed up as .bak), " +
          "or add `web.enabled: true` + `web.users` to it yourself.",
      );
    }
    if (!existsSync(spec.credsPath) && existingCreds.password === undefined) {
      writeFileSync(spec.credsPath, JSON.stringify({ user: cfg.user, password }, null, 2), { mode: 0o600 });
    }
    return { created: false, backup: null, path, password };
  }

  let backup: string | null = null;
  if (existsSync(path)) {
    backup = `${path}.bak`;
    writeFileSync(backup, readFileSync(path), { mode: 0o600 });
  }

  // No password supplied: generate one and keep it in a 0600 file next to the
  // config, so registering this MCP never requires a secret in the runtime's
  // config and a hand-driven `curl` can still read the credential.
  writeFileSync(spec.credsPath, JSON.stringify({ user: cfg.user, password }, null, 2), { mode: 0o600 });

  const yaml = [
    "proxy:",
    `  historyfile: ${JSON.stringify(join(spec.workspace, "ligolo-ng.history"))}`,
    `  selfcertcache: ${JSON.stringify(spec.selfcertDir)}`,
    "web:",
    "  enabled: true",
    "  enableui: false",
    `  listen: ${JSON.stringify(spec.apiUrl.replace(/^https?:\/\//, ""))}`,
    '  logfile: ""',
    "  users:",
    `    ${cfg.user}: ${JSON.stringify(password)}`,
    "",
  ].join("\n");
  writeFileSync(path, yaml, { mode: 0o600 });
  return { created: true, backup, path, password };
}

function stateOf(cfg: Config, spec: InstanceSpec, entry: InstanceEntry | null): ProxyState {
  return {
    running: entry !== null,
    pid: entry?.pid ?? null,
    instance: spec.name,
    index: spec.index,
    apiUrl: spec.apiUrl,
    binary: cfg.proxyBin,
    configPath: spec.configPath,
    logPath: spec.logPath,
    assessment: cfg.assessment,
  };
}

export async function instanceStatus(cfg: Config, name?: string): Promise<ProxyState> {
  const live = liveInstances(cfg);
  const target =
    name === undefined || name === "" ? live.find((e) => e.index === 1) : live.find((e) => e.name === name);
  if (target) {
    const spec = planInstanceQuiet(cfg, target);
    return { ...stateOf(instanceConfig(cfg, target), spec, target), managed: true };
  }
  // No manifest entry: the proxy may still be up because the operator started
  // it by hand or through the console wrapper. Ask the configured API rather
  // than reporting a stopped instance that is answering requests.
  const spec = planInstance(cfg, name === undefined ? {} : { instance: name });
  let reachable = false;
  try {
    await new LigoloApi(cfg).ping();
    reachable = true;
  } catch {
    reachable = false;
  }
  return {
    ...stateOf(cfg, spec, null),
    running: reachable,
    managed: false,
    note: reachable
      ? "external proxy answering the configured API (not started by this server; stop it where it was started)"
      : undefined,
  };
}

function planInstanceQuiet(cfg: Config, entry: InstanceEntry): InstanceSpec {
  return {
    name: entry.name,
    index: entry.index,
    workspace: entry.workspace,
    configPath: entry.configPath,
    credsPath: entry.credsPath,
    selfcertDir: entry.selfcertDir,
    apiUrl: entry.apiUrl,
    proxyAddr: entry.proxyAddr,
    logPath: entry.logPath,
  };
}

export async function startProxy(
  cfg: Config,
  opts: { instance?: string; port?: string; apiPort?: string; rewriteConfig?: boolean } = {},
): Promise<ProxyState & { seeded: boolean; fingerprintError?: string }> {
  if (cfg.proxyBin === null) {
    throw new Error(
      "proxy binary not found. Set LIGOLO_NG_DIR to the directory holding the ligolo-ng release binaries " +
        "(proxy + agent), or LIGOLO_PROXY_BIN to the binary itself.",
    );
  }

  const spec = planInstance(cfg, opts);
  const seeded = seedConfig(cfg, spec, Boolean(opts.rewriteConfig));
  const scoped = { ...cfg, apiUrl: spec.apiUrl, password: seeded.password };
  const api = new LigoloApi(scoped);

  // Already answering on this instance's API: nothing to spawn.
  try {
    await api.ping();
    const existing = liveInstances(cfg).find((e) => e.index === spec.index);
    if (existing) return { ...stateOf(scoped, spec, existing), seeded: false };
  } catch {
    /* not up — start it */
  }

  mkdirSync(dirname(spec.logPath), { recursive: true });
  mkdirSync(spec.workspace, { recursive: true });
  const out = openSync(spec.logPath, "a", 0o600);
  const child = spawn(
    cfg.proxyBin,
    ["-daemon", "-selfcert", "-nobanner", "-laddr", spec.proxyAddr, "-config", spec.configPath],
    {
      cwd: spec.workspace,
      detached: true,
      stdio: ["ignore", out, out],
    },
  );
  child.unref();
  closeSync(out);
  if (child.pid === undefined) throw new Error("failed to spawn the proxy process");

  const record: InstanceEntry = {
    name: spec.name,
    index: spec.index,
    pid: child.pid,
    apiUrl: spec.apiUrl,
    proxyAddr: spec.proxyAddr,
    configPath: spec.configPath,
    credsPath: spec.credsPath,
    selfcertDir: spec.selfcertDir,
    workspace: spec.workspace,
    logPath: spec.logPath,
    assessment: cfg.assessment,
    startedAt: new Date().toISOString(),
  };

  const deadline = Date.now() + 20000;
  let lastError = "";
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 400));
    try {
      await api.ping();
      writeManifest(cfg, { ...readManifest(cfg), [record.name]: record });
      return { ...stateOf(scoped, spec, record), seeded: Boolean(seeded.created) };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    if (!alive(child.pid)) break;
  }

  try {
    process.kill(child.pid, "SIGTERM");
  } catch {
    /* already gone */
  }
  throw new Error(
    `proxy did not answer ${spec.apiUrl}/api/v1/ping within 20s (log: ${spec.logPath}). ` +
      `Last error: ${lastError}`,
  );
}

export async function stopProxy(
  cfg: Config,
  name?: string,
): Promise<ProxyState & { signal: string; stoppedPid: number | null }> {
  const live = liveInstances(cfg);
  const target =
    name === undefined || name === "" ? live.find((e) => e.index === 1) : live.find((e) => e.name === name);
  if (!target) {
    const spec = planInstance(cfg, name === undefined ? {} : { instance: name });
    return { ...stateOf(cfg, spec, null), running: false, pid: null, signal: "not-running", stoppedPid: null };
  }

  process.kill(target.pid, "SIGTERM");
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && alive(target.pid)) await new Promise((r) => setTimeout(r, 200));
  const stillAlive = alive(target.pid);
  if (!stillAlive) {
    const remaining = readManifest(cfg);
    delete remaining[target.name];
    writeManifest(cfg, remaining);
  }
  const spec = planInstanceQuiet(cfg, target);
  return {
    ...stateOf(instanceConfig(cfg, target), spec, stillAlive ? target : null),
    running: stillAlive,
    pid: stillAlive ? target.pid : null,
    signal: "SIGTERM",
    stoppedPid: target.pid,
  };
}

/** Every live instance, for `ligolo_proxy_status` with no name. */
export function listInstances(cfg: Config): { entries: InstanceEntry[]; logDir: string | null } {
  return { entries: liveInstances(cfg), logDir: assessmentStateDir(cfg) };
}
