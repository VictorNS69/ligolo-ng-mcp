// Ligolo-ng MCP — proxy lifecycle (start / stop / status).
//
// Formerly this was `ssh kali "nohup ligolo-proxy …"`: a wrong binary
// name (`ligolo-proxy` does not exist — upstream ships `proxy`), a
// remote-host assumption, and a `pgrep` that cannot tell "my proxy" from
// "somebody else's". Here the proxy is a local child process with a pid
// file next to its config, and liveness is answered by its own API.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { Config, LigoloApi } from "./ligolo.js";

/**
 * Per-call agent-facing port override.
 *
 * `LIGOLO_PROXY_ADDR` is the session-wide default, but the port is the one
 * thing that legitimately changes between pivots (an operator may already
 * hold 11601 for another proxy, or need a port that survives a restrictive
 * egress rule). Only the port is replaceable, and only if it is numeric —
 * a malformed value must not silently rewrite the listen address.
 */
export function applyPortOverride(cfg: Config, port: string): void {
  const trimmed = port.trim();
  if (trimmed === "") return;
  if (!/^\d{1,5}$/.test(trimmed) || Number(trimmed) > 65535) {
    throw new Error(`invalid port '${port}': expected 1-65535`);
  }
  const host = cfg.proxyAddr.includes(":") ? cfg.proxyAddr.slice(0, cfg.proxyAddr.lastIndexOf(":")) : cfg.proxyAddr;
  cfg.proxyAddr = `${host}:${Number(trimmed)}`;
}

export interface ProxyState {
  running: boolean;
  pid: number | null;
  apiUrl: string;
  binary: string | null;
  configPath: string;
  logPath: string;
}

function pidPath(cfg: Config): string {
  return join(dirname(cfg.proxyConfig), ".ligolo-mcp-proxy.pid");
}

function logPath(cfg: Config): string {
  return join(dirname(cfg.proxyConfig), "ligolo-proxy.log");
}

function readPid(cfg: Config): number | null {
  const file = pidPath(cfg);
  if (!existsSync(file)) return null;
  const raw = readFileSync(file, "utf8").trim();
  const pid = Number(raw);
  return Number.isInteger(pid) && pid > 1 ? pid : null;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Write the minimum config that makes the proxy headless and API-only:
 *
 *  - web.enabled / web.enableui: the REST API is what we drive; the
 *    browser UI and its first-run prompt are not wanted.
 *  - web.logfile: "" — otherwise every start drops a gin `ui.log` in the
 *    working directory.
 *  - web.users: a plaintext password here is what /api/auth needs; the
 *    proxy re-hashes it to argon2id and rewrites the file on first load.
 *
 * An existing config is never rewritten silently: `rewrite` must be
 * explicit, and the original is backed up first.
 */
export function seedConfig(cfg: Config, rewrite: boolean): { created: boolean; backup: string | null; path: string } {
  const path = cfg.proxyConfig;
  mkdirSync(dirname(path), { recursive: true });

  if (existsSync(path) && !rewrite) {
    const existing = readFileSync(path, "utf8");
    if (!/^\s*enabled:\s*true/m.test(existing) || !/^\s*users:/m.test(existing)) {
      throw new Error(
        `${path} exists but does not enable the web/API surface or define web.users. ` +
          "Re-call ligolo_proxy_start with rewriteConfig: true (the original is backed up as .bak), " +
          "or add `web.enabled: true` + `web.users` to it yourself.",
      );
    }
    return { created: false, backup: null, path };
  }

  let backup: string | null = null;
  if (existsSync(path)) {
    backup = `${path}.bak`;
    writeFileSync(backup, readFileSync(path), { mode: 0o600 });
  }

  // No password supplied: generate one and keep it in a 0600 file next to the
  // config, so registering this MCP never requires a secret in the runtime's
  // config and a hand-driven `curl` can still read the credential.
  if (cfg.password === "") {
    cfg.password = randomBytes(24).toString("hex");
    writeFileSync(cfg.credsPath, JSON.stringify({ user: cfg.user, password: cfg.password }, null, 2), {
      mode: 0o600,
    });
  }

  const yaml = [
    "proxy:",
    "  historyfile: ligolo-ng.history",
    `  selfcertcache: ${JSON.stringify(cfg.selfcertDir)}`,
    "web:",
    "  enabled: true",
    "  enableui: false",
    `  listen: ${JSON.stringify(cfg.apiListen)}`,
    '  logfile: ""',
    "  users:",
    `    ${cfg.user}: ${JSON.stringify(cfg.password)}`,
    "",
  ].join("\n");
  writeFileSync(path, yaml, { mode: 0o600 });
  return { created: true, backup, path };
}

export async function proxyStatus(cfg: Config): Promise<ProxyState> {
  const pid = readPid(cfg);
  const api = new LigoloApi(cfg);
  let apiUp = false;
  try {
    await api.ping();
    apiUp = true;
  } catch {
    apiUp = false;
  }
  return {
    running: apiUp || (pid !== null && alive(pid)),
    pid: pid !== null && alive(pid) ? pid : null,
    apiUrl: cfg.apiUrl,
    binary: cfg.proxyBin,
    configPath: cfg.proxyConfig,
    logPath: logPath(cfg),
  };
}

export async function startProxy(cfg: Config, rewriteConfig: boolean): Promise<ProxyState & { seeded: boolean }> {
  if (cfg.proxyBin === null) {
    throw new Error(
      "proxy binary not found. Set LIGOLO_NG_DIR to the directory holding the ligolo-ng release binaries " +
        "(proxy + agent), or LIGOLO_PROXY_BIN to the binary itself.",
    );
  }

  const api = new LigoloApi(cfg);
  try {
    await api.ping();
    const state = await proxyStatus(cfg);
    return { ...state, running: true, seeded: false };
  } catch {
    /* not up — start it */
  }

  const existingPid = readPid(cfg);
  if (existingPid !== null && alive(existingPid)) {
    throw new Error(
      `a proxy process (pid ${existingPid}) is running but ${cfg.apiUrl} does not answer /api/v1/ping. ` +
        "Stop it (ligolo_proxy_stop) and start again, or point LIGOLO_API at the right address.",
    );
  }

  const seeded = seedConfig(cfg, rewriteConfig);
  const out = openSync(logPath(cfg), "a", 0o600);
  const child = spawn(
    cfg.proxyBin,
    ["-daemon", "-selfcert", "-nobanner", "-laddr", cfg.proxyAddr, "-config", cfg.proxyConfig],
    {
      cwd: dirname(cfg.proxyConfig),
      detached: true,
      stdio: ["ignore", out, out],
    },
  );
  child.unref();
  closeSync(out);
  if (child.pid === undefined) throw new Error("failed to spawn the proxy process");
  writeFileSync(pidPath(cfg), `${child.pid}\n`);

  const deadline = Date.now() + 20000;
  let lastError = "";
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 400));
    try {
      await api.ping();
      const state = await proxyStatus(cfg);
      return { ...state, running: true, seeded: Boolean(seeded.created) };
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
    `proxy did not answer ${cfg.apiUrl}/api/v1/ping within 20s (log: ${logPath(cfg)}). ` +
      `Last error: ${lastError}`,
  );
}

export async function stopProxy(cfg: Config): Promise<ProxyState & { signal: string; stoppedPid: number | null }> {
  const pid = readPid(cfg);
  if (pid === null || !alive(pid)) {
    return { ...(await proxyStatus(cfg)), running: false, pid: null, signal: "not-running", stoppedPid: null };
  }
  process.kill(pid, "SIGTERM");
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && alive(pid)) await new Promise((r) => setTimeout(r, 200));
  const stillAlive = alive(pid);
  if (!stillAlive) {
    try {
      writeFileSync(pidPath(cfg), "");
    } catch {
      /* best effort */
    }
  }
  const state = await proxyStatus(cfg);
  return {
    ...state,
    running: stillAlive && state.running,
    pid: stillAlive ? pid : null,
    signal: "SIGTERM",
    stoppedPid: pid,
  };
}
