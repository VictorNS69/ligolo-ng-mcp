// End-to-end tests for the ligolo-ng MCP server.
//
// These drive the built server over real MCP stdio JSON-RPC against a
// stub proxy API, so they assert what actually leaves the process: the
// HTTP request bodies sent to the proxy, whether a denied call reached
// the API at all, and the exact fingerprints generated. No ligolo binary
// and no root are required — the live smoke test in README §Testing is
// what exercises the real proxy.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = resolve(HERE, "..", "dist", "index.js");

// ---------------------------------------------------------------- fixtures

function makeFramework(root, { deny = false } = {}) {
  const common = join(root, "scripts", "common");
  mkdirSync(common, { recursive: true });
  writeFileSync(
    join(common, "scope_check.py"),
    [
      "#!/usr/bin/env python3",
      "import os, sys",
      `root = ${JSON.stringify(root)}`,
      "open(os.path.join(root, 'scope_calls.log'), 'a').write(' '.join(sys.argv[1:]) + '\\n')",
      "deny = os.path.exists(os.path.join(root, 'deny'))",
      "if '--checkpoint' not in sys.argv:",
      "    sys.stderr.write('fixture: checkpoint flag missing\\n'); sys.exit(2)",
      "if '--confirmed' not in sys.argv and deny:",
      "    sys.stderr.write('fixture: checkpoint pending human approval\\n'); sys.exit(5)",
      "sys.exit(0)",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(common, "log_command.sh"),
    [
      "#!/usr/bin/env bash",
      `printf '%s\\n' "$*" >> ${JSON.stringify(join(root, "commands.log"))}`,
      "",
    ].join("\n"),
  );
  chmodSync(join(common, "scope_check.py"), 0o755);
  chmodSync(join(common, "log_command.sh"), 0o755);
  if (deny) writeFileSync(join(root, "deny"), "1\n");
  return root;
}

function makeCerts(dir, domain = "ligolo") {
  mkdirSync(dir, { recursive: true });
  const key = join(dir, "key.pem");
  const cert = join(dir, `${domain}_cert`);
  const r = spawnSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", `/CN=${domain}`],
    { encoding: "utf8" },
  );
  if (r.status !== 0) throw new Error(`openssl failed: ${r.error ?? r.stderr}`);
  return cert;
}

/** Stub of the ligolo proxy REST API, recording every mutating request. */
function makeApi() {
  const state = {
    calls: [],
    agents: {
      1: {
        Name: "victim@host",
        Network: [
          { Index: 1, MTU: 1500, Name: "eth0", HardwareAddr: "00:11:22:33:44:55", Flags: 51, Addresses: ["10.0.0.5/24"] },
          { Index: 2, MTU: 1500, Name: "eth1", HardwareAddr: "00:11:22:33:44:66", Flags: 51, Addresses: ["172.16.5.9/24"] },
        ],
        SessionID: "abc123",
        RemoteAddr: "10.0.0.5:51234",
        Interface: "",
        Running: false,
        Listeners: null,
      },
    },
    interfaces: {},
    listeners: [],
    tokens: 0,
  };
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const url = req.url ?? "/";
      const send = (code, payload) => {
        res.writeHead(code, { "Content-Type": "application/json" });
        res.end(JSON.stringify(payload));
      };
      if (url === "/api/auth" && req.method === "POST") {
        state.tokens += 1;
        return send(200, { token: fakeJwt() });
      }
      const auth = req.headers.authorization;
      if (!auth || auth.startsWith("Bearer ")) return send(401, { error: "Unauthorized" });
      const parsed = body === "" ? undefined : JSON.parse(body);
      state.calls.push({ method: req.method, path: url, body: parsed });

      if (url === "/api/v1/ping") return send(200, { message: "pong" });
      if (url === "/api/v1/agents") return send(200, state.agents);
      if (url === "/api/v1/interfaces" && req.method === "GET") return send(200, state.interfaces);
      if (url === "/api/v1/interfaces" && req.method === "POST") {
        if (parsed.Interface === "busyif") {
          return send(500, { error: "Tuntap IOCTL TUNSETIFF failed [0], errno device or resource busy" });
        }
        state.interfaces[parsed.Interface] = { Routes: [], Active: true };
        return send(200, { message: `Interface ${parsed.Interface} created.` });
      }
      if (url === "/api/v1/interfaces" && req.method === "DELETE") {
        delete state.interfaces[parsed.Interface];
        return send(200, { message: "interface deleted" });
      }
      if (url === "/api/v1/routes" && req.method === "POST") {
        const rec = (state.interfaces[parsed.Interface] ??= { Routes: [], Active: true });
        // The real proxy answers 500 for a route it already has; the fake has to
        // reproduce that or the idempotency path below is never exercised.
        const dup = parsed.Route.find((r) => rec.Routes.some((existing) => existing.Destination === r));
        if (dup !== undefined) return send(500, { error: `route ${dup} already exists` });
        for (const r of parsed.Route) rec.Routes.push({ Destination: r, Active: true });
        return send(200, { message: `Routes ${parsed.Route} added.` });
      }
      if (url === "/api/v1/routes" && req.method === "DELETE") {
        const rec = state.interfaces[parsed.Interface];
        if (rec) rec.Routes = rec.Routes.filter((r) => r.Destination !== parsed.Route);
        return send(200, { message: `Route ${parsed.Route} deleted.` });
      }
      if (url === "/api/v1/listeners" && req.method === "GET") return send(200, state.listeners);
      if (url === "/api/v1/listeners" && req.method === "POST") {
        const rec = {
          ListenerID: state.listeners.length,
          AgentID: parsed.AgentID,
          Agent: "victim@host",
          RemoteAddr: "10.0.0.5:51234",
          SessionID: "abc123",
          Network: parsed.Network,
          ListenerAddr: parsed.ListenerAddr,
          RedirectAddr: parsed.RedirectAddr,
          Online: true,
        };
        state.listeners.push(rec);
        return send(200, { message: "listener created" });
      }
      if (url === "/api/v1/listeners" && req.method === "DELETE") {
        const before = state.listeners.length;
        state.listeners = state.listeners.filter((l) => l.ListenerID !== parsed.ListenerID);
        if (before === state.listeners.length) return send(500, { error: "invalid listener" });
        return send(200, { message: "listener deleted" });
      }
      if (/^\/api\/v1\/tunnel\/\d+$/.test(url) && req.method === "POST") {
        state.calls.at(-1).body = parsed;
        if (parsed.Interface === "heldtun") {
          return send(500, { error: "unable to open tun interface 'heldtun' (tun.New device or resource busy)" });
        }
        return send(200, { message: "tunnel starting" });
      }
      if (/^\/api\/v1\/tunnel\/\d+$/.test(url) && req.method === "DELETE") {
        return send(200, { message: "tunnel stopping" });
      }
      return send(404, { error: `no route ${req.method} ${url}` });
    });
  });
  return { server, state };
}

function fakeJwt(expOffsetSeconds = 3600) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const claims = Buffer.from(
    JSON.stringify({ username: "ligolo", exp: Math.floor(Date.now() / 1000) + expOffsetSeconds }),
  ).toString("base64url");
  return `${header}.${claims}.sig`;
}

// ---------------------------------------------------------------- MCP client

class McpClient {
  constructor(child) {
    this.child = child;
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      this.buffer += chunk;
      let idx;
      while ((idx = this.buffer.indexOf("\n")) !== -1) {
        const line = this.buffer.slice(0, idx).trim();
        this.buffer = this.buffer.slice(idx + 1);
        if (line === "") continue;
        const msg = JSON.parse(line);
        const waiter = this.pending.get(msg.id);
        if (waiter) {
          this.pending.delete(msg.id);
          waiter(msg);
        }
      }
    });
    child.stderr.setEncoding("utf8");
    this.stderr = "";
    child.stderr.on("data", (c) => (this.stderr += c));
  }

  request(method, params = {}) {
    const id = this.nextId++;
    const payload = { jsonrpc: "2.0", id, method, params };
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => rejectPromise(new Error(`timeout waiting for ${method}`)), 20000);
      this.pending.set(id, (msg) => {
        clearTimeout(timer);
        if (msg.error) rejectPromise(new Error(JSON.stringify(msg.error)));
        else resolvePromise(msg.result);
      });
      this.child.stdin.write(`${JSON.stringify(payload)}\n`);
    });
  }

  async call(name, args = {}) {
    const result = await this.request("tools/call", { name, arguments: args });
    const text = result.content?.[0]?.text ?? "";
    return { isError: Boolean(result.isError), payload: JSON.parse(text) };
  }

  async initAndList() {
    await this.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "1" },
    });
    const listed = await this.request("tools/list");
    return listed.tools.map((t) => t.name);
  }
}

// ---------------------------------------------------------------- harness

async function startServer({
  deny = false,
  readOnly = false,
  certDomain = "ligolo",
  assessment = "test-assessment",
  markerAssessment = null,
  markerAgeHours = 0,
  password = "testpass",
  mcpFlag = true,
  standaloneScope = "",
  env: extraEnv = {},
} = {}) {
  const root = mkdtempSync(join(tmpdir(), "ligolo-mcp-"));
  const framework = makeFramework(join(root, "framework"), { deny });
  // The assessment's scope.yaml decides whether the MCP server is allowed for
  // this engagement at all (`ligolo.mcp`, off by default like the Burp block).
  const assessmentDir = join(framework, "assessments", "test-assessment", "state");
  mkdirSync(assessmentDir, { recursive: true });
  writeFileSync(
    join(framework, "assessments", "test-assessment", "scope.yaml"),
    mcpFlag === null
      ? "in_scope:\n  hosts: ['10.0.0.0/8']\n"
      : `in_scope:\n  hosts: ['10.0.0.0/8']\nligolo:\n  mcp: ${mcpFlag ? "true" : "false"}\n`,
  );
  if (markerAssessment) {
    const stamp = new Date(Date.now() - markerAgeHours * 3_600_000).toISOString().replace(/\.\d+Z$/, "Z");
    mkdirSync(join(framework, "assessments", markerAssessment), { recursive: true });
    writeFileSync(
      join(framework, "assessments", markerAssessment, "scope.yaml"),
      `in_scope:\n  hosts: ['10.0.0.0/8']\nligolo:\n  mcp: ${mcpFlag === false ? "false" : "true"}\n`,
    );
    mkdirSync(join(framework, "state"), { recursive: true });
    writeFileSync(
      join(framework, "state", "assessment-scope.json"),
      JSON.stringify({ assessment: markerAssessment, updated_at: stamp }, null, 2),
    );
  }
  const certDir = join(root, "ligolo-selfcerts");
  const cert = makeCerts(certDir, certDomain);
  const { server, state } = makeApi();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  const workdir = join(root, "work");
  mkdirSync(workdir, { recursive: true });
  const child = spawn(process.execPath, [SERVER], {
    cwd: workdir,
    env: {
      ...process.env,
      LIGOLO_API: `http://127.0.0.1:${port}`,
      LIGOLO_USER: "ligolo",
      LIGOLO_PASSWORD: password,
      LIGOLO_ASSESSMENT: assessment ?? "",
      LIGOLO_BITORIA_ROOT: framework,
      LIGOLO_SELFCERT_DIR: certDir,
      LIGOLO_SELFCERT_DOMAIN: certDomain,
      LIGOLO_PROXY_CONFIG: join(workdir, "ligolo-ng.yaml"),
      LIGOLO_MCP_READ_ONLY: readOnly ? "1" : "",
      LIGOLO_SCOPE: standaloneScope,
      LIGOLO_NG_DIR: "",
      LIGOLO_PROXY_BIN: "",
      ...extraEnv,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const client = new McpClient(child);
  const tools = await client.initAndList();
  const cleanup = async () => {
    child.kill("SIGKILL");
    await new Promise((r) => server.close(r));
  };
  return { client, state, tools, framework, cert, cleanup, workdir };
}

/**
 * A process that looks like a proxy this server spawned: its argv carries
 * `-config <configPath>`, which is how a manifest entry is told apart from an
 * unrelated process that inherited a recycled pid.
 */
function standInProxy(configPath) {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "--", "-config", configPath], {
    stdio: "ignore",
  });
  return child;
}

function mutatingCalls(state) {
  return state.calls.filter((c) => c.method !== "GET" && c.path !== "/api/auth");
}

// ---------------------------------------------------------------- tests

describe("tool surface", () => {
  it("exposes the full 19-tool surface in read-write mode", async () => {
    const h = await startServer();
    try {
      assert.equal(h.tools.length, 19);
      for (const name of [
        "ligolo_proxy_start",
        "ligolo_proxy_status",
        "ligolo_agents_list",
        "ligolo_tunnel_start",
        "ligolo_route_add",
        "ligolo_listener_add",
        "ligolo_teardown",
        "ligolo_certificate_fingerprint",
      ]) {
        assert.ok(h.tools.includes(name), `missing ${name}`);
      }
      assert.ok(!h.tools.includes("ligolo_send_command"), "console passthrough must be gone");
    } finally {
      await h.cleanup();
    }
  });

  it("hides every mutating tool in read-only mode", async () => {
    const h = await startServer({ readOnly: true });
    try {
      assert.ok(h.tools.length < 19);
      assert.ok(h.tools.includes("ligolo_agents_list"));
      for (const name of ["ligolo_tunnel_start", "ligolo_route_add", "ligolo_listener_add", "ligolo_teardown"]) {
        assert.ok(!h.tools.includes(name), `${name} must not be registered read-only`);
      }
    } finally {
      await h.cleanup();
    }
  });
});

describe("agent introspection", () => {
  it("returns interfaces and addresses from GET /api/v1/agents (console ifconfig replacement)", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_agents_list");
      assert.equal(isError, false);
      assert.equal(payload.count, 1);
      const agent = payload.agents[0];
      assert.equal(agent.agent_id, "1");
      assert.equal(agent.name, "victim@host");
      assert.deepEqual(
        agent.interfaces.map((i) => i.name),
        ["eth0", "eth1"],
      );
      assert.deepEqual(agent.interfaces[1].addresses, ["172.16.5.9/24"]);
    } finally {
      await h.cleanup();
    }
  });

  it("resolves a session id and keeps the compatibility tool name", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_session_select", { sessionId: 1 });
      assert.equal(isError, false);
      assert.equal(payload.agent_id, "1");
      assert.equal(payload.session_id, "abc123");
    } finally {
      await h.cleanup();
    }
  });

  it("names the known ids when an agent is missing", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_agent_info", { sessionId: 99 });
      assert.equal(isError, true);
      assert.match(payload.message, /agent 99 not connected \(known ids: 1\)/);
    } finally {
      await h.cleanup();
    }
  });
});

describe("lateral-movement gate", () => {
  it("refuses a denied tunnel start without touching the API", async () => {
    const h = await startServer({ deny: true });
    try {
      const { isError, payload } = await h.client.call("ligolo_tunnel_start", {
        agentId: "1",
        target: "172.16.5.0/24",
      });
      assert.equal(isError, true);
      assert.equal(payload.error, "checkpoint-denied");
      assert.equal(payload.action_taken, false);
      assert.equal(payload.exit_code, 5);
      assert.deepEqual(mutatingCalls(h.state), [], "no mutating HTTP request may leave the process");
      const log = readFileSync(join(h.framework, "scope_calls.log"), "utf8");
      assert.match(log, /--technique lateral --checkpoint/);
      assert.doesNotMatch(log, /--confirmed/);
    } finally {
      await h.cleanup();
    }
  });

  it("passes target + --confirmed when the checkpoint is cleared", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "172.16.5.0/24",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, false);
      assert.equal(payload.scope_checked, true);
      const log = readFileSync(join(h.framework, "scope_calls.log"), "utf8");
      assert.match(log, /172\.16\.5\.9 --assessment test-assessment --technique lateral --checkpoint --confirmed/);
      const post = mutatingCalls(h.state).find((c) => c.path === "/api/v1/routes" && c.method === "POST");
      assert.deepEqual(post.body, { Interface: "ligolo", Route: ["172.16.5.0/24"] });
      const audit = readFileSync(join(h.framework, "commands.log"), "utf8");
      assert.match(audit, /ligolo_route_add instance=ligolo 172\.16\.5\.0\/24 dev ligolo/);
    } finally {
      await h.cleanup();
    }
  });

  it("demands an explicit target for a range wider than /32", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", { network: "10.10.10.0/24" });
      assert.equal(isError, true);
      assert.match(payload.message, /target is required for a range wider than \/32/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("derives the target from a /32 route", async () => {
    const h = await startServer();
    try {
      const { isError } = await h.client.call("ligolo_route_add", { network: "10.10.10.5/32", confirmed: true });
      assert.equal(isError, false);
      const log = readFileSync(join(h.framework, "scope_calls.log"), "utf8");
      assert.match(log, /10\.10\.10\.5 --assessment/);
    } finally {
      await h.cleanup();
    }
  });
});

describe("tunnel and listener operations", () => {
  it("registers the interface, then starts the tunnel", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_tunnel_start", {
        agentId: "1",
        tun: "ligolo2",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, false);
      assert.equal(payload.interface_created, true);
      const calls = mutatingCalls(h.state);
      const created = calls.find((c) => c.path === "/api/v1/interfaces" && c.method === "POST");
      const started = calls.find((c) => c.method === "POST" && c.path === "/api/v1/tunnel/1");
      assert.deepEqual(created.body, { Interface: "ligolo2" });
      assert.deepEqual(started.body, { Interface: "ligolo2" });
      assert.ok(calls.indexOf(created) < calls.indexOf(started), "interface must exist before tunnel start");
    } finally {
      await h.cleanup();
    }
  });

  it("creates a listener with AgentID and Network (the fields the old server omitted)", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_listener_add", {
        localAddress: "0.0.0.0:4444",
        remoteAddress: "127.0.0.1:443",
        agentId: "1",
        target: "10.0.0.5",
        confirmed: true,
      });
      assert.equal(isError, false);
      assert.equal(payload.listener.ListenerAddr, "0.0.0.0:4444");
      const post = mutatingCalls(h.state).find((c) => c.path === "/api/v1/listeners" && c.method === "POST");
      assert.deepEqual(post.body, {
        AgentID: 1,
        ListenerAddr: "0.0.0.0:4444",
        RedirectAddr: "127.0.0.1:443",
        Network: "tcp",
      });
      assert.match(payload.cleanup, /state\/cleanup-pending\.md/);
    } finally {
      await h.cleanup();
    }
  });

  it("tears down listeners, tunnel and interface in that order", async () => {
    const h = await startServer();
    try {
      await h.client.call("ligolo_listener_add", {
        localAddress: "0.0.0.0:4444",
        remoteAddress: "127.0.0.1:443",
        agentId: "1",
        target: "10.0.0.5",
        confirmed: true,
      });
      await h.client.call("ligolo_route_add", { network: "172.16.5.0/24", target: "172.16.5.9", confirmed: true });
      h.state.calls.length = 0;
      const { isError, payload } = await h.client.call("ligolo_teardown", {
        agentId: "1",
        interface: "ligolo",
        deleteInterface: true,
      });
      assert.equal(isError, false);
      assert.ok(payload.steps.every((s) => s.ok), JSON.stringify(payload.steps));
      const order = mutatingCalls(h.state).map((c) => `${c.method} ${c.path}`);
      assert.deepEqual(order, [
        "DELETE /api/v1/listeners",
        "DELETE /api/v1/routes",
        "DELETE /api/v1/tunnel/1",
        "DELETE /api/v1/interfaces",
      ]);
    } finally {
      await h.cleanup();
    }
  });
});

describe("certificate pinning", () => {
  it("returns the same SHA-256 the cert carries, without a console", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_certificate_fingerprint");
      assert.equal(isError, false);
      const expected = new X509Certificate(readFileSync(h.cert)).fingerprint256.replace(/:/g, "").toUpperCase();
      assert.equal(payload.fingerprint, expected);
      assert.match(payload.fingerprint, /^[0-9A-F]{64}$/);
    } finally {
      await h.cleanup();
    }
  });

  it("pins the agent command to the fingerprint and never defaults to -ignore-cert", async () => {
    const h = await startServer();
    try {
      const { payload } = await h.client.call("ligolo_agent_command", { proxyIp: "192.0.2.10" });
      assert.equal(payload.pinned, true);
      assert.match(payload.linux, /-accept-fingerprint [0-9A-F]{64}/);
      assert.doesNotMatch(payload.linux, /-ignore-cert/);
      assert.match(payload.windows, /agent\.exe -connect 192\.0\.2\.10:11601/);
    } finally {
      await h.cleanup();
    }
  });

  it("requires an explicit debug flag for -ignore-cert", async () => {
    const h = await startServer();
    try {
      const { payload } = await h.client.call("ligolo_agent_command", {
        proxyIp: "192.0.2.10",
        debugIgnoreCert: true,
      });
      assert.equal(payload.pinned, false);
      assert.match(payload.linux, /-ignore-cert/);
      assert.match(payload.warning, /accepts any MITM/);
    } finally {
      await h.cleanup();
    }
  });
});

describe("proxy lifecycle", () => {
  it("reports the API as running and surfaces binary/config paths", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_proxy_status");
      assert.equal(isError, false);
      assert.equal(payload.running, true);
      assert.equal(payload.managed, false, "a proxy this server did not spawn is reported as external");
      assert.match(payload.compatibility, /ligolo-ng proxy 0\.9\.x \(tested 0\.9\.1, 0\.9\.2\)/);
      assert.equal(payload.apiUrl, process.env.LIGOLO_API ?? payload.apiUrl);
      assert.ok(existsSync(dirname(payload.configPath)));
    } finally {
      await h.cleanup();
    }
  });
});

describe("assessment resolution", () => {
  it("falls back to the framework's own active-assessment marker", async () => {
    const h = await startServer({ assessment: "", markerAssessment: "marker-assessment" });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "172.16.5.0/24",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, false, JSON.stringify(payload));
      const log = readFileSync(join(h.framework, "scope_calls.log"), "utf8");
      assert.match(log, /--assessment marker-assessment/);
    } finally {
      await h.cleanup();
    }
  });

  it("treats a stale marker as no assessment (same 12h TTL as the filesystem guard)", async () => {
    const h = await startServer({ assessment: "", markerAssessment: "stale-assessment", markerAgeHours: 48 });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "10.10.10.0/24",
        target: "10.10.10.5",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.equal(payload.exit_code, 4);
      assert.match(payload.message, /no authorization source configured/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });
});

describe("credential seeding", () => {
  it("generates a 0600 credential file when no password is supplied", async () => {
    const { loadConfig } = await import("../dist/ligolo.js");
    const { seedConfig, planInstance } = await import("../dist/proxy.js");
    const root = mkdtempSync(join(tmpdir(), "ligolo-seed-"));
    const cfg = loadConfig(
      {
        LIGOLO_PROXY_CONFIG: join(root, "ligolo-ng.yaml"),
        LIGOLO_SELFCERT_DIR: join(root, "ligolo-selfcerts"),
        LIGOLO_USER: "ligolo",
        LIGOLO_PASSWORD: "",
        LIGOLO_BITORIA_ROOT: "",
        LIGOLO_ASSESSMENT: "",
      },
      root,
    );
    assert.equal(cfg.password, "");
    const spec = planInstance(cfg, {});
    const seeded = seedConfig(cfg, spec, false);
    assert.equal(seeded.created, true);
    assert.match(seeded.password, /^[0-9a-f]{48}$/, "seedConfig must return the generated password");
    const credsPath = join(root, ".ligolo-mcp-credentials");
    assert.ok(existsSync(credsPath), "credential file must be written");
    const creds = JSON.parse(readFileSync(credsPath, "utf8"));
    assert.equal(creds.user, "ligolo");
    assert.equal(creds.password, seeded.password);
    assert.equal(statSync(credsPath).mode & 0o777, 0o600);
    const yaml = readFileSync(join(root, "ligolo-ng.yaml"), "utf8");
    assert.match(yaml, /enabled: true/);
    assert.match(yaml, /enableui: false/);
    assert.match(yaml, new RegExp(`ligolo: "${seeded.password}"`));
    // second call must not rewrite an existing, usable config
    const again = seedConfig(cfg, planInstance(cfg, {}), false);
    assert.equal(again.created, false);
  });
});

describe("agent-facing port override", () => {
  it("replaces only the port of LIGOLO_PROXY_ADDR", async () => {
    const { loadConfig } = await import("../dist/ligolo.js");
    const { applyPortOverride } = await import("../dist/proxy.js");
    const cfg = loadConfig({ LIGOLO_PROXY_ADDR: "192.0.2.5:11601", LIGOLO_API_LISTEN: "127.0.0.1:8080" }, process.cwd());
    applyPortOverride(cfg, "443");
    assert.equal(cfg.proxyAddr, "192.0.2.5:443");
    assert.equal(cfg.apiListen, "127.0.0.1:8080", "the API listen address must not move with the agent port");
  });

  it("keeps the default when no port is passed", async () => {
    const { loadConfig } = await import("../dist/ligolo.js");
    const { applyPortOverride } = await import("../dist/proxy.js");
    const cfg = loadConfig({ LIGOLO_PROXY_ADDR: "" }, process.cwd());
    assert.equal(cfg.proxyAddr, "0.0.0.0:11601");
    applyPortOverride(cfg, "");
    assert.equal(cfg.proxyAddr, "0.0.0.0:11601");
  });

  it("refuses a non-numeric or out-of-range port instead of rewriting the address", async () => {
    const { loadConfig } = await import("../dist/ligolo.js");
    const { applyPortOverride } = await import("../dist/proxy.js");
    const cfg = loadConfig({ LIGOLO_PROXY_ADDR: "0.0.0.0:11601" }, process.cwd());
    assert.throws(() => applyPortOverride(cfg, "0.0.0.0:443"), /invalid port/);
    assert.throws(() => applyPortOverride(cfg, "70000"), /invalid port/);
    assert.equal(cfg.proxyAddr, "0.0.0.0:11601");
  });
});

describe("log placement", () => {
  const mkCfg = async (root, extra = {}) => {
    const { loadConfig } = await import("../dist/ligolo.js");
    mkdirSync(join(root, "assessments", "test-assessment", "state"), { recursive: true });
    return loadConfig(
      {
        LIGOLO_PROXY_CONFIG: join(root, "ws", "ligolo-ng.yaml"),
        LIGOLO_SELFCERT_DIR: join(root, "ws", "ligolo-selfcerts"),
        LIGOLO_ASSESSMENT: "test-assessment",
        LIGOLO_BITORIA_ROOT: root,
        ...extra,
      },
      root,
    );
  };

  it("writes the proxy log into the assessment state tree", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-log-"));
    const cfg = await mkCfg(root);
    const { planInstance } = await import("../dist/proxy.js");
    const spec = planInstance(cfg, {});
    assert.equal(spec.logPath, join(root, "assessments", "test-assessment", "state", "ligolo.log"));
  });

  it("numbers a second instance ligolo2.log and shifts both ports", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-log2-"));
    const cfg = await mkCfg(root);
    const { planInstance } = await import("../dist/proxy.js");
    const first = planInstance(cfg, {});
    // a live first instance, as the manifest would hold it
    mkdirSync(join(root, "ws"), { recursive: true });
    const proxy1 = standInProxy(first.configPath);
    await new Promise((r) => setTimeout(r, 200));
    after(() => proxy1.kill("SIGKILL"));
    writeFileSync(
      join(root, "ws", ".ligolo-mcp-instances.json"),
      JSON.stringify({
        ligolo: {
          name: "ligolo", index: 1, pid: proxy1.pid,
          apiUrl: "http://127.0.0.1:8080", proxyAddr: "0.0.0.0:11601",
          configPath: first.configPath, credsPath: first.credsPath, selfcertDir: first.selfcertDir,
          workspace: first.workspace, logPath: first.logPath, assessment: "test-assessment",
          startedAt: new Date().toISOString(),
        },
      }),
    );
    const second = planInstance(cfg, {});
    assert.equal(second.name, "ligolo2");
    assert.equal(second.index, 2);
    assert.equal(second.logPath, join(root, "assessments", "test-assessment", "state", "ligolo2.log"));
    assert.equal(second.proxyAddr, "0.0.0.0:11602", "agent port must not collide with instance 1");
    assert.equal(second.apiUrl, "http://127.0.0.1:8081", "API port must not collide with instance 1");
    assert.equal(second.configPath, join(root, "ws", "ligolo2", "ligolo-ng.yaml"), "own workspace per instance");
    const third = planInstance(cfg, { instance: "ligolo3" });
    assert.equal(third.logPath, join(root, "assessments", "test-assessment", "state", "ligolo3.log"));
  });

  it("falls back to the workspace when no assessment is active", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-log3-"));
    const { loadConfig } = await import("../dist/ligolo.js");
    const { planInstance } = await import("../dist/proxy.js");
    const cfg = loadConfig(
      {
        LIGOLO_PROXY_CONFIG: join(root, "ws", "ligolo-ng.yaml"),
        LIGOLO_SELFCERT_DIR: join(root, "ws", "ligolo-selfcerts"),
        LIGOLO_ASSESSMENT: "",
        LIGOLO_BITORIA_ROOT: "",
      },
      root,
    );
    assert.equal(planInstance(cfg, {}).logPath, join(root, "ws", "ligolo.log"));
    assert.equal(planInstance(cfg, { instance: "ligolo2" }).logPath, join(root, "ws", "ligolo2.log"));
  });

  it("reports the log path and instance in proxy_start's payload shape", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-log4-"));
    const cfg = await mkCfg(root);
    const { planInstance } = await import("../dist/proxy.js");
    const spec = planInstance(cfg, {});
    assert.match(spec.logPath, /assessments\/test-assessment\/state\/ligolo\.log$/);
    assert.equal(spec.name, "ligolo");
  });
});

describe("instances", () => {
  it("exposes an `instance` parameter on every tool", async () => {
    const h = await startServer();
    try {
      const listed = await h.client.request("tools/list");
      for (const tool of listed.tools) {
        assert.ok(
          tool.inputSchema?.properties?.instance,
          `${tool.name} must accept an instance parameter`,
        );
      }
    } finally {
      await h.cleanup();
    }
  });

  it("routes a call to the named instance's API", async () => {
    const h = await startServer();
    const second = makeApi();
    await new Promise((r) => second.server.listen(0, "127.0.0.1", r));
    const port2 = second.server.address().port;
    const proxy2 = standInProxy(join(h.workdir, "ligolo2", "ligolo-ng.yaml"));
    await new Promise((r) => setTimeout(r, 200));
    try {
      const manifest = {
        ligolo2: {
          name: "ligolo2",
          index: 2,
          pid: proxy2.pid,
          apiUrl: `http://127.0.0.1:${port2}`,
          proxyAddr: "0.0.0.0:11602",
          configPath: join(h.workdir, "ligolo2", "ligolo-ng.yaml"),
          credsPath: join(h.workdir, "ligolo2", ".ligolo-mcp-credentials"),
          selfcertDir: join(h.workdir, "ligolo2", "ligolo-selfcerts"),
          workspace: join(h.workdir, "ligolo2"),
          logPath: join(h.workdir, "ligolo2.log"),
          assessment: "test-assessment",
          startedAt: new Date().toISOString(),
        },
      };
      writeFileSync(join(h.workdir, ".ligolo-mcp-instances.json"), JSON.stringify(manifest));

      h.state.calls.length = 0;
      const { isError, payload } = await h.client.call("ligolo_route_list", { instance: "ligolo2" });
      assert.equal(isError, false, JSON.stringify(payload));
      assert.equal(payload.instance, "ligolo2");
      assert.equal(second.state.calls.length, 1, "the call must reach instance 2's API");
      assert.equal(second.state.calls[0].path, "/api/v1/interfaces");
      assert.equal(h.state.calls.length, 0, "instance 1's API must not be touched");

      h.state.calls.length = 0;
      await h.client.call("ligolo_route_list");
      assert.equal(h.state.calls.length, 1, "omitting instance uses the default proxy");
    } finally {
      proxy2.kill("SIGKILL");
      await new Promise((r) => second.server.close(r));
      await h.cleanup();
    }
  });

  it("refuses a call to an instance that is not running", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_route_list", { instance: "ligolo7" });
      assert.equal(isError, true);
      assert.match(payload.message, /unknown or stopped instance 'ligolo7'/);
    } finally {
      await h.cleanup();
    }
  });
});

describe("authorization sources", () => {
  it("refuses when the assessment has no ligolo block (off by default)", async () => {
    const h = await startServer({ mcpFlag: null });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "172.16.5.0/24",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.equal(payload.exit_code, 4);
      assert.match(payload.message, /not enabled for assessment test-assessment/);
      assert.match(payload.message, /off by default/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("refuses when the assessment sets ligolo.mcp: false", async () => {
    const h = await startServer({ mcpFlag: false });
    try {
      const { isError, payload } = await h.client.call("ligolo_tunnel_start", {
        agentId: "1",
        target: "10.0.0.5",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.match(payload.message, /`ligolo\.mcp: false`/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("works standalone: LIGOLO_SCOPE + confirmed authorizes an in-scope target", async () => {
    const h = await startServer({
      assessment: "",
      standaloneScope: "172.16.5.0/24,10.10.10.5",
    });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "172.16.5.0/24",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, false, JSON.stringify(payload));
      assert.equal(payload.scope_checked, true);
      const post = mutatingCalls(h.state).find((c) => c.path === "/api/v1/routes" && c.method === "POST");
      assert.deepEqual(post.body, { Interface: "ligolo", Route: ["172.16.5.0/24"] });
    } finally {
      await h.cleanup();
    }
  });

  it("still requires the human confirmation in standalone mode", async () => {
    const h = await startServer({ assessment: "", standaloneScope: "172.16.5.0/24" });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "172.16.5.0/24",
        target: "172.16.5.9",
      });
      assert.equal(isError, true);
      assert.equal(payload.exit_code, 5);
      assert.match(payload.message, /hard checkpoint/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("refuses a standalone target outside LIGOLO_SCOPE, even when confirmed", async () => {
    const h = await startServer({ assessment: "", standaloneScope: "10.10.10.0/24" });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "10.9.9.0/24",
        target: "10.9.9.9",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.equal(payload.exit_code, 3);
      assert.match(payload.message, /not inside LIGOLO_SCOPE/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("explains both authorization sources when neither is configured", async () => {
    const h = await startServer({ assessment: "", standaloneScope: "" });
    try {
      const { isError, payload } = await h.client.call("ligolo_listener_add", {
        localAddress: "0.0.0.0:4444",
        remoteAddress: "127.0.0.1:443",
        agentId: "1",
        target: "10.0.0.5",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.equal(payload.exit_code, 4);
      assert.match(payload.message, /LIGOLO_SCOPE/);
      assert.match(payload.message, /BITORIA assessment/);
    } finally {
      await h.cleanup();
    }
  });

  it("keeps read-only tools working with no authorization at all", async () => {
    const h = await startServer({ assessment: "", standaloneScope: "" });
    try {
      const { isError } = await h.client.call("ligolo_agents_list");
      assert.equal(isError, false);
    } finally {
      await h.cleanup();
    }
  });
});

describe("argument validation and proxy error mapping", () => {
  it("rejects an unknown argument and names the near miss, without calling the API", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_listener_add", {
        agentId: "1",
        listenAddr: "0.0.0.0:11601",
        redirectAddr: "10.0.0.1:11601",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.match(payload.message, /unknown argument\(s\) for ligolo_listener_add: listenAddr, redirectAddr/);
      // No near-miss guess here on purpose: both 0.0.0.0-side names are equally
      // close to "addr", so the useful part of the message is the accepted list.
      assert.match(payload.message, /Accepted: .*localAddress.*remoteAddress/);
      assert.deepEqual(mutatingCalls(h.state), [], "a rejected call must not reach the proxy");
    } finally {
      await h.cleanup();
    }
  });

  it("suggests the declared name for a plain typo", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_listener_add", {
        agentId: "1",
        localAdress: "0.0.0.0:11601",
        remoteAddress: "10.0.0.1:11601",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.match(payload.message, /localAdress \(did you mean localAddress\?\)/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("rejects a non-CIDR network before the route call", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "not-a-cidr",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, true);
      assert.match(payload.message, /is not a CIDR/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("treats an already-present route as success", async () => {
    const h = await startServer();
    try {
      h.state.interfaces.ligolo = { Routes: [{ Destination: "172.16.5.0/24", Active: true }], Active: true };
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "172.16.5.0/24",
        target: "172.16.5.9",
        confirmed: true,
      });
      assert.equal(isError, false);
      assert.equal(payload.already_present, true);
      assert.equal(payload.scope_checked, true);
    } finally {
      await h.cleanup();
    }
  });

  it("reports every missing listener argument in one response", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_listener_add", {});
      assert.equal(isError, true);
      for (const field of ["agentId", "localAddress", "remoteAddress", "target"]) {
        assert.match(payload.message, new RegExp(field));
      }
      assert.match(payload.message, /Nothing was sent to the proxy/);
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("reports interface_create as a registry action, not a device", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_interface_create", { name: "ligolo" });
      assert.equal(isError, false);
      assert.equal(payload.registered, true);
      assert.equal(payload.os_created, "unknown");
      assert.match(payload.hint, /ip -d link show ligolo/);
    } finally {
      await h.cleanup();
    }
  });
});

describe("observer WebUI", () => {
  const mkCfg = async (root, extra = {}) => {
    const { loadConfig } = await import("../dist/ligolo.js");
    return loadConfig(
      {
        LIGOLO_PROXY_CONFIG: join(root, "ligolo-ng.yaml"),
        LIGOLO_SELFCERT_DIR: join(root, "ligolo-selfcerts"),
        LIGOLO_USER: "ligolo",
        LIGOLO_PASSWORD: "agentpw",
        LIGOLO_BITORIA_ROOT: "",
        LIGOLO_ASSESSMENT: "",
        LIGOLO_WEBUI: "1",
        LIGOLO_WEBUI_PASSWORD: "human-secret-pw",
        ...extra,
      },
      root,
    );
  };

  it("is off by default and seeds enableui: false with a single user", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-ui0-"));
    const cfg = await mkCfg(root, { LIGOLO_WEBUI: "" });
    const { seedConfig, planInstance, webUiState } = await import("../dist/proxy.js");
    const spec = planInstance(cfg, {});
    seedConfig(cfg, spec, false);
    const yaml = readFileSync(spec.configPath, "utf8");
    assert.match(yaml, /enableui: false/);
    assert.doesNotMatch(yaml, /operator:/);
    assert.doesNotMatch(yaml, /corsallowedorigin/);
    assert.deepEqual(webUiState(cfg, spec.configPath, spec.apiUrl), { enabled: false });
  });

  it("seeds the UI on the API listener with a separate human user, never in the creds file", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-ui1-"));
    const cfg = await mkCfg(root);
    const { seedConfig, planInstance, webUiState, assertWebUiAllowed } = await import("../dist/proxy.js");
    const spec = planInstance(cfg, {});
    assertWebUiAllowed(cfg, spec.apiUrl);
    seedConfig(cfg, spec, false);
    const yaml = readFileSync(spec.configPath, "utf8");
    assert.match(yaml, /enableui: true/);
    assert.match(yaml, /corsallowedorigin:\n {4}- "http:\/\/127\.0\.0\.1:8080"/);
    assert.match(yaml, /ligolo: "agentpw"/);
    assert.match(yaml, /operator: "human-secret-pw"/);
    assert.equal(statSync(spec.configPath).mode & 0o777, 0o600);
    const creds = readFileSync(spec.credsPath, "utf8");
    assert.doesNotMatch(creds, /human-secret-pw/, "the human password must not land where the agent's creds live");
    assert.doesNotMatch(creds, /operator/);
    const state = webUiState(cfg, spec.configPath, spec.apiUrl);
    assert.equal(state.enabled, true);
    assert.equal(state.url, "http://127.0.0.1:8080/");
    assert.deepEqual(state.login, { api_url: "http://127.0.0.1:8080", user: "operator" });
    assert.match(state.note, /NOT read-only/);
    assert.doesNotMatch(JSON.stringify(state), /human-secret-pw/, "tool output must never carry the human password");
  });

  it("refuses a non-loopback listener, a missing password and a shared user, all at once", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-ui2-"));
    const cfg = await mkCfg(root, {
      LIGOLO_API_LISTEN: "0.0.0.0:8080",
      LIGOLO_WEBUI_PASSWORD: "",
      LIGOLO_WEBUI_USER: "ligolo",
    });
    const { planInstance, assertWebUiAllowed } = await import("../dist/proxy.js");
    const spec = planInstance(cfg, {});
    assert.throws(
      () => assertWebUiAllowed(cfg, spec.apiUrl),
      (err) =>
        /not loopback/.test(err.message) &&
        /LIGOLO_WEBUI_PASSWORD is not set/.test(err.message) &&
        /same as the MCP's API user/.test(err.message) &&
        /Nothing was started/.test(err.message),
    );
    assert.equal(existsSync(spec.configPath), false, "a refused request writes nothing");
  });

  it("accepts every loopback spelling", async () => {
    const { isLoopback, listenHost } = await import("../dist/ligolo.js");
    for (const addr of ["127.0.0.1:8080", "127.10.0.3:9", "localhost:8080", "[::1]:8080", "http://127.0.0.1:8080"]) {
      assert.equal(isLoopback(listenHost(addr)), true, addr);
    }
    for (const addr of ["0.0.0.0:8080", "10.0.0.5:8080", "[::]:8080", "192.168.1.2:80"]) {
      assert.equal(isLoopback(listenHost(addr)), false, addr);
    }
  });

  it("will not silently reuse an existing config that has the UI off", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-ui3-"));
    const off = await mkCfg(root, { LIGOLO_WEBUI: "" });
    const { seedConfig, planInstance } = await import("../dist/proxy.js");
    seedConfig(off, planInstance(off, {}), false);
    const on = await mkCfg(root);
    assert.throws(
      () => seedConfig(on, planInstance(on, {}), false),
      /web\.enableui off and has no web\.users entry for operator.*rewriteConfig: true/,
    );
    const rewritten = seedConfig(on, planInstance(on, {}), true);
    assert.equal(rewritten.created, true);
    assert.ok(rewritten.backup && existsSync(rewritten.backup), "original kept as .bak");
    assert.match(readFileSync(rewritten.path, "utf8"), /enableui: true/);
  });

  it("reports the UI as off over MCP when nothing enabled it", async () => {
    const h = await startServer();
    try {
      const { payload } = await h.client.call("ligolo_proxy_status");
      assert.deepEqual(payload.webui, { enabled: false });
    } finally {
      await h.cleanup();
    }
  });
});

describe("changes made outside the MCP", () => {
  const scoped = { standaloneScope: "10.0.0.0/8,172.16.0.0/12", assessment: "" };

  it("labels routes by origin and reports MCP routes removed elsewhere", async () => {
    const h = await startServer(scoped);
    try {
      let r = await h.client.call("ligolo_route_add", { network: "172.16.5.0/24", target: "172.16.5.9", confirmed: true });
      assert.equal(r.isError, false, JSON.stringify(r.payload));
      // a human adds one in the WebUI
      h.state.interfaces.ligolo.Routes.push({ Destination: "10.9.9.0/24", Active: true });
      h.state.interfaces.ligolo.Routes.push({ Destination: "fe80::/64", Active: true });
      r = await h.client.call("ligolo_route_list");
      const byDest = Object.fromEntries(r.payload.routes.map((x) => [x.destination, x.origin]));
      assert.deepEqual(byDest, { "172.16.5.0/24": "mcp", "10.9.9.0/24": "external", "fe80::/64": "proxy" });

      const status = await h.client.call("ligolo_proxy_status");
      const ext = status.payload.outside_mcp.external;
      assert.ok(ext.some((e) => e.kind === "route" && e.destination === "10.9.9.0/24"));
      assert.ok(ext.some((e) => e.kind === "interface" && e.interface === "ligolo"), "interface was not made via MCP");
      assert.ok(!ext.some((e) => e.destination === "172.16.5.0/24"));
      assert.ok(!ext.some((e) => e.destination === "fe80::/64"), "proxy link-local routes are nobody's change");

      // the human then removes the MCP's route
      h.state.interfaces.ligolo.Routes = h.state.interfaces.ligolo.Routes.filter((x) => x.Destination !== "172.16.5.0/24");
      r = await h.client.call("ligolo_route_list");
      assert.deepEqual(r.payload.removed_outside_mcp.map((e) => e.key), ["ligolo 172.16.5.0/24"]);
      // reported until the MCP acts on it, not just once
      r = await h.client.call("ligolo_proxy_status");
      assert.deepEqual(r.payload.outside_mcp.removed_outside_mcp.map((e) => e.key), ["ligolo 172.16.5.0/24"]);
      await h.client.call("ligolo_route_delete", { network: "172.16.5.0/24" });
      r = await h.client.call("ligolo_route_list");
      assert.equal(r.payload.removed_outside_mcp, undefined);
    } finally {
      await h.cleanup();
    }
  });

  it("labels tunnels by agent session and ignores agents that simply disconnected", async () => {
    const h = await startServer(scoped);
    try {
      const r = await h.client.call("ligolo_tunnel_start", { agentId: "1", target: "10.0.0.5", confirmed: true });
      assert.equal(r.isError, false, JSON.stringify(r.payload));
      h.state.agents[1].Running = true;
      h.state.agents[2] = { ...h.state.agents[1], Name: "other@host", SessionID: "zzz999", Running: true };
      let list = await h.client.call("ligolo_agents_list");
      const origin = Object.fromEntries(list.payload.agents.map((a) => [a.session_id, a.tunnel_origin]));
      assert.deepEqual(origin, { abc123: "mcp", zzz999: "external" });

      // stopped from the WebUI while the agent stays connected
      h.state.agents[1].Running = false;
      list = await h.client.call("ligolo_agents_list");
      assert.deepEqual(list.payload.tunnels_stopped_outside_mcp.map((e) => e.key), ["abc123"]);

      // the agent disconnects: normal life, not drift
      delete h.state.agents[1];
      const status = await h.client.call("ligolo_proxy_status");
      assert.ok(!status.payload.outside_mcp.removed_outside_mcp.some((e) => e.kind === "tunnel"));
    } finally {
      await h.cleanup();
    }
  });

  it("labels listeners and treats one deleted in the UI as already absent", async () => {
    const h = await startServer(scoped);
    try {
      const r = await h.client.call("ligolo_listener_add", {
        agentId: "1", localAddress: "0.0.0.0:4444", remoteAddress: "127.0.0.1:4444", target: "10.0.0.5", confirmed: true,
      });
      assert.equal(r.isError, false, JSON.stringify(r.payload));
      h.state.listeners.push({ ...h.state.listeners[0], ListenerID: 7, ListenerAddr: "0.0.0.0:8000", RedirectAddr: "127.0.0.1:80" });
      let list = await h.client.call("ligolo_listener_list");
      assert.deepEqual(list.payload.listeners.map((l) => [l.ListenerID, l.origin]), [[0, "mcp"], [7, "external"]]);

      h.state.listeners = h.state.listeners.filter((l) => l.ListenerID !== 0);
      list = await h.client.call("ligolo_listener_list");
      assert.equal(list.payload.removed_outside_mcp.length, 1);
      const del = await h.client.call("ligolo_listener_delete", { listenerId: 0, agentId: "1" });
      assert.equal(del.isError, false, JSON.stringify(del.payload));
      assert.equal(del.payload.already_absent, true);
      list = await h.client.call("ligolo_listener_list");
      assert.equal(list.payload.removed_outside_mcp, undefined);
    } finally {
      await h.cleanup();
    }
  });
});

describe("regressions", () => {
  it("refuses a mutating tool called by name in read-only mode, before the gate or the API", async () => {
    const h = await startServer({ readOnly: true });
    try {
      const { isError, payload } = await h.client.call("ligolo_route_add", {
        network: "10.1.1.0/24", target: "10.1.1.1", confirmed: true,
      });
      assert.equal(isError, true);
      assert.match(payload.message, /not available: this server runs read-only/);
      assert.deepEqual(mutatingCalls(h.state), []);
      assert.equal(existsSync(join(h.framework, "scope_calls.log")), false, "the gate must not even run");
    } finally {
      await h.cleanup();
    }
  });

  it("accepts apiPort on ligolo_proxy_start (it was read but undeclared, so always rejected)", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_proxy_start", { apiPort: "18099" });
      assert.equal(isError, true);
      assert.doesNotMatch(payload.message, /unknown argument/);
      assert.match(payload.message, /proxy binary not found/);
    } finally {
      await h.cleanup();
    }
  });

  it("does not spawn a second proxy over one that already answers", async () => {
    const root = mkdtempSync(join(tmpdir(), "ligolo-foreign-"));
    const marker = join(root, "spawned");
    const fakeBin = join(root, "proxy");
    writeFileSync(fakeBin, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nsleep 5\n`);
    chmodSync(fakeBin, 0o755);
    const probe = makeApi();
    await new Promise((r) => probe.server.listen(0, "127.0.0.1", r));
    const port = probe.server.address().port;
    await new Promise((r) => probe.server.close(r));
    const h = await startServer({ env: { LIGOLO_PROXY_BIN: fakeBin, LIGOLO_API_LISTEN: `127.0.0.1:${port}` } });
    // a proxy this server did not start, already on the planned API port
    const foreign = makeApi();
    await new Promise((r) => foreign.server.listen(port, "127.0.0.1", r));
    try {
      const { isError, payload } = await h.client.call("ligolo_proxy_start");
      assert.equal(isError, false, JSON.stringify(payload));
      assert.equal(payload.managed, false);
      assert.equal(payload.pid, null);
      assert.match(payload.note, /not started by this server already answers/);
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(existsSync(marker), false, "no proxy process may be spawned");
    } finally {
      await new Promise((r) => foreign.server.close(r));
      await h.cleanup();
    }
  });

  it("ignores a manifest pid that now belongs to an unrelated process, and never signals it", async () => {
    const h = await startServer();
    const bystander = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 200));
    try {
      writeFileSync(
        join(h.workdir, ".ligolo-mcp-instances.json"),
        JSON.stringify({
          ligolo: {
            name: "ligolo", index: 1, pid: bystander.pid, apiUrl: "http://127.0.0.1:1", proxyAddr: "0.0.0.0:11601",
            configPath: join(h.workdir, "ligolo-ng.yaml"), credsPath: join(h.workdir, ".ligolo-mcp-credentials"),
            selfcertDir: join(h.workdir, "ligolo-selfcerts"), workspace: h.workdir, logPath: join(h.workdir, "ligolo.log"),
            assessment: "test-assessment", startedAt: new Date().toISOString(),
          },
        }),
      );
      const stop = await h.client.call("ligolo_proxy_stop");
      assert.equal(stop.payload.signal, "not-running");
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(bystander.exitCode, null, "the unrelated process must still be alive");
      assert.equal(bystander.signalCode, null);
    } finally {
      bystander.kill("SIGKILL");
      await h.cleanup();
    }
  });

  it("explains a TUN device left behind by an earlier proxy", async () => {
    const h = await startServer();
    try {
      const { isError, payload } = await h.client.call("ligolo_interface_create", { name: "busyif" });
      assert.equal(isError, true);
      assert.match(payload.message, /TUN device named busyif already exists/);
      assert.match(payload.message, /ip link delete busyif/);
    } finally {
      await h.cleanup();
    }
  });

  it("reports the URL it talks to for a proxy it did not start (webui.url included)", async () => {
    const h = await startServer();
    try {
      writeFileSync(
        join(h.workdir, "ligolo-ng.yaml"),
        "web:\n  enabled: true\n  enableui: true\n  listen: 0.0.0.0:8080\n  users:\n    ligolo: x\n    operator: y\n",
      );
      const { payload } = await h.client.call("ligolo_proxy_status");
      const api = payload.apiUrl;
      assert.match(api, /^http:\/\/127\.0\.0\.1:\d+$/);
      assert.notEqual(api, "http://127.0.0.1:8080", "must be LIGOLO_API, not the planned listen address");
      assert.equal(payload.webui.url, `${api}/`);
      assert.equal(payload.webui.login.api_url, api);
    } finally {
      await h.cleanup();
    }
  });

  it("refuses an interface name Linux rejects, before the proxy registers it", async () => {
    const h = await startServer({ standaloneScope: "10.0.0.0/8", assessment: "" });
    try {
      for (const [tool, args] of [
        ["ligolo_interface_create", { name: "test desde ui" }],
        ["ligolo_interface_create", { name: "a-name-way-too-long" }],
        ["ligolo_tunnel_start", { agentId: "1", tun: "bad/name", target: "10.0.0.5", confirmed: true }],
      ]) {
        const { isError, payload } = await h.client.call(tool, args);
        assert.equal(isError, true, tool);
        assert.match(payload.message, /not a valid Linux interface name/);
      }
      assert.deepEqual(mutatingCalls(h.state), []);
    } finally {
      await h.cleanup();
    }
  });

  it("never moves a running tunnel to another interface (ligolo orphans the TUN)", async () => {
    const h = await startServer({ standaloneScope: "10.0.0.0/8", assessment: "" });
    try {
      h.state.agents[1].Running = true;
      h.state.agents[1].Interface = "ligolo";
      const moved = await h.client.call("ligolo_tunnel_start", { agentId: "1", tun: "ligolo2", target: "10.0.0.5", confirmed: true });
      assert.equal(moved.isError, true);
      assert.match(moved.payload.message, /already runs a tunnel on ligolo.*Stop it first/);
      const same = await h.client.call("ligolo_tunnel_start", { agentId: "1", tun: "ligolo", target: "10.0.0.5", confirmed: true });
      assert.equal(same.isError, false, JSON.stringify(same.payload));
      assert.equal(same.payload.already_running, true);
      assert.deepEqual(mutatingCalls(h.state), [], "neither call may reach the proxy");
    } finally {
      await h.cleanup();
    }
  });

  it("explains a TUN the proxy itself still holds", async () => {
    const h = await startServer({ standaloneScope: "10.0.0.0/8", assessment: "" });
    try {
      const { isError, payload } = await h.client.call("ligolo_tunnel_start", { agentId: "1", tun: "heldtun", target: "10.0.0.5", confirmed: true });
      assert.equal(isError, true);
      assert.match(payload.message, /the proxy still holds heldtun.*fresh interface name/);
    } finally {
      await h.cleanup();
    }
  });

  it("derives the default API URL from LIGOLO_API_LISTEN", async () => {
    const { loadConfig } = await import("../dist/ligolo.js");
    const base = { LIGOLO_BITORIA_ROOT: "", LIGOLO_ASSESSMENT: "" };
    assert.equal(loadConfig({ ...base }, process.cwd()).apiUrl, "http://127.0.0.1:8080");
    assert.equal(loadConfig({ ...base, LIGOLO_API_LISTEN: "127.0.0.1:9090" }, process.cwd()).apiUrl, "http://127.0.0.1:9090");
    assert.equal(loadConfig({ ...base, LIGOLO_API_LISTEN: "0.0.0.0:9090" }, process.cwd()).apiUrl, "http://127.0.0.1:9090");
    assert.equal(loadConfig({ ...base, LIGOLO_API_LISTEN: "[::1]:9090" }, process.cwd()).apiUrl, "http://[::1]:9090");
    assert.equal(
      loadConfig({ ...base, LIGOLO_API_LISTEN: "127.0.0.1:9090", LIGOLO_API: "http://127.0.0.1:7000/" }, process.cwd()).apiUrl,
      "http://127.0.0.1:7000",
      "an explicit LIGOLO_API still wins",
    );
  });
});
