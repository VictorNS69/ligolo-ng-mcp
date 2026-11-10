// Pre-spawn port-availability check (proposal: a port collision with another
// live listener failed silently). Measured 2026-11-10: the registered API
// listen address was 127.0.0.1:8080, which Burp held; the proxy was spawned
// anyway, the bind failed inside the child, and the first visible symptom was
// `/api/auth returned no token` on a later call.

import assert from "node:assert/strict";
import { createServer } from "node:net";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer as createHttpServer } from "node:http";
import { describe, it } from "node:test";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(HERE, "..", "dist", "proxy.js");
const { portFree } = await import(DIST);

function listen(server) {
  return new Promise((res) => server.listen(0, "127.0.0.1", () => res(server.address().port)));
}

describe("portFree", () => {
  it("is false for a port another process holds", async () => {
    const server = createServer();
    const port = await listen(server);
    try {
      assert.equal(await portFree(`127.0.0.1:${port}`), false);
    } finally {
      await new Promise((res) => server.close(res));
    }
  });

  it("is true once the holder is gone", async () => {
    const server = createServer();
    const port = await listen(server);
    await new Promise((res) => server.close(res));
    assert.equal(await portFree(`127.0.0.1:${port}`), true);
  });

  it("treats port 0 (kernel-assigned) as free", async () => {
    assert.equal(await portFree("127.0.0.1:0"), true);
  });

  it("does not mistake an HTTP listener for a free port", async () => {
    // The real collision case: Burp's proxy is an HTTP listener, not ligolo.
    const server = createHttpServer((_req, res) => res.end("burp"));
    const port = await listen(server);
    try {
      assert.equal(await portFree(`127.0.0.1:${port}`), false);
    } finally {
      await new Promise((res) => server.close(res));
    }
  });
});

describe("startProxy refusal text", () => {
  it("names the port, the collision and the knob that moves it", () => {
    const src = readFileSync(DIST, "utf8");
    assert.match(src, /is already bound by another process/);
    assert.match(src, /apiPort/);
    assert.match(src, /8080/);
  });
});
