// Unit tests for the pure pieces behind the lateral-movement gate and the
// ledger. They import the built modules directly — no MCP, no stub API — so
// edge cases of the scope matcher and the drift computation stay cheap to pin.

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const DIST = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const { targetInScope, assertScope, GateError } = await import(pathToFileURL(join(DIST, "ligolo.js")).href);
const { Ledger, computeDrift, liveResources, keys } = await import(pathToFileURL(join(DIST, "ledger.js")).href);

describe("targetInScope", () => {
  const cases = [
    // [scope, target, expected, why]
    [["10.0.0.0/8"], "10.255.1.1", true, "inside an IPv4 range"],
    [["10.0.0.0/8"], "11.0.0.1", false, "just outside an IPv4 range"],
    [["10.10.10.0/24"], "10.10.10.0", true, "network address itself"],
    [["10.10.10.0/24"], "10.10.10.255", true, "broadcast address"],
    [["10.10.10.0/24"], "10.10.11.0", false, "first address of the next /24"],
    [["10.10.10.5"], "10.10.10.5", true, "exact host"],
    [["10.10.10.5"], "10.10.10.6", false, "neighbouring host"],
    [["10.10.10.5"], "10.10.10.5/32", true, "target given as /32"],
    [["10.10.10.5/32"], "10.10.10.5", true, "scope given as /32"],
    [["0.0.0.0/0"], "8.8.8.8", true, "/0 covers everything"],
    [["10.0.0.0/33"], "10.0.0.1", false, "invalid prefix is ignored, not widened"],
    [["10.0.0.0/abc"], "10.0.0.1", false, "non-numeric prefix is ignored"],
    [["999.0.0.0/8"], "999.0.0.1", false, "invalid octets never match a range"],
    [["10.0.0.0/24"], "10.0.0.1.5", false, "five octets is not an address"],
    [["DC01.corp"], "dc01.CORP", true, "hostnames match case-insensitively"],
    [["dc01.corp"], "dc02.corp", false, "different hostname"],
    [["fd00::1"], "[fd00::1]", true, "bracketed IPv6 matches exactly"],
    // IPv6 ranges are exact-match only (documented); this fails closed.
    [["fd00::/64"], "fd00::1", false, "IPv6 CIDR is not range-matched"],
    [["192.168.1.0/24", " 10.0.0.0/8 "], "10.1.2.3", true, "later entry, padded with spaces"],
    [[], "10.0.0.1", false, "empty scope"],
    [[""], "10.0.0.1", false, "blank entry"],
  ];
  for (const [scope, target, expected, why] of cases) {
    it(`${why}: ${JSON.stringify(scope)} ∋ ${target} → ${expected}`, () => {
      assert.equal(targetInScope(scope, target), expected);
    });
  }
});

describe("assertScope", () => {
  const cfg = (scope) => ({ scope });
  const codeOf = (fn) => {
    try {
      fn();
    } catch (err) {
      assert.ok(err instanceof GateError, `expected GateError, got ${err}`);
      return err.code;
    }
    return null;
  };

  it("refuses with code 4 when no scope is configured, even if confirmed", () => {
    assert.equal(codeOf(() => assertScope(cfg([]), "10.0.0.1", true)), 4);
  });
  it("refuses with code 3 outside the scope, even if confirmed", () => {
    assert.equal(codeOf(() => assertScope(cfg(["10.0.0.0/8"]), "192.168.0.1", true)), 3);
  });
  it("refuses with code 5 inside the scope without confirmation", () => {
    assert.equal(codeOf(() => assertScope(cfg(["10.0.0.0/8"]), "10.0.0.1", false)), 5);
  });
  it("checks scope before confirmation (an out-of-scope target is never 'just unconfirmed')", () => {
    assert.equal(codeOf(() => assertScope(cfg(["10.0.0.0/8"]), "192.168.0.1", false)), 3);
  });
  it("passes an in-scope, confirmed target", () => {
    assert.equal(codeOf(() => assertScope(cfg(["10.0.0.0/8"]), "10.0.0.1", true)), null);
  });
});

describe("ledger and drift", () => {
  const configPath = () => join(mkdtempSync(join(tmpdir(), "ligolo-ledger-")), "ligolo-ng.yaml");
  const agent = (sessionId, running = true) => ({
    Name: `user@${sessionId}`,
    SessionID: sessionId,
    Running: running,
    Interface: "ligolo",
  });

  it("persists records across loads and forgets them", () => {
    const path = configPath();
    const l = Ledger.load(path);
    l.record("route", keys.route("ligolo", "10.0.0.0/24"));
    assert.equal(Ledger.load(path).origin("route", keys.route("ligolo", "10.0.0.0/24")), "mcp");
    Ledger.load(path).forget("route", keys.route("ligolo", "10.0.0.0/24"));
    assert.equal(Ledger.load(path).origin("route", keys.route("ligolo", "10.0.0.0/24")), "external");
  });

  it("reset empties the ledger", () => {
    const path = configPath();
    Ledger.load(path).record("interface", "ligolo");
    Ledger.reset(path);
    assert.deepEqual(Ledger.load(path).entries(), []);
  });

  it("liveResources skips ligolo's fe80 link-local routes and stopped tunnels", () => {
    const live = liveResources(
      {
        ligolo: {
          Active: true,
          Routes: [
            { Destination: "fe80::/64", Active: true },
            { Destination: "10.0.0.0/24", Active: true },
            { Destination: "fd00::/64", Active: true },
          ],
        },
      },
      { 1: agent("s1", true), 2: agent("s2", false) },
      [],
    );
    const ids = live.map((r) => `${r.kind}:${r.key}`).sort();
    assert.deepEqual(ids, ["interface:ligolo", "route:ligolo 10.0.0.0/24", "route:ligolo fd00::/64", "tunnel:s1"]);
  });

  it("labels unknown live resources external and reports MCP ones removed elsewhere", () => {
    const l = Ledger.load(configPath());
    l.record("route", keys.route("ligolo", "10.0.0.0/24"));
    l.record("route", keys.route("ligolo", "10.9.0.0/24")); // deleted in the UI
    const live = liveResources(
      {
        ligolo: {
          Active: true,
          Routes: [
            { Destination: "10.0.0.0/24", Active: true },
            { Destination: "172.16.0.0/16", Active: true }, // added in the UI
          ],
        },
      },
      {},
      [],
    );
    const drift = computeDrift(l, live, {});
    assert.deepEqual(
      drift.external.map((r) => r.key).sort(),
      ["ligolo", "ligolo 172.16.0.0/16"],
    );
    assert.deepEqual(drift.removed_outside_mcp.map((e) => e.key), ["ligolo 10.9.0.0/24"]);
  });

  it("keeps reporting a removed resource on every read until the MCP acts on it", () => {
    const l = Ledger.load(configPath());
    l.record("interface", "ligolo2");
    assert.equal(computeDrift(l, [], {}).removed_outside_mcp.length, 1);
    assert.equal(computeDrift(l, [], {}).removed_outside_mcp.length, 1);
  });

  it("prunes a tunnel whose agent session is gone, but reports one stopped while connected", () => {
    const l = Ledger.load(configPath());
    l.record("tunnel", keys.tunnel("gone"));
    l.record("tunnel", keys.tunnel("stopped"));
    const agents = { 1: agent("stopped", false) };
    const drift = computeDrift(l, liveResources({}, agents, []), agents);
    assert.deepEqual(drift.removed_outside_mcp.map((e) => e.key), ["stopped"]);
    assert.equal(l.has("tunnel", "gone"), false);
  });

  it("starts empty instead of failing on a corrupt ledger file", async () => {
    const path = configPath();
    const { writeFileSync } = await import("node:fs");
    const { ledgerPath } = await import(pathToFileURL(join(DIST, "ledger.js")).href);
    writeFileSync(ledgerPath(path), "{not json");
    assert.deepEqual(Ledger.load(path).entries(), []);
  });
});
