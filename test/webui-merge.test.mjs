// Turning the observer WebUI on must not cost the pivot's routes.
//
// Before this, `LIGOLO_WEBUI=1` against an existing config refused to start and
// the only cure was `rewriteConfig: true`, which regenerates the file and drops
// every interface and route stored in it (measured 2026-11-12). The merge adds
// web.enabled / web.enableui / the missing users / the CORS origin and leaves
// everything else alone.

import test from "node:test";
import assert from "node:assert";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DIST = resolve(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const { mergeWebUi } = await import(pathToFileURL(join(DIST, "webui.js")).href);
const { seedConfig } = await import(pathToFileURL(join(DIST, "proxy.js")).href);

const LEGACY = `proxy:
  historyfile: "/tmp/hist"
  selfcertcache: "/tmp/certs"
web:
  enabled: true
  enableui: false
  listen: "127.0.0.1:8082"
  users:
    ligolo: "api-pass"
interfaces:
  - name: ligolo
routes:
  - destination: 172.16.132.10/32
    interface: ligolo
  - destination: 172.16.132.11/32
    interface: ligolo
`;

const INPUT = {
  apiUser: "ligolo",
  password: "api-pass",
  webUi: true,
  webUiUser: "observer",
  webUiPassword: "observer-pass",
  apiUrl: "http://127.0.0.1:8082",
};

test("merge enables the UI, adds the observer, and keeps routes byte for byte", () => {
  const out = mergeWebUi(LEGACY, INPUT);
  assert.ok(out, "a change was reported");
  assert.match(out, /^\s*enableui: true$/m);
  assert.match(out, /^\s*observer: "observer-pass"$/m);
  assert.match(out, /^\s*ligolo: "api-pass"$/m, "existing api user untouched");
  for (const route of ["172.16.132.10/32", "172.16.132.11/32"]) {
    assert.ok(out.includes(`destination: ${route}`), `${route} preserved`);
  }
  assert.match(out, /corsallowedorigin:/);
  assert.match(out, /interfaces:/);
});

test("a config that already has everything returns null (no rewrite, no backup)", () => {
  const merged = mergeWebUi(LEGACY, INPUT);
  assert.strictEqual(mergeWebUi(merged, INPUT), null);
});

test("a config without a web block gets one appended", () => {
  const out = mergeWebUi("proxy:\n  historyfile: /tmp/h\n", INPUT);
  assert.ok(out);
  assert.match(out, /^web:$/m);
  assert.match(out, /^\s*enabled: true$/m);
  assert.match(out, /^\s*observer: "observer-pass"$/m);
});

test("seedConfig merges instead of throwing, and backs the original up", () => {
  const dir = mkdtempSync(join(tmpdir(), "ligolo-webui-"));
  const configPath = join(dir, "ligolo-ng.yaml");
  writeFileSync(configPath, LEGACY);
  const spec = {
    name: "ligolo", index: 1, workspace: dir, configPath,
    credsPath: join(dir, ".creds.json"), selfcertDir: join(dir, "certs"),
    apiUrl: "http://127.0.0.1:8082", proxyAddr: "0.0.0.0:11601", logPath: join(dir, "l.log"),
  };
  const cfg = { user: "ligolo", password: "", webUi: true, webUiUser: "observer",
                webUiPassword: "observer-pass", proxyBin: "/bin/true" };
  const res = seedConfig(cfg, spec, false);
  assert.strictEqual(res.created, false);
  assert.ok(res.backup && existsSync(res.backup), "backup written");
  const text = readFileSync(configPath, "utf8");
  assert.match(text, /^\s*enableui: true$/m);
  assert.ok(text.includes("172.16.132.10/32"), "routes survived the merge");
  assert.strictEqual(readFileSync(res.backup, "utf8"), LEGACY, "backup is the original");
});
