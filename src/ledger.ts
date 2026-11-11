// Ligolo-ng MCP — ledger of what *this server* created on a proxy.
//
// With the observer WebUI enabled (or a human on the console), the proxy's
// state is no longer written only by the MCP. An agent that reads routes,
// listeners or tunnels it did not create, or misses one it did, would
// otherwise reason from a picture it cannot explain. The ledger is the
// minimum needed to tell the two apart:
//
//   - every successful MCP mutation records (or forgets) the resource it made;
//   - reads compare the live API state against the ledger and label each
//     resource `origin: "mcp" | "external"`;
//   - ledger entries that are no longer live are reported as
//     `removed_outside_mcp` until the MCP itself deletes or recreates them.
//
// "external" means "not created through this MCP": the WebUI, the console, or
// state the proxy restored from an existing config. ligolo does not record
// which user made a change, so this is attribution by elimination, not an
// audit log. The ledger lives next to the instance's proxy config and is
// reset whenever that config is freshly seeded.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { Agents, InterfaceRecord, ListenerRecord } from "./ligolo.js";

export type Kind = "interface" | "route" | "listener" | "tunnel";

export interface LedgerEntry {
  kind: Kind;
  key: string;
  createdAt: string;
  /** listeners only: the proxy's ListenerID and numeric agent id, for delete-by-id. */
  listenerId?: number;
  agentId?: number;
}

interface LedgerFile {
  version: 1;
  entries: Record<string, LedgerEntry>;
}

export function ledgerPath(configPath: string): string {
  return join(dirname(configPath), ".ligolo-mcp-ledger.json");
}

const id = (kind: Kind, key: string): string => `${kind}:${key}`;

export const keys = {
  interface: (name: string): string => name,
  route: (iface: string, destination: string): string => `${iface} ${destination}`,
  listener: (l: Pick<ListenerRecord, "SessionID" | "Network" | "ListenerAddr" | "RedirectAddr">): string =>
    `${l.SessionID} ${l.Network} ${l.ListenerAddr}->${l.RedirectAddr}`,
  /** A tunnel belongs to an agent session; agent ids are reused across reconnects, session ids are not. */
  tunnel: (sessionId: string): string => sessionId,
};

export class Ledger {
  private constructor(
    private readonly path: string,
    private data: LedgerFile,
  ) {}

  static load(configPath: string): Ledger {
    const path = ledgerPath(configPath);
    let data: LedgerFile = { version: 1, entries: {} };
    if (existsSync(path)) {
      try {
        const parsed = JSON.parse(readFileSync(path, "utf8")) as LedgerFile;
        if (parsed && typeof parsed === "object" && parsed.entries && typeof parsed.entries === "object") {
          data = { version: 1, entries: parsed.entries };
        }
      } catch {
        /* unreadable ledger: start empty rather than fail every read */
      }
    }
    return new Ledger(path, data);
  }

  /** Forget everything: the proxy config was freshly seeded, so nothing on it is ours yet. */
  static reset(configPath: string): void {
    new Ledger(ledgerPath(configPath), { version: 1, entries: {} }).save();
  }

  private save(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, `${JSON.stringify(this.data, null, 2)}\n`, { mode: 0o600 });
  }

  has(kind: Kind, key: string): boolean {
    return id(kind, key) in this.data.entries;
  }

  origin(kind: Kind, key: string): "mcp" | "external" {
    return this.has(kind, key) ? "mcp" : "external";
  }

  record(kind: Kind, key: string, extra: Partial<LedgerEntry> = {}): void {
    this.data.entries[id(kind, key)] = { ...extra, kind, key, createdAt: new Date().toISOString() };
    this.save();
  }

  forget(kind: Kind, key: string): void {
    if (!(id(kind, key) in this.data.entries)) return;
    delete this.data.entries[id(kind, key)];
    this.save();
  }

  forgetWhere(pred: (e: LedgerEntry) => boolean): void {
    const before = Object.keys(this.data.entries).length;
    this.data.entries = Object.fromEntries(Object.entries(this.data.entries).filter(([, e]) => !pred(e)));
    if (Object.keys(this.data.entries).length !== before) this.save();
  }

  entries(): LedgerEntry[] {
    return Object.values(this.data.entries);
  }
}

/** ligolo adds IPv6 link-local routes to every TUN on its own; they are nobody's change. */
function isAutoRoute(destination: string): boolean {
  return /^fe80:/i.test(destination);
}

export interface LiveResource {
  kind: Kind;
  key: string;
  detail: Record<string, unknown>;
}

/** The live state of a proxy, as ledger-comparable resources. */
export function liveResources(
  interfaces: Record<string, InterfaceRecord> | null,
  agents: Agents | null,
  listeners: ListenerRecord[] | null,
): LiveResource[] {
  const out: LiveResource[] = [];
  for (const [name, rec] of Object.entries(interfaces ?? {})) {
    out.push({ kind: "interface", key: keys.interface(name), detail: { interface: name, active: rec.Active } });
    for (const r of rec.Routes ?? []) {
      if (isAutoRoute(r.Destination)) continue;
      out.push({
        kind: "route",
        key: keys.route(name, r.Destination),
        detail: { interface: name, destination: r.Destination, active: r.Active },
      });
    }
  }
  for (const [agentId, a] of Object.entries(agents ?? {})) {
    if (!a.Running) continue;
    out.push({
      kind: "tunnel",
      key: keys.tunnel(a.SessionID),
      detail: { agent_id: agentId, agent_name: a.Name, session_id: a.SessionID, interface: a.Interface },
    });
  }
  for (const l of listeners ?? []) {
    out.push({
      kind: "listener",
      key: keys.listener(l),
      detail: {
        listener_id: l.ListenerID,
        agent_id: l.AgentID,
        agent_name: l.Agent,
        network: l.Network,
        listen: l.ListenerAddr,
        redirect: l.RedirectAddr,
      },
    });
  }
  return out;
}

export interface Drift {
  /** Live on the proxy, not created through this MCP. */
  external: LiveResource[];
  /** Created through this MCP, no longer live — removed from the WebUI, console or a proxy restart. */
  removed_outside_mcp: LedgerEntry[];
}

/**
 * Compare live state with the ledger.
 *
 * A tunnel whose agent session is gone is pruned silently: an agent dropping
 * its connection is normal life, not somebody else's change. Every other
 * missing entry stays in the ledger and keeps being reported until the MCP
 * deletes or recreates it, so a change made in the UI cannot be missed just
 * because a different tool happened to look first.
 */
export function computeDrift(ledger: Ledger, live: LiveResource[], agents: Agents | null): Drift {
  const liveIds = new Set(live.map((r) => id(r.kind, r.key)));
  const sessions = new Set(Object.values(agents ?? {}).map((a) => a.SessionID));
  ledger.forgetWhere((e) => e.kind === "tunnel" && !sessions.has(e.key));
  return {
    external: live.filter((r) => !ledger.has(r.kind, r.key)),
    removed_outside_mcp: ledger.entries().filter((e) => !liveIds.has(id(e.kind, e.key))),
  };
}
