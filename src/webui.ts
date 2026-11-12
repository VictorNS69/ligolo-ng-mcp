// Merging the observer-WebUI keys into an existing ligolo config.
//
// `seedConfig` regenerated the whole file to turn the WebUI on, which meant
// `rewriteConfig: true` and the loss of every interface and route stored there
// (measured 2026-11-12: a live pivot with seven routes had to choose between
// the WebUI and its routes). This module edits in place instead: it adds
// `web.enabled`, `web.enableui`, the missing `web.users` entries and the CORS
// origin, and leaves every other line — routes, interfaces, other users —
// exactly as it found them.

export interface WebUiMergeInput {
  apiUser: string;
  password: string;
  webUi: boolean;
  webUiUser: string;
  webUiPassword: string;
  apiUrl: string;
}

interface Block {
  start: number; // index of the `web:` line
  end: number; // first index after the block's children
  indent: string; // indent of child keys
}

function findWebBlock(lines: string[]): Block | null {
  const start = lines.findIndex((l) => /^web:\s*$/.test(l));
  if (start === -1) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\S/.test(line) && line.trim() !== "") {
      end = i;
      break;
    }
  }
  return { start, end, indent: "  " };
}

function keyIndex(lines: string[], block: Block, key: string): number {
  const re = new RegExp(`^\\s+${key}\\s*:`);
  for (let i = block.start + 1; i < block.end; i += 1) if (re.test(lines[i])) return i;
  return -1;
}

function setScalar(lines: string[], block: Block, key: string, value: string): boolean {
  const idx = keyIndex(lines, block, key);
  if (idx === -1) {
    lines.splice(block.end, 0, `${block.indent}${key}: ${value}`);
    block.end += 1;
    return true;
  }
  const want = `${block.indent}${key}: ${value}`;
  if (lines[idx].trim() === `${key}: ${value}`) return false;
  lines[idx] = want;
  return true;
}

function userIndent(lines: string[], usersIdx: number): string {
  // children of `users:` are the lines after it with a deeper indent
  const base = (lines[usersIdx].match(/^\s*/) ?? [""])[0].length;
  for (let i = usersIdx + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === "") continue;
    const ind = (line.match(/^\s*/) ?? [""])[0].length;
    if (ind <= base) break;
    return " ".repeat(ind);
  }
  return `${" ".repeat(base)}  `;
}

function ensureUser(lines: string[], block: Block, user: string, password: string): boolean {
  const usersIdx = keyIndex(lines, block, "users");
  const re = new RegExp(`^\\s+${user.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`);
  if (usersIdx === -1) {
    const entry = [`${block.indent}users:`, `${block.indent}  ${user}: ${JSON.stringify(password)}`];
    lines.splice(block.end, 0, ...entry);
    block.end += entry.length;
    return true;
  }
  for (let i = usersIdx + 1; i < block.end; i += 1) if (re.test(lines[i])) return false;
  const pad = userIndent(lines, usersIdx);
  lines.splice(usersIdx + 1, 0, `${pad}${user}: ${JSON.stringify(password)}`);
  block.end += 1;
  return true;
}

/**
 * Return the merged config text, or `null` when nothing needed changing.
 * Lines the caller already has (routes, interfaces, other users) are untouched.
 */
export function mergeWebUi(existing: string, input: WebUiMergeInput): string | null {
  const lines = existing.split("\n");
  let changed = false;

  let block = findWebBlock(lines);
  if (!block) {
    const add = [
      "web:",
      "  enabled: true",
      `  enableui: ${input.webUi ? "true" : "false"}`,
      `  listen: ${JSON.stringify(input.apiUrl.replace(/^https?:\/\//, ""))}`,
      "  users:",
      `    ${input.apiUser}: ${JSON.stringify(input.password)}`,
      ...(input.webUi ? [`    ${input.webUiUser}: ${JSON.stringify(input.webUiPassword)}`] : []),
      ...(input.webUi ? ["  corsallowedorigin:", `    - ${JSON.stringify(input.apiUrl)}`] : []),
      "",
    ];
    const out = [...lines.filter((l, i) => !(i === lines.length - 1 && l === "")), ...add].join("\n");
    return out;
  }

  changed = setScalar(lines, block, "enabled", "true") || changed;
  if (input.webUi) {
    changed = setScalar(lines, block, "enableui", "true") || changed;
    changed = ensureUser(lines, block, input.apiUser, input.password) || changed;
    changed = ensureUser(lines, block, input.webUiUser, input.webUiPassword) || changed;
    if (keyIndex(lines, block, "corsallowedorigin") === -1) {
      lines.splice(block.end, 0, `${block.indent}corsallowedorigin:`, `${block.indent}  - ${JSON.stringify(input.apiUrl)}`);
      block.end += 2;
      changed = true;
    }
  } else {
    changed = ensureUser(lines, block, input.apiUser, input.password) || changed;
  }

  return changed ? lines.join("\n") : null;
}
