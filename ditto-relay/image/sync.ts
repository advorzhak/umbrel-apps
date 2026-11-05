/**
 * Sync events authored by configured identifiers from public relays into the
 * local OpenSearch index, and report sync state for the relay dashboard.
 *
 * This service intentionally bypasses the relay's NIP-42 write policy: it
 * fetches signed events from public relays, verifies them, and feeds them to
 * the relay's own import script. That lets an operator back up activity from
 * approved npubs without holding their private keys.
 *
 * Settings come from `SYNC_DATA_DIR/config.json` when the dashboard has saved
 * them, and otherwise from the environment:
 *   SYNC_IDENTIFIERS        Comma-separated npub, nprofile, or NIP-05 values.
 *   SYNC_RELAYS             Optional comma-separated public relay URLs.
 *   SYNC_KINDS              Optional comma-separated kinds; empty means all.
 *   SYNC_INTERVAL_SECONDS   Seconds between sync runs (default 300).
 *   SYNC_SINCE_DAYS         Days of history for the first backfill (default 0 = all).
 *   SYNC_DATA_DIR           Config/state/cursor directory (default /sync).
 *
 * Progress is written to `state.json` for the dashboard to read.
 */

import { spawn } from "node:child_process";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import process from "node:process";

import { type Filter, type NostrEvent, nip19, verifyEvent } from "nostr-tools";
import { SimplePool } from "nostr-tools/pool";

const DEFAULT_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.nostr.band",
  "wss://relay.primal.net",
  "wss://relay.snort.social",
  "wss://nostr.mom",
];

const PAGE_SIZE = 500;
const OVERLAP_SECONDS = 300;

interface Cursor {
  latest: number;
  backfillComplete: boolean;
  backfillUntil?: number;
}

type Cursors = Record<string, Cursor>;

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function normalizeRelay(value: string): string | undefined {
  try {
    const url = new URL(value.trim());
    if (url.protocol === "http:") url.protocol = "ws:";
    if (url.protocol === "https:") url.protocol = "wss:";
    if (url.protocol !== "ws:" && url.protocol !== "wss:") return undefined;
    return url.toString().replace(/\/$/, "");
  } catch {
    return undefined;
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

const dataDir = process.env.SYNC_DATA_DIR ?? "/sync";
const cursorFile = join(dataDir, "cursors.json");
const configFile = join(dataDir, "config.json");
const stateFile = join(dataDir, "state.json");

const envRejectedKinds = new Set(
  splitList(
    process.env.REJECTED_KINDS ?? "13,9734,20013,20014,22242,24242,27235",
  )
    .map((value) => Number.parseInt(value, 10))
    .filter((value) => Number.isInteger(value)),
);
const envBannedHashtags = new Set(
  splitList(process.env.BANNED_HASHTAGS).map((value) => value.toLowerCase()),
);

interface SyncConfig {
  identifiers: string[];
  relays: string[];
  kinds: number[];
  intervalSeconds: number;
  sinceDays: number;
  rejectedKinds: Set<number>;
  bannedHashtags: Set<string>;
}

async function readJson<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return undefined;
  }
}

function fromEnv(): SyncConfig {
  return {
    identifiers: splitList(process.env.SYNC_IDENTIFIERS),
    relays: splitList(process.env.SYNC_RELAYS),
    kinds: splitList(process.env.SYNC_KINDS)
      .map((value) => Number.parseInt(value, 10))
      .filter((value) => Number.isInteger(value)),
    intervalSeconds: Math.max(
      30,
      Number.parseInt(process.env.SYNC_INTERVAL_SECONDS ?? "300", 10) || 300,
    ),
    sinceDays: Math.max(
      0,
      Number.parseInt(process.env.SYNC_SINCE_DAYS ?? "0", 10) || 0,
    ),
    rejectedKinds: envRejectedKinds,
    bannedHashtags: envBannedHashtags,
  };
}

/**
 * Dashboard settings win over environment settings, so the operator can
 * change sync from the relay page without editing app settings.
 */
async function resolveConfig(): Promise<SyncConfig> {
  const base = fromEnv();
  const file = await readJson<{
    identifiers?: string[];
    relays?: string[];
    kinds?: number[];
    intervalSeconds?: number;
    sinceDays?: number;
  }>(configFile);
  if (!file) return base;

  return {
    ...base,
    identifiers: Array.isArray(file.identifiers)
      ? file.identifiers.filter((value) => typeof value === "string")
      : base.identifiers,
    relays: Array.isArray(file.relays)
      ? file.relays.filter((value) => typeof value === "string")
      : base.relays,
    kinds: Array.isArray(file.kinds)
      ? file.kinds.filter((value) => Number.isInteger(value))
      : base.kinds,
    intervalSeconds:
      Number.isInteger(file.intervalSeconds) && (file.intervalSeconds ?? 0) >= 30
        ? (file.intervalSeconds as number)
        : base.intervalSeconds,
    sinceDays:
      Number.isInteger(file.sinceDays) && (file.sinceDays ?? -1) >= 0
        ? (file.sinceDays as number)
        : base.sinceDays,
  };
}

async function writeState(state: {
  lastRunAt?: number;
  lastImported?: number;
  lastError?: string;
}): Promise<void> {
  try {
    await mkdir(dataDir, { recursive: true });
    await writeFile(`${stateFile}.tmp`, `${JSON.stringify(state, null, 2)}\n`);
    await rename(`${stateFile}.tmp`, stateFile);
  } catch {
    // The dashboard is optional; never fail a sync over a status write.
  }
}

function log(message: string): void {
  console.log(`sync: ${message}`);
}

function error(message: string, cause: unknown): void {
  console.error(`sync: ${message}`, cause);
}

async function resolveIdentifier(
  identifier: string,
): Promise<{ pubkey: string; relays: string[] }> {
  if (identifier.startsWith("npub1")) {
    const decoded = nip19.decode(identifier);
    if (decoded.type !== "npub") {
      throw new Error(`invalid npub: ${identifier}`);
    }
    return { pubkey: decoded.data, relays: [] };
  }

  if (identifier.startsWith("nprofile1")) {
    const decoded = nip19.decode(identifier);
    if (decoded.type !== "nprofile") {
      throw new Error(`invalid nprofile: ${identifier}`);
    }
    return {
      pubkey: decoded.data.pubkey,
      relays: (decoded.data.relays ?? [])
        .map(normalizeRelay)
        .filter((value): value is string => value !== undefined),
    };
  }

  const at = identifier.lastIndexOf("@");
  if (at <= 0 || at === identifier.length - 1) {
    throw new Error(
      `invalid identifier (expected npub, nprofile, or name@domain): ${identifier}`,
    );
  }

  const name = identifier.slice(0, at);
  const domain = identifier.slice(at + 1);
  const response = await fetch(
    `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(name)}`,
    { signal: AbortSignal.timeout(15_000) },
  );
  if (!response.ok) {
    throw new Error(`NIP-05 lookup for ${identifier} failed: HTTP ${response.status}`);
  }

  const data = (await response.json()) as {
    names?: Record<string, string>;
    relays?: Record<string, string[]>;
  };
  const pubkey = data.names?.[name]?.toLowerCase();
  if (!pubkey || !/^[0-9a-f]{64}$/.test(pubkey)) {
    throw new Error(`NIP-05 response has no valid pubkey for ${identifier}`);
  }

  return {
    pubkey,
    relays: (data.relays?.[pubkey] ?? [])
      .map(normalizeRelay)
      .filter((value): value is string => value !== undefined),
  };
}

async function discoverRelays(
  pool: SimplePool,
  pubkey: string,
): Promise<string[]> {
  try {
    const events = await pool.querySync(
      DEFAULT_RELAYS,
      { kinds: [10002], authors: [pubkey], limit: 1 },
      { maxWait: 15_000 },
    );
    const latest = events.sort((a, b) => b.created_at - a.created_at)[0];
    if (!latest) return [];

    return latest.tags
      .filter(
        (tag) =>
          tag[0] === "r" &&
          tag[1] &&
          (tag[2] === undefined || tag[2] === "" || tag[2] === "read"),
      )
      .map((tag) => normalizeRelay(tag[1]))
      .filter((value): value is string => value !== undefined);
  } catch (cause) {
    error(`NIP-65 discovery failed for ${pubkey}`, cause);
    return [];
  }
}

function isAllowed(
  event: NostrEvent,
  pubkey: string,
  config: SyncConfig,
): boolean {
  if (event.pubkey !== pubkey) return false;
  if (config.rejectedKinds.has(event.kind)) return false;
  if (
    event.tags.some(
      (tag) =>
        tag[0] === "t" &&
        tag[1] &&
        config.bannedHashtags.has(tag[1].toLowerCase()),
    )
  ) {
    return false;
  }
  return verifyEvent(event);
}

async function fetchPage(
  pool: SimplePool,
  relays: string[],
  pubkey: string,
  filter: Filter,
  config: SyncConfig,
): Promise<NostrEvent[]> {
  const events = await pool.querySync(relays, filter, { maxWait: 20_000 });
  return events.filter((event) => isAllowed(event, pubkey, config));
}

function runImport(file: string, workDir: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(
      "bun",
      [
        "/app/scripts/import.ts",
        file,
        "--phase",
        "all",
        "--work-dir",
        workDir,
      ],
      {
        cwd: "/app",
        stdio: "inherit",
        env: process.env,
      },
    );
    child.on("error", (cause) => {
      error("failed to start import", cause);
      resolve(1);
    });
    child.on("exit", (code) => resolve(code ?? 1));
  });
}

async function ingest(events: NostrEvent[]): Promise<void> {
  const uniqueEvents = [
    ...new Map(events.map((event) => [event.id, event])).values(),
  ];
  if (uniqueEvents.length === 0) return;

  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const workDir = join(dataDir, "work", stamp);
  await mkdir(workDir, { recursive: true });
  const file = join(workDir, "events.jsonl");
  await writeFile(
    file,
    `${uniqueEvents.map((event) => JSON.stringify(event)).join("\n")}\n`,
  );

  log(`importing ${uniqueEvents.length} events`);
  const code = await runImport(file, workDir);
  if (code === 0) {
    await rm(workDir, { recursive: true, force: true });
  } else {
    console.error(`sync: import failed with exit ${code}; kept ${workDir}`);
  }
}

async function loadCursors(): Promise<Cursors> {
  try {
    return JSON.parse(await readFile(cursorFile, "utf8")) as Cursors;
  } catch {
    return {};
  }
}

async function saveCursors(cursors: Cursors): Promise<void> {
  await mkdir(dataDir, { recursive: true });
  const temporaryPath = `${cursorFile}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(cursors, null, 2)}\n`);
  await rename(temporaryPath, cursorFile);
}

async function syncRange(
  pool: SimplePool,
  relays: string[],
  pubkey: string,
  since: number,
  until: number,
  config: SyncConfig,
  onPage: (events: NostrEvent[], nextUntil: number) => Promise<void>,
): Promise<number> {
  let cursorUntil = until;
  let maxCreatedAt = 0;

  while (cursorUntil >= since) {
    const filter: Filter = {
      authors: [pubkey],
      until: cursorUntil,
      limit: PAGE_SIZE,
    };
    if (since > 0) filter.since = since;
    if (config.kinds.length > 0) filter.kinds = config.kinds;

    const events = await fetchPage(pool, relays, pubkey, filter, config);
    if (events.length === 0) break;

    const oldest = Math.min(...events.map((event) => event.created_at));
    maxCreatedAt = Math.max(
      maxCreatedAt,
      ...events.map((event) => event.created_at),
    );

    const nextUntil = oldest > 0 ? oldest - 1 : 0;
    await onPage(events, nextUntil);
    if (oldest <= since) break;
    cursorUntil = nextUntil;
  }

  return maxCreatedAt;
}

async function main(): Promise<void> {
  await mkdir(dataDir, { recursive: true });
  const cursors = await loadCursors();
  const pool = new SimplePool();
  let nextRunAt = 0;
  let lastSignature = "";

  // Re-read settings frequently so a save from the dashboard takes effect
  // within seconds, while still honouring the configured run interval.
  while (true) {
    const config = await resolveConfig();
    const now = Math.floor(Date.now() / 1000);
    const signature = JSON.stringify({
      identifiers: config.identifiers,
      relays: config.relays,
      kinds: config.kinds,
      sinceDays: config.sinceDays,
    });

    if (signature !== lastSignature) {
      lastSignature = signature;
      nextRunAt = 0;
    }

    if (config.identifiers.length === 0) {
      await writeState({ lastRunAt: now, lastImported: 0 });
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      continue;
    }

    if (now < nextRunAt) {
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      continue;
    }

    const relayOverride = config.relays
      .map(normalizeRelay)
      .filter((value): value is string => value !== undefined);
    let imported = 0;
    let lastError: string | undefined;

    for (const identifier of config.identifiers) {
      try {
        const { pubkey, relays: nip05Relays } = await resolveIdentifier(
          identifier,
        );
        const discovered = relayOverride.length
          ? relayOverride
          : await discoverRelays(pool, pubkey);
        const relays = unique([
          ...nip05Relays,
          ...discovered,
          ...(relayOverride.length > 0 ? [] : DEFAULT_RELAYS),
        ]);
        if (relays.length === 0) {
          throw new Error("no relays available");
        }

        const cursor: Cursor = cursors[pubkey] ?? {
          latest: 0,
          backfillComplete: false,
        };
        cursors[pubkey] = cursor;

        if (!cursor.backfillComplete) {
          const cutoff =
            config.sinceDays > 0
              ? now - config.sinceDays * 24 * 60 * 60
              : 0;
          log(
            `backfilling ${identifier} (${pubkey}) across ${relays.length} relays`,
          );
          await syncRange(
            pool,
            relays,
            pubkey,
            cutoff,
            cursor.backfillUntil ?? now,
            config,
            async (events, nextUntil) => {
              imported += events.length;
              await writeState({ lastRunAt: now, lastImported: imported });
              await ingest(events);
              cursor.backfillUntil = nextUntil;
              await saveCursors(cursors);
            },
          );
          cursor.backfillComplete = true;
          delete cursor.backfillUntil;
          cursor.latest = now;
          await saveCursors(cursors);
          log(`backfill complete for ${identifier}`);
        } else {
          const since = Math.max(0, cursor.latest - OVERLAP_SECONDS);
          await syncRange(
            pool,
            relays,
            pubkey,
            since,
            now,
            config,
            async (events) => {
              imported += events.length;
              await ingest(events);
            },
          );
          cursor.latest = now;
          await saveCursors(cursors);
          log(`synced ${identifier}`);
        }
      } catch (cause) {
        lastError = cause instanceof Error ? cause.message : String(cause);
        error(`identifier ${identifier} failed`, cause);
      }
    }

    await writeState({
      lastRunAt: now,
      lastImported: imported,
      ...(lastError ? { lastError } : {}),
    });

    nextRunAt = now + config.intervalSeconds;
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
}

main().catch((cause) => {
  error("fatal", cause);
  process.exit(1);
});
