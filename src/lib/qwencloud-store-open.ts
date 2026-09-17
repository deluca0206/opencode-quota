import { copyFile, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  openOpenCodeSqliteReadOnly,
  openOpenCodeSqliteWritable,
  type SqliteConn,
} from "./opencode-sqlite.js";

/**
 * Upper bound for one synchronous wait on a browser's cookie database.
 *
 * Browser writers can hold the database for seconds, so waiting longer only
 * freezes the host event loop (`DatabaseSync` is synchronous). Failed waits are
 * remembered per store and not repeated for a while.
 */
export const BROWSER_SQLITE_BUSY_TIMEOUT_MS = 15;

/** After a busy failure, the store's plain open is skipped for this long. */
export const BROWSER_NORMAL_OPEN_BUSY_BACKOFF_MS = 10_000;

/** Upper bound for the total size of one copied snapshot (database plus logs). */
export const MAX_BROWSER_SNAPSHOT_COPY_BYTES = 64 * 1024 * 1024;

export type BrowserSqliteCompanion = "wal" | "shm" | "journal";

/** Companion files that indicate live writer activity next to a cookie database. */
export async function detectSqliteCompanionFiles(
  dbPath: string,
): Promise<BrowserSqliteCompanion[]> {
  const candidates: Array<[BrowserSqliteCompanion, string]> = [
    ["wal", `${dbPath}-wal`],
    ["shm", `${dbPath}-shm`],
    ["journal", `${dbPath}-journal`],
  ];
  const found: BrowserSqliteCompanion[] = [];
  for (const [kind, path] of candidates) {
    try {
      const info = await stat(path);
      if (info.isFile()) found.push(kind);
    } catch {
      // Absent companion files are the normal steady state.
    }
  }
  return found;
}

/**
 * Whether this runtime can open SQLite URI filenames (`file:…?immutable=1`).
 *
 * Node supports them; `bun:sqlite` (the OpenCode plugin runtime) may not and
 * treats the whole string as a literal path. The capability is probed once per
 * process, and when unavailable the plain read-only open becomes the only
 * strategy.
 */
let immutableUriSupported: boolean | null = null;
const normalOpenBusyFailures = new Map<string, number>();
const snapshotCopyFailures = new Map<string, number>();
let lastOpenError: unknown = null;

export function resetBrowserSqliteStateForTests(immutableSupported?: boolean): void {
  immutableUriSupported = immutableSupported ?? null;
  normalOpenBusyFailures.clear();
  snapshotCopyFailures.clear();
  lastOpenError = null;
}

async function immutableSnapshotsSupported(dbPath: string): Promise<boolean> {
  if (immutableUriSupported !== null) return immutableUriSupported;
  try {
    const conn = await openOpenCodeSqliteReadOnly(dbPath, {
      immutable: true,
      busyTimeoutMs: 0,
    });
    try {
      conn.get("SELECT 1");
    } finally {
      conn.close();
    }
    immutableUriSupported = true;
  } catch {
    immutableUriSupported = false;
  }
  return immutableUriSupported;
}

function isOpenBusyError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /locked|busy/iu.test(message);
}

function normalOpenSuppressed(dbPath: string, now: number): boolean {
  const failedAt = normalOpenBusyFailures.get(dbPath);
  return failedAt !== undefined && now - failedAt < BROWSER_NORMAL_OPEN_BUSY_BACKOFF_MS;
}

/**
 * Open a browser cookie database without stalling the host event loop.
 *
 * - A plain read-only open is attempted first when writer artifacts exist: it
 *   sees write-ahead-log content that a snapshot misses, so a freshly signed-in
 *   session is visible immediately. Its busy wait is tiny and, once it loses to
 *   the writer, the attempt is not repeated for the backoff window.
 * - When immutable URI snapshots are supported they are the reliable fallback:
 *   they never block and never create files inside the browser profile.
 * - Without URI support (bun:sqlite), the plain open is the only strategy and is
 *   still attempted with the same tiny bound.
 *
 * Returns `null` when the store cannot be read at all.
 */
export interface OpenBrowserStoreOptions {
  /** Skip direct opens and read a copied snapshot right away. */
  preferSnapshotCopy?: boolean;
  /** Override for tests of the snapshot size cap. */
  maxCopyBytes?: number;
}

/** True when the store has write-ahead-log frames a direct read may miss. */
export async function hasNonEmptyCompanionWal(dbPath: string): Promise<boolean> {
  try {
    const info = await stat(`${dbPath}-wal`);
    return info.isFile() && info.size > 0;
  } catch {
    return false;
  }
}

export async function openBrowserCookieDatabase(
  dbPath: string,
  options?: OpenBrowserStoreOptions,
): Promise<SqliteConn | null> {
  if (options?.preferSnapshotCopy) {
    return openCopiedSnapshot(dbPath, options.maxCopyBytes);
  }

  const companions = await detectSqliteCompanionFiles(dbPath);
  const writerArtifactsPresent = companions.includes("shm") || companions.includes("journal");

  const attemptNormalOpen = async (): Promise<SqliteConn | null> => {
    if (normalOpenSuppressed(dbPath, Date.now())) return null;
    const conn = await tryOpen(dbPath, { busyTimeoutMs: BROWSER_SQLITE_BUSY_TIMEOUT_MS });
    if (conn) return conn;
    if (isOpenBusyError(lastOpenError)) {
      normalOpenBusyFailures.set(dbPath, Date.now());
    }
    return null;
  };

  if (await immutableSnapshotsSupported(dbPath)) {
    if (writerArtifactsPresent) {
      const conn = await attemptNormalOpen();
      if (conn) return conn;
    }
    const conn = await tryOpen(dbPath, {
      immutable: true,
      busyTimeoutMs: BROWSER_SQLITE_BUSY_TIMEOUT_MS,
    });
    if (conn) return conn;
    return openCopiedSnapshot(dbPath, options?.maxCopyBytes);
  }

  if (writerArtifactsPresent) {
    const conn = await attemptNormalOpen();
    if (conn) return conn;
  } else {
    const conn = await tryOpen(dbPath, { busyTimeoutMs: BROWSER_SQLITE_BUSY_TIMEOUT_MS });
    if (conn) return conn;
  }
  return openCopiedSnapshot(dbPath, options?.maxCopyBytes);
}

/**
 * Read a browser store through a private copy.
 *
 * A running browser can hold its database and keep fresh data in a write-ahead
 * log that neither a locked plain open nor an immutable snapshot can see. File
 * copies need no SQLite locks, and opening the copy writable lets SQLite
 * recover the log — so a login performed with the browser open becomes visible
 * immediately. The copy lives in a private 0700 temporary directory and is
 * deleted as soon as the connection closes.
 */
async function openCopiedSnapshot(
  dbPath: string,
  maxCopyBytes = MAX_BROWSER_SNAPSHOT_COPY_BYTES,
): Promise<SqliteConn | null> {
  const failedAt = snapshotCopyFailures.get(dbPath);
  if (failedAt !== undefined && Date.now() - failedAt < BROWSER_NORMAL_OPEN_BUSY_BACKOFF_MS) {
    return null;
  }
  try {
    const totalBytes = await totalSnapshotBytes(dbPath);
    if (totalBytes === null || totalBytes > maxCopyBytes) return null;

    const dir = await mkdtemp(join(tmpdir(), "opencode-quota-snapshot-"));
    try {
      const copyPath = join(dir, basename(dbPath));
      await copyFile(dbPath, copyPath);
      for (const suffix of ["-wal", "-journal"]) {
        try {
          await copyFile(`${dbPath}${suffix}`, `${copyPath}${suffix}`);
        } catch {
          // Absent companions are the normal steady state.
        }
      }
      const conn = await openOpenCodeSqliteWritable(copyPath, {
        busyTimeoutMs: BROWSER_SQLITE_BUSY_TIMEOUT_MS,
      });
      try {
        conn.get("SELECT 1");
      } catch (error) {
        conn.close();
        throw error;
      }
      return withTempCleanup(conn, dir);
    } catch {
      snapshotCopyFailures.set(dbPath, Date.now());
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
      return null;
    }
  } catch {
    return null;
  }
}

function withTempCleanup(conn: SqliteConn, dir: string): SqliteConn {
  return {
    all: (sql, params) => conn.all(sql, params),
    get: (sql, params) => conn.get(sql, params),
    close: () => {
      try {
        conn.close();
      } finally {
        void rm(dir, { recursive: true, force: true }).catch(() => undefined);
      }
    },
  };
}

async function totalSnapshotBytes(dbPath: string): Promise<number | null> {
  let total = 0;
  for (const path of [dbPath, `${dbPath}-wal`, `${dbPath}-journal`]) {
    try {
      const info = await stat(path);
      if (!info.isFile()) continue;
      total += info.size;
    } catch {
      // A missing companion contributes nothing.
    }
  }
  return total > 0 ? total : null;
}

async function tryOpen(
  dbPath: string,
  options: Parameters<typeof openOpenCodeSqliteReadOnly>[1],
): Promise<SqliteConn | null> {
  lastOpenError = null;
  let conn: SqliteConn | null = null;
  try {
    conn = await openOpenCodeSqliteReadOnly(dbPath, options);
  } catch (error) {
    lastOpenError = error;
    return null;
  }
  // SQLite opens lazily, so a truncated or non-database file only fails on the
  // first statement. Validate here to keep the contract "usable connection or
  // null" for callers.
  try {
    conn.get("SELECT 1");
    return conn;
  } catch (error) {
    lastOpenError = error;
    conn.close();
    return null;
  }
}
