import { pathToFileURL } from "node:url";

export interface SqliteConn {
  all<T = unknown>(sql: string, params?: unknown[]): T[];
  get<T = unknown>(sql: string, params?: unknown[]): T | null;
  close(): void;
}

export const DEFAULT_SQLITE_BUSY_TIMEOUT_MS = 5_000;

export interface OpenSqliteReadOnlyOptions {
  immutable?: boolean;
  /**
   * Upper bound for waiting on a contended database. Browser cookie stores use a
   * small value so a writer holding the database can never stall the caller.
   */
  busyTimeoutMs?: number;
}

function busyTimeoutPragma(options?: OpenSqliteReadOnlyOptions): string {
  const busyTimeoutMs = Math.max(0, options?.busyTimeoutMs ?? DEFAULT_SQLITE_BUSY_TIMEOUT_MS);
  return `PRAGMA busy_timeout = ${busyTimeoutMs};`;
}

export function sqliteDatabasePath(dbPath: string, options?: OpenSqliteReadOnlyOptions): string {
  if (!options?.immutable) return dbPath;
  const url = pathToFileURL(dbPath);
  url.searchParams.set("immutable", "1");
  return url.href;
}

interface SqliteStatement {
  all(...params: unknown[]): unknown[];
  get(...params: unknown[]): unknown;
  run(...params: unknown[]): unknown;
}

interface BunSqliteDatabase {
  query(sql: string): SqliteStatement;
  close(): void;
}

interface BunSqliteModule {
  Database: new (path: string, options?: { readonly?: boolean }) => BunSqliteDatabase;
}

interface PreparedSqliteDatabase {
  prepare(sql: string): SqliteStatement;
  close(): void;
}

interface NodeSqliteDatabase extends PreparedSqliteDatabase {
  exec(sql: string): unknown;
}

interface NodeSqliteModule {
  DatabaseSync: new (
    path: string,
    options?: {
      readOnly?: boolean;
      enableForeignKeyConstraints?: boolean;
      open?: boolean;
    },
  ) => NodeSqliteDatabase;
}

interface BetterSqlite3Module {
  default: new (path: string, options?: { readonly?: boolean }) => PreparedSqliteDatabase;
}

function toParams(params?: unknown[]): unknown[] {
  return Array.isArray(params) ? params : [];
}

function runBunPragma(db: BunSqliteDatabase, sql: string): void {
  try {
    db.query(sql).run();
  } catch {
    // ignore
  }
}

function runPreparedPragma(db: PreparedSqliteDatabase, sql: string): void {
  try {
    db.prepare(sql).run();
  } catch {
    // ignore
  }
}

function runNodePragma(db: NodeSqliteDatabase, sql: string): void {
  try {
    db.exec(sql);
  } catch {
    // ignore
  }
}

function createPreparedSqliteConn(db: PreparedSqliteDatabase): SqliteConn {
  return {
    all<T = unknown>(sql: string, params?: unknown[]): T[] {
      const stmt = db.prepare(sql);
      return stmt.all(...toParams(params)) as T[];
    },

    get<T = unknown>(sql: string, params?: unknown[]): T | null {
      const stmt = db.prepare(sql);
      const row = stmt.get(...toParams(params)) as T | undefined;
      return row ?? null;
    },

    close(): void {
      try {
        db.close();
      } catch {
        // ignore
      }
    },
  };
}

function createBunSqliteConn(db: BunSqliteDatabase): SqliteConn {
  return {
    all<T = unknown>(sql: string, params?: unknown[]): T[] {
      const stmt = db.query(sql);
      return stmt.all(...toParams(params)) as T[];
    },

    get<T = unknown>(sql: string, params?: unknown[]): T | null {
      const stmt = db.query(sql);
      const row = stmt.get(...toParams(params)) as T | undefined;
      return row ?? null;
    },

    close(): void {
      try {
        db.close();
      } catch {
        // ignore
      }
    },
  };
}

async function openWithBunSqlite(
  dbPath: string,
  options?: OpenSqliteReadOnlyOptions,
): Promise<SqliteConn> {
  const mod = (await import("bun:sqlite")) as unknown as BunSqliteModule;
  const db = new mod.Database(sqliteDatabasePath(dbPath, options), { readonly: true });

  // Keep reads deterministic and avoid accidental writes.
  runBunPragma(db, "PRAGMA query_only = ON;");

  // Avoid transient SQLITE_BUSY errors (WAL).
  runBunPragma(db, busyTimeoutPragma(options));

  return createBunSqliteConn(db);
}

/**
 * Writable open for plugin-owned temporary snapshot copies only.
 *
 * Browser cookie stores hold fresh data in a write-ahead log that a read-only
 * connection cannot recover. Copying the files first and letting SQLite recover
 * the copy needs write access to that copy, so this entry point exists — but it
 * must never be pointed at files inside a browser profile.
 */
export async function openOpenCodeSqliteWritable(
  dbPath: string,
  options?: { busyTimeoutMs?: number },
): Promise<SqliteConn> {
  if (typeof globalThis === "object" && "Bun" in globalThis) {
    const mod = (await import("bun:sqlite")) as unknown as BunSqliteModule;
    const db = new mod.Database(dbPath);
    runBunPragma(db, busyTimeoutPragma(options));
    return createBunSqliteConn(db);
  }

  const nodeSqlite = await importNodeSqlite();
  if (nodeSqlite) {
    const db = new nodeSqlite.DatabaseSync(dbPath);
    runNodePragma(db, busyTimeoutPragma(options));
    return createPreparedSqliteConn(db);
  }

  try {
    const mod = (await import("better-sqlite3")) as unknown as BetterSqlite3Module;
    const db = new mod.default(dbPath);
    runPreparedPragma(db, busyTimeoutPragma(options));
    return createPreparedSqliteConn(db);
  } catch (cause) {
    throw new Error(
      "OpenCode SQLite backend unavailable in this Node runtime; node:sqlite or optional better-sqlite3 is required for local history reads.",
      { cause },
    );
  }
}

async function importNodeSqlite(): Promise<NodeSqliteModule | null> {
  try {
    return (await import("node:sqlite")) as unknown as NodeSqliteModule;
  } catch {
    return null;
  }
}

async function openWithNodeSqlite(
  dbPath: string,
  mod: NodeSqliteModule,
  options?: OpenSqliteReadOnlyOptions,
): Promise<SqliteConn> {
  const db = new mod.DatabaseSync(sqliteDatabasePath(dbPath, options), {
    readOnly: true,
    enableForeignKeyConstraints: true,
    open: true,
  });

  // Keep reads deterministic and avoid accidental writes.
  runNodePragma(db, "PRAGMA query_only = ON;");

  // Avoid transient SQLITE_BUSY errors (WAL).
  runNodePragma(db, busyTimeoutPragma(options));

  return createPreparedSqliteConn(db);
}

async function openWithBetterSqlite3(
  dbPath: string,
  options?: OpenSqliteReadOnlyOptions,
): Promise<SqliteConn> {
  const mod = (await import("better-sqlite3")) as unknown as BetterSqlite3Module;
  const db = new mod.default(sqliteDatabasePath(dbPath, options), { readonly: true });

  // Keep reads deterministic and avoid accidental writes.
  runPreparedPragma(db, "PRAGMA query_only = ON;");

  // Avoid transient SQLITE_BUSY errors (WAL).
  runPreparedPragma(db, busyTimeoutPragma(options));

  return createPreparedSqliteConn(db);
}

async function openWithNodeRuntimeSqlite(
  dbPath: string,
  options?: OpenSqliteReadOnlyOptions,
): Promise<SqliteConn> {
  const nodeSqlite = await importNodeSqlite();

  if (nodeSqlite) {
    return openWithNodeSqlite(dbPath, nodeSqlite, options);
  }

  try {
    return await openWithBetterSqlite3(dbPath, options);
  } catch (cause) {
    throw new Error(
      "OpenCode SQLite backend unavailable in this Node runtime; node:sqlite or optional better-sqlite3 is required for local history reads.",
      { cause },
    );
  }
}

export async function openOpenCodeSqliteReadOnly(
  dbPath: string,
  options?: OpenSqliteReadOnlyOptions,
): Promise<SqliteConn> {
  if (typeof globalThis === "object" && "Bun" in globalThis) {
    return openWithBunSqlite(dbPath, options);
  }

  return openWithNodeRuntimeSqlite(dbPath, options);
}
