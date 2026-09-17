import { mkdtemp, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";

import {
  BROWSER_SNAPSHOT_DIR_PREFIX,
  BROWSER_SQLITE_BUSY_TIMEOUT_MS,
  browserSqliteNormalOpenAttempts,
  detectSqliteCompanionFiles,
  openBrowserCookieDatabase,
  resetBrowserSqliteStateForTests,
} from "../src/lib/browser-store-open.js";

const tempRoots: string[] = [];

async function createTempDir(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qwencloud-store-open-"));
  tempRoots.push(root);
  return root;
}

function createWalDatabase(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("CREATE TABLE moz_cookies (name TEXT, value TEXT);");
  db.exec("INSERT INTO moz_cookies VALUES ('login_qwencloud_ticket', 'ticket-secret');");
  return db;
}

/** Rollback-journal database with an exclusive writer, as a live Chromium. */
function createExclusiveLockedDatabase(dbPath: string): DatabaseSync {
  const writer = new DatabaseSync(dbPath);
  writer.exec("PRAGMA journal_mode = DELETE;");
  writer.exec("CREATE TABLE cookies (name TEXT, value TEXT);");
  writer.exec("INSERT INTO cookies VALUES ('login_qwencloud_ticket', 'ticket-secret');");
  writer.exec("BEGIN EXCLUSIVE;");
  writer.exec("INSERT INTO cookies VALUES ('pending', 'value');");
  return writer;
}

describe("browser cookie database opening", () => {
  afterEach(async () => {
    resetBrowserSqliteStateForTests();
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("detects write-ahead-log companions of a live database", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      const companions = await detectSqliteCompanionFiles(dbPath);
      expect(companions).toContain("wal");
    } finally {
      writer.close();
    }
  });

  it("reads write-ahead-log content a writer has not checkpointed yet", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      // A new login lands in the WAL while the browser stays open.
      writer.exec("INSERT INTO moz_cookies VALUES ('cna', 'fresh-anon');");

      const conn = await openBrowserCookieDatabase(dbPath);
      expect(conn).not.toBeNull();
      const rows = conn?.all<{ name: string }>("SELECT name FROM moz_cookies ORDER BY name");
      conn?.close();
      expect(rows?.map((row) => row.name)).toEqual(["cna", "login_qwencloud_ticket"]);
    } finally {
      writer.close();
    }
  });

  it("reads through a live write-ahead-log writer without exceeding the bound", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    writer.exec("BEGIN IMMEDIATE;");
    writer.exec("INSERT INTO moz_cookies VALUES ('pending', 'value');");
    try {
      const started = performance.now();
      const conn = await openBrowserCookieDatabase(dbPath);
      const elapsed = performance.now() - started;
      expect(conn).not.toBeNull();
      expect(elapsed).toBeLessThan(1_000);
      conn?.close();
    } finally {
      writer.exec("ROLLBACK;");
      writer.close();
    }
  });

  it("falls back to a bounded snapshot when a writer holds an exclusive lock", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = createExclusiveLockedDatabase(dbPath);
    try {
      const started = performance.now();
      const conn = await openBrowserCookieDatabase(dbPath);
      const elapsed = performance.now() - started;

      expect(conn).not.toBeNull();
      // Bounded by one short busy wait plus the snapshot open, never seconds.
      expect(elapsed).toBeLessThan(BROWSER_SQLITE_BUSY_TIMEOUT_MS * 4);
      expect(conn?.all<{ name: string }>("SELECT name FROM cookies")).toEqual([
        { name: "login_qwencloud_ticket" },
      ]);
      conn?.close();
    } finally {
      writer.exec("ROLLBACK;");
      writer.close();
    }
  });

  it("reads a locked store through a copied snapshot without URI support", async () => {
    // Simulates runtimes such as bun:sqlite that reject URI filenames: the
    // locked plain open gives up within the busy bound, and the private copy
    // still reads the committed state (the hot journal rolls back) instead of
    // blocking for the seconds a browser writer can hold locks.
    resetBrowserSqliteStateForTests(false);
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = createExclusiveLockedDatabase(dbPath);
    try {
      const started = performance.now();
      const conn = await openBrowserCookieDatabase(dbPath);
      const elapsed = performance.now() - started;
      expect(conn).not.toBeNull();
      expect(elapsed).toBeLessThan(BROWSER_SQLITE_BUSY_TIMEOUT_MS * 4);
      expect(conn?.all<{ name: string }>("SELECT name FROM cookies")).toEqual([
        { name: "login_qwencloud_ticket" },
      ]);
      conn?.close();
    } finally {
      writer.exec("ROLLBACK;");
      writer.close();
    }
  });

  it("sees write-ahead-log-only rows through a forced copied snapshot", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      // The browser stays open and never checkpoints: the login exists only in
      // the write-ahead log.
      writer.exec("INSERT INTO moz_cookies VALUES ('login_qwencloud_ticket_fresh', 'x');");

      const conn = await openBrowserCookieDatabase(dbPath, { preferSnapshotCopy: true });
      expect(conn).not.toBeNull();
      const rows = conn?.all<{ name: string }>("SELECT name FROM moz_cookies ORDER BY name");
      conn?.close();
      expect(rows?.map((row) => row.name)).toContain("login_qwencloud_ticket_fresh");
    } finally {
      writer.close();
    }
  });

  it("skips the copied snapshot when the store exceeds the size bound", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      const conn = await openBrowserCookieDatabase(dbPath, {
        preferSnapshotCopy: true,
        maxCopyBytes: 8,
      });
      expect(conn).toBeNull();
    } finally {
      writer.close();
    }
  });

  it("deletes the copied snapshot when the connection closes", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      const before = (await readdir(tmpdir())).filter((name) =>
        name.startsWith("opencode-quota-snapshot-"),
      ).length;
      const conn = await openBrowserCookieDatabase(dbPath, { preferSnapshotCopy: true });
      expect(conn).not.toBeNull();
      conn?.all("SELECT name FROM moz_cookies");
      conn?.close();
      await new Promise((resolve) => setTimeout(resolve, 50));
      const after = (await readdir(tmpdir())).filter((name) =>
        name.startsWith("opencode-quota-snapshot-"),
      ).length;
      expect(after).toBe(before);
    } finally {
      writer.close();
    }
  });

  it("still reads a quiet database when immutable snapshots are unavailable", async () => {
    resetBrowserSqliteStateForTests(false);
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = new DatabaseSync(dbPath);
    writer.exec("CREATE TABLE cookies (name TEXT, value TEXT);");
    writer.exec("INSERT INTO cookies VALUES ('login_qwencloud_ticket', 'ticket-secret');");
    writer.close();

    const conn = await openBrowserCookieDatabase(dbPath);
    expect(conn).not.toBeNull();
    expect(conn?.get<{ name: string }>("SELECT name FROM cookies")).toEqual({
      name: "login_qwencloud_ticket",
    });
    conn?.close();
  });

  it("treats a write-ahead log without shared memory as writer activity", async () => {
    // Only the log carries the uncheckpointed rows, so the plain open has to be
    // attempted even when no shared-memory or journal file is present.
    resetBrowserSqliteStateForTests(true);
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    await writeFile(dbPath, "not a database");
    await writeFile(`${dbPath}-wal`, "frames");

    await openBrowserCookieDatabase(dbPath);
    expect(browserSqliteNormalOpenAttempts(dbPath)).toBe(1);
  });

  it("skips the contended open when a quiet store has no writer artifacts", async () => {
    resetBrowserSqliteStateForTests(true);
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    await writeFile(dbPath, "not a database");

    await openBrowserCookieDatabase(dbPath);
    expect(browserSqliteNormalOpenAttempts(dbPath)).toBe(0);
  });

  it("does not repeat a lost busy wait for the backoff window", async () => {
    resetBrowserSqliteStateForTests(false);
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = createExclusiveLockedDatabase(dbPath);
    try {
      const first = await openBrowserCookieDatabase(dbPath);
      first?.close();
      expect(browserSqliteNormalOpenAttempts(dbPath)).toBe(1);

      const second = await openBrowserCookieDatabase(dbPath);
      // The contended open is not retried inside the backoff window; the store is
      // still readable through the private copied snapshot.
      expect(browserSqliteNormalOpenAttempts(dbPath)).toBe(1);
      expect(second).not.toBeNull();
      expect(second?.get<{ name: string }>("SELECT name FROM cookies")).toEqual({
        name: "login_qwencloud_ticket",
      });
      second?.close();
    } finally {
      writer.exec("ROLLBACK;");
      writer.close();
    }
  });

  it("prunes a snapshot directory a killed process left behind", async () => {
    resetBrowserSqliteStateForTests();
    const stale = await mkdtemp(join(tmpdir(), `${BROWSER_SNAPSHOT_DIR_PREFIX}stale-`));
    const fresh = await mkdtemp(join(tmpdir(), `${BROWSER_SNAPSHOT_DIR_PREFIX}fresh-`));
    await writeFile(join(stale, "Cookies"), "leftover");
    const old = new Date(Date.now() / 1000 - 7200);
    await utimes(stale, old, old);

    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      const conn = await openBrowserCookieDatabase(dbPath, { preferSnapshotCopy: true });
      conn?.close();
    } finally {
      writer.close();
    }

    const remaining = await readdir(tmpdir());
    expect(remaining).not.toContain(stale.split("/").pop());
    // A directory another process may still be using is left alone.
    expect(remaining).toContain(fresh.split("/").pop());
    await rm(fresh, { recursive: true, force: true });
  });

  it("prunes leftover snapshot directories only once per process", async () => {
    resetBrowserSqliteStateForTests();
    const first = await mkdtemp(join(tmpdir(), `${BROWSER_SNAPSHOT_DIR_PREFIX}once-`));
    const old = new Date(Date.now() / 1000 - 7200);
    await utimes(first, old, old);

    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      const conn = await openBrowserCookieDatabase(dbPath, { preferSnapshotCopy: true });
      conn?.close();
      // A directory created after the prune survives until the next process.
      const second = await mkdtemp(join(tmpdir(), `${BROWSER_SNAPSHOT_DIR_PREFIX}twice-`));
      await utimes(second, old, old);
      const secondConn = await openBrowserCookieDatabase(dbPath, { preferSnapshotCopy: true });
      secondConn?.close();
      expect(await readdir(tmpdir())).toContain(second.split("/").pop());
      await rm(second, { recursive: true, force: true });
    } finally {
      writer.close();
    }
    expect(await readdir(tmpdir())).not.toContain(first.split("/").pop());
  });

  it("keeps the host event loop responsive while the store is contended", async () => {
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = createExclusiveLockedDatabase(dbPath);
    try {
      let maxGap = 0;
      let lastTick = Date.now();
      const heartbeat = setInterval(() => {
        const now = Date.now();
        maxGap = Math.max(maxGap, now - lastTick);
        lastTick = now;
      }, 1);

      for (let i = 0; i < 5; i++) {
        resetBrowserSqliteStateForTests();
        const conn = await openBrowserCookieDatabase(dbPath);
        conn?.close();
      }
      clearInterval(heartbeat);

      // Each open pays at most one short busy wait; the host loop may never
      // stall for the seconds a browser writer can hold the database.
      expect(maxGap).toBeLessThan(30);
    } finally {
      writer.exec("ROLLBACK;");
      writer.close();
    }
  });

  it("creates no files inside the browser profile", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    const writer = createWalDatabase(dbPath);
    try {
      const before = (await readdir(dir)).sort();
      const conn = await openBrowserCookieDatabase(dbPath);
      conn?.all("SELECT name FROM moz_cookies");
      conn?.close();
      const after = (await readdir(dir)).sort();
      expect(after).toEqual(before);
    } finally {
      writer.close();
    }
  });

  it("reads a plain journal-mode database", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = new DatabaseSync(dbPath);
    writer.exec("CREATE TABLE cookies (name TEXT, value TEXT);");
    writer.exec("INSERT INTO cookies VALUES ('login_qwencloud_ticket', 'ticket-secret');");
    writer.close();

    const conn = await openBrowserCookieDatabase(dbPath);
    expect(conn).not.toBeNull();
    expect(conn?.get<{ name: string }>("SELECT name FROM cookies")).toEqual({
      name: "login_qwencloud_ticket",
    });
    conn?.close();
  });

  it("returns null for a missing or invalid database", async () => {
    resetBrowserSqliteStateForTests();
    const dir = await createTempDir();
    await expect(openBrowserCookieDatabase(join(dir, "missing.sqlite"))).resolves.toBeNull();

    const corrupt = join(dir, "corrupt.sqlite");
    await writeFile(corrupt, "this is not a sqlite database at all");
    await expect(openBrowserCookieDatabase(corrupt)).resolves.toBeNull();
  });
});
