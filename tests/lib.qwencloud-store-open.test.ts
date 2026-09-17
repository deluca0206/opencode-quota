import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";

import {
  BROWSER_SQLITE_BUSY_TIMEOUT_MS,
  detectSqliteCompanionFiles,
  openBrowserCookieDatabase,
  resetBrowserSqliteStateForTests,
} from "../src/lib/qwencloud-store-open.js";

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

  it("does not repeat a lost busy wait for the backoff window", async () => {
    resetBrowserSqliteStateForTests(false);
    const dir = await createTempDir();
    const dbPath = join(dir, "Cookies");
    const writer = createExclusiveLockedDatabase(dbPath);
    try {
      const firstStarted = performance.now();
      await openBrowserCookieDatabase(dbPath);
      const firstMs = performance.now() - firstStarted;

      const secondStarted = performance.now();
      await openBrowserCookieDatabase(dbPath);
      const secondMs = performance.now() - secondStarted;

      // The first call waits out the busy timeout; the second must skip it.
      expect(firstMs).toBeGreaterThan(BROWSER_SQLITE_BUSY_TIMEOUT_MS / 2);
      expect(secondMs).toBeLessThan(BROWSER_SQLITE_BUSY_TIMEOUT_MS / 2);
    } finally {
      writer.exec("ROLLBACK;");
      writer.close();
    }
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
