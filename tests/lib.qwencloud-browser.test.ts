import { mkdir, mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const backendMocks = vi.hoisted(() => ({
  listFirefoxCookieStores: vi.fn(),
  readFirefoxCookieDatabase: vi.fn(),
  listChromiumCookieStores: vi.fn(),
  readChromiumQwenCloudCookies: vi.fn(),
}));

vi.mock("../src/lib/qwencloud-firefox.js", () => ({
  listFirefoxCookieStores: backendMocks.listFirefoxCookieStores,
  readFirefoxCookieDatabase: backendMocks.readFirefoxCookieDatabase,
}));

vi.mock("../src/lib/qwencloud-chromium.js", () => ({
  listChromiumCookieStores: backendMocks.listChromiumCookieStores,
  readChromiumQwenCloudCookies: backendMocks.readChromiumQwenCloudCookies,
}));

import {
  browserStoresSignature,
  discoverBrowserCookieStores,
  fingerprintBrowserCookieStores,
  importBrowserQwenCloudSession,
  summarizeRead,
} from "../src/lib/qwencloud-browser.js";

const tempRoots: string[] = [];
const NOW_MS = 1_700_000_000_000;
const TICKET = [{ name: "login_qwencloud_ticket", value: "secret", host: ".qwencloud.com" }];

function firefoxStore(name: string, path: string) {
  return { name, path, isDefault: false };
}

function chromiumStore(browser: string, profile: string, path: string) {
  return { browser, profile, rootPath: path, dbPath: join(path, "Cookies") };
}

async function createTempDir(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qwencloud-browser-"));
  tempRoots.push(root);
  return root;
}

describe("QwenCloud browser session orchestrator", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    backendMocks.listFirefoxCookieStores.mockResolvedValue([]);
    backendMocks.listChromiumCookieStores.mockResolvedValue([]);
  });

  afterEach(async () => {
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("merges Firefox and Chromium stores without any environment variable", async () => {
    backendMocks.listFirefoxCookieStores.mockResolvedValue([
      firefoxStore("default-release", "/tmp/ff"),
    ]);
    backendMocks.listChromiumCookieStores.mockResolvedValue([
      chromiumStore("google-chrome", "Default", "/tmp/chrome"),
    ]);
    const stores = await discoverBrowserCookieStores({ env: {} });
    expect(stores.map((store) => `${store.kind}:${store.browser}/${store.profile}`)).toEqual([
      "firefox:firefox/default-release",
      "chromium:google-chrome/Default",
    ]);
  });

  it("returns no stores when browser import is disabled", async () => {
    backendMocks.listFirefoxCookieStores.mockResolvedValue([
      firefoxStore("default-release", "/tmp/ff"),
    ]);
    await expect(
      discoverBrowserCookieStores({ env: { QWEN_CLOUD_BROWSER: "none" } }),
    ).resolves.toEqual([]);
    await expect(
      importBrowserQwenCloudSession({ env: { QWEN_CLOUD_BROWSER: "none" }, nowMs: NOW_MS }),
    ).resolves.toEqual({ state: "disabled" });
  });

  it("reports no_stores when the machine has no supported browser", async () => {
    await expect(
      importBrowserQwenCloudSession({ env: {}, nowMs: NOW_MS, stores: [] }),
    ).resolves.toEqual({ state: "no_stores" });
  });

  it("reads the most recently used browser first and stops at the first ticket", async () => {
    const dir = await createTempDir();
    const stalePath = join(dir, "stale.sqlite");
    const freshPath = join(dir, "fresh.sqlite");
    await writeFile(stalePath, "stale");
    await writeFile(freshPath, "fresh");
    const past = new Date(NOW_MS / 1000 - 7200);
    const recent = new Date(NOW_MS / 1000 - 60);
    await utimes(stalePath, past, past);
    await utimes(freshPath, recent, recent);

    backendMocks.readFirefoxCookieDatabase.mockImplementation(async (dbPath: string) =>
      dbPath === freshPath ? TICKET : [{ name: "cna", value: "anon" }],
    );

    const stores = [
      { kind: "firefox" as const, browser: "firefox", profile: "a", dbPath: stalePath },
      { kind: "firefox" as const, browser: "firefox", profile: "b", dbPath: freshPath },
    ];
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores,
    });
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.store.profile).toBe("b");
    expect(backendMocks.readFirefoxCookieDatabase).toHaveBeenCalledTimes(1);
    expect(backendMocks.readFirefoxCookieDatabase).toHaveBeenCalledWith(freshPath, NOW_MS, {});
  });

  it("falls through to Chromium when Firefox has no QwenCloud ticket", async () => {
    backendMocks.readFirefoxCookieDatabase.mockResolvedValue([{ name: "cna", value: "anon" }]);
    backendMocks.readChromiumQwenCloudCookies.mockResolvedValue({
      state: "imported",
      cookies: TICKET,
      keyringProtected: false,
    });
    const dir = await createTempDir();
    const ffPath = join(dir, "ff.sqlite");
    await writeFile(ffPath, "ff");
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        {
          kind: "firefox" as const,
          browser: "firefox",
          profile: "default-release",
          dbPath: ffPath,
        },
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath: join(dir, "Cookies"),
          rootPath: dir,
        },
      ],
    });
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.store.browser).toBe("google-chrome");
  });

  it("reports keyring-protected Chromium stores as no session with a hint", async () => {
    backendMocks.readChromiumQwenCloudCookies.mockResolvedValue({ state: "keyring" });
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath: "/tmp/chrome/Cookies",
          rootPath: "/tmp/chrome",
        },
      ],
    });
    expect(result).toMatchObject({ state: "no_session", keyringSeen: true });
  });

  it("keeps the keyring hint when another browser simply has no session", async () => {
    backendMocks.readChromiumQwenCloudCookies.mockResolvedValue({ state: "keyring" });
    backendMocks.readFirefoxCookieDatabase.mockResolvedValue([{ name: "cna", value: "anon" }]);
    const dir = await createTempDir();
    const ffPath = join(dir, "ff.sqlite");
    await writeFile(ffPath, "ff");
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        { kind: "firefox" as const, browser: "firefox", profile: "p", dbPath: ffPath },
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath: "/tmp/chrome/Cookies",
          rootPath: "/tmp/chrome",
        },
      ],
    });
    expect(result).toMatchObject({ state: "no_session", keyringSeen: true });
  });

  it("keeps the keyring hint when readable cookies exist but the ticket does not", async () => {
    backendMocks.readChromiumQwenCloudCookies.mockResolvedValue({
      state: "imported",
      cookies: [{ name: "cna", value: "anon" }],
      keyringProtected: true,
    });
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath: "/tmp/chrome/Cookies",
          rootPath: "/tmp/chrome",
        },
      ],
    });
    expect(result).toMatchObject({ state: "no_session", keyringSeen: true });
  });

  it("re-reads through a copied snapshot when a login lives only in the WAL", async () => {
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    await writeFile(dbPath, "db");
    await writeFile(`${dbPath}-wal`, "un-checkpointed login frame");

    backendMocks.readFirefoxCookieDatabase.mockImplementation(
      async (_dbPath: string, _nowMs: number, options?: { preferSnapshotCopy?: boolean }) =>
        options?.preferSnapshotCopy
          ? TICKET
          : [{ name: "cna", value: "anon", host: ".qwencloud.com" }],
    );

    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [{ kind: "firefox" as const, browser: "firefox", profile: "p", dbPath }],
    });
    expect(result.state).toBe("imported");
    expect(backendMocks.readFirefoxCookieDatabase).toHaveBeenCalledTimes(2);
    expect(backendMocks.readFirefoxCookieDatabase).toHaveBeenLastCalledWith(dbPath, NOW_MS, {
      preferSnapshotCopy: true,
    });
  });

  it("pins a profile through the generic browser profile override", async () => {
    backendMocks.listFirefoxCookieStores.mockResolvedValue([
      firefoxStore("default-release", "/tmp/ff/a"),
      firefoxStore("work", "/tmp/ff/b"),
    ]);
    const stores = await discoverBrowserCookieStores({
      env: { QWEN_CLOUD_BROWSER_PROFILE: "work" },
    });
    expect(stores.map((store) => store.profile)).toEqual(["work"]);
  });

  it("produces a stable fingerprint that changes when a cookie database changes", async () => {
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    await writeFile(dbPath, "original");
    const stores = [{ kind: "firefox" as const, browser: "firefox", profile: "p", dbPath }];

    const before = browserStoresSignature(await fingerprintBrowserCookieStores(stores));
    const sameAgain = browserStoresSignature(await fingerprintBrowserCookieStores(stores));
    expect(before).not.toBeNull();
    expect(sameAgain).toBe(before);

    await writeFile(dbPath, "changed-content");
    const later = new Date(Date.now() / 1000 + 5);
    await utimes(dbPath, later, later);
    const after = browserStoresSignature(await fingerprintBrowserCookieStores(stores));
    expect(after).not.toBe(before);
  });

  it("watches write-ahead-log companions so a fresh login invalidates the cache", async () => {
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    await writeFile(dbPath, "original");
    const stores = [{ kind: "firefox" as const, browser: "firefox", profile: "p", dbPath }];
    const before = browserStoresSignature(await fingerprintBrowserCookieStores(stores));

    // The browser writes a new cookie into its write-ahead log only.
    await writeFile(`${dbPath}-wal`, "wal-frame-with-new-cookie");
    const after = browserStoresSignature(await fingerprintBrowserCookieStores(stores));
    expect(after).not.toBe(before);
  });

  it("ignores disappeared stores in the fingerprint", async () => {
    await expect(
      browserStoresSignature(
        await fingerprintBrowserCookieStores([
          {
            kind: "firefox" as const,
            browser: "firefox",
            profile: "p",
            dbPath: "/tmp/does-not-exist/cookies.sqlite",
          },
        ]),
      ),
    ).toBeNull();
  });

  it("marks unreadable stores instead of silently passing", async () => {
    backendMocks.readFirefoxCookieDatabase.mockRejectedValue(new Error("locked"));
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        {
          kind: "firefox" as const,
          browser: "firefox",
          profile: "p",
          dbPath: "/tmp/locked.sqlite",
        },
      ],
    });
    expect(result).toMatchObject({ state: "unreadable" });
  });

  it("passes the key store to the Chromium reader and never to Firefox", async () => {
    const dir = await createTempDir();
    const ffPath = join(dir, "ff.sqlite");
    const chromePath = join(dir, "Cookies");
    await writeFile(ffPath, "ff");
    await writeFile(chromePath, "chrome");
    const nowSeconds = Date.now() / 1000;
    await utimes(ffPath, new Date(nowSeconds), new Date(nowSeconds));
    await utimes(chromePath, new Date(nowSeconds - 600), new Date(nowSeconds - 600));
    backendMocks.readFirefoxCookieDatabase.mockResolvedValue([]);
    backendMocks.readChromiumQwenCloudCookies.mockResolvedValue({
      state: "imported",
      cookies: TICKET,
      keyringProtected: false,
    });
    const keyStore = { id: "fake", getSecrets: async () => ({ state: "missing" }) };

    await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      keyStore,
      stores: [
        { kind: "firefox" as const, browser: "firefox", profile: "p", dbPath: ffPath },
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath: chromePath,
          rootPath: dir,
          keyringApplications: ["chrome"],
        },
      ],
    });

    expect(backendMocks.readFirefoxCookieDatabase).toHaveBeenCalledWith(ffPath, NOW_MS, {});
    expect(backendMocks.readChromiumQwenCloudCookies).toHaveBeenCalledWith(
      expect.objectContaining({ browser: "google-chrome", keyringApplications: ["chrome"] }),
      NOW_MS,
      { keyStore },
    );
  });

  it("reads keyring-protected Chromium stores without a key store as keyring", async () => {
    backendMocks.readChromiumQwenCloudCookies.mockImplementation(
      async (_store: unknown, _nowMs: number, options?: { keyStore?: { id: string } }) =>
        options?.keyStore
          ? { state: "imported", cookies: TICKET, keyringProtected: false }
          : { state: "keyring" },
    );
    const stores = [
      {
        kind: "chromium" as const,
        browser: "google-chrome",
        profile: "Default",
        dbPath: "/tmp/chrome/Cookies",
        rootPath: "/tmp/chrome",
        keyringApplications: ["chrome"],
      },
    ];

    await expect(
      importBrowserQwenCloudSession({ env: {}, nowMs: NOW_MS, keyStore: null, stores }),
    ).resolves.toMatchObject({ state: "no_session", keyringSeen: true });

    const withKeyStore = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      keyStore: { id: "fake", getSecrets: async () => ({ state: "missing" }) },
      stores,
    });
    expect(withKeyStore.state).toBe("imported");
  });

  it("re-reads through a copied snapshot when the first read found no session at all", async () => {
    const dir = await createTempDir();
    const dbPath = join(dir, "cookies.sqlite");
    await writeFile(dbPath, "db");
    await writeFile(`${dbPath}-wal`, "un-checkpointed login frame");

    backendMocks.readChromiumQwenCloudCookies.mockImplementation(
      async (_store: unknown, _nowMs: number, options?: { preferSnapshotCopy?: boolean }) =>
        options?.preferSnapshotCopy
          ? { state: "imported", cookies: TICKET, keyringProtected: false }
          : { state: "no_session" },
    );

    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath,
          rootPath: dir,
        },
      ],
    });
    expect(result.state).toBe("imported");
    expect(backendMocks.readChromiumQwenCloudCookies).toHaveBeenCalledTimes(2);
  });

  it("orders a store with a fresh write-ahead log ahead of a newer idle database", async () => {
    const dir = await createTempDir();
    const idlePath = join(dir, "idle.sqlite");
    const walPath = join(dir, "wal.sqlite");
    await writeFile(idlePath, "idle");
    await writeFile(walPath, "wal");
    await writeFile(`${walPath}-wal`, "fresh login frame");

    const nowSeconds = Date.now() / 1000;
    await utimes(idlePath, new Date(nowSeconds - 60), new Date(nowSeconds - 60));
    await utimes(walPath, new Date(nowSeconds - 600), new Date(nowSeconds - 600));
    await utimes(`${walPath}-wal`, new Date(nowSeconds), new Date(nowSeconds));

    const readOrder: string[] = [];
    backendMocks.readFirefoxCookieDatabase.mockImplementation(async (dbPath: string) => {
      readOrder.push(dbPath);
      return dbPath === walPath ? TICKET : [];
    });

    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores: [
        { kind: "firefox" as const, browser: "firefox", profile: "idle", dbPath: idlePath },
        { kind: "firefox" as const, browser: "firefox", profile: "wal", dbPath: walPath },
      ],
    });
    expect(result.state).toBe("imported");
    expect(readOrder[0]).toBe(walPath);
  });

  it("tries the preferred stores first without dropping the others", async () => {
    const dir = await createTempDir();
    const firstPath = join(dir, "first.sqlite");
    const secondPath = join(dir, "second.sqlite");
    await writeFile(firstPath, "first");
    await writeFile(secondPath, "second");
    const nowSeconds = Date.now() / 1000;
    await utimes(firstPath, new Date(nowSeconds), new Date(nowSeconds));
    await utimes(secondPath, new Date(nowSeconds - 600), new Date(nowSeconds - 600));

    backendMocks.readFirefoxCookieDatabase.mockImplementation(async (dbPath: string) =>
      dbPath === secondPath ? TICKET : [],
    );

    const stores = [
      { kind: "firefox" as const, browser: "firefox", profile: "first", dbPath: firstPath },
      { kind: "firefox" as const, browser: "firefox", profile: "second", dbPath: secondPath },
    ];
    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      stores,
      preferredStores: [stores[1]],
    });
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.store.profile).toBe("second");
    expect(backendMocks.readFirefoxCookieDatabase).toHaveBeenCalledTimes(1);
  });

  it("reports a value-free inspection for every store it read", async () => {
    const dir = await createTempDir();
    const ffPath = join(dir, "ff.sqlite");
    const chromePath = join(dir, "Cookies");
    const lockedPath = join(dir, "locked.sqlite");
    await writeFile(ffPath, "ff");
    await writeFile(chromePath, "chrome");
    await writeFile(lockedPath, "locked");

    backendMocks.readFirefoxCookieDatabase.mockImplementation(async (dbPath: string) => {
      if (dbPath === lockedPath) throw new Error("database is locked");
      return [{ name: "cna", value: "anonymous-value", host: ".qwencloud.com" }];
    });
    backendMocks.readChromiumQwenCloudCookies.mockResolvedValue({
      state: "keyring",
      summary: { rows: 3, protections: { keyring: 3 }, schemaVersion: 24, keyring: "locked" },
    });

    const result = await importBrowserQwenCloudSession({
      env: {},
      nowMs: NOW_MS,
      keyStore: null,
      stores: [
        { kind: "firefox" as const, browser: "firefox", profile: "p", dbPath: ffPath },
        {
          kind: "chromium" as const,
          browser: "google-chrome",
          profile: "Default",
          dbPath: chromePath,
          rootPath: dir,
        },
        { kind: "firefox" as const, browser: "firefox", profile: "locked", dbPath: lockedPath },
      ],
    });

    const inspections = result.state === "imported" ? result.inspections : result.inspections;
    const serialized = JSON.stringify(inspections);
    expect(serialized).toContain('"outcome":"no_ticket"');
    expect(serialized).toContain('"outcome":"keyring"');
    expect(serialized).toContain('"outcome":"unreadable"');
    expect(serialized).toContain("v11=3");
    expect(serialized).toContain("schema=24");
    expect(serialized).toContain("keyring=locked");
    // Neither cookie values nor database paths may reach the report.
    expect(serialized).not.toContain("anonymous-value");
    expect(serialized).not.toContain(dir);
  });

  it("summarises a store read without exposing values", () => {
    expect(
      summarizeRead({
        rows: 102,
        protections: { keyring: 100, local: 2 },
        schemaVersion: 24,
        keyring: "available",
      }),
    ).toBe("rows=102 v11=100 v10=2 schema=24 keyring=available");
    expect(summarizeRead({ rows: 0, protections: {} })).toBe("rows=0");
    expect(summarizeRead(undefined)).toBeUndefined();
  });

  it("creates no directories while discovering browsers", async () => {
    const dir = await createTempDir();
    await mkdir(join(dir, ".config"), { recursive: true });
    await discoverBrowserCookieStores({ homeDir: dir, env: {} });
    const { readdir } = await import("node:fs/promises");
    expect(await readdir(join(dir, ".config"))).toEqual([]);
  });
});
