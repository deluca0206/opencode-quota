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

  it("creates no directories while discovering browsers", async () => {
    const dir = await createTempDir();
    await mkdir(join(dir, ".config"), { recursive: true });
    await discoverBrowserCookieStores({ homeDir: dir, env: {} });
    const { readdir } = await import("node:fs/promises");
    expect(await readdir(join(dir, ".config"))).toEqual([]);
  });
});
