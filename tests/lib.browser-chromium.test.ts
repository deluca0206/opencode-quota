import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  CHROMIUM_BROWSER_DESCRIPTORS,
  CHROMIUM_ROOT_PROFILE_LABEL,
  chromiumBrowserRoots,
  isProfileNameInsideRoot,
  listChromiumCookieStores,
  parseChromiumLocalStateProfiles,
  readChromiumCookies,
  resetChromiumKeyringCacheForTests,
} from "../src/lib/browser-chromium.js";
import type { SystemKeyStore, SystemSecretLookup } from "../src/lib/browser-keystore.js";
import {
  createChromiumProfile,
  FIXTURE_SAFE_STORAGE_PASSWORD,
  toChromiumExpiry,
} from "./helpers/browser-chromium-fixtures.js";

const NOW_MS = 1_700_000_000_000;
const HOST = ".qwencloud.com";
const TICKET = "ticket-value-1234567890";

const tempRoots: string[] = [];

const qwenQuery = {
  query: {
    hostSql: {
      sql: "host_key LIKE ? OR host_key LIKE ?",
      params: ["%qwencloud.com", "%qwencloud.com"],
    },
  },
  nowMs: NOW_MS,
  expiryToUnixSeconds: (value: unknown): number | undefined => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
    return Math.floor((parsed - 11_644_473_600_000_000) / 1_000_000);
  },
  expiryDeadlineMs: (expiry: number | undefined): number | undefined =>
    expiry === undefined ? undefined : expiry * 1000,
};

async function createHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "browser-chromium-"));
  tempRoots.push(root);
  return root;
}

function createKeyStore(lookup: SystemSecretLookup): SystemKeyStore & { calls: number } {
  const store = {
    id: "fake",
    calls: 0,
    async getSecrets(): Promise<SystemSecretLookup> {
      store.calls += 1;
      return lookup;
    },
  };
  return store;
}

const availableKeyStore = (): SystemKeyStore & { calls: number } =>
  createKeyStore({ state: "available", secrets: [FIXTURE_SAFE_STORAGE_PASSWORD] });

describe("Chromium browser discovery", () => {
  beforeEach(() => {
    resetChromiumKeyringCacheForTests();
  });

  afterEach(async () => {
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("describes the keyring identity of every supported browser", () => {
    const byId = Object.fromEntries(
      CHROMIUM_BROWSER_DESCRIPTORS.map((descriptor) => [descriptor.id, descriptor]),
    );
    expect(Object.keys(byId).sort()).toEqual(
      ["brave", "chrome", "chromium", "edge", "opera", "vivaldi"].sort(),
    );
    expect(byId.chrome?.keyringApplications).toContain("chrome");
    expect(byId.chromium?.keyringApplications).toContain("chromium");
    expect(byId.brave?.keyringApplications).toContain("brave");
    expect(byId.edge?.keyringApplications).toContain("microsoft-edge");
    expect(byId.edge?.configDirs).toContain("microsoft-edge-beta");
    expect(byId.chrome?.configDirs).toContain("google-chrome-unstable");
  });

  it("builds native, Flatpak, and Snap roots without duplicates", () => {
    const home = "/home/tester";
    const roots = chromiumBrowserRoots({ homeDir: home, env: {} }).map((root) => root.rootPath);

    expect(roots).toContain("/home/tester/.config/google-chrome");
    expect(roots).toContain("/home/tester/.config/google-chrome-beta");
    expect(roots).toContain("/home/tester/.config/microsoft-edge-dev");
    expect(roots).toContain("/home/tester/.config/BraveSoftware/Brave-Browser-Nightly");
    // Flatpak maps XDG config to `config`, not `.config`.
    expect(roots).toContain("/home/tester/.var/app/com.google.Chrome/config/google-chrome");
    expect(roots).toContain(
      "/home/tester/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
    );
    expect(roots).not.toContain("/home/tester/.var/app/com.google.Chrome/.config/google-chrome");
    expect(roots).toContain("/home/tester/snap/chromium/current/.config/chromium");
    expect(roots).toContain("/home/tester/snap/chromium/common/.config/chromium");
    expect(new Set(roots).size).toBe(roots.length);
  });

  it("honours XDG_CONFIG_HOME and a custom browser home", () => {
    const xdgRoots = chromiumBrowserRoots({
      homeDir: "/home/tester",
      env: { XDG_CONFIG_HOME: "/mnt/data/config" },
    }).map((root) => root.rootPath);
    expect(xdgRoots).toContain("/mnt/data/config/google-chrome");

    const custom = chromiumBrowserRoots({
      homeDir: "/home/tester",
      env: { QWEN_CLOUD_BROWSER_HOME: "/mnt/browsers/portable-chrome" },
    });
    expect(custom[0]?.rootPath).toBe("/mnt/browsers/portable-chrome");
    expect(new Set(custom.map((root) => root.rootPath)).size).toBe(custom.length);
  });

  it("parses profile metadata from Local State", () => {
    expect(
      parseChromiumLocalStateProfiles(
        JSON.stringify({
          profile: {
            info_cache: {
              Default: { name: "Person 1" },
              "Profile 3": { name: "Work" },
              "Custom Dir": { name: "Custom" },
            },
            last_used: "Profile 3",
          },
        }),
      ),
    ).toEqual({ profiles: ["Default", "Profile 3", "Custom Dir"], lastUsed: "Profile 3" });

    expect(parseChromiumLocalStateProfiles("{}")).toEqual({ profiles: [], lastUsed: null });
    expect(parseChromiumLocalStateProfiles("not json")).toEqual({ profiles: [], lastUsed: null });
  });

  it("discovers numbered, guest, arbitrary, and root-level profiles", async () => {
    const home = await createHome();
    const rootPath = join(home, ".config", "google-chrome");
    await createChromiumProfile({ rootPath, profile: "Default", nowMs: NOW_MS });
    await createChromiumProfile({ rootPath, profile: "Profile 2", nowMs: NOW_MS });
    await createChromiumProfile({ rootPath, profile: "Guest Profile", nowMs: NOW_MS });
    await createChromiumProfile({ rootPath, profile: "Custom Dir", nowMs: NOW_MS });
    // A cache directory must never be mistaken for a profile.
    await mkdir(join(rootPath, "GPUCache"), { recursive: true });
    await writeFile(
      join(rootPath, "Local State"),
      JSON.stringify({ profile: { info_cache: { "Custom Dir": {} }, last_used: "Profile 2" } }),
    );

    const stores = await listChromiumCookieStores({ homeDir: home, env: {} });
    const chromeProfiles = stores
      .filter((store) => store.rootPath === rootPath)
      .map((store) => store.profile)
      .sort();
    expect(chromeProfiles).toEqual(["Custom Dir", "Default", "Guest Profile", "Profile 2"]);
    expect(
      stores.find((store) => store.rootPath === rootPath && store.profile === "Profile 2")
        ?.preferred,
    ).toBe(true);
    expect(
      stores.find((store) => store.rootPath === rootPath && store.profile === "Custom Dir")
        ?.browserId,
    ).toBe("chrome");
    expect(stores.find((store) => store.rootPath === rootPath)?.keyringApplications).toContain(
      "chrome",
    );
  });

  it("ignores Local State profile names that leave the browser root", async () => {
    const home = await createHome();
    const rootPath = join(home, ".config", "google-chrome");
    await createChromiumProfile({ rootPath, profile: "Default", nowMs: NOW_MS });
    // A real cookie database outside the root, which a hostile Local State could
    // otherwise point the reader at.
    const outsideRoot = join(home, "outside");
    await createChromiumProfile({ rootPath: outsideRoot, profile: "Default", nowMs: NOW_MS });
    await writeFile(
      join(rootPath, "Local State"),
      JSON.stringify({
        profile: {
          info_cache: {
            "../../outside/Default": {},
            "/etc": {},
            "..": {},
            ".": {},
            Default: {},
          },
          last_used: "../../outside/Default",
        },
      }),
    );

    const stores = await listChromiumCookieStores({ homeDir: home, env: {} });
    const chrome = stores.filter((store) => store.rootPath === rootPath);
    expect(chrome.map((store) => store.profile)).toEqual(["Default"]);
    expect(chrome.every((store) => store.dbPath.startsWith(`${rootPath}${sep}`))).toBe(true);
    // A `last_used` outside the root must not suppress the real preference.
    expect(chrome[0]?.preferred).toBe(true);

    expect(isProfileNameInsideRoot(rootPath, "../../outside/Default")).toBe(false);
    expect(isProfileNameInsideRoot(rootPath, "/etc")).toBe(false);
    expect(isProfileNameInsideRoot(rootPath, "..")).toBe(false);
    expect(isProfileNameInsideRoot(rootPath, ".")).toBe(false);
    expect(isProfileNameInsideRoot(rootPath, "")).toBe(false);
    expect(isProfileNameInsideRoot(rootPath, "Profile 1")).toBe(true);
    expect(isProfileNameInsideRoot(rootPath, "Custom Dir")).toBe(true);
  });

  it("reads a browser that keeps its cookie database at the root", async () => {
    const home = await createHome();
    const rootPath = join(home, ".config", "opera");
    await createChromiumProfile({ rootPath, profile: CHROMIUM_ROOT_PROFILE_LABEL, nowMs: NOW_MS });

    const stores = await listChromiumCookieStores({ homeDir: home, env: {} });
    const opera = stores.filter((store) => store.rootPath === rootPath);
    expect(opera.map((store) => store.profile)).toEqual([CHROMIUM_ROOT_PROFILE_LABEL]);
    expect(opera[0]?.dbPath).toBe(join(rootPath, "Cookies"));
  });

  it("prefers the Network layout and deduplicates identical databases", async () => {
    const home = await createHome();
    const rootPath = join(home, ".config", "chromium");
    await createChromiumProfile({ rootPath, dbRel: "Network/Cookies", nowMs: NOW_MS });
    await createChromiumProfile({ rootPath, dbRel: "Cookies", nowMs: NOW_MS });

    const stores = await listChromiumCookieStores({ homeDir: home, env: {} });
    const chromium = stores.filter((store) => store.rootPath === rootPath);
    expect(chromium).toHaveLength(1);
    expect(chromium[0]?.dbPath).toBe(join(rootPath, "Default", "Network", "Cookies"));
  });
});

describe("Chromium cookie reading", () => {
  beforeEach(() => {
    resetChromiumKeyringCacheForTests();
  });

  afterEach(async () => {
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  async function createStore(params: {
    schemaVersion?: number;
    prefix?: "v10" | "v11" | "v20";
    password?: string;
    hostKeyOverride?: string;
    cookies?: Parameters<typeof createChromiumProfile>[0]["cookies"];
  }) {
    const home = await createHome();
    const rootPath = join(home, ".config", "google-chrome");
    const dbPath = await createChromiumProfile({
      rootPath,
      nowMs: NOW_MS,
      schemaVersion: params.schemaVersion,
      cookies: params.cookies ?? [
        {
          host: HOST,
          name: "login_qwencloud_ticket",
          value: TICKET,
          prefix: params.prefix,
          password: params.password,
          hostKeyOverride: params.hostKeyOverride,
        },
      ],
    });
    const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
    if (!store) throw new Error("expected a Chromium store");
    return { store, dbPath };
  }

  it("decrypts a schema 24 v11 ticket using the keyring password", async () => {
    const { store } = await createStore({ schemaVersion: 24, prefix: "v11" });
    const keyStore = availableKeyStore();

    const result = await readChromiumCookies(store, qwenQuery, { keyStore });
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.cookies.map((cookie) => cookie.value)).toEqual([TICKET]);
    expect(result.summary.keyring).toBe("available");
    expect(result.summary.protections).toEqual({ keyring: 1 });
    expect(result.summary.schemaVersion).toBe(24);
    expect(keyStore.calls).toBe(1);
  });

  it("reports keyring protection when no key store is configured", async () => {
    const { store } = await createStore({ schemaVersion: 24, prefix: "v11" });

    const result = await readChromiumCookies(store, qwenQuery);
    expect(result.state).toBe("keyring");
    if (result.state !== "keyring") return;
    expect(result.summary.keyring).toBe("not-configured");
  });

  it("propagates a locked or unavailable keyring without guessing", async () => {
    const { store } = await createStore({ schemaVersion: 24, prefix: "v11" });

    const locked = await readChromiumCookies(store, qwenQuery, {
      keyStore: createKeyStore({ state: "locked" }),
    });
    expect(locked.state).toBe("keyring");
    if (locked.state === "keyring") expect(locked.summary.keyring).toBe("locked");

    resetChromiumKeyringCacheForTests();
    const unavailable = await readChromiumCookies(store, qwenQuery, {
      keyStore: createKeyStore({ state: "unavailable", detail: "no_session_bus" }),
    });
    expect(unavailable.state).toBe("keyring");
    if (unavailable.state === "keyring") expect(unavailable.summary.keyring).toBe("unavailable");
  });

  it("rejects a ticket whose host digest does not match its row", async () => {
    const { store } = await createStore({
      schemaVersion: 24,
      prefix: "v11",
      hostKeyOverride: ".evil.example",
    });

    const result = await readChromiumCookies(store, qwenQuery, {
      keyStore: availableKeyStore(),
    });
    expect(result.state).toBe("no_session");
    if (result.state !== "no_session") return;
    expect(result.summary.rows).toBe(1);
    expect(result.summary.keyring).toBe("available");
  });

  it("reports an unsupported encryption format without importing it", async () => {
    const { store } = await createStore({ schemaVersion: 24, prefix: "v20" });

    const result = await readChromiumCookies(store, qwenQuery, {
      keyStore: availableKeyStore(),
    });
    expect(result.state).toBe("no_session");
    if (result.state !== "no_session") return;
    expect(result.summary.protections).toEqual({ unsupported: 1 });
    // A format we cannot read must not trigger a keyring lookup.
    expect(result.summary.keyring).toBeUndefined();
  });

  it("reuses the cached Safe Storage password across reads", async () => {
    const { store } = await createStore({ schemaVersion: 24, prefix: "v11" });
    const keyStore = availableKeyStore();

    await readChromiumCookies(store, qwenQuery, { keyStore });
    await readChromiumCookies(store, qwenQuery, { keyStore });
    expect(keyStore.calls).toBe(1);

    resetChromiumKeyringCacheForTests();
    await readChromiumCookies(store, qwenQuery, { keyStore });
    expect(keyStore.calls).toBe(2);
  });

  it("does not consult the keyring when no value needs it", async () => {
    const { store } = await createStore({
      schemaVersion: 24,
      cookies: [{ host: HOST, name: "login_qwencloud_ticket", value: TICKET, prefix: "v10" }],
    });
    const keyStore = availableKeyStore();

    const result = await readChromiumCookies(store, qwenQuery, { keyStore });
    expect(result.state).toBe("imported");
    expect(keyStore.calls).toBe(0);
    if (result.state !== "imported") return;
    expect(result.summary.protections).toEqual({ local: 1 });
  });

  it("drops expired cookies and keeps session cookies", async () => {
    const { store } = await createStore({
      schemaVersion: 24,
      cookies: [
        { host: HOST, name: "live", value: TICKET, prefix: "v11" },
        {
          host: HOST,
          name: "stale",
          value: "old",
          prefix: "v11",
          expiresUtc: toChromiumExpiry(NOW_MS - 60_000),
        },
        { host: HOST, name: "session-cookie", value: "keep", prefix: "v11", expiresUtc: "0" },
        { host: "example.com", name: "unrelated", value: "nope", prefix: "v11" },
      ],
    });

    const result = await readChromiumCookies(store, qwenQuery, {
      keyStore: availableKeyStore(),
    });
    if (result.state !== "imported") throw new Error(`unexpected state ${result.state}`);
    expect(result.cookies.map((cookie) => cookie.name).sort()).toEqual(["live", "session-cookie"]);
  });

  it("reports an unreadable store without throwing", async () => {
    const home = await createHome();
    const result = await readChromiumCookies(
      {
        browser: "google-chrome",
        profile: "Default",
        rootPath: join(home, ".config", "google-chrome"),
        dbPath: join(home, "missing", "Cookies"),
        browserId: "chrome",
        keyringApplications: ["chrome"],
      },
      qwenQuery,
      { keyStore: availableKeyStore() },
    );
    expect(result.state).toBe("unreadable");
  });
});
