import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { SystemKeyStore, SystemSecretLookup } from "../src/lib/browser-keystore.js";
import {
  listChromiumCookieStores,
  readChromiumQwenCloudCookies,
  resetChromiumKeyringCacheForTests,
} from "../src/lib/qwencloud-chromium.js";
import { chromiumExpiryToUnixSeconds } from "../src/lib/qwencloud-cookies.js";
import {
  createChromiumProfile,
  FIXTURE_SAFE_STORAGE_PASSWORD,
  toChromiumExpiry,
} from "./helpers/browser-chromium-fixtures.js";

const tempRoots: string[] = [];
const NOW_MS = 1_700_000_000_000;
const TICKET = "ticket-value-1234567890";

function keyStoreWith(lookup: SystemSecretLookup): SystemKeyStore {
  return { id: "fake", getSecrets: async () => lookup };
}

const availableKeyStore = (): SystemKeyStore =>
  keyStoreWith({ state: "available", secrets: [FIXTURE_SAFE_STORAGE_PASSWORD] });

async function createHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qwencloud-chromium-"));
  tempRoots.push(root);
  return root;
}

async function createStore(params: {
  dir?: string;
  profile?: string;
  schemaVersion?: number;
  cookies: Parameters<typeof createChromiumProfile>[0]["cookies"];
}) {
  const home = await createHome();
  const rootPath = join(home, ".config", params.dir ?? "google-chrome");
  await createChromiumProfile({
    rootPath,
    profile: params.profile,
    schemaVersion: params.schemaVersion ?? 24,
    nowMs: NOW_MS,
    cookies: params.cookies,
  });
  const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
  if (!store) throw new Error("expected a Chromium store");
  return store;
}

describe("QwenCloud Chromium cookie import", () => {
  beforeEach(() => {
    resetChromiumKeyringCacheForTests();
  });

  afterEach(async () => {
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("converts Chromium Windows-epoch expiry without overflowing", () => {
    expect(chromiumExpiryToUnixSeconds(toChromiumExpiry(NOW_MS))).toBe(Math.floor(NOW_MS / 1000));
    expect(chromiumExpiryToUnixSeconds("0")).toBeUndefined();
    expect(chromiumExpiryToUnixSeconds(0)).toBeUndefined();
    expect(chromiumExpiryToUnixSeconds("not-a-number")).toBeUndefined();
    expect(chromiumExpiryToUnixSeconds(null)).toBeUndefined();
  });

  it("discovers cookie stores across Chromium browsers and profiles", async () => {
    const home = await createHome();
    await createChromiumProfile({
      rootPath: join(home, ".config", "google-chrome"),
      nowMs: NOW_MS,
    });
    await createChromiumProfile({
      rootPath: join(home, ".config", "chromium"),
      profile: "Profile 1",
      nowMs: NOW_MS,
    });
    await createChromiumProfile({
      rootPath: join(home, ".config", "microsoft-edge"),
      nowMs: NOW_MS,
    });

    const stores = await listChromiumCookieStores({ homeDir: home, env: {} });
    const labels = stores.map((store) => `${store.browser}/${store.profile}`).sort();
    expect(labels).toEqual([
      "chromium/Profile 1",
      "google-chrome/Default",
      "microsoft-edge/Default",
    ]);
  });

  it("imports only QwenCloud cookies and drops expired ones", async () => {
    const store = await createStore({
      cookies: [
        { host: ".qwencloud.com", name: "login_qwencloud_ticket", value: TICKET, prefix: "v11" },
        { host: ".qwencloud.com", name: "cna", value: "anon", prefix: "v10" },
        {
          host: ".qwencloud.com",
          name: "stale",
          value: "old",
          prefix: "v10",
          expiresUtc: toChromiumExpiry(NOW_MS - 60_000),
        },
        { host: "example.com", name: "unrelated", value: "nope", prefix: "v10" },
      ],
    });

    const result = await readChromiumQwenCloudCookies(store, NOW_MS, {
      keyStore: availableKeyStore(),
    });
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.keyringProtected).toBe(false);
    expect(result.cookies.map((cookie) => cookie.name).sort()).toEqual([
      "cna",
      "login_qwencloud_ticket",
    ]);
    expect(result.cookies.find((cookie) => cookie.name === "login_qwencloud_ticket")?.value).toBe(
      TICKET,
    );
    expect(result.summary.rows).toBe(3);
    expect(result.summary.keyring).toBe("available");
  });

  it("keeps session cookies that have no expiry", async () => {
    const store = await createStore({
      cookies: [
        {
          host: ".qwencloud.com",
          name: "session-cookie",
          value: "keep",
          prefix: "v10",
          expiresUtc: "0",
        },
      ],
    });

    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    if (result.state !== "imported") throw new Error(`unexpected state ${result.state}`);
    expect(result.cookies.map((cookie) => cookie.name)).toEqual(["session-cookie"]);
  });

  it("flags a keyring-protected ticket even when other cookies are readable", async () => {
    const store = await createStore({
      cookies: [
        { host: ".qwencloud.com", name: "cna", value: "anon", prefix: "v10" },
        { host: ".qwencloud.com", name: "login_qwencloud_ticket", value: "x", prefix: "v11" },
      ],
    });

    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.keyringProtected).toBe(true);
    expect(result.cookies.map((cookie) => cookie.name)).toEqual(["cna"]);
    expect(result.summary.keyring).toBe("not-configured");
  });

  it("reads the keyring-protected ticket once a key store is available", async () => {
    const store = await createStore({
      cookies: [
        { host: ".qwencloud.com", name: "cna", value: "anon", prefix: "v10" },
        { host: ".qwencloud.com", name: "login_qwencloud_ticket", value: TICKET, prefix: "v11" },
      ],
    });

    const result = await readChromiumQwenCloudCookies(store, NOW_MS, {
      keyStore: availableKeyStore(),
    });
    if (result.state !== "imported") throw new Error(`unexpected state ${result.state}`);
    expect(result.keyringProtected).toBe(false);
    expect(result.cookies.map((cookie) => cookie.name).sort()).toEqual([
      "cna",
      "login_qwencloud_ticket",
    ]);
  });

  it("reports keyring-protected cookies instead of guessing a key", async () => {
    const store = await createStore({
      cookies: [
        { host: ".qwencloud.com", name: "login_qwencloud_ticket", value: "x", prefix: "v11" },
      ],
    });

    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    expect(result).toMatchObject({ state: "keyring" });
    if (result.state !== "keyring") return;
    expect(result.summary.protections).toEqual({ keyring: 1 });
  });

  it("reports a locked keyring distinctly from a missing one", async () => {
    const store = await createStore({
      cookies: [
        { host: ".qwencloud.com", name: "login_qwencloud_ticket", value: "x", prefix: "v11" },
      ],
    });

    const locked = await readChromiumQwenCloudCookies(store, NOW_MS, {
      keyStore: keyStoreWith({ state: "locked" }),
    });
    expect(locked).toMatchObject({ state: "keyring" });
    if (locked.state === "keyring") expect(locked.summary.keyring).toBe("locked");
  });

  it("reports no session when the browser has no QwenCloud cookies", async () => {
    const store = await createStore({
      dir: "chromium",
      cookies: [{ host: "example.com", name: "unrelated", value: "nope", prefix: "v10" }],
    });

    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    expect(result).toMatchObject({ state: "no_session" });
    if (result.state !== "no_session") return;
    expect(result.summary.rows).toBe(0);
  });
});
