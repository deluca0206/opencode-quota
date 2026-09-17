import { mkdir, mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetChromiumKeyringCacheForTests } from "../src/lib/browser-chromium.js";
import {
  browserCookieQueryForDomains,
  chromiumCookieQueryForDomains,
  readBrowserCookies,
} from "../src/lib/browser-cookie-reader.js";
import type { SystemKeyStore } from "../src/lib/browser-keystore.js";
import {
  createChromiumProfile,
  FIXTURE_SAFE_STORAGE_PASSWORD,
} from "./helpers/browser-chromium-fixtures.js";

/**
 * The reader is reusable: these cases use a domain that has nothing to do with
 * QwenCloud, so a future provider can rely on the same discovery, decryption, and
 * fallback behaviour.
 */
const NOW_MS = 1_700_000_000_000;
const DOMAIN = "example.org";
const API_HOST = "api.example.org";

const tempRoots: string[] = [];

async function createHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "browser-cookie-reader-"));
  tempRoots.push(root);
  return root;
}

function keyStoreWithPassword(): SystemKeyStore & { calls: number } {
  const store = {
    id: "fake",
    calls: 0,
    async getSecrets() {
      store.calls += 1;
      return { state: "available" as const, secrets: [FIXTURE_SAFE_STORAGE_PASSWORD] };
    },
  };
  return store;
}

async function createFirefoxProfile(
  home: string,
  rows: Array<{ name: string; value: string; host: string }>,
): Promise<string> {
  const root = join(home, ".mozilla", "firefox");
  const profilePath = join(root, "abc123.default-release");
  await mkdir(profilePath, { recursive: true });
  await writeFile(
    join(root, "profiles.ini"),
    "[Install]\nDefault=abc123.default-release\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=abc123.default-release\nDefault=1\n",
  );

  const db = new DatabaseSync(join(profilePath, "cookies.sqlite"));
  db.exec(`CREATE TABLE moz_cookies (
    id INTEGER PRIMARY KEY,
    originAttributes TEXT NOT NULL DEFAULT '',
    name TEXT,
    value TEXT,
    host TEXT,
    path TEXT,
    expiry INTEGER,
    isSecure INTEGER
  )`);
  const insert = db.prepare(
    `INSERT INTO moz_cookies (originAttributes, name, value, host, path, expiry, isSecure)
     VALUES ('', ?, ?, ?, '/', ?, 1)`,
  );
  for (const row of rows) {
    insert.run(row.name, row.value, row.host, NOW_MS / 1000 + 3600);
  }
  db.close();
  return profilePath;
}

describe("generic browser cookie reader", () => {
  beforeEach(() => {
    resetChromiumKeyringCacheForTests();
  });

  afterEach(async () => {
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("builds host filters for any domain set", () => {
    const firefoxQuery = browserCookieQueryForDomains([DOMAIN]);
    expect(firefoxQuery.hostSql.sql).toContain("host LIKE ?");
    expect(firefoxQuery.hostSql.params).toContain(`%.${DOMAIN}`);
    expect(firefoxQuery.acceptHost?.(API_HOST)).toBe(true);
    expect(firefoxQuery.acceptHost?.("example.com")).toBe(false);

    const chromiumQuery = chromiumCookieQueryForDomains([DOMAIN]);
    expect(chromiumQuery.hostSql.sql).toContain("host_key LIKE ?");
    expect(chromiumQuery.acceptHost?.(API_HOST)).toBe(true);
  });

  it("reads another provider's domain from a Firefox profile", async () => {
    const home = await createHome();
    await createFirefoxProfile(home, [
      { name: "session", value: "firefox-secret", host: `.${DOMAIN}` },
      { name: "unrelated", value: "other", host: ".qwencloud.com" },
    ]);

    const result = await readBrowserCookies({
      domains: [DOMAIN],
      homeDir: home,
      env: {},
      nowMs: NOW_MS,
    });

    expect(result?.store.browser).toBe("firefox");
    expect(result?.cookies.map((cookie) => cookie.name)).toEqual(["session"]);
    expect(result?.inspections[0]?.outcome).toBe("session");
    expect(JSON.stringify(result?.inspections)).not.toContain("firefox-secret");
  });

  it("reads a keyring-protected Chromium cookie for another domain", async () => {
    const home = await createHome();
    await createChromiumProfile({
      rootPath: join(home, ".config", "google-chrome"),
      schemaVersion: 24,
      nowMs: NOW_MS,
      cookies: [{ host: `.${DOMAIN}`, name: "session", value: "chrome-secret", prefix: "v11" }],
    });
    const keyStore = keyStoreWithPassword();

    const result = await readBrowserCookies({
      domains: [DOMAIN],
      homeDir: home,
      env: {},
      nowMs: NOW_MS,
      keyStore,
    });

    expect(result?.store.browser).toBe("google-chrome");
    expect(result?.cookies.map((cookie) => cookie.name)).toEqual(["session"]);
    expect(keyStore.calls).toBe(1);
    expect(JSON.stringify(result?.inspections)).not.toContain("chrome-secret");
  });

  it("falls back to the browser that actually holds the domain cookies", async () => {
    const home = await createHome();
    await createChromiumProfile({
      rootPath: join(home, ".config", "google-chrome"),
      schemaVersion: 24,
      nowMs: NOW_MS,
      cookies: [{ host: ".other.example", name: "session", value: "not-it", prefix: "v10" }],
    });
    await createFirefoxProfile(home, [
      { name: "session", value: "firefox-secret", host: `.${DOMAIN}` },
    ]);
    // Chromium is the more recently written store, so it is inspected first.
    const chromeDb = join(home, ".config", "google-chrome", "Default", "Cookies");
    const firefoxDb = join(home, ".mozilla", "firefox", "abc123.default-release", "cookies.sqlite");
    const nowSeconds = Date.now() / 1000;
    await utimes(chromeDb, new Date(nowSeconds), new Date(nowSeconds));
    await utimes(firefoxDb, new Date(nowSeconds - 600), new Date(nowSeconds - 600));

    const result = await readBrowserCookies({
      domains: [DOMAIN],
      homeDir: home,
      env: {},
      nowMs: NOW_MS,
    });

    expect(result?.store.browser).toBe("firefox");
    expect(
      result?.inspections.map((inspection) => `${inspection.browser}:${inspection.outcome}`),
    ).toEqual(["google-chrome:no_rows", "firefox:session"]);
  });

  it("returns nothing when no browser holds the domain", async () => {
    const home = await createHome();
    await createFirefoxProfile(home, [{ name: "session", value: "x", host: ".elsewhere.test" }]);

    await expect(
      readBrowserCookies({ domains: [DOMAIN], homeDir: home, env: {}, nowMs: NOW_MS }),
    ).resolves.toBeNull();
  });

  it("returns nothing when the machine has no supported browser", async () => {
    const home = await createHome();
    await expect(
      readBrowserCookies({ domains: [DOMAIN], homeDir: home, env: {}, nowMs: NOW_MS }),
    ).resolves.toBeNull();
  });
});
