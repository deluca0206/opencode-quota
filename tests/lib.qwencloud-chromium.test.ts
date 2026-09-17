import { createCipheriv, pbkdf2Sync } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";

import {
  chromiumValueProtection,
  decryptChromiumCookieValue,
  listChromiumCookieStores,
  readChromiumQwenCloudCookies,
} from "../src/lib/qwencloud-chromium.js";
import { chromiumExpiryToUnixSeconds } from "../src/lib/qwencloud-cookies.js";

const tempRoots: string[] = [];
const NOW_MS = 1_700_000_000_000;
/** Microseconds since 1601-01-01 for a given unix-ms instant. */
const CHROMIUM_EPOCH_OFFSET_MS = 11_644_473_600_000;

function toChromiumExpiry(unixMs: number): string {
  return String(BigInt(unixMs + CHROMIUM_EPOCH_OFFSET_MS) * 1000n);
}

function encryptValue(value: string): Buffer {
  const key = pbkdf2Sync("peanuts", "saltysalt", 1, 16, "sha1");
  const iv = Buffer.alloc(16, 0x20);
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([
    Buffer.from("v10", "latin1"),
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
}

async function createHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qwencloud-chromium-"));
  tempRoots.push(root);
  return root;
}

async function createChromiumBrowser(params: {
  home: string;
  dir: string;
  profile?: string;
  localState?: string;
  cookies?: Array<{
    host: string;
    name: string;
    value: string;
    expiresUtc?: string;
    plaintext?: boolean;
    /** `v11` simulates an OS-keyring-protected value that cannot be read locally. */
    protection?: "v10" | "v11";
  }>;
}): Promise<string> {
  const profile = params.profile ?? "Default";
  const rootPath = join(params.home, ".config", params.dir);
  const profilePath = join(rootPath, profile);
  await mkdir(profilePath, { recursive: true });
  if (params.localState !== null) {
    await writeFile(join(rootPath, "Local State"), params.localState ?? "{}");
  }

  const dbPath = join(profilePath, "Cookies");
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL PRIMARY KEY,
    host_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    encrypted_value BLOB DEFAULT '',
    path TEXT NOT NULL DEFAULT '/',
    expires_utc INTEGER NOT NULL DEFAULT 0,
    is_secure INTEGER NOT NULL DEFAULT 0
  )`);
  const insert = db.prepare(
    `INSERT INTO cookies (creation_utc, host_key, name, value, encrypted_value, path, expires_utc, is_secure)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  let index = 0;
  for (const cookie of params.cookies ?? []) {
    const encrypted = cookie.plaintext
      ? Buffer.alloc(0)
      : cookie.protection === "v11"
        ? Buffer.concat([Buffer.from("v11", "latin1"), Buffer.alloc(64, 7)])
        : encryptValue(cookie.value);
    insert.run(
      index++,
      cookie.host,
      cookie.name,
      cookie.plaintext ? cookie.value : "",
      encrypted,
      "/",
      cookie.expiresUtc ?? toChromiumExpiry(NOW_MS + 3_600_000),
      1,
    );
  }
  db.close();
  return rootPath;
}

describe("QwenCloud Chromium cookie import", () => {
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
    await createChromiumBrowser({ home, dir: "google-chrome" });
    await createChromiumBrowser({ home, dir: "chromium", profile: "Profile 1" });
    await mkdir(join(home, ".config", "vivaldi"), { recursive: true });

    const stores = await listChromiumCookieStores({ homeDir: home, env: {} });
    const labels = stores.map((store) => `${store.browser}/${store.profile}`).sort();
    expect(labels).toEqual(["chromium/Profile 1", "google-chrome/Default"]);
  });

  it("decrypts a QwenCloud ticket stored with the Linux fallback key", async () => {
    const home = await createHome();
    await createChromiumBrowser({
      home,
      dir: "google-chrome",
      cookies: [
        { host: ".qwencloud.com", name: "login_qwencloud_ticket", value: "chrome-secret" },
        { host: ".qwencloud.com", name: "cna", value: "anon" },
        { host: "example.com", name: "unrelated", value: "nope" },
      ],
    });
    const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
    expect(store).toBeDefined();
    if (!store) return;

    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.keyringProtected).toBe(false);
    expect(result.cookies.map((cookie) => cookie.name).sort()).toEqual([
      "cna",
      "login_qwencloud_ticket",
    ]);
    expect(result.cookies.find((cookie) => cookie.name === "login_qwencloud_ticket")?.value).toBe(
      "chrome-secret",
    );
  });

  it("drops Chromium cookies whose expiry has passed", async () => {
    const home = await createHome();
    await createChromiumBrowser({
      home,
      dir: "google-chrome",
      cookies: [
        {
          host: ".qwencloud.com",
          name: "login_qwencloud_ticket",
          value: "live",
          expiresUtc: toChromiumExpiry(NOW_MS + 60_000),
        },
        {
          host: ".qwencloud.com",
          name: "stale",
          value: "old",
          expiresUtc: toChromiumExpiry(NOW_MS - 60_000),
        },
        {
          host: ".qwencloud.com",
          name: "session-cookie",
          value: "keep",
          expiresUtc: "0",
        },
      ],
    });
    const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
    if (!store) throw new Error("expected a Chromium store");
    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    if (result.state !== "imported") throw new Error(`unexpected state ${result.state}`);
    expect(result.cookies.map((cookie) => cookie.name).sort()).toEqual([
      "login_qwencloud_ticket",
      "session-cookie",
    ]);
  });

  it("flags a keyring-protected ticket even when other cookies are readable", async () => {
    const home = await createHome();
    await createChromiumBrowser({
      home,
      dir: "google-chrome",
      cookies: [
        { host: ".qwencloud.com", name: "cna", value: "anon" },
        {
          host: ".qwencloud.com",
          name: "login_qwencloud_ticket",
          value: "unreadable",
          protection: "v11",
        },
      ],
    });
    const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
    if (!store) throw new Error("expected a Chromium store");
    const result = await readChromiumQwenCloudCookies(store, NOW_MS);
    expect(result.state).toBe("imported");
    if (result.state !== "imported") return;
    expect(result.keyringProtected).toBe(true);
    expect(result.cookies.map((cookie) => cookie.name)).toEqual(["cna"]);
  });

  it("reports v11 keyring-protected cookies instead of guessing a key", async () => {
    const home = await createHome();
    await createChromiumBrowser({
      home,
      dir: "google-chrome",
      cookies: [
        {
          host: ".qwencloud.com",
          name: "login_qwencloud_ticket",
          value: "unreadable",
          protection: "v11",
        },
      ],
    });

    const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
    if (!store) throw new Error("expected a Chromium store");
    await expect(readChromiumQwenCloudCookies(store, NOW_MS)).resolves.toEqual({
      state: "keyring",
    });
    expect(
      decryptChromiumCookieValue(
        Buffer.concat([Buffer.from("v11", "latin1"), Buffer.alloc(64, 7)]),
      ),
    ).toBeNull();
  });

  it("classifies value protection by prefix", () => {
    expect(chromiumValueProtection(null)).toBe("plaintext");
    expect(chromiumValueProtection(Buffer.alloc(0))).toBe("plaintext");
    expect(chromiumValueProtection(Buffer.from("v10abc", "latin1"))).toBe("local");
    expect(chromiumValueProtection(Buffer.from("v11abc", "latin1"))).toBe("keyring");
    expect(chromiumValueProtection(Buffer.from("plain", "utf8"))).toBe("unknown");
  });

  it("rejects values that do not decrypt to printable text", () => {
    expect(decryptChromiumCookieValue(Buffer.from("v10\x00\x01\x02\x03\x04", "latin1"))).toBeNull();
    expect(decryptChromiumCookieValue(Buffer.from("plain-value", "utf8"))).toBe("plain-value");
    expect(decryptChromiumCookieValue(Buffer.alloc(0))).toBeNull();
  });

  it("reports no session when the browser has no QwenCloud cookies", async () => {
    const home = await createHome();
    await createChromiumBrowser({
      home,
      dir: "chromium",
      cookies: [{ host: "example.com", name: "unrelated", value: "nope" }],
    });
    const [store] = await listChromiumCookieStores({ homeDir: home, env: {} });
    if (!store) throw new Error("expected a Chromium store");
    await expect(readChromiumQwenCloudCookies(store, NOW_MS)).resolves.toEqual({
      state: "no_session",
    });
  });
});
