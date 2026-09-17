import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  chromiumCookieHostSql,
  chromiumExpiryToUnixSeconds,
  cookieExpiryDeadlineMs,
  type QwenCloudCookie,
} from "./qwencloud-cookies.js";
import { type OpenBrowserStoreOptions, openBrowserCookieDatabase } from "./qwencloud-store-open.js";

/**
 * Chromium-family cookie reader.
 *
 * Linux Chromium encrypts cookie values with a key derived from the OS keyring
 * password. When no keyring password is configured the browser falls back to
 * the well-known literal `peanuts`, which needs no external command. Stores
 * that did configure a keyring password are reported as `keyring` and skipped:
 * reading them would require a native libsecret binding.
 */
const CHROMIUM_KEYRING_PASSWORD_FALLBACK = "peanuts";
const CHROMIUM_SALT = "saltysalt";
const CHROMIUM_KEY_LENGTH = 16;
/**
 * `v10` is encrypted with the well-known Linux fallback password and can be read
 * locally. `v11` is encrypted with a key held in the OS keyring, which needs a
 * native secret-service binding, so those stores are reported rather than guessed.
 */
const CHROMIUM_LOCAL_PREFIX = "v10";
const CHROMIUM_KEYRING_PREFIX = "v11";

export type ChromiumValueProtection = "plaintext" | "local" | "keyring" | "unknown";

export interface ChromiumBrowserRoot {
  browser: string;
  rootPath: string;
}

export interface ChromiumCookieStore {
  browser: string;
  profile: string;
  rootPath: string;
  dbPath: string;
}

export type ChromiumCookieReadResult =
  | { state: "imported"; cookies: QwenCloudCookie[]; keyringProtected: boolean }
  | { state: "keyring" }
  | { state: "no_session" }
  | { state: "unreadable" };

type ChromiumCookieRow = {
  host_key: unknown;
  name: unknown;
  value: unknown;
  encrypted_value: unknown;
  path: unknown;
  expires_utc: unknown;
  is_secure: unknown;
};

const CHROMIUM_CONFIG_DIRS = [
  "google-chrome",
  "chromium",
  "BraveSoftware/Brave-Browser",
  "microsoft-edge",
  "vivaldi",
  "opera",
  "Google/Chrome",
] as const;

const CHROMIUM_FLATPAK_DIRS = [
  "app/com.google.Chrome/.config/google-chrome",
  "app/org.chromium.Chromium/.config/chromium",
  "app/com.brave.Browser/.config/BraveSoftware/Brave-Browser",
  "app/com.microsoft.Edge/.config/microsoft-edge",
  "app/com.opera.Opera/.config/opera",
] as const;

const CHROMIUM_COOKIE_DB_RELS = ["Network/Cookies", "Cookies"] as const;

let cachedDecryptionKey: Buffer | null = null;

export function chromiumBrowserRoots(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): ChromiumBrowserRoot[] {
  const home = params?.homeDir ?? homedir();
  const env = params?.env ?? process.env;
  const configHome = env.XDG_CONFIG_HOME?.trim() || join(home, ".config");
  const roots: ChromiumBrowserRoot[] = [];
  for (const dir of CHROMIUM_CONFIG_DIRS) {
    roots.push({ browser: chromiumBrowserLabel(dir), rootPath: join(configHome, dir) });
  }
  for (const dir of CHROMIUM_FLATPAK_DIRS) {
    roots.push({ browser: chromiumBrowserLabel(dir), rootPath: join(home, ".var", dir) });
  }
  const extra = env.QWEN_CLOUD_BROWSER_HOME?.trim();
  if (extra) {
    roots.unshift({ browser: chromiumBrowserLabel(extra), rootPath: extra });
  }
  return roots;
}

function chromiumBrowserLabel(dir: string): string {
  const last = dir.split("/").filter(Boolean).pop() ?? dir;
  return last.toLowerCase();
}

export async function listChromiumCookieStores(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<ChromiumCookieStore[]> {
  const roots = chromiumBrowserRoots(params);
  const stores: ChromiumCookieStore[] = [];
  for (const root of roots) {
    const profiles = await listChromiumProfiles(root.rootPath);
    for (const profile of profiles) {
      for (const rel of CHROMIUM_COOKIE_DB_RELS) {
        const dbPath = join(root.rootPath, profile, ...rel.split("/"));
        if (await fileExists(dbPath)) {
          stores.push({
            browser: root.browser,
            profile,
            rootPath: root.rootPath,
            dbPath,
          });
          break;
        }
      }
    }
  }
  return stores;
}

async function listChromiumProfiles(rootPath: string): Promise<string[]> {
  if (!(await dirExists(rootPath))) return [];
  const profiles: string[] = [];
  if (await dirExists(join(rootPath, "Default"))) profiles.push("Default");
  try {
    const entries = await readdir(rootPath, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (!/^Profile \d+$/u.test(entry.name)) continue;
      profiles.push(entry.name);
    }
  } catch {
    // A missing or unreadable browser root simply contributes no profiles.
  }
  return profiles;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    const info = await stat(path);
    return info.isFile();
  } catch {
    return false;
  }
}

async function dirExists(path: string): Promise<boolean> {
  try {
    const info = await stat(path);
    return info.isDirectory();
  } catch {
    return false;
  }
}

export async function readChromiumQwenCloudCookies(
  store: ChromiumCookieStore,
  nowMs: number,
  options?: OpenBrowserStoreOptions,
): Promise<ChromiumCookieReadResult> {
  const db = await openBrowserCookieDatabase(store.dbPath, options);
  if (!db) return { state: "unreadable" };

  try {
    const hostFilter = chromiumCookieHostSql();
    const rows = db.all<ChromiumCookieRow>(
      `SELECT host_key, name, value, encrypted_value, path, CAST(expires_utc AS TEXT) AS expires_utc, is_secure
       FROM cookies
       WHERE name IS NOT NULL AND host_key IS NOT NULL
         AND (${hostFilter.sql})`,
      hostFilter.params,
    );

    const cookies: QwenCloudCookie[] = [];
    // Recorded even when some cookies are readable, so a keyring-protected login
    // ticket is still reported as such instead of looking like a plain absence.
    let keyringProtected = false;
    for (const row of rows) {
      if (typeof row.name !== "string" || !row.name) continue;
      if (typeof row.host_key !== "string" || !row.host_key) continue;
      if (chromiumValueProtection(toBytes(row.encrypted_value)) === "keyring") {
        keyringProtected = true;
      }
      const value = resolveChromiumCookieValue(row);
      if (!value) continue;
      const expiry = chromiumExpiryToUnixSeconds(row.expires_utc);
      const expiryMs = cookieExpiryDeadlineMs(expiry);
      if (expiryMs !== undefined && expiryMs <= nowMs) continue;
      cookies.push({
        name: row.name,
        value,
        host: row.host_key,
        path: typeof row.path === "string" && row.path ? row.path : "/",
        expiry,
        secure: row.is_secure === 1 || row.is_secure === true,
      });
    }

    if (cookies.length > 0) return { state: "imported", cookies, keyringProtected };
    return keyringProtected ? { state: "keyring" } : { state: "no_session" };
  } catch {
    return { state: "unreadable" };
  } finally {
    db.close();
  }
}

function resolveChromiumCookieValue(row: ChromiumCookieRow): string | null {
  if (typeof row.value === "string" && row.value.length > 0) return row.value;
  const encrypted = row.encrypted_value;
  if (!encrypted) return null;
  const bytes = toBytes(encrypted);
  if (!bytes || bytes.length === 0) return null;
  return decryptChromiumCookieValue(bytes);
}

function toBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
}

function chromiumDecryptionKey(): Buffer {
  if (!cachedDecryptionKey) {
    cachedDecryptionKey = pbkdf2Sync(
      CHROMIUM_KEYRING_PASSWORD_FALLBACK,
      CHROMIUM_SALT,
      1,
      CHROMIUM_KEY_LENGTH,
      "sha1",
    );
  }
  return cachedDecryptionKey;
}

export function chromiumValueProtection(bytes: Uint8Array | null): ChromiumValueProtection {
  if (!bytes || bytes.length === 0) return "plaintext";
  const prefix = Buffer.from(bytes.subarray(0, 3)).toString("latin1");
  if (prefix === CHROMIUM_LOCAL_PREFIX) return "local";
  if (prefix === CHROMIUM_KEYRING_PREFIX) return "keyring";
  return "unknown";
}

export function decryptChromiumCookieValue(bytes: Uint8Array): string | null {
  const protection = chromiumValueProtection(bytes);
  if (protection === "keyring") return null;
  if (protection === "plaintext" || protection === "unknown") {
    return printableOrNull(Buffer.from(bytes).toString("utf8"));
  }
  try {
    const iv = Buffer.alloc(16, 0x20);
    const decipher = createDecipheriv("aes-128-cbc", chromiumDecryptionKey(), iv);
    const plain = Buffer.concat([
      decipher.update(Buffer.from(bytes.subarray(3))),
      decipher.final(),
    ]);
    return printableOrNull(plain.toString("utf8"));
  } catch {
    return null;
  }
}

function printableOrNull(value: string): string | null {
  if (value.length === 0) return null;
  // Reject padding garbage from a wrong key instead of sending it as a cookie.
  return /^[\u0020-\u007E]+$/u.test(value) ? value : null;
}
