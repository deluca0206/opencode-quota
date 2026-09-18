import { readdir, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";
import { chromiumValueProtection, decryptChromiumCookieValue } from "./browser-chromium-crypto.js";
import {
  type BrowserCookie,
  type BrowserCookieQuery,
  type BrowserStoreReadSummary,
  emptyReadSummary,
  recordProtection,
} from "./browser-cookie-types.js";
import {
  type SystemKeyStore,
  type SystemSecretLookup,
  systemSecretRequestKey,
} from "./browser-keystore.js";
import { type OpenBrowserStoreOptions, openBrowserCookieDatabase } from "./browser-store-open.js";
import type { SqliteConn } from "./opencode-sqlite.js";

/**
 * Chromium-family cookie reader.
 *
 * Discovery is descriptor-driven so a new browser is a data entry: native,
 * Flatpak, and Snap roots, release channels, profile enumeration from the
 * browser's own `Local State`, and the libsecret identities that browser uses
 * for its Safe Storage password. The reader is service-independent — the caller
 * supplies the host filter and, when keyring-protected values are present, the
 * system key store to read the password from.
 */

/** libsecret schemas Chromium builds have used for the Safe Storage password. */
export const CHROMIUM_KEYRING_SCHEMAS = [
  "chrome_libsecret_os_crypt_password_v2",
  "chrome_libsecret_os_crypt_password_v1",
  "chrome_libsecret_os_crypt_password",
] as const;

/** How long a Safe Storage password is reused before the keyring is asked again. */
export const CHROMIUM_KEYRING_CACHE_MS = 10 * 60_000;

/** How long a failed keyring lookup is skipped, so an absent bus is not retried per row. */
export const CHROMIUM_KEYRING_FAILURE_CACHE_MS = 60_000;

/** Cookie database locations inside a profile, newest layout first. */
export const CHROMIUM_COOKIE_DB_RELS = ["Network/Cookies", "Cookies"] as const;

/** Profile label used when a browser keeps its cookie database at the root. */
export const CHROMIUM_ROOT_PROFILE_LABEL = "(root)";

export interface ChromiumFlatpakLayout {
  appId: string;
  configDir: string;
}

export interface ChromiumSnapLayout {
  snapName: string;
  configDir: string;
}

export interface ChromiumBrowserDescriptor {
  /** Stable identifier used for diagnostics and keyring lookup. */
  id: string;
  /** Native config directory names under `XDG_CONFIG_HOME`, channels included. */
  configDirs: readonly string[];
  flatpak: readonly ChromiumFlatpakLayout[];
  snap: readonly ChromiumSnapLayout[];
  /** libsecret `application` attribute candidates, most likely first. */
  keyringApplications: readonly string[];
}

export const CHROMIUM_BROWSER_DESCRIPTORS: readonly ChromiumBrowserDescriptor[] = [
  {
    id: "chrome",
    configDirs: ["google-chrome", "google-chrome-beta", "google-chrome-unstable"],
    flatpak: [{ appId: "com.google.Chrome", configDir: "google-chrome" }],
    snap: [],
    keyringApplications: ["chrome"],
  },
  {
    id: "chromium",
    configDirs: ["chromium", "chromium-browser"],
    flatpak: [{ appId: "org.chromium.Chromium", configDir: "chromium" }],
    snap: [{ snapName: "chromium", configDir: "chromium" }],
    keyringApplications: ["chromium"],
  },
  {
    id: "brave",
    configDirs: [
      "BraveSoftware/Brave-Browser",
      "BraveSoftware/Brave-Browser-Beta",
      "BraveSoftware/Brave-Browser-Nightly",
    ],
    flatpak: [{ appId: "com.brave.Browser", configDir: "BraveSoftware/Brave-Browser" }],
    snap: [{ snapName: "brave", configDir: "BraveSoftware/Brave-Browser" }],
    keyringApplications: ["brave", "Brave"],
  },
  {
    id: "edge",
    configDirs: ["microsoft-edge", "microsoft-edge-beta", "microsoft-edge-dev"],
    flatpak: [{ appId: "com.microsoft.Edge", configDir: "microsoft-edge" }],
    snap: [],
    keyringApplications: ["microsoft-edge", "msedge", "edge", "chromium"],
  },
  {
    id: "vivaldi",
    configDirs: ["vivaldi", "vivaldi-snapshot"],
    flatpak: [{ appId: "com.vivaldi.Vivaldi", configDir: "vivaldi" }],
    snap: [],
    keyringApplications: ["vivaldi", "chrome", "chromium"],
  },
  {
    id: "opera",
    configDirs: ["opera", "opera-beta", "opera-developer"],
    flatpak: [{ appId: "com.opera.Opera", configDir: "opera" }],
    snap: [{ snapName: "opera", configDir: "opera" }],
    keyringApplications: ["opera", "chromium"],
  },
];

export interface ChromiumBrowserRoot {
  browser: string;
  rootPath: string;
  descriptor: ChromiumBrowserDescriptor;
}

export interface ChromiumCookieStore {
  /** Lowercase browser identifier, e.g. `google-chrome`, `brave-browser`. */
  browser: string;
  profile: string;
  rootPath: string;
  dbPath: string;
  /** Descriptor id, e.g. `chrome`; used for keyring lookup and diagnostics. */
  browserId?: string;
  /** libsecret `application` candidates for this browser. */
  keyringApplications?: readonly string[];
  /** Marked by the browser's own `Local State` as the profile in use. */
  preferred?: boolean;
}

export type ChromiumCookieReadResult =
  | {
      state: "imported";
      cookies: BrowserCookie[];
      keyringProtected: boolean;
      summary: BrowserStoreReadSummary;
    }
  | { state: "keyring"; summary: BrowserStoreReadSummary }
  | { state: "no_session"; summary: BrowserStoreReadSummary }
  | { state: "unreadable"; summary: BrowserStoreReadSummary };

export interface ChromiumReadOptions extends OpenBrowserStoreOptions {
  keyStore?: SystemKeyStore;
}

type ChromiumCookieRow = {
  host_key: unknown;
  name: unknown;
  value: unknown;
  encrypted_value: unknown;
  path: unknown;
  expires_utc: unknown;
  is_secure: unknown;
};

/**
 * Cookie expiry is stored as microseconds since 1601-01-01. The caller supplies
 * the conversion so the reader stays free of service-specific time helpers.
 */
export interface ChromiumReadContext {
  query: BrowserCookieQuery;
  nowMs: number;
  expiryToUnixSeconds: (value: unknown) => number | undefined;
  expiryDeadlineMs: (expiry: number | undefined) => number | undefined;
}

export function chromiumBrowserLabel(configDir: string): string {
  const last = configDir.split("/").filter(Boolean).pop() ?? configDir;
  return last.toLowerCase();
}

export function chromiumBrowserRoots(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): ChromiumBrowserRoot[] {
  const home = params?.homeDir ?? homedir();
  const env = params?.env ?? process.env;
  const configHome = env.XDG_CONFIG_HOME?.trim() || join(home, ".config");
  const roots: ChromiumBrowserRoot[] = [];

  const extra = env.QWEN_CLOUD_BROWSER_HOME?.trim();
  if (extra) {
    const descriptor = matchDescriptorByRoot(extra) ?? CHROMIUM_BROWSER_DESCRIPTORS[0];
    roots.push({ browser: chromiumBrowserLabel(extra), rootPath: extra, descriptor });
  }

  for (const descriptor of CHROMIUM_BROWSER_DESCRIPTORS) {
    for (const configDir of descriptor.configDirs) {
      roots.push({
        browser: chromiumBrowserLabel(configDir),
        rootPath: join(configHome, configDir),
        descriptor,
      });
    }
    for (const layout of descriptor.flatpak) {
      roots.push({
        browser: chromiumBrowserLabel(layout.configDir),
        rootPath: join(home, ".var", "app", layout.appId, "config", layout.configDir),
        descriptor,
      });
    }
    for (const layout of descriptor.snap) {
      // `current` follows the active revision, `common` survives upgrades.
      for (const revision of ["current", "common"]) {
        roots.push({
          browser: chromiumBrowserLabel(layout.configDir),
          rootPath: join(home, "snap", layout.snapName, revision, ".config", layout.configDir),
          descriptor,
        });
      }
    }
  }

  const unique: ChromiumBrowserRoot[] = [];
  const seen = new Set<string>();
  for (const root of roots) {
    if (seen.has(root.rootPath)) continue;
    seen.add(root.rootPath);
    unique.push(root);
  }
  return unique;
}

function matchDescriptorByRoot(rootPath: string): ChromiumBrowserDescriptor | undefined {
  const label = chromiumBrowserLabel(rootPath);
  return CHROMIUM_BROWSER_DESCRIPTORS.find((descriptor) =>
    [...descriptor.configDirs, ...descriptor.flatpak.map((entry) => entry.configDir)].some(
      (configDir) => chromiumBrowserLabel(configDir) === label,
    ),
  );
}

/** Profile directories reported by the browser's own `Local State`, when present. */
export function parseChromiumLocalStateProfiles(content: string): {
  profiles: string[];
  lastUsed: string | null;
} {
  try {
    const parsed = JSON.parse(content) as {
      profile?: { info_cache?: Record<string, unknown>; last_used?: unknown };
    };
    const infoCache = parsed?.profile?.info_cache;
    const profiles =
      infoCache && typeof infoCache === "object"
        ? Object.keys(infoCache).filter((name) => name.length > 0)
        : [];
    const lastUsed =
      typeof parsed?.profile?.last_used === "string" && parsed.profile.last_used.length > 0
        ? parsed.profile.last_used
        : null;
    return { profiles, lastUsed };
  } catch {
    return { profiles: [], lastUsed: null };
  }
}

export async function listChromiumProfiles(
  rootPath: string,
): Promise<Array<{ name: string; preferred: boolean }>> {
  if (!(await isDirectory(rootPath))) return [];

  let localState: { profiles: string[]; lastUsed: string | null } = {
    profiles: [],
    lastUsed: null,
  };
  try {
    localState = parseChromiumLocalStateProfiles(
      await readFile(join(rootPath, "Local State"), "utf8"),
    );
  } catch {
    // A browser without Local State still has discoverable profile directories.
  }

  // `Local State` is browser-controlled JSON, so its profile names are only used
  // when they resolve to a directory inside this browser root.
  const names = new Set<string>(
    localState.profiles.filter((name) => isProfileNameInsideRoot(rootPath, name)),
  );
  if (await isDirectory(join(rootPath, "Default"))) names.add("Default");
  try {
    for (const entry of await readdir(rootPath, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      if (!isProfileNameInsideRoot(rootPath, entry.name)) continue;
      if (/^Profile \d+$/u.test(entry.name) || entry.name === "Guest Profile") {
        names.add(entry.name);
        continue;
      }
      // Arbitrarily named profile directories are accepted only when they really
      // hold a cookie database, so cache directories are never treated as profiles.
      if (await hasCookieDatabase(join(rootPath, entry.name))) names.add(entry.name);
    }
  } catch {
    // An unreadable root contributes the profiles found so far.
  }

  const lastUsed =
    localState.lastUsed !== null && isProfileNameInsideRoot(rootPath, localState.lastUsed)
      ? localState.lastUsed
      : null;
  const preferredName = lastUsed ?? (names.has("Default") ? "Default" : null);
  return [...names]
    .filter((name) => name !== CHROMIUM_ROOT_PROFILE_LABEL)
    .sort()
    .map((name) => ({ name, preferred: name === preferredName }));
}

/**
 * Whether a profile name stays inside the browser root.
 *
 * Rejects absolute paths, `..` segments, and anything that resolves outside the
 * root, so a hostile `Local State` cannot point the reader at another directory.
 */
export function isProfileNameInsideRoot(rootPath: string, name: string): boolean {
  if (!name || name.includes("\0")) return false;
  const root = resolve(rootPath);
  const candidate = resolve(root, name);
  return candidate !== root && candidate.startsWith(root + sep);
}

async function hasCookieDatabase(profilePath: string): Promise<boolean> {
  for (const rel of CHROMIUM_COOKIE_DB_RELS) {
    if (await isFile(join(profilePath, ...rel.split("/")))) return true;
  }
  return false;
}

export async function listChromiumCookieStores(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<ChromiumCookieStore[]> {
  const roots = chromiumBrowserRoots(params);
  const stores: ChromiumCookieStore[] = [];
  const seen = new Set<string>();

  const push = (store: ChromiumCookieStore): void => {
    if (seen.has(store.dbPath)) return;
    seen.add(store.dbPath);
    stores.push(store);
  };

  for (const root of roots) {
    const descriptor = root.descriptor;
    const base = {
      browser: root.browser,
      rootPath: root.rootPath,
      browserId: descriptor.id,
      keyringApplications: descriptor.keyringApplications,
    };

    // Opera and some portable layouts keep the database at the browser root.
    const rootDb = await firstExistingCookieDatabase(root.rootPath);
    if (rootDb) {
      push({ ...base, profile: CHROMIUM_ROOT_PROFILE_LABEL, dbPath: rootDb });
    }

    for (const profile of await listChromiumProfiles(root.rootPath)) {
      const dbPath = await firstExistingCookieDatabase(join(root.rootPath, profile.name));
      if (!dbPath) continue;
      push({ ...base, profile: profile.name, dbPath, preferred: profile.preferred });
    }
  }

  return stores;
}

async function firstExistingCookieDatabase(profilePath: string): Promise<string | null> {
  for (const rel of CHROMIUM_COOKIE_DB_RELS) {
    const dbPath = join(profilePath, ...rel.split("/"));
    if (await isFile(dbPath)) return dbPath;
  }
  return null;
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Read the cookies one Chromium store holds for the requested hosts.
 *
 * `v11` values need the browser's Safe Storage password. When no key store is
 * supplied they are reported as keyring-protected rather than guessed, which
 * keeps unit tests and Firefox-only hosts free of D-Bus traffic.
 */
export async function readChromiumCookies(
  store: ChromiumCookieStore,
  context: ChromiumReadContext,
  options?: ChromiumReadOptions,
): Promise<ChromiumCookieReadResult> {
  const db = await openBrowserCookieDatabase(store.dbPath, options);
  const summary = emptyReadSummary();
  if (!db) return { state: "unreadable", summary };

  try {
    summary.schemaVersion = readChromiumSchemaVersion(db);
    const rows = db.all<ChromiumCookieRow>(
      `SELECT host_key, name, value, encrypted_value, path, CAST(expires_utc AS TEXT) AS expires_utc, is_secure
       FROM cookies
       WHERE name IS NOT NULL AND host_key IS NOT NULL
         AND (${context.query.hostSql.sql})`,
      context.query.hostSql.params,
    );
    summary.rows = rows.length;

    const keyring = await resolveKeyringPasswords(store, rows, options?.keyStore, summary);
    const cookies: BrowserCookie[] = [];
    let needsKeyring = false;

    for (const row of rows) {
      if (typeof row.name !== "string" || !row.name) continue;
      if (typeof row.host_key !== "string" || !row.host_key) continue;
      if (context.query.acceptHost && !context.query.acceptHost(row.host_key)) continue;

      const encrypted = toBytes(row.encrypted_value);
      const protection = chromiumValueProtection(encrypted);
      recordProtection(summary, protection);
      if (protection === "keyring") needsKeyring = true;

      const decrypted = decryptChromiumCookieValue({
        encryptedValue: encrypted,
        plaintextValue: row.value,
        hostKey: row.host_key,
        schemaVersion: summary.schemaVersion ?? 0,
        keyringPasswords: keyring.passwords,
      });
      if (decrypted.state !== "decrypted") continue;

      const expiry = context.expiryToUnixSeconds(row.expires_utc);
      const deadline = context.expiryDeadlineMs(expiry);
      if (deadline !== undefined && deadline <= context.nowMs) continue;

      cookies.push({
        name: row.name,
        value: decrypted.value,
        host: row.host_key,
        path: typeof row.path === "string" && row.path ? row.path : "/",
        expiry,
        secure: row.is_secure === 1 || row.is_secure === true,
      });
    }

    // Only a missing password makes a store keyring-blocked: with a usable
    // password a failed decryption is a data problem, not a keyring problem.
    const keyringBlocked = needsKeyring && !keyring.available;
    if (cookies.length > 0) {
      return { state: "imported", cookies, keyringProtected: keyringBlocked, summary };
    }
    return keyringBlocked ? { state: "keyring", summary } : { state: "no_session", summary };
  } catch {
    return { state: "unreadable", summary };
  } finally {
    db.close();
  }
}

function readChromiumSchemaVersion(db: SqliteConn): number {
  try {
    const rows = db.all<{ value: unknown }>("SELECT value FROM meta WHERE key = 'version' LIMIT 1");
    const value = rows[0]?.value;
    const version = typeof value === "number" ? value : Number.parseInt(String(value ?? ""), 10);
    return Number.isFinite(version) && version > 0 ? version : 0;
  } catch {
    // Stores without a meta table predate schema versioning.
    return 0;
  }
}

interface KeyringResolution {
  passwords: string[];
  /** True when the keyring yielded usable Safe Storage passwords. */
  available: boolean;
}

/**
 * Safe Storage passwords for the stores that need them.
 *
 * The keyring is consulted at most once per read and only when a `v11` value is
 * present; the result is cached in memory for the lifetime of a session so
 * repeated refreshes do not reopen D-Bus. Passwords are never persisted.
 */
async function resolveKeyringPasswords(
  store: ChromiumCookieStore,
  rows: readonly ChromiumCookieRow[],
  keyStore: SystemKeyStore | undefined,
  summary: BrowserStoreReadSummary,
): Promise<KeyringResolution> {
  const needsKeyring = rows.some(
    (row) => chromiumValueProtection(toBytes(row.encrypted_value)) === "keyring",
  );
  if (!needsKeyring) return { passwords: [], available: false };
  if (!keyStore) {
    summary.keyring = "not-configured";
    return { passwords: [], available: false };
  }

  const applications = store.keyringApplications ?? [];
  if (applications.length === 0) {
    summary.keyring = "unavailable";
    return { passwords: [], available: false };
  }

  const request = { schemas: CHROMIUM_KEYRING_SCHEMAS, applications };
  const cached = readKeyringCache(request);
  let lookup: SystemSecretLookup;
  if (cached) {
    lookup = cached;
  } else {
    lookup = await keyStore.getSecrets(request);
    writeKeyringCache(request, lookup);
  }

  if (lookup.state === "available") {
    summary.keyring = "available";
    return { passwords: lookup.secrets, available: lookup.secrets.length > 0 };
  }
  summary.keyring = lookup.state;
  return { passwords: [], available: false };
}

interface KeyringCacheEntry {
  lookup: SystemSecretLookup;
  at: number;
}

const keyringCache = new Map<string, KeyringCacheEntry>();

function keyringCacheKey(request: {
  schemas: readonly string[];
  applications: readonly string[];
}): string {
  return systemSecretRequestKey(request);
}

function readKeyringCache(request: {
  schemas: readonly string[];
  applications: readonly string[];
}): SystemSecretLookup | null {
  const entry = keyringCache.get(keyringCacheKey(request));
  if (!entry) return null;
  const ttl =
    entry.lookup.state === "available"
      ? CHROMIUM_KEYRING_CACHE_MS
      : CHROMIUM_KEYRING_FAILURE_CACHE_MS;
  if (Date.now() - entry.at >= ttl) {
    keyringCache.delete(keyringCacheKey(request));
    return null;
  }
  return entry.lookup;
}

function writeKeyringCache(
  request: { schemas: readonly string[]; applications: readonly string[] },
  lookup: SystemSecretLookup,
): void {
  keyringCache.set(keyringCacheKey(request), { lookup, at: Date.now() });
}

export function resetChromiumKeyringCacheForTests(): void {
  keyringCache.clear();
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
