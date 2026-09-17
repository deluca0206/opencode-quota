import { stat } from "node:fs/promises";
import { join } from "node:path";

import {
  type ChromiumCookieStore,
  listChromiumCookieStores,
  readChromiumQwenCloudCookies,
} from "./qwencloud-chromium.js";
import type { QwenCloudCookie } from "./qwencloud-cookies.js";
import { hasAuthTicket } from "./qwencloud-cookies.js";
import {
  type FirefoxProfile,
  listFirefoxCookieStores,
  readFirefoxCookieDatabase,
} from "./qwencloud-firefox.js";
import { hasNonEmptyCompanionWal, type OpenBrowserStoreOptions } from "./qwencloud-store-open.js";

export const QWEN_CLOUD_BROWSER_ENV = "QWEN_CLOUD_BROWSER";
export const QWEN_CLOUD_BROWSER_PROFILE_ENV = "QWEN_CLOUD_BROWSER_PROFILE";

export type BrowserKind = "firefox" | "chromium";

export interface BrowserCookieStore {
  kind: BrowserKind;
  /** Lowercase browser identifier, e.g. `firefox`, `google-chrome`, `brave-browser`. */
  browser: string;
  profile: string;
  dbPath: string;
  /** Chromium browser root used for the keyring check. */
  rootPath?: string;
  /** Preferred by the browser's own install metadata. */
  preferred?: boolean;
}

export type BrowserSessionImportResult =
  | { state: "imported"; store: BrowserCookieStore; cookies: QwenCloudCookie[] }
  | { state: "no_stores" }
  | { state: "disabled" }
  | { state: "no_session"; stores: BrowserCookieStore[]; keyringSeen: boolean }
  | { state: "unreadable"; stores: BrowserCookieStore[] };

export interface BrowserStoreFingerprint {
  path: string;
  mtimeMs: number;
  size: number;
}

/**
 * Companion files whose contents reflect newly written cookies.
 *
 * A write-ahead log grows on every cookie write and is truncated by a
 * checkpoint, and a rollback journal appears while a writer is active. Watching
 * them makes a fresh browser login visible without waiting for the main database
 * file to change.
 */
const FINGERPRINT_COMPANION_SUFFIXES = ["-wal", "-journal"] as const;

export function isBrowserImportDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[QWEN_CLOUD_BROWSER_ENV]?.trim().toLowerCase() === "none";
}

export async function discoverBrowserCookieStores(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<BrowserCookieStore[]> {
  const env = params?.env ?? process.env;
  if (isBrowserImportDisabled(env)) return [];

  const requested = resolveRequestedProfile(env);
  const [firefox, chromium] = await Promise.all([
    listFirefoxBrowserStores({ homeDir: params?.homeDir, env }),
    listChromiumBrowserStores({ homeDir: params?.homeDir, env }),
  ]);

  const stores = [...firefox, ...chromium];
  if (!requested) return stores;
  const pinned = stores.filter((store) => matchesRequestedProfile(store, requested));
  return pinned.length > 0 ? pinned : stores;
}

function resolveRequestedProfile(env: NodeJS.ProcessEnv): string | undefined {
  const generic = env[QWEN_CLOUD_BROWSER_PROFILE_ENV]?.trim();
  if (generic) return generic;
  const legacy = env.QWEN_CLOUD_FIREFOX_PROFILE?.trim();
  return legacy || undefined;
}

function matchesRequestedProfile(store: BrowserCookieStore, requested: string): boolean {
  if (store.profile === requested) return true;
  if (store.dbPath === requested) return true;
  if (store.dbPath.endsWith(`/${requested}`)) return true;
  return store.dbPath.endsWith(`\\${requested}`);
}

async function listFirefoxBrowserStores(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<BrowserCookieStore[]> {
  const profiles = await listFirefoxCookieStores(params);
  return profiles.map((profile: FirefoxProfile) => ({
    kind: "firefox" as const,
    browser: "firefox",
    profile: profile.name,
    dbPath: join(profile.path, "cookies.sqlite"),
    preferred: profile.isDefault,
  }));
}

async function listChromiumBrowserStores(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<BrowserCookieStore[]> {
  const stores: ChromiumCookieStore[] = await listChromiumCookieStores(params);
  return stores.map((store) => ({
    kind: "chromium" as const,
    browser: store.browser,
    profile: store.profile,
    dbPath: store.dbPath,
    rootPath: store.rootPath,
  }));
}

/**
 * Cheap invalidation key: cookie database and companion file identity, mtime,
 * and size.
 *
 * Uses `stat` only, so it is safe to call on every availability check without
 * opening a SQLite database.
 */
export async function fingerprintBrowserCookieStores(
  stores: readonly BrowserCookieStore[],
): Promise<BrowserStoreFingerprint[]> {
  const fingerprints: BrowserStoreFingerprint[] = [];
  for (const store of stores) {
    for (const path of [
      store.dbPath,
      ...FINGERPRINT_COMPANION_SUFFIXES.map((suffix) => `${store.dbPath}${suffix}`),
    ]) {
      try {
        const info = await stat(path);
        fingerprints.push({ path, mtimeMs: info.mtimeMs, size: info.size });
      } catch {
        // An absent or vanished companion contributes no fingerprint.
      }
    }
  }
  return fingerprints.sort((a, b) => (a.path < b.path ? -1 : 1));
}

export function browserStoresSignature(
  fingerprints: readonly BrowserStoreFingerprint[],
): string | null {
  if (fingerprints.length === 0) return null;
  return fingerprints
    .map((item) => `${item.path}:${Math.floor(item.mtimeMs)}:${item.size}`)
    .join("|");
}

/**
 * Read a QwenCloud login session from the local browsers.
 *
 * Stores are tried most-recently-used first so the common case opens exactly one
 * cookie database and stops as soon as a login ticket is found.
 */
export async function importBrowserQwenCloudSession(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
  nowMs?: number;
  stores?: readonly BrowserCookieStore[];
}): Promise<BrowserSessionImportResult> {
  const env = params?.env ?? process.env;
  if (isBrowserImportDisabled(env)) return { state: "disabled" };

  const nowMs = params?.nowMs ?? Date.now();
  const stores = params?.stores ?? (await discoverBrowserCookieStores(params));
  if (stores.length === 0) return { state: "no_stores" };

  const ordered = await orderStoresByRecency(stores);
  let keyringSeen = false;
  let unreadable = false;

  for (const store of ordered) {
    const result = await readBrowserCookieStore(store, nowMs);
    switch (result.state) {
      case "imported":
        if (result.keyringProtected) keyringSeen = true;
        if (hasAuthTicket(result.cookies)) {
          return { state: "imported", store, cookies: result.cookies };
        }
        break;
      case "keyring":
        keyringSeen = true;
        break;
      case "unreadable":
        unreadable = true;
        break;
      case "no_session":
        break;
    }
  }

  const inspected = [...ordered];
  if (unreadable && !keyringSeen) return { state: "unreadable", stores: inspected };
  return { state: "no_session", stores: inspected, keyringSeen };
}

type BrowserStoreReadResult =
  | { state: "imported"; cookies: QwenCloudCookie[]; keyringProtected: boolean }
  | { state: "keyring" }
  | { state: "no_session" }
  | { state: "unreadable" };

async function readBrowserCookieStore(
  store: BrowserCookieStore,
  nowMs: number,
): Promise<BrowserStoreReadResult> {
  const readDirect = (options: OpenBrowserStoreOptions = {}): Promise<BrowserStoreReadResult> => {
    if (store.kind === "firefox") {
      return readFirefoxCookieDatabase(store.dbPath, nowMs, options).then(
        (cookies): BrowserStoreReadResult =>
          cookies.length > 0
            ? { state: "imported", cookies, keyringProtected: false }
            : { state: "no_session" },
      );
    }
    return readChromiumQwenCloudCookies(
      {
        browser: store.browser,
        profile: store.profile,
        rootPath: store.rootPath ?? "",
        dbPath: store.dbPath,
      },
      nowMs,
      options,
    );
  };

  try {
    const first = await readDirect();
    // An immutable snapshot or a busy-locked browser can hide a login that only
    // exists in the write-ahead log: retry once through a copied snapshot.
    if (
      first.state === "imported" &&
      !hasAuthTicket(first.cookies) &&
      (await hasNonEmptyCompanionWal(store.dbPath))
    ) {
      const second = await readDirect({ preferSnapshotCopy: true });
      if (second.state === "imported") return second;
    }
    return first;
  } catch {
    return { state: "unreadable" };
  }
}

async function orderStoresByRecency(
  stores: readonly BrowserCookieStore[],
): Promise<BrowserCookieStore[]> {
  const withMtime = await Promise.all(
    stores.map(async (store) => {
      try {
        const info = await stat(store.dbPath);
        return { store, mtimeMs: info.mtimeMs };
      } catch {
        return { store, mtimeMs: 0 };
      }
    }),
  );
  return withMtime
    .sort((a, b) => {
      if (b.mtimeMs !== a.mtimeMs) return b.mtimeMs - a.mtimeMs;
      const preferredDiff = Number(b.store.preferred === true) - Number(a.store.preferred === true);
      if (preferredDiff !== 0) return preferredDiff;
      return a.store.dbPath < b.store.dbPath ? -1 : 1;
    })
    .map((item) => item.store);
}
