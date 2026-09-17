import { stat } from "node:fs/promises";
import { join } from "node:path";

import type { BrowserStoreReadSummary } from "./browser-cookie-types.js";
import type { SystemKeyStore } from "./browser-keystore.js";
import { resolveSystemKeyStore } from "./browser-secret-service.js";
import { hasNonEmptyCompanionWal, type OpenBrowserStoreOptions } from "./browser-store-open.js";
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

export const QWEN_CLOUD_BROWSER_ENV = "QWEN_CLOUD_BROWSER";
export const QWEN_CLOUD_BROWSER_PROFILE_ENV = "QWEN_CLOUD_BROWSER_PROFILE";

export type BrowserKind = "firefox" | "chromium";

export interface BrowserCookieStore {
  kind: BrowserKind;
  /** Lowercase browser identifier, e.g. `firefox`, `google-chrome`, `brave-browser`. */
  browser: string;
  profile: string;
  dbPath: string;
  /** Chromium browser root; identifies the Safe Storage keyring entry. */
  rootPath?: string;
  /** Chromium descriptor id, e.g. `chrome`, `edge`. */
  browserId?: string;
  /** libsecret `application` candidates for keyring-protected values. */
  keyringApplications?: readonly string[];
  /** Preferred by the browser's own install or profile metadata. */
  preferred?: boolean;
}

/** Value-free outcome of reading one store, safe to surface in diagnostics. */
export interface BrowserStoreInspection {
  browser: string;
  profile: string;
  outcome: "session" | "no_ticket" | "no_rows" | "keyring" | "unreadable";
  /** Protection and keyring counts, never cookie names or values. */
  detail?: string;
}

export type BrowserSessionImportResult =
  | {
      state: "imported";
      store: BrowserCookieStore;
      cookies: QwenCloudCookie[];
      inspections: BrowserStoreInspection[];
    }
  | { state: "no_stores" }
  | { state: "disabled" }
  | {
      state: "no_session";
      stores: BrowserCookieStore[];
      keyringSeen: boolean;
      inspections: BrowserStoreInspection[];
    }
  | { state: "unreadable"; stores: BrowserCookieStore[]; inspections: BrowserStoreInspection[] };

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
    browserId: store.browserId,
    keyringApplications: store.keyringApplications,
    preferred: store.preferred,
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

export interface ImportBrowserSessionOptions {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
  nowMs?: number;
  stores?: readonly BrowserCookieStore[];
  /** Keyring backend for `v11` values; defaults to the platform's own. */
  keyStore?: SystemKeyStore | null;
  /** Try these stores before the recency order, e.g. the last valid session. */
  preferredStores?: readonly BrowserCookieStore[];
}

/**
 * Read a QwenCloud login session from the local browsers.
 *
 * Stores are tried most-recently-used first so the common case opens exactly one
 * cookie database and stops as soon as a login ticket is found. A store whose
 * login only exists in an uncheckpointed write-ahead log is re-read once through
 * a private copied snapshot.
 */
export async function importBrowserQwenCloudSession(
  params?: ImportBrowserSessionOptions,
): Promise<BrowserSessionImportResult> {
  const env = params?.env ?? process.env;
  if (isBrowserImportDisabled(env)) return { state: "disabled" };

  const nowMs = params?.nowMs ?? Date.now();
  const stores = params?.stores ?? (await discoverBrowserCookieStores(params));
  if (stores.length === 0) return { state: "no_stores" };

  const keyStore =
    params?.keyStore === null ? undefined : (params?.keyStore ?? resolveSystemKeyStore());
  const ordered = orderPreferredFirst(
    params?.preferredStores ?? [],
    await orderStoresByRecency(stores),
  );

  const inspections: BrowserStoreInspection[] = [];
  let keyringSeen = false;
  let unreadable = false;

  for (const store of ordered) {
    const result = await readBrowserCookieStore(store, nowMs, keyStore);
    inspections.push(result.inspection);
    switch (result.read.state) {
      case "imported": {
        if (result.read.keyringProtected) keyringSeen = true;
        if (hasAuthTicket(result.read.cookies)) {
          return {
            state: "imported",
            store,
            cookies: result.read.cookies,
            inspections,
          };
        }
        break;
      }
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
  if (unreadable && !keyringSeen) return { state: "unreadable", stores: inspected, inspections };
  return { state: "no_session", stores: inspected, keyringSeen, inspections };
}

type BrowserStoreReadResult =
  | {
      state: "imported";
      cookies: QwenCloudCookie[];
      keyringProtected: boolean;
      summary?: BrowserStoreReadSummary;
    }
  | { state: "keyring"; summary?: BrowserStoreReadSummary }
  | { state: "no_session"; summary?: BrowserStoreReadSummary }
  | { state: "unreadable"; summary?: BrowserStoreReadSummary };

interface StoreReadOutcome {
  read: BrowserStoreReadResult;
  inspection: BrowserStoreInspection;
}

async function readBrowserCookieStore(
  store: BrowserCookieStore,
  nowMs: number,
  keyStore?: SystemKeyStore,
): Promise<StoreReadOutcome> {
  const options: OpenBrowserStoreOptions & { keyStore?: SystemKeyStore } = keyStore
    ? { keyStore }
    : {};
  const readDirect = (overrides: OpenBrowserStoreOptions = {}): Promise<BrowserStoreReadResult> => {
    if (store.kind === "firefox") {
      return readFirefoxCookieDatabase(store.dbPath, nowMs, overrides).then(
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
        browserId: store.browserId,
        keyringApplications: store.keyringApplications,
      },
      nowMs,
      { ...options, ...overrides },
    );
  };

  try {
    const first = await readDirect();
    // An immutable snapshot or a busy-locked browser can hide a login that only
    // exists in the write-ahead log: retry once through a copied snapshot.
    const missingTicket =
      (first.state === "imported" && !hasAuthTicket(first.cookies)) || first.state === "no_session";
    if (missingTicket && (await hasNonEmptyCompanionWal(store.dbPath))) {
      const second = await readDirect({ preferSnapshotCopy: true });
      if (second.state === "imported" && hasAuthTicket(second.cookies)) {
        return { read: second, inspection: inspectStore(store, second) };
      }
      if (second.state !== "unreadable") {
        return { read: first, inspection: inspectStore(store, first) };
      }
    }
    return { read: first, inspection: inspectStore(store, first) };
  } catch {
    const read: BrowserStoreReadResult = { state: "unreadable" };
    return { read, inspection: inspectStore(store, read) };
  }
}

function inspectStore(
  store: BrowserCookieStore,
  read: BrowserStoreReadResult,
): BrowserStoreInspection {
  const base = { browser: store.browser, profile: store.profile };
  const detail = summarizeRead(read.summary);
  switch (read.state) {
    case "imported":
      return {
        ...base,
        outcome: hasAuthTicket(read.cookies) ? "session" : "no_ticket",
        ...(detail ? { detail } : {}),
      };
    case "keyring":
      return { ...base, outcome: "keyring", ...(detail ? { detail } : {}) };
    case "unreadable":
      return { ...base, outcome: "unreadable", ...(detail ? { detail } : {}) };
    case "no_session":
      return {
        ...base,
        outcome: (read.summary?.rows ?? 0) > 0 ? "no_ticket" : "no_rows",
        ...(detail ? { detail } : {}),
      };
  }
}

/** Compact, value-free description of what a store read observed. */
export function summarizeRead(summary: BrowserStoreReadSummary | undefined): string | undefined {
  if (!summary) return undefined;
  const parts: string[] = [`rows=${summary.rows}`];
  // Protection formats are labelled the way Chromium names them so the detail
  // cannot be confused with the keyring outcome that follows it.
  const labels: Record<string, string> = {
    plaintext: "plain",
    local: "v10",
    keyring: "v11",
    unsupported: "other",
  };
  for (const [protection, count] of Object.entries(summary.protections)) {
    if (count) parts.push(`${labels[protection] ?? protection}=${count}`);
  }
  if (summary.schemaVersion) parts.push(`schema=${summary.schemaVersion}`);
  if (summary.keyring) parts.push(`keyring=${summary.keyring}`);
  return parts.join(" ");
}

function orderPreferredFirst(
  preferred: readonly BrowserCookieStore[],
  ordered: readonly BrowserCookieStore[],
): BrowserCookieStore[] {
  if (preferred.length === 0) return [...ordered];
  const preferredPaths = new Set(preferred.map((store) => store.dbPath));
  const first = ordered.filter((store) => preferredPaths.has(store.dbPath));
  const rest = ordered.filter((store) => !preferredPaths.has(store.dbPath));
  return [...first, ...rest];
}

/**
 * Most recently written store first.
 *
 * Write-ahead-log and journal timestamps count as activity: a login that has not
 * been checkpointed yet must still win over an idle profile.
 */
async function orderStoresByRecency(
  stores: readonly BrowserCookieStore[],
): Promise<BrowserCookieStore[]> {
  const withMtime = await Promise.all(
    stores.map(async (store) => ({ store, mtimeMs: await storeActivityMs(store.dbPath) })),
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

async function storeActivityMs(dbPath: string): Promise<number> {
  let latest = 0;
  for (const suffix of ["", "-wal", "-journal"]) {
    try {
      const info = await stat(`${dbPath}${suffix}`);
      if (info.mtimeMs > latest) latest = info.mtimeMs;
    } catch {
      // An absent companion contributes no activity.
    }
  }
  return latest;
}
