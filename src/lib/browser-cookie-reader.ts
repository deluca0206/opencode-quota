import { stat } from "node:fs/promises";
import { join } from "node:path";

import { listChromiumCookieStores, readChromiumCookies } from "./browser-chromium.js";
import {
  browserCookieHostSql,
  chromiumExpiryToUnixSeconds,
  cookieExpiryDeadlineMs,
  hostMatchesAnyDomain,
} from "./browser-cookie-sql.js";
import type {
  BrowserCookie,
  BrowserCookieQuery,
  BrowserStoreReadSummary,
} from "./browser-cookie-types.js";
import { listFirefoxCookieStores, readFirefoxCookieDatabase } from "./browser-firefox.js";
import type { SystemKeyStore } from "./browser-keystore.js";
import { resolveSystemKeyStore } from "./browser-secret-service.js";
import { hasNonEmptyCompanionWal, type OpenBrowserStoreOptions } from "./browser-store-open.js";

/**
 * Service-independent browser cookie reader.
 *
 * The sweep knows how to order stores, retry a store whose login is still in an
 * uncheckpointed write-ahead log, and report what it observed — but not which
 * service the cookies belong to. Callers inject the readers and decide what
 * counts as a usable session, so another provider can reuse this unchanged.
 */

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

export type BrowserStoreReadResult =
  | {
      state: "imported";
      cookies: BrowserCookie[];
      keyringProtected: boolean;
      summary?: BrowserStoreReadSummary;
    }
  | { state: "keyring"; summary?: BrowserStoreReadSummary }
  | { state: "no_session"; summary?: BrowserStoreReadSummary }
  | { state: "unreadable"; summary?: BrowserStoreReadSummary };

/** The three browser-specific operations a sweep needs. */
export interface BrowserReaders {
  readStore(
    store: BrowserCookieStore,
    nowMs: number,
    options: OpenBrowserStoreOptions,
    keyStore?: SystemKeyStore,
  ): Promise<BrowserStoreReadResult>;
  /** Whether the cookies read from a store are enough to use it. */
  isUsableSession(cookies: readonly BrowserCookie[]): boolean;
}

export type BrowserSessionImportResult =
  | {
      state: "imported";
      store: BrowserCookieStore;
      cookies: BrowserCookie[];
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
 * A write-ahead log grows on every cookie write and is truncated by a checkpoint,
 * and a rollback journal appears while a writer is active. Watching them makes a
 * fresh browser login visible without waiting for the main database to change.
 */
const FINGERPRINT_COMPANION_SUFFIXES = ["-wal", "-journal"] as const;

export interface BrowserSweepOptions {
  stores: readonly BrowserCookieStore[];
  readers: BrowserReaders;
  nowMs: number;
  /** Keyring backend for `v11` values; `null` disables keyring reads. */
  keyStore?: SystemKeyStore | null;
  /** Cookie database paths to try first, e.g. the last store that worked. */
  preferredStorePaths?: readonly string[];
  /**
   * Cookie database paths whose session the service already rejected.
   *
   * Exclusion never empties the candidate list: once every store has been
   * rejected the sweep starts over instead of dead-ending.
   */
  excludeStorePaths?: readonly string[];
}

/**
 * Read the first store that satisfies the caller's session rule.
 *
 * Stores are tried most recently written first, counting write-ahead-log and
 * journal activity, and a store whose usable cookies may still sit in an
 * uncheckpointed log is re-read once through a private copied snapshot.
 */
export async function importBrowserSession(
  options: BrowserSweepOptions,
): Promise<BrowserSessionImportResult> {
  const { stores, readers, nowMs } = options;
  if (stores.length === 0) return { state: "no_stores" };

  const ordered = orderPreferredFirst(
    options.preferredStorePaths ?? [],
    await orderStoresByRecency(withoutExcludedStores(stores, options.excludeStorePaths ?? [])),
  );
  const keyStore = options.keyStore === null ? undefined : options.keyStore;

  const inspections: BrowserStoreInspection[] = [];
  let keyringSeen = false;
  let unreadable = false;

  for (const store of ordered) {
    const result = await readStoreWithWalRetry(store, readers, nowMs, keyStore);
    inspections.push(result.inspection);
    switch (result.read.state) {
      case "imported": {
        if (result.read.keyringProtected) keyringSeen = true;
        if (readers.isUsableSession(result.read.cookies)) {
          return { state: "imported", store, cookies: result.read.cookies, inspections };
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

async function readStoreWithWalRetry(
  store: BrowserCookieStore,
  readers: BrowserReaders,
  nowMs: number,
  keyStore?: SystemKeyStore,
): Promise<{ read: BrowserStoreReadResult; inspection: BrowserStoreInspection }> {
  const { isUsableSession } = readers;
  const readDirect = (overrides: OpenBrowserStoreOptions = {}) =>
    readers.readStore(store, nowMs, overrides, keyStore);

  try {
    const first = await readDirect();
    // An immutable snapshot or a busy-locked browser can hide a login that only
    // exists in the write-ahead log: retry once through a copied snapshot.
    const missingSession =
      (first.state === "imported" && !isUsableSession(first.cookies)) ||
      first.state === "no_session";
    if (missingSession && (await hasNonEmptyCompanionWal(store.dbPath))) {
      const second = await readDirect({ preferSnapshotCopy: true });
      if (second.state === "imported" && isUsableSession(second.cookies)) {
        return { read: second, inspection: inspectStore(store, second, isUsableSession) };
      }
      if (second.state !== "unreadable") {
        return { read: first, inspection: inspectStore(store, first, isUsableSession) };
      }
    }
    return { read: first, inspection: inspectStore(store, first, isUsableSession) };
  } catch {
    const read: BrowserStoreReadResult = { state: "unreadable" };
    return { read, inspection: inspectStore(store, read, isUsableSession) };
  }
}

function inspectStore(
  store: BrowserCookieStore,
  read: BrowserStoreReadResult,
  isUsableSession: (cookies: readonly BrowserCookie[]) => boolean,
): BrowserStoreInspection {
  const base = { browser: store.browser, profile: store.profile };
  const detail = summarizeRead(read.summary);
  switch (read.state) {
    case "imported":
      return {
        ...base,
        outcome: isUsableSession(read.cookies) ? "session" : "no_ticket",
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

/**
 * Cheap invalidation key: cookie database and companion file identity, mtime, and
 * size. Uses `stat` only, so it is safe on every availability check.
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

function orderPreferredFirst(
  preferredPaths: readonly string[],
  ordered: readonly BrowserCookieStore[],
): BrowserCookieStore[] {
  if (preferredPaths.length === 0) return [...ordered];
  const preferred = new Set(preferredPaths);
  const first = ordered.filter((store) => preferred.has(store.dbPath));
  const rest = ordered.filter((store) => !preferred.has(store.dbPath));
  return [...first, ...rest];
}

function withoutExcludedStores(
  stores: readonly BrowserCookieStore[],
  excludedPaths: readonly string[],
): BrowserCookieStore[] {
  if (excludedPaths.length === 0) return [...stores];
  const excluded = new Set(excludedPaths);
  const remaining = stores.filter((store) => !excluded.has(store.dbPath));
  return remaining.length > 0 ? remaining : [...stores];
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

// ---------------------------------------------------------------------------
// Reusable facade
// ---------------------------------------------------------------------------

export interface BrowserCookieRequest {
  /** Domains whose cookies are wanted, e.g. `["example.com", "api.example.com"]`. */
  domains: readonly string[];
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
  nowMs?: number;
  /** Keyring backend for `v11` values; defaults to the platform's own. */
  keyStore?: SystemKeyStore | null;
  /** Restrict the sweep to these stores instead of discovering them. */
  stores?: readonly BrowserCookieStore[];
}

export interface BrowserCookiesResult {
  store: BrowserCookieStore;
  cookies: BrowserCookie[];
  summary?: BrowserStoreReadSummary;
  /** Value-free per-store outcomes for diagnostics. */
  inspections: BrowserStoreInspection[];
}

/**
 * Read the cookies of one domain set from the local browsers.
 *
 * This is the entry point another provider can reuse: it discovers Firefox and
 * Chromium profiles, decrypts what the platform allows, and returns the first
 * store that actually holds matching cookies, along with a value-free report of
 * what each inspected store contained.
 */
export async function readBrowserCookies(
  request: BrowserCookieRequest,
): Promise<BrowserCookiesResult | null> {
  const nowMs = request.nowMs ?? Date.now();
  // Each engine names its host column differently, so the filter is built twice.
  const firefoxQuery = browserCookieQueryForDomains(request.domains);
  const chromiumQuery = chromiumCookieQueryForDomains(request.domains);
  const stores = request.stores ?? (await discoverBrowserCookieStoresFor(request));
  if (stores.length === 0) return null;

  const keyStore =
    request.keyStore === null ? undefined : (request.keyStore ?? resolveSystemKeyStore());

  const result = await importBrowserSession({
    stores,
    nowMs,
    keyStore,
    readers: {
      readStore: (store, readNowMs, options, storeKeyStore) => {
        if (store.kind === "firefox") {
          return readFirefoxCookieDatabase(store.dbPath, readNowMs, {
            ...options,
            query: firefoxQuery,
          }).then(
            (cookies): BrowserStoreReadResult =>
              cookies.length > 0
                ? { state: "imported", cookies, keyringProtected: false }
                : { state: "no_session" },
          );
        }
        return readChromiumCookies(
          {
            browser: store.browser,
            profile: store.profile,
            rootPath: store.rootPath ?? "",
            dbPath: store.dbPath,
            browserId: store.browserId,
            keyringApplications: store.keyringApplications,
          },
          {
            query: chromiumQuery,
            nowMs: readNowMs,
            expiryToUnixSeconds: chromiumExpiryToUnixSeconds,
            expiryDeadlineMs: cookieExpiryDeadlineMs,
          },
          storeKeyStore ? { ...options, keyStore: storeKeyStore } : options,
        );
      },
      isUsableSession: (cookies) => cookies.length > 0,
    },
  });

  if (result.state !== "imported") return null;
  return {
    store: result.store,
    cookies: result.cookies,
    inspections: result.inspections,
  };
}

/** Host filter and row guard for a set of domains. */
export function browserCookieQueryForDomains(domains: readonly string[]): BrowserCookieQuery {
  return {
    hostSql: browserCookieHostSql("host", domains),
    acceptHost: (host: string) => hostMatchesAnyDomain(host, domains),
  };
}

/**
 * Chromium host filter for the same domains.
 *
 * Chromium names its host column differently, so the query is rebuilt rather than
 * shared with Firefox.
 */
export function chromiumCookieQueryForDomains(domains: readonly string[]): BrowserCookieQuery {
  return {
    hostSql: browserCookieHostSql("host_key", domains),
    acceptHost: (host: string) => hostMatchesAnyDomain(host, domains),
  };
}

async function discoverBrowserCookieStoresFor(
  request: BrowserCookieRequest,
): Promise<BrowserCookieStore[]> {
  const params = { homeDir: request.homeDir, env: request.env };
  const [firefox, chromium] = await Promise.all([
    listFirefoxCookieStores(params),
    listChromiumCookieStores(params),
  ]);
  return [
    ...firefox.map((profile) => ({
      kind: "firefox" as const,
      browser: "firefox",
      profile: profile.name,
      dbPath: joinProfileCookieDatabase(profile.path),
      preferred: profile.isDefault,
    })),
    ...chromium.map((store) => ({
      kind: "chromium" as const,
      browser: store.browser,
      profile: store.profile,
      dbPath: store.dbPath,
      rootPath: store.rootPath,
      browserId: store.browserId,
      keyringApplications: store.keyringApplications,
      preferred: store.preferred,
    })),
  ];
}

function joinProfileCookieDatabase(profilePath: string): string {
  return join(profilePath, "cookies.sqlite");
}
