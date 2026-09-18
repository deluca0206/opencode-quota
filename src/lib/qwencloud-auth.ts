import {
  type BrowserCookieStore,
  type BrowserSessionImportResult,
  type BrowserStoreInspection,
  browserStoresSignature,
  discoverBrowserCookieStores,
  fingerprintBrowserCookieStores,
  importBrowserQwenCloudSession,
  isBrowserImportDisabled,
} from "./qwencloud-browser.js";
import {
  cookieExpiryDeadlineMs,
  cookieHeaderFromCookies,
  hasAuthTicket,
  parseCookieHeader,
  QWENCLOUD_AUTH_TICKET_COOKIE_NAMES,
  type QwenCloudCookie,
} from "./qwencloud-cookies.js";

export const QWEN_CLOUD_COOKIE_ENV = "QWEN_CLOUD_COOKIE";

/**
 * Browser sessions are invalidated by a cookie-database fingerprint, so this TTL
 * only bounds how long a genuinely unchanged session may be reused. Keeping it
 * long avoids repeated SQLite opens on the availability hot path.
 */
export const DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS = 300_000;

/** Browser directory discovery is cached separately; it is pure filesystem metadata. */
export const QWENCLOUD_BROWSER_DISCOVERY_MAX_AGE_MS = 60_000;

/**
 * Minimum spacing between full cookie-store reads.
 *
 * An actively used browser rewrites its cookie database constantly, which would
 * otherwise invalidate the fingerprint on nearly every render. Reads stay cheap,
 * but this keeps repeated refreshes from stacking database opens.
 */
export const QWENCLOUD_BROWSER_IMPORT_MIN_INTERVAL_MS = 5_000;

/**
 * How long a negative resolution ("no session found") may be served unchanged.
 *
 * A negative can be produced by a transiently unreadable cookie store, so it
 * must self-heal quickly even when the browser is idle and the fingerprint does
 * not change.
 */
export const QWENCLOUD_NEGATIVE_AUTH_CACHE_MS = 30_000;

/**
 * How long the last successfully read console session is reused when the next
 * read fails (for example, while the browser holds its cookie database).
 */
export const QWENCLOUD_LAST_GOOD_SESSION_MAX_AGE_MS = 10 * 60_000;

export const QWENCLOUD_STALE_SESSION_NOTE =
  "showing last known session; browser cookie store is busy";

export interface QwenCloudSession {
  dashboardCookies: QwenCloudCookie[];
  apiCookies: QwenCloudCookie[];
}

export type ResolvedQwenCloudAuth =
  | { state: "none"; note?: string }
  | {
      state: "configured";
      session: QwenCloudSession;
      source: string;
      note?: string;
      /** Cookie database the session came from; never a cookie or key value. */
      storePath?: string;
    }
  | { state: "invalid"; source: string; error: string };

export interface QwenCloudAuthDiagnostics {
  state: ResolvedQwenCloudAuth["state"];
  source: string | null;
  error: string | null;
  note: string | null;
  /** Browser/profile labels inspected. Never contains cookie names or values. */
  browsers: string[];
  /** Per-store outcomes, bounded and free of cookie names, values, and paths. */
  inspections: BrowserStoreInspection[];
}

/** How many store inspections a single diagnostics report may carry. */
export const QWENCLOUD_MAX_REPORTED_INSPECTIONS = 8;

export function resolveQwenCloudAuthFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ResolvedQwenCloudAuth | null {
  if (env[QWEN_CLOUD_COOKIE_ENV] === undefined) return null;
  const cookies = parseCookieHeader(env[QWEN_CLOUD_COOKIE_ENV] ?? "");
  if (!cookies || !hasAuthTicket(cookies)) {
    return {
      state: "invalid",
      source: `env:${QWEN_CLOUD_COOKIE_ENV}`,
      error: "QwenCloud cookie header is missing a login ticket",
    };
  }
  return {
    state: "configured",
    source: `env:${QWEN_CLOUD_COOKIE_ENV}`,
    session: { dashboardCookies: cookies, apiCookies: cookies },
  };
}

interface AuthCacheEntry {
  auth: ResolvedQwenCloudAuth;
  signature: string | null;
  browsers: string[];
  inspections: BrowserStoreInspection[];
  storePath: string | null;
  at: number;
}

let cachedEntry: AuthCacheEntry | null = null;
let inFlight: Promise<AuthCacheEntry> | null = null;
let cachedDiscovery: { stores: BrowserCookieStore[]; at: number } | null = null;
let lastImportAt = 0;
let lastGoodSession: {
  auth: Extract<ResolvedQwenCloudAuth, { state: "configured" }>;
  at: number;
} | null = null;

/**
 * Stores whose session QwenCloud itself rejected.
 *
 * Finding a login ticket only proves the browser has one; the console decides
 * whether it still authenticates. Rejected stores are skipped on later sweeps so
 * an expired profile cannot shadow a valid one, and the sweep restarts once every
 * store has been rejected.
 */
const rejectedStorePaths = new Set<string>();
let lastValidatedStorePath: string | null = null;

async function resolveAuthEntry(params?: {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  nowMs?: number;
  maxAgeMs?: number;
}): Promise<AuthCacheEntry> {
  const env = params?.env ?? process.env;
  const now = params?.nowMs ?? Date.now();

  const fromEnv = resolveQwenCloudAuthFromEnv(env);
  if (fromEnv) {
    return {
      auth: fromEnv,
      signature: null,
      browsers: [],
      inspections: [],
      storePath: null,
      at: now,
    };
  }

  if (isBrowserImportDisabled(env)) {
    return {
      auth: { state: "none", note: "browser import disabled" },
      signature: null,
      browsers: [],
      inspections: [],
      storePath: null,
      at: now,
    };
  }

  const maxAgeMs = Math.max(0, params?.maxAgeMs ?? DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS);
  const stores = await resolveBrowserStores({ env, homeDir: params?.homeDir, now });
  const signature = browserStoresSignature(await fingerprintBrowserCookieStores(stores));

  // Negative results must self-heal quickly; successful ones may be reused for
  // the whole window because the fingerprint invalidates real changes.
  const cacheMaxAgeMs =
    cachedEntry?.auth.state === "none"
      ? Math.min(maxAgeMs, QWENCLOUD_NEGATIVE_AUTH_CACHE_MS)
      : maxAgeMs;
  const withinMaxAge = cachedEntry !== null && now - cachedEntry.at < cacheMaxAgeMs;
  const signatureUnchanged = cachedEntry !== null && cachedEntry.signature === signature;
  const importThrottled = now - lastImportAt < QWENCLOUD_BROWSER_IMPORT_MIN_INTERVAL_MS;
  if (cachedEntry && withinMaxAge && (signatureUnchanged || importThrottled)) {
    return cachedEntry;
  }

  lastImportAt = now;
  const sweep = {
    env,
    homeDir: params?.homeDir,
    nowMs: now,
    stores,
    preferredStorePaths: lastValidatedStorePath ? [lastValidatedStorePath] : [],
    excludeStorePaths: [...rejectedStorePaths],
  };
  let imported = await importBrowserQwenCloudSession(sweep);
  if (imported.state === "unreadable") {
    // A torn snapshot read is transient; retry once before degrading.
    imported = await importBrowserQwenCloudSession(sweep);
  }

  const browsers = uniqueBrowserLabels(inspectedStores(imported, stores));
  let auth = toResolvedAuth(imported);

  if (auth.state === "configured") {
    lastGoodSession = { auth, at: now };
  } else if (
    auth.state === "none" &&
    lastGoodSession &&
    shouldServeLastGoodSession(lastGoodSession, now)
  ) {
    auth = { ...lastGoodSession.auth, note: QWENCLOUD_STALE_SESSION_NOTE };
  } else if (lastGoodSession && now - lastGoodSession.at > QWENCLOUD_LAST_GOOD_SESSION_MAX_AGE_MS) {
    lastGoodSession = null;
  }

  const entry: AuthCacheEntry = {
    auth,
    signature,
    browsers,
    inspections: importInspections(imported).slice(0, QWENCLOUD_MAX_REPORTED_INSPECTIONS),
    storePath: auth.state === "configured" ? (auth.storePath ?? null) : null,
    at: now,
  };
  cachedEntry = entry;
  return entry;
}

function shouldServeLastGoodSession(
  lastGood: { auth: Extract<ResolvedQwenCloudAuth, { state: "configured" }>; at: number },
  now: number,
): boolean {
  if (now - lastGood.at > QWENCLOUD_LAST_GOOD_SESSION_MAX_AGE_MS) return false;
  // A session the console rejected must not be served again while the browser is
  // merely busy.
  if (lastGood.auth.storePath && rejectedStorePaths.has(lastGood.auth.storePath)) return false;
  return qwenCloudSessionTicketValidAt(lastGood.auth.session, now);
}

function qwenCloudSessionTicketValidAt(session: QwenCloudSession, nowMs: number): boolean {
  const tickets = [...session.dashboardCookies, ...session.apiCookies].filter((cookie) =>
    QWENCLOUD_AUTH_TICKET_COOKIE_NAMES.includes(
      cookie.name as (typeof QWENCLOUD_AUTH_TICKET_COOKIE_NAMES)[number],
    ),
  );
  if (tickets.length === 0) return false;
  return tickets.every((cookie) => {
    const deadlineMs = cookieExpiryDeadlineMs(cookie.expiry);
    return deadlineMs === undefined || deadlineMs > nowMs;
  });
}

/** Inspections a sweep reported; absent on results produced before they existed. */
function importInspections(imported: BrowserSessionImportResult): BrowserStoreInspection[] {
  if ("inspections" in imported && Array.isArray(imported.inspections)) return imported.inspections;
  return [];
}

function inspectedStores(
  imported: BrowserSessionImportResult,
  stores: readonly BrowserCookieStore[],
): readonly BrowserCookieStore[] {
  if (imported.state === "imported") return [imported.store];
  if (imported.state === "no_session" || imported.state === "unreadable") return imported.stores;
  return stores;
}

function uniqueBrowserLabels(stores: readonly BrowserCookieStore[]): string[] {
  const labels = new Set<string>();
  for (const store of stores) {
    labels.add(`${store.browser}/${store.profile}`);
    if (labels.size >= 8) break;
  }
  return [...labels];
}

function toResolvedAuth(imported: BrowserSessionImportResult): ResolvedQwenCloudAuth {
  switch (imported.state) {
    case "imported":
      return {
        state: "configured",
        source: `browser:${imported.store.browser}/${imported.store.profile}`,
        storePath: imported.store.dbPath,
        session: {
          dashboardCookies: imported.cookies,
          apiCookies: imported.cookies,
        },
      };
    case "disabled":
      return { state: "none", note: "browser import disabled" };
    case "no_stores":
      return { state: "none", note: "no supported local browser profile found" };
    case "no_session":
      return {
        state: "none",
        note: imported.keyringSeen
          ? "no readable QwenCloud ticket; a browser cookie store is keyring protected and its keyring is locked or unavailable"
          : "no QwenCloud login ticket in local browsers",
      };
    case "unreadable":
      return { state: "none", note: "local browser cookie store is unreadable" };
  }
}

async function resolveBrowserStores(params: {
  env: NodeJS.ProcessEnv;
  homeDir?: string;
  now: number;
}): Promise<BrowserCookieStore[]> {
  // A negative view of the installed browsers is re-checked as often as the
  // negative session itself, so a profile created after a failed sign-in attempt
  // is found within seconds instead of waiting out the positive cache window.
  const maxAgeMs =
    cachedEntry === null || cachedEntry.auth.state === "none"
      ? Math.min(QWENCLOUD_BROWSER_DISCOVERY_MAX_AGE_MS, QWENCLOUD_NEGATIVE_AUTH_CACHE_MS)
      : QWENCLOUD_BROWSER_DISCOVERY_MAX_AGE_MS;
  const fresh = cachedDiscovery && params.now - cachedDiscovery.at < maxAgeMs;
  if (fresh && cachedDiscovery) return cachedDiscovery.stores;

  const stores = await discoverBrowserCookieStores({
    env: params.env,
    homeDir: params.homeDir,
  });
  cachedDiscovery = { stores, at: params.now };
  return stores;
}

export async function resolveQwenCloudAuth(params?: {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  nowMs?: number;
  maxAgeMs?: number;
}): Promise<ResolvedQwenCloudAuth> {
  return (await resolveQwenCloudAuthEntry(params)).auth;
}

async function resolveQwenCloudAuthEntry(params?: {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  nowMs?: number;
  maxAgeMs?: number;
}): Promise<AuthCacheEntry> {
  if (inFlight) return inFlight;
  const pending = resolveAuthEntry(params).finally(() => {
    inFlight = null;
  });
  inFlight = pending;
  return pending;
}

export async function resolveQwenCloudAuthCached(params?: {
  maxAgeMs?: number;
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  nowMs?: number;
}): Promise<ResolvedQwenCloudAuth> {
  return resolveQwenCloudAuth(params);
}

export function toQwenCloudAuthDiagnostics(entry: AuthCacheEntry): QwenCloudAuthDiagnostics {
  const resolved = entry.auth;
  return {
    state: resolved.state,
    source: "source" in resolved ? resolved.source : null,
    error: "error" in resolved ? resolved.error : null,
    note: "note" in resolved ? (resolved.note ?? null) : null,
    browsers: entry.browsers,
    inspections: entry.inspections,
  };
}

/**
 * Record that QwenCloud accepted the session this process resolved last.
 *
 * Its store is tried first on the next sweep and is no longer considered
 * rejected.
 */
export function markQwenCloudSessionValidated(source?: string | null): void {
  const entry = cachedEntry;
  if (!entry || entry.storePath === null) return;
  if (source !== undefined && source !== null && entry.auth.state === "configured") {
    if (entry.auth.source !== source) return;
  }
  rejectedStorePaths.delete(entry.storePath);
  lastValidatedStorePath = entry.storePath;
}

/**
 * Record that QwenCloud rejected the session this process resolved last.
 *
 * The cached auth entry, the cached browser inventory, and any stale copy of that
 * session are dropped so the next resolution re-discovers the browsers and
 * continues the sweep with a different profile.
 */
export function markQwenCloudSessionRejected(source?: string | null): void {
  const entry = cachedEntry;
  if (!entry || entry.storePath === null) return;
  if (
    source !== undefined &&
    source !== null &&
    entry.auth.state === "configured" &&
    entry.auth.source !== source
  ) {
    return;
  }
  rejectedStorePaths.add(entry.storePath);
  if (lastValidatedStorePath === entry.storePath) lastValidatedStorePath = null;
  if (lastGoodSession?.auth.storePath === entry.storePath) lastGoodSession = null;
  cachedEntry = null;
  // A rejected session means the inventory it came from may be stale: a profile
  // created since the last discovery has to be visible to the very next sweep.
  cachedDiscovery = null;
}

/** Store paths QwenCloud rejected; exposed for status reporting, never values. */
export function qwenCloudRejectedStorePaths(): string[] {
  return [...rejectedStorePaths];
}

export async function getQwenCloudAuthDiagnostics(params?: {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  nowMs?: number;
  maxAgeMs?: number;
}): Promise<QwenCloudAuthDiagnostics> {
  return toQwenCloudAuthDiagnostics(await resolveQwenCloudAuthEntry(params));
}

/**
 * Resolve auth and diagnostics from a single cached lookup.
 *
 * Providers must use this instead of calling the diagnostics and auth helpers
 * separately, so one render performs at most one browser resolution.
 */
export async function resolveQwenCloudAuthWithDiagnostics(params?: {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  nowMs?: number;
  maxAgeMs?: number;
}): Promise<{ auth: ResolvedQwenCloudAuth; diagnostics: QwenCloudAuthDiagnostics }> {
  const entry = await resolveQwenCloudAuthEntry(params);
  return { auth: entry.auth, diagnostics: toQwenCloudAuthDiagnostics(entry) };
}

export function qwenCloudSessionCookieHeader(
  session: QwenCloudSession,
  kind: "dashboard" | "api",
): string {
  return cookieHeaderFromCookies(kind === "api" ? session.apiCookies : session.dashboardCookies);
}

export function clearQwenCloudAuthCacheForTests(): void {
  cachedEntry = null;
  inFlight = null;
  cachedDiscovery = null;
  lastImportAt = 0;
  lastGoodSession = null;
  rejectedStorePaths.clear();
  lastValidatedStorePath = null;
}
