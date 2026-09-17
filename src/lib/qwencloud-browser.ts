import { join } from "node:path";

import {
  type BrowserCookieStore,
  type BrowserReaders,
  type BrowserSessionImportResult,
  type BrowserStoreReadResult,
  browserStoresSignature,
  fingerprintBrowserCookieStores,
  importBrowserSession,
  summarizeRead,
} from "./browser-cookie-reader.js";
import type { SystemKeyStore } from "./browser-keystore.js";
import { resolveSystemKeyStore } from "./browser-secret-service.js";
import type { OpenBrowserStoreOptions } from "./browser-store-open.js";
import {
  type ChromiumCookieStore,
  listChromiumCookieStores,
  readChromiumQwenCloudCookies,
} from "./qwencloud-chromium.js";
import type { QwenCloudCookie } from "./qwencloud-cookies.js";
import { hasQwenCloudRequestTickets } from "./qwencloud-cookies.js";
import {
  type FirefoxProfile,
  listFirefoxCookieStores,
  readFirefoxCookieDatabase,
} from "./qwencloud-firefox.js";

/**
 * QwenCloud browser session discovery.
 *
 * The sweep, ordering, write-ahead-log retry, and reporting are generic and live
 * in `browser-cookie-reader.ts`. This module owns what is specific to the
 * console: which hosts a ticket must be valid for, the environment overrides, and
 * the readers that filter cookies down to QwenCloud domains.
 */

export const QWEN_CLOUD_BROWSER_ENV = "QWEN_CLOUD_BROWSER";
export const QWEN_CLOUD_BROWSER_PROFILE_ENV = "QWEN_CLOUD_BROWSER_PROFILE";

export type {
  BrowserCookieStore,
  BrowserKind,
  BrowserSessionImportResult,
  BrowserStoreFingerprint,
  BrowserStoreInspection,
} from "./browser-cookie-reader.js";

export { browserStoresSignature, fingerprintBrowserCookieStores, summarizeRead };

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

export interface ImportBrowserSessionOptions {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
  nowMs?: number;
  stores?: readonly BrowserCookieStore[];
  /** Keyring backend for `v11` values; defaults to the platform's own. */
  keyStore?: SystemKeyStore | null;
  /** Cookie database paths to try first, e.g. the store the console accepted last. */
  preferredStorePaths?: readonly string[];
  /** Cookie database paths whose session QwenCloud already rejected. */
  excludeStorePaths?: readonly string[];
}

/**
 * Read a QwenCloud login session from the local browsers.
 *
 * A store is only accepted when it holds a login ticket the console hosts would
 * actually receive, so a profile with an Alibaba-domain ticket alone cannot
 * shadow a browser that works.
 */
export async function importBrowserQwenCloudSession(
  params?: ImportBrowserSessionOptions,
): Promise<BrowserSessionImportResult> {
  const env = params?.env ?? process.env;
  if (isBrowserImportDisabled(env)) return { state: "disabled" };

  const nowMs = params?.nowMs ?? Date.now();
  const stores = params?.stores ?? (await discoverBrowserCookieStores(params));
  const keyStore =
    params?.keyStore === null ? undefined : (params?.keyStore ?? resolveSystemKeyStore());

  return importBrowserSession({
    stores,
    nowMs,
    keyStore,
    readers: qwenCloudReaders(nowMs),
    preferredStorePaths: params?.preferredStorePaths,
    excludeStorePaths: params?.excludeStorePaths,
  });
}

function qwenCloudReaders(nowMs: number): BrowserReaders {
  return {
    readStore: (store, readNowMs, options: OpenBrowserStoreOptions, keyStore) => {
      if (store.kind === "firefox") {
        return readFirefoxCookieDatabase(store.dbPath, readNowMs, options).then(
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
        readNowMs,
        keyStore ? { ...options, keyStore } : options,
      );
    },
    isUsableSession: (cookies: readonly QwenCloudCookie[]) =>
      hasQwenCloudRequestTickets(cookies, nowMs),
  };
}
