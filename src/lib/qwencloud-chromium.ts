import {
  CHROMIUM_BROWSER_DESCRIPTORS,
  CHROMIUM_COOKIE_DB_RELS,
  CHROMIUM_KEYRING_SCHEMAS,
  CHROMIUM_ROOT_PROFILE_LABEL,
  type ChromiumBrowserDescriptor,
  type ChromiumBrowserRoot,
  type ChromiumCookieStore,
  type ChromiumReadOptions,
  chromiumBrowserLabel,
  chromiumBrowserRoots,
  listChromiumCookieStores,
  parseChromiumLocalStateProfiles,
  readChromiumCookies,
  resetChromiumKeyringCacheForTests,
} from "./browser-chromium.js";
import {
  CHROMIUM_FALLBACK_PASSWORD,
  CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
  CHROMIUM_KEYRING_PREFIX,
  CHROMIUM_LOCAL_PREFIX,
  type ChromiumDecryptionContext,
  type ChromiumDecryptionResult,
  type ChromiumValueProtection,
  chromiumEncryptedPrefix,
  chromiumValueProtection,
  decryptChromiumCookieValue,
  deriveChromiumKey,
} from "./browser-chromium-crypto.js";
import type { BrowserStoreReadSummary } from "./browser-cookie-types.js";
import {
  chromiumCookieHostSql,
  chromiumExpiryToUnixSeconds,
  cookieExpiryDeadlineMs,
  isQwenCloudCookieDomain,
  type QwenCloudCookie,
} from "./qwencloud-cookies.js";

/**
 * QwenCloud bindings for the generic Chromium reader.
 *
 * The reader itself is service-independent; this module supplies the QwenCloud
 * host filter and expiry conversion, and keeps the names the provider code and
 * its tests already use.
 */

export type ChromiumCookieReadResult =
  | {
      state: "imported";
      cookies: QwenCloudCookie[];
      keyringProtected: boolean;
      summary: BrowserStoreReadSummary;
    }
  | { state: "keyring"; summary: BrowserStoreReadSummary }
  | { state: "no_session"; summary: BrowserStoreReadSummary }
  | { state: "unreadable"; summary: BrowserStoreReadSummary };

export async function readChromiumQwenCloudCookies(
  store: ChromiumCookieStore,
  nowMs: number,
  options?: ChromiumReadOptions,
): Promise<ChromiumCookieReadResult> {
  const hostFilter = chromiumCookieHostSql();
  const result = await readChromiumCookies(
    store,
    {
      query: { hostSql: hostFilter, acceptHost: isQwenCloudCookieDomain },
      nowMs,
      expiryToUnixSeconds: chromiumExpiryToUnixSeconds,
      expiryDeadlineMs: cookieExpiryDeadlineMs,
    },
    options,
  );
  return result as ChromiumCookieReadResult;
}

export {
  CHROMIUM_BROWSER_DESCRIPTORS,
  CHROMIUM_COOKIE_DB_RELS,
  CHROMIUM_FALLBACK_PASSWORD,
  CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
  CHROMIUM_KEYRING_PREFIX,
  CHROMIUM_KEYRING_SCHEMAS,
  CHROMIUM_LOCAL_PREFIX,
  CHROMIUM_ROOT_PROFILE_LABEL,
  chromiumBrowserLabel,
  chromiumBrowserRoots,
  chromiumEncryptedPrefix,
  chromiumValueProtection,
  decryptChromiumCookieValue,
  deriveChromiumKey,
  listChromiumCookieStores,
  parseChromiumLocalStateProfiles,
  resetChromiumKeyringCacheForTests,
};

export type {
  ChromiumBrowserDescriptor,
  ChromiumBrowserRoot,
  ChromiumCookieStore,
  ChromiumDecryptionContext,
  ChromiumDecryptionResult,
  ChromiumReadOptions,
  ChromiumValueProtection,
};
