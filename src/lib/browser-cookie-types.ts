/**
 * Browser-independent cookie types.
 *
 * Providers ask a browser reader for the cookies of a host set; the reader
 * knows nothing about which service they belong to. Keeping these shapes here
 * lets another provider reuse the Firefox and Chromium readers unchanged.
 */

export interface BrowserCookie {
  name: string;
  value: string;
  host?: string;
  path?: string;
  /** Unix seconds; `undefined` for a session cookie. */
  expiry?: number;
  secure?: boolean;
  /** Firefox container context, used to keep default-context cookies only. */
  originAttributes?: string;
}

/** How a cookie value was protected inside the browser's store. */
export type BrowserValueProtection = "plaintext" | "local" | "keyring" | "unsupported";

/**
 * Host selection for one read.
 *
 * `hostSql` narrows rows inside SQLite so a read never materialises the whole
 * cookie jar; `acceptHost` re-checks each decrypted row.
 */
export interface BrowserCookieQuery {
  hostSql: { sql: string; params: string[] };
  acceptHost?: (host: string) => boolean;
}

/** Safe, value-free summary of what a store read observed. */
export interface BrowserStoreReadSummary {
  /** Rows matching the host filter, before expiry and decryption outcomes. */
  rows: number;
  /** How many values used each protection format. */
  protections: Partial<Record<BrowserValueProtection, number>>;
  /** Cookie database schema version, when the store reports one. */
  schemaVersion?: number;
  /** Keyring outcome when `v11` values were present. */
  keyring?: "available" | "missing" | "locked" | "unavailable" | "error" | "not-configured";
}

export function emptyReadSummary(): BrowserStoreReadSummary {
  return { rows: 0, protections: {} };
}

export function recordProtection(
  summary: BrowserStoreReadSummary,
  protection: BrowserValueProtection,
): void {
  summary.protections[protection] = (summary.protections[protection] ?? 0) + 1;
}
