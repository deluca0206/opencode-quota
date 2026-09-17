import type { BrowserCookie } from "./browser-cookie-types.js";

/**
 * Host selection shared by every browser cookie reader.
 *
 * Readers must never materialise a whole cookie jar: the host filter is pushed
 * into SQL, and the same domain list drives the row-level re-check. Keeping this
 * here lets a new provider reuse the Firefox and Chromium readers by supplying
 * its own domains.
 */

/** SQL fragment plus bound parameters selecting rows whose host column is in `domains`. */
export function browserCookieHostSql(
  column: string,
  domains: readonly string[],
): { sql: string; params: string[] } {
  const clauses: string[] = [];
  const params: string[] = [];
  const seen = new Set<string>();
  for (const domain of domains) {
    for (const value of [domain, `.${domain}`, `%.${domain}`]) {
      if (seen.has(value)) continue;
      seen.add(value);
      clauses.push(value.startsWith("%") ? `${column} LIKE ?` : `${column} = ?`);
      params.push(value);
    }
  }
  return { sql: clauses.join(" OR "), params };
}

/** True when `host` is `domain` or a subdomain of it. */
export function hostMatchesDomain(host: string, domain: string): boolean {
  const normalized = normalizeHost(host);
  const target = normalizeHost(domain);
  if (!normalized || !target) return false;
  return normalized === target || normalized.endsWith(`.${target}`);
}

export function hostMatchesAnyDomain(host: string, domains: readonly string[]): boolean {
  return domains.some((domain) => hostMatchesDomain(host, domain));
}

/**
 * Cookie scope rules shared by readers.
 *
 * A leading dot means the cookie covers subdomains; an exact host does not.
 */
export function cookieHostMatchesRequestHost(cookieHost: string, requestHost: string): boolean {
  const host = normalizeHost(cookieHost);
  const target = normalizeHost(requestHost);
  if (!host || !target) return false;
  if (cookieHost.startsWith(".")) {
    return target === host || target.endsWith(`.${host}`);
  }
  return target === host;
}

/** Chromium stores `expires_utc` as microseconds since 1601-01-01 UTC. */
const CHROMIUM_EPOCH_OFFSET_MS = 11_644_473_600_000;

export function chromiumExpiryToUnixSeconds(expiresUtc: unknown): number | undefined {
  if (expiresUtc === null || expiresUtc === undefined) return undefined;
  const raw =
    typeof expiresUtc === "bigint" || typeof expiresUtc === "number"
      ? expiresUtc
      : String(expiresUtc).trim();
  if (raw === "") return undefined;
  let micros: bigint;
  try {
    micros = BigInt(raw);
  } catch {
    return undefined;
  }
  if (micros <= 0n) return undefined;
  const unixMs = Number(micros / 1000n) - CHROMIUM_EPOCH_OFFSET_MS;
  return Number.isFinite(unixMs) ? Math.floor(unixMs / 1000) : undefined;
}

const COOKIE_EXPIRY_MS_THRESHOLD = 1_000_000_000_000;

/**
 * Expiry as a millisecond deadline.
 *
 * Browsers report seconds, and some stores report milliseconds; values below the
 * threshold are seconds. `undefined` means a session cookie.
 */
export function cookieExpiryDeadlineMs(expiry: number | undefined): number | undefined {
  if (expiry === undefined || expiry <= 0) return undefined;
  return expiry >= COOKIE_EXPIRY_MS_THRESHOLD ? expiry : expiry * 1000;
}

/** Cookie path scope: a cookie path prefixes the request path on a boundary. */
export function cookiePathMatchesUrlPath(urlPath: string, cookiePath: string): boolean {
  const path = cookiePath === "/" ? "/" : cookiePath;
  if (path === "/") return true;
  if (urlPath === path) return true;
  const prefix = path.endsWith("/") ? path : `${path}/`;
  return urlPath.startsWith(prefix);
}

/** Whether a cookie would be sent to `url` right now. */
export function browserCookieMatchesUrl(
  cookie: BrowserCookie,
  url: URL,
  nowMs: number,
  options?: { allowNonDefaultContext?: boolean },
): boolean {
  const expiryMs = cookieExpiryDeadlineMs(cookie.expiry);
  if (expiryMs !== undefined && expiryMs <= nowMs) return false;
  if (cookie.secure && url.protocol !== "https:") return false;
  if (!options?.allowNonDefaultContext && !isDefaultCookieContext(cookie.originAttributes)) {
    return false;
  }
  if (!cookiePathMatchesUrlPath(url.pathname || "/", cookie.path ?? "")) return false;
  if (!cookie.host) return true;
  return cookieHostMatchesRequestHost(cookie.host, url.hostname);
}

/** Firefox tags container cookies; only the default context is shared with sites. */
export function isDefaultCookieContext(originAttributes: string | undefined): boolean {
  if (!originAttributes) return true;
  return !/userContextId=/u.test(originAttributes);
}

function normalizeHost(host: string): string {
  return host.trim().replace(/^\./u, "").toLowerCase();
}
