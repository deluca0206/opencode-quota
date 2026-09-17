import type { BrowserCookie } from "./browser-cookie-types.js";

export const QWENCLOUD_AUTH_TICKET_COOKIE_NAMES = [
  "login_aliyunid_ticket",
  "login_qwencloud_ticket",
  "qwen_sso_ticket",
] as const;

export const QWENCLOUD_COOKIE_DOMAINS = [
  "qwencloud.com",
  "home.qwencloud.com",
  "account.qwencloud.com",
  "signin.qwencloud.com",
  "www.qwencloud.com",
  "cs-data.qwencloud.com",
  "alibabacloud.com",
  "account.alibabacloud.com",
  "aliyun.com",
  "console.aliyun.com",
] as const;

/**
 * QwenCloud cookies are plain browser cookies. The alias keeps provider code
 * readable while the browser readers stay service-independent, and guarantees
 * the two shapes cannot drift apart.
 */
export type QwenCloudCookie = BrowserCookie;

const AUTH_TICKET_NAME_SET = new Set<string>(QWENCLOUD_AUTH_TICKET_COOKIE_NAMES);

export function parseCookieHeader(raw: string): QwenCloudCookie[] | null {
  if (raw.includes("\r") || raw.includes("\n")) return null;

  const withoutPrefix = raw.trim().replace(/^cookie\s*:\s*/iu, "");
  if (!withoutPrefix) return null;

  const cookies: QwenCloudCookie[] = [];
  const seen = new Set<string>();
  for (const rawPair of withoutPrefix.split(";")) {
    const pair = rawPair.trim();
    if (!pair) continue;

    const separator = pair.indexOf("=");
    if (separator <= 0) return null;

    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (!name || !value) return null;
    if (seen.has(name)) return null;
    seen.add(name);
    cookies.push({ name, value });
  }

  return cookies.length > 0 ? cookies : null;
}

export function cookieHeaderFromCookies(cookies: readonly QwenCloudCookie[]): string {
  return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
}

export function cookieValue(cookies: readonly QwenCloudCookie[], name: string): string | undefined {
  const match = cookies.find((cookie) => cookie.name.toLowerCase() === name.toLowerCase());
  return match?.value;
}

export function hasAuthTicket(cookies: readonly QwenCloudCookie[]): boolean {
  return cookies.some((cookie) => AUTH_TICKET_NAME_SET.has(cookie.name));
}

export function isQwenCloudCookieDomain(host: string): boolean {
  const normalized = normalizeHost(host);
  if (!normalized) return false;
  return QWENCLOUD_COOKIE_DOMAINS.some(
    (domain) => normalized === domain || normalized.endsWith(`.${domain}`),
  );
}

const COOKIE_EXPIRY_MS_THRESHOLD = 1_000_000_000_000;

export function cookieExpiryDeadlineMs(expiry: number | undefined): number | undefined {
  if (expiry === undefined || expiry <= 0) return undefined;
  return expiry >= COOKIE_EXPIRY_MS_THRESHOLD ? expiry : expiry * 1000;
}

export function cookieMatchesUrl(cookie: QwenCloudCookie, url: URL, nowMs: number): boolean {
  const expiryMs = cookieExpiryDeadlineMs(cookie.expiry);
  if (expiryMs !== undefined && expiryMs <= nowMs) {
    return false;
  }
  if (cookie.secure && url.protocol !== "https:") return false;
  if (!isDefaultFirefoxContext(cookie.originAttributes)) return false;

  const path = cookie.path && cookie.path.length > 0 ? cookie.path : "/";
  if (!urlPathMatchesCookie(url.pathname || "/", path)) return false;

  if (!cookie.host) return true;
  return cookieMatchesHost(cookie.host, url.hostname);
}

export const QWENCLOUD_REQUEST_HOSTS = ["home.qwencloud.com", "cs-data.qwencloud.com"] as const;

export function cookiesForUrl(
  cookies: readonly QwenCloudCookie[],
  url: URL,
  nowMs: number,
): QwenCloudCookie[] {
  if (!isAuthorizedQwenCloudRequestUrl(url)) return [];
  return cookies.filter((cookie) => cookieMatchesUrl(cookie, url, nowMs));
}

export function isAuthorizedQwenCloudRequestUrl(url: URL): boolean {
  if (url.protocol !== "https:") return false;
  return (QWENCLOUD_REQUEST_HOSTS as readonly string[]).includes(url.hostname);
}

export function firefoxCookieHostSql(): { sql: string; params: string[] } {
  return cookieHostSql("host");
}

export function chromiumCookieHostSql(): { sql: string; params: string[] } {
  return cookieHostSql("host_key");
}

function cookieHostSql(column: string): { sql: string; params: string[] } {
  const clauses: string[] = [];
  const params: string[] = [];
  const seen = new Set<string>();
  for (const domain of QWENCLOUD_COOKIE_DOMAINS) {
    for (const value of [domain, `.${domain}`, `%.${domain}`]) {
      if (seen.has(value)) continue;
      seen.add(value);
      clauses.push(value.startsWith("%") ? `${column} LIKE ?` : `${column} = ?`);
      params.push(value);
    }
  }
  return { sql: clauses.join(" OR "), params };
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

export function cookieMatchesHost(cookieHost: string, requestHost: string): boolean {
  const host = normalizeHost(cookieHost);
  const target = normalizeHost(requestHost);
  if (!host || !target) return false;
  if (cookieHost.startsWith(".")) {
    return target === host || target.endsWith(`.${host}`);
  }
  return target === host;
}

export function getCookieSecrets(cookies: readonly QwenCloudCookie[]): string[] {
  return cookies.flatMap((cookie) => (cookie.value ? [cookie.value] : []));
}

export function sanitizeQwenCloudError(error: unknown, secrets: readonly string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) {
    if (!secret) continue;
    message = message.split(secret).join("[redacted]");
  }
  return message;
}

function normalizeHost(host: string): string {
  return host.trim().replace(/^\./u, "").toLowerCase();
}

function urlPathMatchesCookie(urlPath: string, cookiePath: string): boolean {
  if (cookiePath === "/") return true;
  if (urlPath === cookiePath) return true;
  const prefix = cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`;
  return urlPath.startsWith(prefix);
}

function isDefaultFirefoxContext(originAttributes: string | undefined): boolean {
  if (!originAttributes) return true;
  return !/userContextId=/u.test(originAttributes);
}
