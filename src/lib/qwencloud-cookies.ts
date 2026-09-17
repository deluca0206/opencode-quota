import {
  browserCookieHostSql,
  chromiumExpiryToUnixSeconds,
  cookieExpiryDeadlineMs,
  cookieHostMatchesRequestHost,
  cookiePathMatchesUrlPath,
  hostMatchesAnyDomain,
  isDefaultCookieContext,
} from "./browser-cookie-sql.js";
import type { BrowserCookie } from "./browser-cookie-types.js";

export { chromiumExpiryToUnixSeconds, cookieExpiryDeadlineMs };

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
  return hostMatchesAnyDomain(host, QWENCLOUD_COOKIE_DOMAINS);
}

export function cookieMatchesUrl(cookie: QwenCloudCookie, url: URL, nowMs: number): boolean {
  const expiryMs = cookieExpiryDeadlineMs(cookie.expiry);
  if (expiryMs !== undefined && expiryMs <= nowMs) {
    return false;
  }
  if (cookie.secure && url.protocol !== "https:") return false;
  if (!isDefaultCookieContext(cookie.originAttributes)) return false;

  const path = cookie.path && cookie.path.length > 0 ? cookie.path : "/";
  if (!cookiePathMatchesUrlPath(url.pathname || "/", path)) return false;

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

/**
 * Whether these cookies can actually authenticate a QwenCloud request.
 *
 * A login ticket scoped to another Alibaba host (`login_aliyunid_ticket` on
 * `.aliyun.com`, for example) is a valid cookie but is never sent to the console,
 * so a browser holding only that must not be selected as the session source.
 * Mirrors the guard the API client applies before it sends anything.
 */
export function hasQwenCloudRequestTickets(
  cookies: readonly QwenCloudCookie[],
  nowMs: number,
): boolean {
  return QWENCLOUD_REQUEST_HOSTS.every((host) =>
    hasAuthTicket(cookiesForUrl(cookies, new URL(`https://${host}/`), nowMs)),
  );
}

export function isAuthorizedQwenCloudRequestUrl(url: URL): boolean {
  if (url.protocol !== "https:") return false;
  return (QWENCLOUD_REQUEST_HOSTS as readonly string[]).includes(url.hostname);
}

export function firefoxCookieHostSql(): { sql: string; params: string[] } {
  return browserCookieHostSql("host", QWENCLOUD_COOKIE_DOMAINS);
}

export function chromiumCookieHostSql(): { sql: string; params: string[] } {
  return browserCookieHostSql("host_key", QWENCLOUD_COOKIE_DOMAINS);
}

export function cookieMatchesHost(cookieHost: string, requestHost: string): boolean {
  return cookieHostMatchesRequestHost(cookieHost, requestHost);
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

function isDefaultFirefoxContext(originAttributes: string | undefined): boolean {
  return isDefaultCookieContext(originAttributes);
}
