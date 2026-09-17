import { createHash, randomUUID } from "node:crypto";

import { sanitizeSingleLineDisplaySnippet } from "./display-sanitize.js";
import { fetchWithTimeout } from "./http.js";
import type { QwenCloudSession } from "./qwencloud-auth.js";
import {
  cookieHeaderFromCookies,
  cookiesForUrl,
  cookieValue,
  getCookieSecrets,
  hasAuthTicket,
  isAuthorizedQwenCloudRequestUrl,
  type QwenCloudCookie,
  sanitizeQwenCloudError,
} from "./qwencloud-cookies.js";
import {
  parseQwenCloudUsageSnapshot,
  QwenCloudParseError,
  type QwenCloudUsageSnapshot,
} from "./qwencloud-parser.js";

export const QWENCLOUD_GATEWAY_ORIGIN = "https://home.qwencloud.com";
export const QWENCLOUD_DATA_ORIGIN = "https://cs-data.qwencloud.com";
export const QWENCLOUD_DASHBOARD_PATH = "/billing/subscription/token-plan-individual";
export const QWENCLOUD_USAGE_API = "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/usage";
export const QWENCLOUD_SUBSCRIPTION_API =
  "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/subscription";
export const QWENCLOUD_QUOTA_CONFIG_API =
  "zeldaHttp.apikeyMgr./tokenplan/personal/api/v2/quota-config";
export const QWENCLOUD_PRODUCT_CODE = "sfm_tokenplansolo_public_intl";
export const QWENCLOUD_CONSOLE_PRODUCT = "sfm_bailian";
export const QWENCLOUD_CONSOLE_ACTION = "IntlBroadScopeAspnGateway";
export const QWENCLOUD_REGION = "ap-southeast-1";
export const QWENCLOUD_LANGUAGE = "en-US";
export const QWENCLOUD_RESPONSE_MAX_BYTES = 256 * 1024;
/** Per-request default timeout. */
export const QWENCLOUD_REQUEST_TIMEOUT_MS = 10_000;
/**
 * Overall wall-clock budget for one quota refresh.
 *
 * A refresh performs two sequential phases (CSRF discovery, then the three
 * window calls in parallel), and the console answers each phase in seconds:
 * measured ~10.5s cold and ~4.4s warm. The budget only bounds a pathological
 * hang, so it keeps clear headroom above the measured cold path. Requests are
 * asynchronous, so waiting here never blocks the OpenCode event loop.
 */
export const QWENCLOUD_TOTAL_BUDGET_MS = 20_000;
export const QWENCLOUD_BUDGET_EXHAUSTED_MESSAGE = "QwenCloud request budget exhausted.";
const QWENCLOUD_USER_AGENT =
  "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0";

export type QwenCloudQueryResult =
  | { success: true; snapshot: QwenCloudUsageSnapshot; secTokenSource: string }
  | { success: false; error: string; retryable?: boolean };

type TransportFailureReason =
  | "login_required"
  | "timeout"
  | "unavailable"
  | "rate_limited"
  | "invalid";

export function resolveQwenCloudOrigins(env: NodeJS.ProcessEnv = process.env): {
  gatewayOrigin: string;
  dataOrigin: string;
  dashboardUrl: string;
} {
  const gatewayOrigin = normalizeHttpsOrigin(env.QWEN_CLOUD_HOST) ?? QWENCLOUD_GATEWAY_ORIGIN;
  const dataOrigin =
    normalizeHttpsOrigin(env.QWEN_CLOUD_QUOTA_URL) ??
    (gatewayOrigin === QWENCLOUD_GATEWAY_ORIGIN ? QWENCLOUD_DATA_ORIGIN : gatewayOrigin);
  return {
    gatewayOrigin,
    dataOrigin,
    dashboardUrl: qwenCloudDashboardUrl(gatewayOrigin),
  };
}

/** Console page where the Token Plan session is created; used in setup hints. */
export function qwenCloudDashboardUrl(gatewayOrigin: string = QWENCLOUD_GATEWAY_ORIGIN): string {
  return `${gatewayOrigin}${QWENCLOUD_DASHBOARD_PATH}`;
}

export async function queryQwenCloudTokenPlan(params: {
  session: QwenCloudSession;
  requestTimeoutMs?: number;
  /** Total wall-clock budget across every transaction in one refresh. */
  totalBudgetMs?: number;
  nowMs?: number;
  env?: NodeJS.ProcessEnv;
  fetchFn?: typeof fetch;
}): Promise<QwenCloudQueryResult> {
  const env = params.env ?? process.env;
  const nowMs = params.nowMs ?? Date.now();
  const perRequestTimeoutMs = params.requestTimeoutMs ?? QWENCLOUD_REQUEST_TIMEOUT_MS;
  const deadlineAt = Date.now() + (params.totalBudgetMs ?? QWENCLOUD_TOTAL_BUDGET_MS);
  const timeoutMs = (): number =>
    Math.max(0, Math.min(perRequestTimeoutMs, deadlineAt - Date.now()));
  const origins = resolveQwenCloudOrigins(env);
  const unauthorized = unauthorizedOriginResult(origins);
  if (unauthorized) return unauthorized;

  const dashboardUrl = new URL(origins.dashboardUrl);
  const userInfoUrl = new URL("/tool/user/info.json", `${origins.gatewayOrigin}/`);
  const apiUrl = new URL(qwenCloudApiUrl(origins.dataOrigin, QWENCLOUD_USAGE_API));
  const dashboardCookies = cookiesForUrl(params.session.dashboardCookies, dashboardUrl, nowMs);
  const userInfoCookies = cookiesForUrl(params.session.dashboardCookies, userInfoUrl, nowMs);
  const apiCookies = cookiesForUrl(params.session.apiCookies, apiUrl, nowMs);
  if (!hasAuthTicket(dashboardCookies) || !hasAuthTicket(apiCookies)) {
    return {
      success: false,
      error: "QwenCloud login required. Sign in at home.qwencloud.com and retry.",
    };
  }
  const secrets = getCookieSecrets([...apiCookies, ...dashboardCookies, ...userInfoCookies]);

  try {
    const secTokenParams = {
      dashboardCookies,
      userInfoCookies,
      origins,
      timeoutMs,
      secrets,
      fetchFn: params.fetchFn,
    };
    const resolved = await resolveSecToken(secTokenParams);
    if (!resolved.ok) return transportFailureResult(resolved.reason);

    // Usage, subscription, and quota-config are independent: run them together so
    // one refresh costs roughly a single slow console round trip.
    const fetchAllWindows = (secToken: string) => {
      const attemptTimeoutMs = timeoutMs();
      return Promise.all([
        fetchQwenCloudApi({
          api: QWENCLOUD_USAGE_API,
          dataParameters: {},
          cookies: apiCookies,
          secToken,
          origins,
          timeoutMs: attemptTimeoutMs,
          secrets,
          fetchFn: params.fetchFn,
        }),
        fetchQwenCloudApi({
          api: QWENCLOUD_SUBSCRIPTION_API,
          dataParameters: { commodityCode: QWENCLOUD_PRODUCT_CODE },
          cookies: apiCookies,
          secToken,
          origins,
          timeoutMs: attemptTimeoutMs,
          secrets,
          fetchFn: params.fetchFn,
          optional: true,
        }),
        fetchQwenCloudApi({
          api: QWENCLOUD_QUOTA_CONFIG_API,
          dataParameters: {},
          cookies: apiCookies,
          secToken,
          origins,
          timeoutMs: attemptTimeoutMs,
          secrets,
          fetchFn: params.fetchFn,
          optional: true,
        }),
      ]);
    };

    type WindowAttempt =
      | { kind: "ok"; snapshot: QwenCloudUsageSnapshot }
      | { kind: "failed"; loginSuspected: boolean; result: QwenCloudQueryResult };

    const runAttempt = async (secToken: string): Promise<WindowAttempt> => {
      const [usage, subscription, quotaConfig] = await fetchAllWindows(secToken);
      if (!usage.success) {
        return {
          kind: "failed",
          loginSuspected: /login required/iu.test(usage.error),
          result: usage,
        };
      }
      try {
        const snapshot = parseQwenCloudUsageSnapshot({
          usage: usage.json,
          subscription: subscription.success ? subscription.json : undefined,
          quotaConfig: quotaConfig.success ? quotaConfig.json : undefined,
        });
        const partial = {
          ...snapshot.partial,
          ...(!subscription.success ? { subscription: "unavailable" } : {}),
          ...(!quotaConfig.success ? { quotaConfig: "unavailable" } : {}),
        };
        return {
          kind: "ok",
          snapshot: {
            ...snapshot,
            ...(Object.keys(partial).length > 0 ? { partial } : {}),
          },
        };
      } catch (error) {
        if (error instanceof QwenCloudParseError) {
          return {
            kind: "failed",
            loginSuspected: error.reason === "login_required",
            result: {
              success: false,
              error: error.message,
              retryable: error.reason === "unavailable",
            },
          };
        }
        return {
          kind: "failed",
          loginSuspected: false,
          result: {
            success: false,
            error: "QwenCloud response did not match the expected schema.",
          },
        };
      }
    };

    let attempt = await runAttempt(resolved.value);
    let secTokenSource = resolved.source;

    // The gateway reports a rotated CSRF token as an in-band login failure rather
    // than an HTTP error, so a cached token is discarded and retried exactly once.
    if (attempt.kind === "failed" && attempt.loginSuspected && resolved.cached && timeoutMs() > 0) {
      invalidateSecTokenCache(dashboardCookies);
      const fresh = await resolveSecToken(secTokenParams);
      if (fresh.ok && !fresh.cached && timeoutMs() > 0) {
        attempt = await runAttempt(fresh.value);
        secTokenSource = fresh.source;
      }
    }

    if (attempt.kind === "failed") return attempt.result;
    return { success: true, secTokenSource, snapshot: attempt.snapshot };
  } catch (error) {
    return {
      success: false,
      error: sanitizeVisibleError(error, secrets),
      retryable: isRetryableError(error),
    };
  }
}

function qwenCloudApiUrl(dataOrigin: string, api: string): string {
  const url = new URL("/data/api.json", `${dataOrigin}/`);
  url.searchParams.set("action", QWENCLOUD_CONSOLE_ACTION);
  url.searchParams.set("product", QWENCLOUD_CONSOLE_PRODUCT);
  url.searchParams.set("api", api);
  url.searchParams.set("_v", "undefined");
  return url.toString();
}

type SecTokenResolution =
  | { ok: true; value: string; source: string; cached: boolean }
  | { ok: false; reason: TransportFailureReason };

interface SecTokenSourceParams {
  dashboardCookies: readonly QwenCloudCookie[];
  userInfoCookies: readonly QwenCloudCookie[];
  origins: { gatewayOrigin: string; dashboardUrl: string };
  timeoutMs: () => number;
  secrets: readonly string[];
  fetchFn?: typeof fetch;
}

/**
 * The console CSRF token is stable for a session but costs a full page fetch.
 * Caching it removes one slow round trip from every refresh after the first.
 */
const SEC_TOKEN_CACHE_TTL_MS = 300_000;
const secTokenCache = new Map<string, { value: string; source: string; at: number }>();

export function clearQwenCloudSecTokenCacheForTests(): void {
  secTokenCache.clear();
}

function secTokenCacheKey(cookies: readonly QwenCloudCookie[]): string {
  return createHash("sha256").update(cookieHeaderFromCookies(cookies)).digest("hex");
}

function invalidateSecTokenCache(cookies: readonly QwenCloudCookie[]): void {
  secTokenCache.delete(secTokenCacheKey(cookies));
}

async function resolveSecToken(params: SecTokenSourceParams): Promise<SecTokenResolution> {
  const fromCookie =
    cookieValue(params.dashboardCookies, "sec_token") ??
    cookieValue(params.dashboardCookies, "secToken");
  if (fromCookie) return { ok: true, value: fromCookie, source: "cookie", cached: false };

  const cacheKey = secTokenCacheKey(params.dashboardCookies);
  const now = Date.now();
  const hit = secTokenCache.get(cacheKey);
  if (hit && now - hit.at < SEC_TOKEN_CACHE_TTL_MS) {
    return { ok: true, value: hit.value, source: `${hit.source}:cached`, cached: true };
  }

  const resolved = await raceSecTokenSources(params);
  if (!resolved.ok) return resolved;
  secTokenCache.set(cacheKey, {
    value: resolved.value,
    source: resolved.source,
    at: Date.now(),
  });
  return { ...resolved, cached: false };
}

/**
 * Resolve the CSRF token from whichever console endpoint answers first.
 *
 * The billing HTML and `user/info.json` both expose it, but the console responds
 * to them at very different speeds (measured ~0.4s vs ~4.4s). Racing them keeps
 * a refresh at roughly one round trip instead of two.
 */
async function raceSecTokenSources(
  params: SecTokenSourceParams,
): Promise<
  { ok: true; value: string; source: string } | { ok: false; reason: TransportFailureReason }
> {
  type TaskResult = { token: string | null; reason?: TransportFailureReason };
  const tasks: Array<{ source: string; run: () => Promise<TaskResult> }> = [
    {
      source: "dashboard",
      run: async () => {
        const result = await fetchText({
          url: params.origins.dashboardUrl,
          cookies: params.dashboardCookies,
          origins: params.origins,
          timeoutMs: params.timeoutMs(),
          secrets: params.secrets,
          fetchFn: params.fetchFn,
          accept: "text/html,application/xhtml+xml",
        });
        return result.ok
          ? { token: extractSecToken(result.body) }
          : { token: null, reason: result.reason };
      },
    },
    {
      source: "user-info",
      run: async () => {
        const result = await fetchText({
          url: `${params.origins.gatewayOrigin}/tool/user/info.json`,
          cookies: params.userInfoCookies,
          origins: params.origins,
          timeoutMs: params.timeoutMs(),
          secrets: params.secrets,
          fetchFn: params.fetchFn,
          accept: "application/json, text/plain, */*",
        });
        return result.ok
          ? { token: extractSecToken(result.body) }
          : { token: null, reason: result.reason };
      },
    },
  ];

  return await new Promise((resolve) => {
    let remaining = tasks.length;
    let settled = false;
    const reasons: TransportFailureReason[] = [];

    const finishWithoutToken = (): void => {
      settled = true;
      resolve({ ok: false, reason: pickSecTokenFailureReason(reasons) });
    };

    for (const task of tasks) {
      task
        .run()
        .then((result) => {
          if (settled) return;
          if (result.token) {
            settled = true;
            resolve({ ok: true, value: result.token, source: task.source });
            return;
          }
          if (result.reason) reasons.push(result.reason);
          remaining -= 1;
          if (remaining === 0) finishWithoutToken();
        })
        .catch(() => {
          if (settled) return;
          remaining -= 1;
          if (remaining === 0) finishWithoutToken();
        });
    }
  });
}

function pickSecTokenFailureReason(
  reasons: readonly TransportFailureReason[],
): TransportFailureReason {
  const transport = reasons.find(
    (reason) => reason === "timeout" || reason === "unavailable" || reason === "rate_limited",
  );
  return transport ?? "login_required";
}

async function fetchQwenCloudApi(params: {
  api: string;
  dataParameters: Record<string, string>;
  cookies: readonly QwenCloudCookie[];
  secToken: string;
  origins: { gatewayOrigin: string; dataOrigin: string; dashboardUrl: string };
  timeoutMs: number;
  secrets: readonly string[];
  fetchFn?: typeof fetch;
  optional?: boolean;
}): Promise<
  { success: true; json: unknown } | { success: false; error: string; retryable?: boolean }
> {
  if (params.timeoutMs <= 0) {
    return params.optional
      ? { success: false, error: "optional" }
      : { success: false, error: QWENCLOUD_BUDGET_EXHAUSTED_MESSAGE, retryable: true };
  }
  const url = qwenCloudApiUrl(params.origins.dataOrigin, params.api);
  if (!isAuthorizedQwenCloudRequestUrl(new URL(url))) {
    return { success: false, error: "QwenCloud host override is not allowed." };
  }
  const cookieHeader = cookieHeaderFromCookies(params.cookies);
  const cna = cookieValue(params.cookies, "cna");
  const csrf =
    cookieValue(params.cookies, "login_aliyunid_csrf") ?? cookieValue(params.cookies, "csrf");
  const paramsJson = JSON.stringify({
    Api: params.api,
    V: "1.0",
    Data: {
      ...params.dataParameters,
      cornerstoneParam: {
        feTraceId: randomUUID().toLowerCase(),
        feURL: params.origins.dashboardUrl,
        protocol: "V2",
        console: "ONE_CONSOLE",
        productCode: "p_efm",
        domain: new URL(params.origins.dashboardUrl).hostname,
        consoleSite: "QWENCLOUD",
        userNickName: "",
        userPrincipalName: "",
        xsp_lang: QWENCLOUD_LANGUAGE,
        ...(cna ? { "X-Anonymous-Id": cna } : {}),
      },
    },
  });
  const body = new URLSearchParams({
    product: QWENCLOUD_CONSOLE_PRODUCT,
    action: QWENCLOUD_CONSOLE_ACTION,
    sec_token: params.secToken,
    region: QWENCLOUD_REGION,
    language: QWENCLOUD_LANGUAGE,
    params: paramsJson,
  });

  try {
    return await fetchWithTimeout(url, {
      fetchFn: params.fetchFn,
      timeoutMs: params.timeoutMs,
      request: {
        method: "POST",
        redirect: "manual",
        headers: {
          Accept: "application/json, text/plain, */*",
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: params.origins.gatewayOrigin,
          Referer: params.origins.dashboardUrl,
          "User-Agent": QWENCLOUD_USER_AGENT,
          "X-Requested-With": "XMLHttpRequest",
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
          ...(csrf ? { "x-xsrf-token": csrf, "x-csrf-token": csrf } : {}),
        },
        body,
      },
      consume: async (response, timeoutSignal) => {
        if (response.status >= 300 && response.status < 400) {
          return loginResult(params.optional);
        }
        if (response.status === 401 || response.status === 403) {
          return loginResult(params.optional);
        }
        if (response.status === 429) {
          return unavailableResult("QwenCloud rate limit reached.", params.optional, true);
        }
        if (response.status >= 500) {
          return unavailableResult("QwenCloud API is unavailable.", params.optional, true);
        }
        if (!response.ok) {
          return unavailableResult(
            `QwenCloud request failed (HTTP ${response.status}).`,
            params.optional,
            false,
          );
        }
        try {
          return { success: true, json: await readBoundedJson(response) };
        } catch (error) {
          if (timeoutSignal.aborted) throw error;
          return unavailableResult(
            "QwenCloud response could not be parsed.",
            params.optional,
            false,
          );
        }
      },
    });
  } catch (error) {
    if (params.optional) return { success: false, error: "optional" };
    return {
      success: false,
      error: sanitizeVisibleError(error, [...params.secrets, params.secToken]),
      retryable: isRetryableError(error),
    };
  }
}

async function fetchText(params: {
  url: string;
  cookies: readonly QwenCloudCookie[];
  origins: { gatewayOrigin: string; dashboardUrl: string };
  timeoutMs: number;
  secrets: readonly string[];
  fetchFn?: typeof fetch;
  accept: string;
}): Promise<{ ok: true; body: string } | { ok: false; reason: TransportFailureReason }> {
  if (params.timeoutMs <= 0) return { ok: false, reason: "timeout" };
  const url = new URL(params.url);
  if (!isAuthorizedQwenCloudRequestUrl(url)) {
    return { ok: false, reason: "invalid" };
  }
  const cookieHeader = cookieHeaderFromCookies(params.cookies);
  try {
    return await fetchWithTimeout(params.url, {
      fetchFn: params.fetchFn,
      timeoutMs: params.timeoutMs,
      request: {
        method: "GET",
        redirect: "manual",
        headers: {
          Accept: params.accept,
          Origin: params.origins.gatewayOrigin,
          Referer: params.origins.dashboardUrl,
          "User-Agent": QWENCLOUD_USER_AGENT,
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
      },
      consume: async (response) => {
        if (response.status >= 300 && response.status < 400) {
          return { ok: false, reason: "login_required" as const };
        }
        if (response.status === 401 || response.status === 403) {
          return { ok: false, reason: "login_required" as const };
        }
        if (response.status === 429) {
          return { ok: false, reason: "rate_limited" as const };
        }
        if (response.status >= 500) {
          return { ok: false, reason: "unavailable" as const };
        }
        if (!response.ok) {
          return { ok: false, reason: "invalid" as const };
        }
        const body = await readBoundedText(response);
        return { ok: true, body };
      },
    });
  } catch (error) {
    return { ok: false, reason: classifyTransportError(error) };
  }
}

function extractSecToken(raw: string): string | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    const token = findSecToken(parsed);
    if (token) return token;
  } catch {}
  const match =
    /(?:sec_token|secToken)["'\s:=]+([A-Za-z0-9._~+/-]+=*)/u.exec(raw) ??
    /name=["']sec_token["'][^>]*value=["']([^"']+)/iu.exec(raw);
  const value = match?.[1]?.trim();
  return value ? value : null;
}

function findSecToken(value: unknown): string | null {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findSecToken(entry);
      if (found) return found;
    }
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  for (const key of ["sec_token", "secToken"]) {
    const candidate = record[key];
    if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
  }
  for (const entry of Object.values(record)) {
    const found = findSecToken(entry);
    if (found) return found;
  }
  return null;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  return JSON.parse(await readBoundedText(response));
}

async function readBoundedText(response: Response): Promise<string> {
  if (!response.body) throw new Error("empty response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  try {
    const contentLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > QWENCLOUD_RESPONSE_MAX_BYTES) {
      throw new Error("response too large");
    }
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteLength += value.byteLength;
      if (byteLength > QWENCLOUD_RESPONSE_MAX_BYTES) throw new Error("response too large");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

function unauthorizedOriginResult(origins: {
  gatewayOrigin: string;
  dataOrigin: string;
  dashboardUrl: string;
}): QwenCloudQueryResult | null {
  try {
    const urls = [
      new URL(`${origins.gatewayOrigin}/`),
      new URL(`${origins.dataOrigin}/`),
      new URL(origins.dashboardUrl),
    ];
    if (urls.some((url) => !isAuthorizedQwenCloudRequestUrl(url))) {
      return { success: false, error: "QwenCloud host override is not allowed." };
    }
  } catch {
    return { success: false, error: "QwenCloud host override is not allowed." };
  }
  return null;
}

function transportFailureResult(reason: TransportFailureReason): {
  success: false;
  error: string;
  retryable?: boolean;
} {
  switch (reason) {
    case "timeout":
      return { success: false, error: "QwenCloud request timed out.", retryable: true };
    case "rate_limited":
      return { success: false, error: "QwenCloud rate limit reached.", retryable: true };
    case "unavailable":
      return { success: false, error: "QwenCloud API is unavailable.", retryable: true };
    case "invalid":
      return { success: false, error: "QwenCloud response did not match the expected schema." };
    default:
      return {
        success: false,
        error: "QwenCloud login required. Sign in at home.qwencloud.com and retry.",
      };
  }
}

function classifyTransportError(error: unknown): TransportFailureReason {
  const message = error instanceof Error ? error.message : String(error);
  if (/timeout/iu.test(message)) return "timeout";
  if (/unavailable|network/iu.test(message)) return "unavailable";
  return "invalid";
}

function loginResult(optional?: boolean): { success: false; error: string } {
  return {
    success: false,
    error: optional
      ? "unavailable"
      : "QwenCloud login required. Sign in at home.qwencloud.com and retry.",
  };
}

function unavailableResult(
  error: string,
  optional: boolean | undefined,
  retryable: boolean,
): { success: false; error: string; retryable?: boolean } {
  if (optional) return { success: false, error: "optional" };
  return { success: false, error, ...(retryable ? { retryable: true } : {}) };
}

function sanitizeVisibleError(error: unknown, secrets: readonly string[]): string {
  const message = sanitizeQwenCloudError(error, secrets);
  if (/timeout/iu.test(message)) return "QwenCloud request timed out.";
  return sanitizeSingleLineDisplaySnippet(message, 120) || "QwenCloud request failed.";
}

function isRetryableError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /timeout|unavailable|network/iu.test(message);
}

function normalizeHttpsOrigin(raw: string | undefined): string | null {
  const trimmed = raw?.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    if (url.protocol !== "https:") return null;
    return url.origin;
  } catch {
    return null;
  }
}
