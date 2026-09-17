import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  clearQwenCloudSecTokenCacheForTests,
  QWENCLOUD_BUDGET_EXHAUSTED_MESSAGE,
  queryQwenCloudTokenPlan,
} from "../src/lib/qwencloud-api.js";
import type { QwenCloudSession } from "../src/lib/qwencloud-auth.js";

const TICKET = "ticket-secret-value";
const SEC_TOKEN = "sec-token-secret";

const session: QwenCloudSession = {
  dashboardCookies: [
    { name: "login_qwencloud_ticket", value: TICKET, host: ".qwencloud.com" },
    { name: "sec_token", value: SEC_TOKEN, host: "home.qwencloud.com" },
  ],
  apiCookies: [
    { name: "login_qwencloud_ticket", value: TICKET, host: ".qwencloud.com" },
    { name: "sec_token", value: SEC_TOKEN, host: "cs-data.qwencloud.com" },
  ],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function envelope(data: unknown) {
  return {
    code: "200",
    successResponse: true,
    data: { DataV2: { success: true, data: { success: true, data } } },
  };
}

function apiFromUrl(url: string): string {
  return new URL(url).searchParams.get("api") ?? "";
}

/** A session without a `sec_token` cookie, forcing CSRF discovery. */
const discoverySession: QwenCloudSession = {
  dashboardCookies: [{ name: "login_qwencloud_ticket", value: TICKET, host: ".qwencloud.com" }],
  apiCookies: [{ name: "login_qwencloud_ticket", value: TICKET, host: ".qwencloud.com" }],
};

function isSecTokenDiscoveryUrl(url: string): boolean {
  return url.includes("/tool/user/info.json") || url.includes("token-plan-individual");
}

function usageEnvelope() {
  return jsonResponse(
    envelope({
      per5HourPercentage: 0.21,
      per1WeekPercentage: 0.37,
    }),
  );
}

function routeApi(url: string): Response {
  const api = apiFromUrl(url);
  if (api.includes("usage")) return usageEnvelope();
  if (api.includes("subscription"))
    return jsonResponse(envelope({ specCode: "pro", status: "VALID" }));
  if (api.includes("quota-config")) {
    return jsonResponse(envelope({ pro: { five_hour: 12000, weekly: 40000 } }));
  }
  return jsonResponse({ ok: false }, 404);
}

function notLoggedInResponse(): Response {
  return jsonResponse({
    code: "200",
    successResponse: true,
    data: { success: false, errorCode: "BailianGateway.Login.NotLogined" },
  });
}

describe("QwenCloud API client", () => {
  beforeEach(() => {
    clearQwenCloudSecTokenCacheForTests();
  });

  it("fetches usage, subscription, and quota-config", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      const api = apiFromUrl(url);
      if (api.includes("usage")) {
        return jsonResponse(
          envelope({
            per5HourPercentage: 0.21,
            per5HourResetTime: 1_784_813_220_000,
            per1WeekPercentage: 0.37,
            per1WeekResetTime: 1_785_234_900_000,
          }),
        );
      }
      if (api.includes("subscription")) {
        return jsonResponse(envelope({ specCode: "pro", status: "VALID" }));
      }
      if (api.includes("quota-config")) {
        return jsonResponse(
          envelope({
            lite: { five_hour: 700, weekly: 2500 },
            standard: { five_hour: 3000, weekly: 10000 },
            pro: { five_hour: 12000, weekly: 40000 },
          }),
        );
      }
      return jsonResponse({ ok: false }, 404);
    });

    const result = await queryQwenCloudTokenPlan({ session, fetchFn, nowMs: Date.now() });
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.snapshot.planName).toBe("Pro");
    expect(result.snapshot.fiveHour?.limit).toBe(12000);
    expect(result.secTokenSource).toBe("cookie");
    expect(fetchFn).toHaveBeenCalledTimes(3);
    const usageCall = fetchFn.mock.calls[0] as [string, RequestInit];
    const body = String(usageCall[1]?.body);
    expect(body).toContain("sec_token=");
    expect(JSON.stringify(result)).not.toContain(TICKET);
    expect(JSON.stringify(result)).not.toContain(SEC_TOKEN);
  });

  it("maps login JSON, HTTP 401, timeout, and 503", async () => {
    const login = await queryQwenCloudTokenPlan({
      session,
      fetchFn: async () =>
        jsonResponse({
          code: "200",
          successResponse: true,
          data: { success: false, errorCode: "BailianGateway.Login.NotLogined", errorMsg: TICKET },
        }),
    });
    expect(login).toMatchObject({ success: false });
    expect(JSON.stringify(login)).not.toContain(TICKET);
    expect(login.success === false && login.error).toMatch(/login required/u);

    const unauthorized = await queryQwenCloudTokenPlan({
      session,
      fetchFn: async () => jsonResponse({ error: TICKET }, 401),
    });
    expect(unauthorized.success).toBe(false);
    expect(JSON.stringify(unauthorized)).not.toContain(TICKET);

    const unavailable = await queryQwenCloudTokenPlan({
      session,
      fetchFn: async () => jsonResponse({ error: "down" }, 503),
    });
    expect(unavailable).toEqual({
      success: false,
      error: "QwenCloud API is unavailable.",
      retryable: true,
    });

    const timeout = await queryQwenCloudTokenPlan({
      session,
      requestTimeoutMs: 20,
      fetchFn: async () => {
        await new Promise((resolve) => setTimeout(resolve, 50));
        return jsonResponse({});
      },
    });
    expect(timeout.success).toBe(false);
    if (timeout.success) return;
    expect(timeout.error).toBe("QwenCloud request timed out.");
    expect(timeout.retryable).toBe(true);
  });

  it("rejects non-https host overrides", async () => {
    const fetchFn = vi.fn();
    const result = await queryQwenCloudTokenPlan({
      session,
      env: { QWEN_CLOUD_HOST: "http://evil.example" } as NodeJS.ProcessEnv,
      fetchFn,
    });
    expect(fetchFn).toHaveBeenCalled();
    const firstUrl = String(fetchFn.mock.calls[0]?.[0]);
    expect(firstUrl.startsWith("https://")).toBe(true);
    expect(firstUrl).not.toContain("evil.example");
    expect(result.success === true || result.success === false).toBe(true);
  });

  it("does not send cookies to an unauthorized HTTPS override", async () => {
    const fetchFn = vi.fn();
    const result = await queryQwenCloudTokenPlan({
      session,
      env: { QWEN_CLOUD_HOST: "https://evil.example" } as NodeJS.ProcessEnv,
      fetchFn,
    });
    expect(fetchFn).not.toHaveBeenCalled();
    expect(result).toEqual({
      success: false,
      error: "QwenCloud host override is not allowed.",
    });
    expect(JSON.stringify(result)).not.toContain(TICKET);
  });

  it("does not fall back to cookies that failed host filtering", async () => {
    const fetchFn = vi.fn();
    const result = await queryQwenCloudTokenPlan({
      session: {
        dashboardCookies: [{ name: "login_qwencloud_ticket", value: TICKET, host: "example.com" }],
        apiCookies: [{ name: "login_qwencloud_ticket", value: TICKET, host: "example.com" }],
      },
      fetchFn,
    });
    expect(fetchFn).not.toHaveBeenCalled();
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error).toMatch(/login required/u);
  });

  it("does not treat a sec_token bootstrap timeout as an expired session", async () => {
    const result = await queryQwenCloudTokenPlan({
      session: {
        dashboardCookies: [
          { name: "login_qwencloud_ticket", value: TICKET, host: ".qwencloud.com" },
        ],
        apiCookies: [{ name: "login_qwencloud_ticket", value: TICKET, host: ".qwencloud.com" }],
      },
      requestTimeoutMs: 20,
      fetchFn: async () => {
        await new Promise((resolve) => setTimeout(resolve, 50));
        return jsonResponse({});
      },
    });
    expect(result).toEqual({
      success: false,
      error: "QwenCloud request timed out.",
      retryable: true,
    });
  });

  it("issues usage, subscription, and quota-config concurrently", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const fetchFn = vi.fn(async (url: string) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 20));
      inFlight -= 1;
      return routeApi(url);
    });

    const result = await queryQwenCloudTokenPlan({ session, fetchFn });
    expect(result.success).toBe(true);
    expect(maxInFlight).toBe(3);
  });

  it("reuses a discovered sec_token on the next refresh", async () => {
    const fetchFn = vi.fn(async (url: string) => {
      if (isSecTokenDiscoveryUrl(url)) return jsonResponse({ secToken: "discovered-token" });
      return routeApi(url);
    });

    const first = await queryQwenCloudTokenPlan({ session: discoverySession, fetchFn });
    expect(first.success).toBe(true);
    if (!first.success) return;
    expect(first.secTokenSource).toMatch(/^(dashboard|user-info)$/u);
    expect(
      fetchFn.mock.calls.filter(([url]) => isSecTokenDiscoveryUrl(String(url))).length,
    ).toBeGreaterThan(0);

    fetchFn.mockClear();
    const second = await queryQwenCloudTokenPlan({ session: discoverySession, fetchFn });
    expect(second.success).toBe(true);
    if (!second.success) return;
    expect(second.secTokenSource).toMatch(/:cached$/u);
    expect(fetchFn.mock.calls.filter(([url]) => isSecTokenDiscoveryUrl(String(url)))).toHaveLength(
      0,
    );
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });

  it("retries once with a fresh sec_token when the cached one was rotated", async () => {
    let currentToken = "token-v0";
    const tokensSeen: string[] = [];
    const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
      if (isSecTokenDiscoveryUrl(url)) return jsonResponse({ secToken: currentToken });
      const usedToken = new URLSearchParams(String(init?.body ?? "")).get("sec_token");
      tokensSeen.push(usedToken ?? "");
      if (usedToken !== currentToken) return notLoggedInResponse();
      return routeApi(url);
    });

    const first = await queryQwenCloudTokenPlan({ session: discoverySession, fetchFn });
    expect(first.success).toBe(true);

    currentToken = "token-v1";
    const second = await queryQwenCloudTokenPlan({ session: discoverySession, fetchFn });
    expect(second.success).toBe(true);
    if (!second.success) return;
    expect(second.secTokenSource).not.toMatch(/:cached$/u);
    expect(tokensSeen).toContain("token-v1");
  });

  it("reports an exhausted total budget as retryable", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({}));
    const result = await queryQwenCloudTokenPlan({
      session,
      totalBudgetMs: 0,
      fetchFn,
    });
    expect(result).toEqual({
      success: false,
      error: QWENCLOUD_BUDGET_EXHAUSTED_MESSAGE,
      retryable: true,
    });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("races the console HTML and user-info for the CSRF token", async () => {
    const started: string[] = [];
    const fetchFn = vi.fn(async (url: string) => {
      if (isSecTokenDiscoveryUrl(url)) {
        started.push(url.includes("user/info.json") ? "user-info" : "dashboard");
        // The slower source must not delay the winner.
        if (url.includes("user/info.json")) {
          await new Promise((resolve) => setTimeout(resolve, 60));
        }
        return jsonResponse({ secToken: "discovered-token" });
      }
      return routeApi(url);
    });

    const result = await queryQwenCloudTokenPlan({ session: discoverySession, fetchFn });
    expect(result.success).toBe(true);
    expect(started).toEqual(["dashboard", "user-info"]);
    if (!result.success) return;
    expect(result.secTokenSource).toBe("dashboard");
  });
});
