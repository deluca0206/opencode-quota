import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  expectAttemptedWithErrorLabel,
  expectAttemptedWithNoErrors,
  expectNotAttempted,
} from "./helpers/provider-assertions.js";

const mocks = vi.hoisted(() => ({
  resolveQwenCloudAuthCached: vi.fn(),
  resolveQwenCloudAuthWithDiagnostics: vi.fn(),
  queryQwenCloudTokenPlan: vi.fn(),
  isQwenCloudTokenPlanActivated: vi.fn(),
  qwenCloudSessionActivation: vi.fn(),
}));

vi.mock("../src/lib/qwencloud-auth.js", () => ({
  DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS: 300_000,
  resolveQwenCloudAuthCached: mocks.resolveQwenCloudAuthCached,
  resolveQwenCloudAuthWithDiagnostics: mocks.resolveQwenCloudAuthWithDiagnostics,
  qwenCloudSessionCookieHeader: vi.fn(),
}));

vi.mock("../src/lib/qwencloud-activation.js", () => ({
  isQwenCloudTokenPlanActivated: mocks.isQwenCloudTokenPlanActivated,
  qwenCloudSessionActivation: mocks.qwenCloudSessionActivation,
}));

vi.mock("../src/lib/qwencloud-api.js", () => ({
  QWENCLOUD_TOTAL_BUDGET_MS: 20_000,
  qwenCloudDashboardUrl: () =>
    "https://home.qwencloud.com/billing/subscription/token-plan-individual",
  queryQwenCloudTokenPlan: mocks.queryQwenCloudTokenPlan,
}));

import { qwenCloudTokenPlanProvider } from "../src/providers/qwencloud-token-plan.js";

const quotaAccounting = {
  resultType: "quota",
  acquisitionMethod: "remote_api",
  ownership: "maintained",
  authority: "provider_reported",
} as const;

function context(config: Record<string, unknown> = {}) {
  return { config };
}

function setAuth(auth: Record<string, unknown>, diagnostics?: Record<string, unknown>): void {
  mocks.resolveQwenCloudAuthCached.mockResolvedValue(auth);
  mocks.resolveQwenCloudAuthWithDiagnostics.mockResolvedValue({
    auth,
    diagnostics: {
      state: auth.state,
      source: auth.source ?? null,
      error: auth.error ?? null,
      note: auth.note ?? null,
      browsers: [],
      ...diagnostics,
    },
  });
}

function configured(): void {
  setAuth({
    state: "configured",
    source: "browser:firefox/default-release",
    session: {
      dashboardCookies: [{ name: "login_qwencloud_ticket", value: "secret" }],
      apiCookies: [{ name: "login_qwencloud_ticket", value: "secret" }],
    },
  });
}

describe("Qwen/Alibaba Token Plan provider", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setAuth({ state: "none", note: "no QwenCloud login ticket in local browsers" });
    mocks.isQwenCloudTokenPlanActivated.mockResolvedValue({ activated: false, source: null });
    mocks.qwenCloudSessionActivation.mockReturnValue(null);
  });

  it("uses the canonical provider id", () => {
    expect(qwenCloudTokenPlanProvider.id).toBe("qwencloud-token-plan");
  });

  it.each([
    ["qwencloud-token-plan/qwen3", true],
    ["alibaba-token-plan/qwen3.8-max", true],
    ["QWENCLOUD-TOKEN-PLAN/x", true],
    ["alibaba-token-plan-cn/qwen", false],
    ["alibaba-coding-plan/qwen", false],
    ["openai/gpt-5", false],
  ])("matchesCurrentModel(%s) -> %s", (model, expected) => {
    expect(qwenCloudTokenPlanProvider.matchesCurrentModel?.(model)).toBe(expected);
  });

  it("does not attempt without a session", async () => {
    setAuth({ state: "none" });
    expectNotAttempted(await qwenCloudTokenPlanProvider.fetch(context()));
    expect(mocks.queryQwenCloudTokenPlan).not.toHaveBeenCalled();
  });

  it("stays silent for users without any Qwen/Alibaba Token Plan credential or session", async () => {
    setAuth(
      { state: "none", note: "no QwenCloud login ticket in local browsers" },
      { browsers: ["google-chrome/Default", "firefox/default-release"] },
    );
    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expectNotAttempted(result);
    expect(result.errors).toEqual([]);
    expect(mocks.queryQwenCloudTokenPlan).not.toHaveBeenCalled();
  });

  it("is unavailable when neither credential nor session matches", async () => {
    setAuth({ state: "none" });
    await expect(qwenCloudTokenPlanProvider.isAvailable(context())).resolves.toBe(false);
  });

  it("becomes available once a Token Plan credential is registered", async () => {
    setAuth({ state: "none" });
    mocks.isQwenCloudTokenPlanActivated.mockResolvedValue({
      activated: true,
      source: "auth.json",
    });
    await expect(qwenCloudTokenPlanProvider.isAvailable(context())).resolves.toBe(true);
  });

  it("shows a sign-in hint with the console link when activated but not signed in", async () => {
    setAuth({ state: "none", note: "no QwenCloud login ticket in local browsers" });
    mocks.isQwenCloudTokenPlanActivated.mockResolvedValue({
      activated: true,
      source: "auth.json",
    });
    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expect(result.attempted).toBe(true);
    expect(result.entries).toEqual([]);
    expect(result.errors).toEqual([
      {
        label: "Qwen/Alibaba Token Plan",
        message:
          "Access https://home.qwencloud.com/billing/subscription/token-plan-individual to show your quota.",
      },
    ]);
    expect(mocks.queryQwenCloudTokenPlan).not.toHaveBeenCalled();
    expect(result.statusDetails?.map((detail) => detail.key)).toContain("activation");
  });

  it("shows the same hint when only the current session uses the provider", async () => {
    setAuth({ state: "none" });
    mocks.qwenCloudSessionActivation.mockReturnValue({ activated: true, source: "session" });
    const result = await qwenCloudTokenPlanProvider.fetch(
      context({ currentProviderID: "alibaba-token-plan" }),
    );
    expect(result.attempted).toBe(true);
    expect(result.errors[0]?.message).toMatch(/home\.qwencloud\.com/u);
    expect(mocks.isQwenCloudTokenPlanActivated).not.toHaveBeenCalled();
  });

  it("bounds one refresh with a total request budget", async () => {
    configured();
    mocks.queryQwenCloudTokenPlan.mockResolvedValue({
      success: true,
      secTokenSource: "cookie",
      snapshot: { planName: "Pro", weekly: { usedFraction: 0, percentRemaining: 100 } },
    });
    await qwenCloudTokenPlanProvider.fetch(context());
    expect(mocks.queryQwenCloudTokenPlan).toHaveBeenCalledWith(
      expect.objectContaining({ totalBudgetMs: 20_000 }),
    );
  });

  it("projects invalid auth as a safe attempted error", async () => {
    setAuth({
      state: "invalid",
      source: "env:QWEN_CLOUD_COOKIE",
      error: "QwenCloud cookie header is missing a login ticket",
    });
    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expectAttemptedWithErrorLabel(result, "Qwen/Alibaba Token Plan");
    expect(JSON.stringify(result)).not.toContain("login_qwencloud_ticket");
  });

  it("maps Pro windows with derived credit facts", async () => {
    configured();
    mocks.queryQwenCloudTokenPlan.mockResolvedValue({
      success: true,
      secTokenSource: "cookie",
      snapshot: {
        planCode: "pro",
        planName: "Pro",
        fiveHour: {
          usedFraction: 0.21,
          percentRemaining: 79,
          limit: 12000,
          used: 2520,
          remaining: 9480,
          resetTimeIso: "2026-07-21T12:07:00.000Z",
        },
        weekly: {
          usedFraction: 0.37,
          percentRemaining: 63,
          limit: 40000,
          used: 14800,
          remaining: 25200,
          resetTimeIso: "2026-07-26T09:15:00.000Z",
        },
      },
    });

    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expectAttemptedWithNoErrors(result);
    expect(result.entries).toHaveLength(2);
    expect(result.entries[0]).toMatchObject({
      accounting: quotaAccounting,
      name: "Qwen/Alibaba Token Plan Pro 5h",
      group: "Qwen/Alibaba Token Plan Pro",
      label: "5h:",
      percentRemaining: 79,
      semantic: { metric: { kind: "window", window: "five_hour" }, prominence: "primary" },
      basis: {
        used: {
          quantity: { decimal: "2520", unit: { kind: "count", unit: "credit" } },
          authority: "locally_derived",
        },
        limit: {
          quantity: { decimal: "12000", unit: { kind: "count", unit: "credit" } },
          authority: "provider_reported",
        },
        remaining: {
          quantity: { decimal: "9480", unit: { kind: "count", unit: "credit" } },
          authority: "locally_derived",
        },
      },
    });
    expect(JSON.stringify(result)).not.toContain("secret");
  });

  it("keeps weekly-only snapshots without inventing a five-hour window", async () => {
    configured();
    mocks.queryQwenCloudTokenPlan.mockResolvedValue({
      success: true,
      secTokenSource: "user-info",
      snapshot: {
        planName: "Standard",
        weekly: { usedFraction: 0, percentRemaining: 100, limit: 10000, used: 0, remaining: 10000 },
      },
    });
    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]?.label).toBe("Weekly:");
  });

  it("keeps usage rows and reports an inactive subscription", async () => {
    configured();
    mocks.queryQwenCloudTokenPlan.mockResolvedValue({
      success: true,
      secTokenSource: "cookie",
      snapshot: {
        planName: "Personal",
        subscriptionActive: false,
        subscriptionStatus: "EXPIRED",
        fiveHour: { usedFraction: 0.21, percentRemaining: 79 },
        weekly: { usedFraction: 0.37, percentRemaining: 63 },
      },
    });
    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expect(result.attempted).toBe(true);
    expect(result.entries).toHaveLength(2);
    expect(result.errors).toEqual([
      { label: "Qwen/Alibaba Token Plan", message: "QwenCloud subscription is not active." },
    ]);
  });

  it("surfaces expired sessions as attempted errors", async () => {
    configured();
    mocks.queryQwenCloudTokenPlan.mockResolvedValue({
      success: false,
      error: "QwenCloud login required. Sign in at home.qwencloud.com and retry.",
    });
    const result = await qwenCloudTokenPlanProvider.fetch(context());
    expectAttemptedWithErrorLabel(result, "Qwen/Alibaba Token Plan");
    expect(result.errors[0]?.message).toMatch(/login required/u);
  });
});
