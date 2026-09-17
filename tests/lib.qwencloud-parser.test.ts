import { describe, expect, it } from "vitest";

import {
  parseQuotaConfigLimits,
  parseQwenCloudUsageSnapshot,
  QwenCloudParseError,
} from "../src/lib/qwencloud-parser.js";

const RESET_5H = 1_784_813_220_000;
const RESET_WEEK = 1_785_234_900_000;

function envelope(data: unknown) {
  return {
    code: "200",
    successResponse: true,
    data: {
      DataV2: {
        success: true,
        httpStatus: 200,
        data: { success: true, data },
      },
    },
  };
}

const quotaConfig = envelope({
  lite: { five_hour: 700, weekly: 2500 },
  standard: { five_hour: 3000, weekly: 10000 },
  pro: { five_hour: 12000, weekly: 40000 },
});

describe("QwenCloud parser", () => {
  it.each([
    ["lite", 700, 2500],
    ["standard", 3000, 10000],
    ["pro", 12000, 40000],
  ])("maps %s limits and partial usage", (plan, fiveHour, weekly) => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({
        per5HourPercentage: 0.21,
        per5HourResetTime: RESET_5H,
        per1WeekPercentage: 0.37,
        per1WeekResetTime: RESET_WEEK,
      }),
      subscription: envelope({ specCode: plan, status: "VALID" }),
      quotaConfig,
    });
    expect(snapshot.planName).toBe(plan === "lite" ? "Lite" : plan === "pro" ? "Pro" : "Standard");
    expect(snapshot.fiveHour?.limit).toBe(fiveHour);
    expect(snapshot.fiveHour?.used).toBeCloseTo(fiveHour * 0.21);
    expect(snapshot.fiveHour?.remaining).toBeCloseTo(fiveHour - fiveHour * 0.21);
    expect(snapshot.fiveHour?.percentRemaining).toBeCloseTo(79);
    expect(snapshot.weekly?.limit).toBe(weekly);
    expect(snapshot.weekly?.percentRemaining).toBeCloseTo(63);
    expect(snapshot.fiveHour?.resetTimeIso).toBe(new Date(RESET_5H).toISOString());
  });

  it("keeps unused quota at 100% remaining", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({
        per5HourPercentage: 0,
        per1WeekPercentage: 0,
      }),
      subscription: envelope({ specCode: "pro" }),
      quotaConfig,
    });
    expect(snapshot.fiveHour?.percentRemaining).toBe(100);
    expect(snapshot.fiveHour?.used).toBe(0);
    expect(snapshot.fiveHour?.remaining).toBe(12000);
  });

  it("keeps exhausted quota at 0% remaining", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({
        per5HourPercentage: 1,
        per1WeekPercentage: 1,
      }),
      subscription: envelope({ specCode: "lite" }),
      quotaConfig,
    });
    expect(snapshot.fiveHour?.percentRemaining).toBe(0);
    expect(snapshot.fiveHour?.remaining).toBe(0);
    expect(snapshot.weekly?.used).toBe(2500);
  });

  it("omits the five-hour window when the API does not report it", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({
        per1WeekPercentage: 0.1,
        per1WeekResetTime: RESET_WEEK,
      }),
      subscription: envelope({ specCode: "standard" }),
      quotaConfig,
    });
    expect(snapshot.fiveHour).toBeUndefined();
    expect(snapshot.weekly?.limit).toBe(10000);
  });

  it("shows percentages without inventing totals when quota-config is absent", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({
        per5HourPercentage: 0.5,
        per1WeekPercentage: 0.25,
      }),
      subscription: envelope({ specCode: "pro" }),
    });
    expect(snapshot.planName).toBe("Pro");
    expect(snapshot.fiveHour?.limit).toBeUndefined();
    expect(snapshot.fiveHour?.percentRemaining).toBe(50);
  });

  it("keeps an unknown plan code and still uses dynamic limits", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({ per5HourPercentage: 0.1, per1WeekPercentage: 0.2 }),
      subscription: envelope({ specCode: "ultra" }),
      quotaConfig: envelope({ ultra: { five_hour: 99, weekly: 123 } }),
    });
    expect(snapshot.planName).toBe("ultra");
    expect(snapshot.fiveHour?.limit).toBe(99);
    expect(snapshot.weekly?.limit).toBe(123);
  });

  it("reads nested string JSON envelopes", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: {
        data: JSON.stringify({
          per5HourPercentage: "0.5",
          per1WeekPercentage: "0.25",
          per5HourResetTime: String(RESET_5H),
        }),
      },
    });
    expect(snapshot.fiveHour?.percentRemaining).toBe(50);
    expect(snapshot.fiveHour?.resetTimeIso).toBe(new Date(RESET_5H).toISOString());
  });

  it("treats inner login errors as expired sessions even when HTTP JSON succeeded", () => {
    expect(() =>
      parseQwenCloudUsageSnapshot({
        usage: {
          code: "200",
          successResponse: true,
          data: {
            success: false,
            httpStatus: 200,
            errorCode: "BailianGateway.Login.NotLogined",
            errorMsg: "secret-session-detail",
          },
        },
      }),
    ).toThrow(QwenCloudParseError);
    try {
      parseQwenCloudUsageSnapshot({
        usage: {
          data: {
            success: false,
            errorCode: "BailianGateway.Login.NotLogined",
            errorMsg: "secret",
          },
        },
      });
    } catch (error) {
      expect(error).toBeInstanceOf(QwenCloudParseError);
      expect((error as QwenCloudParseError).reason).toBe("login_required");
      expect((error as Error).message).not.toContain("secret");
    }
  });

  it("rejects used fractions outside 0..1 instead of rescaling them", () => {
    expect(() =>
      parseQwenCloudUsageSnapshot({
        usage: envelope({
          per5HourPercentage: 1.01,
          per1WeekPercentage: 21,
        }),
      }),
    ).toThrow(/no quota windows/u);
  });

  it("does not treat an inactive subscription as the current plan", () => {
    const snapshot = parseQwenCloudUsageSnapshot({
      usage: envelope({
        per5HourPercentage: 0.21,
        per1WeekPercentage: 0.37,
      }),
      subscription: envelope({ specCode: "pro", status: "EXPIRED" }),
      quotaConfig,
    });
    expect(snapshot.planName).toBe("Personal");
    expect(snapshot.subscriptionActive).toBe(false);
    expect(snapshot.fiveHour?.limit).toBeUndefined();
  });

  it("rejects invalid and empty usage payloads", () => {
    expect(() => parseQwenCloudUsageSnapshot({ usage: "not-json" })).toThrow(/no quota windows/u);
    expect(() => parseQwenCloudUsageSnapshot({ usage: { data: {} } })).toThrow(/no quota windows/u);
    expect(() =>
      parseQwenCloudUsageSnapshot({
        usage: "<html><body>login password sign in</body></html>",
      }),
    ).toThrow(/login required/u);
  });

  it("parses public quota-config limits without a session", () => {
    expect(parseQuotaConfigLimits(quotaConfig)).toEqual({
      lite: { fiveHour: 700, weekly: 2500 },
      standard: { fiveHour: 3000, weekly: 10000 },
      pro: { fiveHour: 12000, weekly: 40000 },
    });
  });
});
