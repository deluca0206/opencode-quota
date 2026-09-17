export type QwenCloudPlanCode = "lite" | "standard" | "pro" | "max" | string;

export interface QwenCloudQuotaWindow {
  usedFraction: number;
  percentRemaining: number;
  resetTimeIso?: string;
  limit?: number;
  used?: number;
  remaining?: number;
}

export interface QwenCloudUsageSnapshot {
  planCode?: QwenCloudPlanCode;
  planName: string;
  subscriptionActive?: boolean;
  subscriptionStatus?: string;
  fiveHour?: QwenCloudQuotaWindow;
  weekly?: QwenCloudQuotaWindow;
  partial?: {
    subscription?: string;
    quotaConfig?: string;
  };
}

export type QwenCloudParseFailureReason =
  | "login_required"
  | "invalid_credentials"
  | "unavailable"
  | "invalid"
  | "no_data";

export class QwenCloudParseError extends Error {
  readonly reason: QwenCloudParseFailureReason;

  constructor(reason: QwenCloudParseFailureReason, message: string) {
    super(message);
    this.name = "QwenCloudParseError";
    this.reason = reason;
  }
}

const MAX_EXPAND_DEPTH = 8;
const MAX_RESET_TIME_MS = 4_102_444_800_000;
const LOGIN_ERROR_RE =
  /notlogined|not[_-]?login|loginrequired|invalidsession|unauthorized|forbidden|tokenexpired|signin/iu;

export function expandEmbeddedJson(value: unknown, depth = 0): unknown {
  if (depth > MAX_EXPAND_DEPTH) return value;
  if (Array.isArray(value)) {
    return value.map((entry) => expandEmbeddedJson(entry, depth + 1));
  }
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = expandEmbeddedJson(entry, depth + 1);
    }
    return out;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        return expandEmbeddedJson(JSON.parse(trimmed), depth + 1);
      } catch {
        return value;
      }
    }
  }
  return value;
}

export function parseQwenCloudUsageSnapshot(params: {
  usage: unknown;
  subscription?: unknown;
  quotaConfig?: unknown;
}): QwenCloudUsageSnapshot {
  const usageTree = expandEmbeddedJson(params.usage);
  assertNotErrorPayload(usageTree);
  if (looksLikeLoginHtml(params.usage)) {
    throw new QwenCloudParseError(
      "login_required",
      "QwenCloud login required. Sign in at home.qwencloud.com and retry.",
    );
  }

  const usage = findObjectContaining(usageTree, ["per5HourPercentage", "per1WeekPercentage"]);
  if (!usage) {
    throw new QwenCloudParseError("no_data", "QwenCloud usage returned no quota windows.");
  }

  const fiveHour = parseWindow(usage, "per5Hour");
  const weekly = parseWindow(usage, "per1Week");
  if (!fiveHour && !weekly) {
    throw new QwenCloudParseError("no_data", "QwenCloud usage returned no quota windows.");
  }

  const subscription = params.subscription ? parseSubscription(params.subscription) : undefined;
  const planCode = subscription?.active ? subscription.planCode : undefined;
  const limits = params.quotaConfig ? parseQuotaLimits(params.quotaConfig, planCode) : undefined;
  const partial: QwenCloudUsageSnapshot["partial"] = {};
  if (params.subscription !== undefined && subscription === undefined) {
    partial.subscription = "unavailable";
  }
  if (params.quotaConfig !== undefined && !limits && planCode) {
    partial.quotaConfig = "unavailable";
  }

  return {
    planCode,
    planName: displayPlanName(planCode),
    subscriptionActive: subscription?.active,
    subscriptionStatus: subscription?.status,
    ...(Object.keys(partial).length > 0 ? { partial } : {}),
    ...(fiveHour ? { fiveHour: withLimits(fiveHour, limits?.fiveHour) } : {}),
    ...(weekly ? { weekly: withLimits(weekly, limits?.weekly) } : {}),
  };
}

export function parseQuotaConfigLimits(
  raw: unknown,
): Record<string, { fiveHour?: number; weekly?: number }> {
  const expanded = expandEmbeddedJson(raw);
  const found: Record<string, { fiveHour?: number; weekly?: number }> = {};
  walk(expanded, (record) => {
    for (const [key, value] of Object.entries(record)) {
      if (!isRecord(value)) continue;
      const fiveHour = finiteNumber(value.five_hour ?? value.fiveHour);
      const weekly = finiteNumber(value.weekly);
      if (fiveHour === undefined && weekly === undefined) continue;
      if (fiveHour !== undefined && fiveHour <= 0) continue;
      if (weekly !== undefined && weekly <= 0) continue;
      found[key.toLowerCase()] = {
        ...(fiveHour !== undefined ? { fiveHour } : {}),
        ...(weekly !== undefined ? { weekly } : {}),
      };
    }
  });
  return found;
}

function parseWindow(
  usage: Record<string, unknown>,
  prefix: "per5Hour" | "per1Week",
): QwenCloudQuotaWindow | undefined {
  const usedFraction = parseUsedFraction(usage[`${prefix}Percentage`]);
  if (usedFraction === undefined) return undefined;
  const resetTimeIso = parseResetTimeIso(usage[`${prefix}ResetTime`]);
  return {
    usedFraction,
    percentRemaining: 100 - usedFraction * 100,
    ...(resetTimeIso ? { resetTimeIso } : {}),
  };
}

function withLimits(window: QwenCloudQuotaWindow, limit: number | undefined): QwenCloudQuotaWindow {
  if (limit === undefined || limit <= 0) return window;
  const used = limit * window.usedFraction;
  return {
    ...window,
    limit,
    used,
    remaining: limit - used,
  };
}

function parseSubscription(
  raw: unknown,
): { planCode?: string; status?: string; active: boolean } | undefined {
  const expanded = expandEmbeddedJson(raw);
  try {
    assertNotErrorPayload(expanded);
  } catch {
    return undefined;
  }
  const plan = findObjectContaining(expanded, [
    "specCode",
    "spec_code",
    "planName",
    "plan_name",
    "status",
  ]);
  if (!plan) return undefined;
  let planCode: string | undefined;
  for (const key of ["specCode", "spec_code", "planName", "plan_name"]) {
    const value = typeof plan[key] === "string" ? plan[key].trim().toLowerCase() : "";
    if (value) {
      planCode = value;
      break;
    }
  }
  const status = typeof plan.status === "string" ? plan.status.trim() : undefined;
  const active = !status || status.toUpperCase() === "VALID";
  if (!planCode && !status) return undefined;
  return { planCode, status, active };
}

function parseQuotaLimits(
  raw: unknown,
  planCode: string | undefined,
): { fiveHour?: number; weekly?: number } | undefined {
  if (!planCode) return undefined;
  const all = parseQuotaConfigLimits(raw);
  return all[planCode];
}

function displayPlanName(planCode: string | undefined): string {
  switch (planCode) {
    case "lite":
      return "Lite";
    case "standard":
      return "Standard";
    case "pro":
      return "Pro";
    case "max":
      return "Max";
    default:
      return planCode ? planCode : "Personal";
  }
}

function parseUsedFraction(value: unknown): number | undefined {
  const number = finiteNumber(value);
  if (number === undefined || number < 0 || number > 1) return undefined;
  return number;
}

function parseResetTimeIso(value: unknown): string | undefined {
  const ms = finiteNumber(value);
  if (ms === undefined || ms <= 0 || ms > MAX_RESET_TIME_MS) return undefined;
  return new Date(ms).toISOString();
}

function assertNotErrorPayload(value: unknown): void {
  walk(value, (record) => {
    const errorCode = typeof record.errorCode === "string" ? record.errorCode : "";
    const code = typeof record.code === "string" ? record.code : "";
    const success = record.success;
    if (LOGIN_ERROR_RE.test(errorCode) || LOGIN_ERROR_RE.test(code)) {
      throw new QwenCloudParseError(
        "login_required",
        "QwenCloud login required. Sign in at home.qwencloud.com and retry.",
      );
    }
    if (success === false || record.successResponse === false) {
      throw new QwenCloudParseError("unavailable", "QwenCloud usage is temporarily unavailable.");
    }
  });
}

function looksLikeLoginHtml(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const lowered = value.toLowerCase();
  return (
    lowered.includes("<html") &&
    (lowered.includes("login.qwencloud.com") ||
      lowered.includes("passport.alibabacloud.com") ||
      lowered.includes("signin.aliyun.com") ||
      (lowered.includes("login") && lowered.includes("password")))
  );
}

function findObjectContaining(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> | undefined {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findObjectContaining(entry, keys);
      if (found) return found;
    }
    return undefined;
  }
  if (!isRecord(value)) return undefined;
  if (keys.some((key) => key in value)) return value;
  for (const entry of Object.values(value)) {
    const found = findObjectContaining(entry, keys);
    if (found) return found;
  }
  return undefined;
}

function walk(value: unknown, visit: (record: Record<string, unknown>) => void): void {
  if (Array.isArray(value)) {
    for (const entry of value) walk(entry, visit);
    return;
  }
  if (!isRecord(value)) return;
  visit(value);
  for (const entry of Object.values(value)) walk(entry, visit);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function finiteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}
