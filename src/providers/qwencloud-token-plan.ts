import type {
  AccountingMetadata,
  QuotaProvider,
  QuotaProviderContext,
  QuotaProviderResult,
  QuotaToastEntry,
} from "../lib/entries.js";
import { getQuotaProviderRuntimeIds } from "../lib/provider-metadata.js";
import {
  isQwenCloudTokenPlanActivated,
  type QwenCloudActivation,
  qwenCloudSessionActivation,
} from "../lib/qwencloud-activation.js";
import {
  QWENCLOUD_TOTAL_BUDGET_MS,
  queryQwenCloudTokenPlan,
  qwenCloudDashboardUrl,
} from "../lib/qwencloud-api.js";
import {
  DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS,
  resolveQwenCloudAuthCached,
  resolveQwenCloudAuthWithDiagnostics,
} from "../lib/qwencloud-auth.js";
import type { QwenCloudQuotaWindow, QwenCloudUsageSnapshot } from "../lib/qwencloud-parser.js";
import { accountingDecimalFromNumber } from "./accounting-decimal.js";
import {
  attemptedErrorResult,
  attemptedResult,
  notAttemptedResult,
  statusDetailsFromRecord,
  withStatusDetails,
} from "./result-helpers.js";

const QWENCLOUD_LABEL = "Qwen/Alibaba Token Plan";
const QWENCLOUD_RUNTIME_IDS = new Set(getQuotaProviderRuntimeIds("qwencloud-token-plan"));
const QWENCLOUD_SETUP_HINT = `Access ${qwenCloudDashboardUrl()} to show your quota.`;

const QUOTA_ACCOUNTING: AccountingMetadata = {
  resultType: "quota",
  acquisitionMethod: "remote_api",
  ownership: "maintained",
  authority: "provider_reported",
};

const CREDIT_UNIT = { kind: "count", unit: "credit" } as const;

export const qwenCloudTokenPlanProvider: QuotaProvider = {
  id: "qwencloud-token-plan",

  async isAvailable(ctx: QuotaProviderContext): Promise<boolean> {
    const auth = await resolveQwenCloudAuthCached({
      maxAgeMs: DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS,
    });
    if (auth.state === "configured" || auth.state === "invalid") return true;
    return (await resolveQwenCloudActivation(ctx)).activated;
  },

  matchesCurrentModel(model: string, context): boolean {
    if (context?.currentProviderID && QWENCLOUD_RUNTIME_IDS.has(context.currentProviderID)) {
      return true;
    }
    const [provider] = model.trim().toLowerCase().split("/", 2);
    return QWENCLOUD_RUNTIME_IDS.has(provider);
  },

  async fetch(ctx: QuotaProviderContext): Promise<QuotaProviderResult> {
    const { auth, diagnostics } = await resolveQwenCloudAuthWithDiagnostics({
      maxAgeMs: DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS,
    });
    const activation = await resolveQwenCloudActivation(ctx);
    const statusDetails = statusDetailsFromRecord({
      auth_state: diagnostics.state,
      auth_source: diagnostics.source ?? "(none)",
      activation: activation.source ?? "(none)",
      browsers_inspected:
        diagnostics.browsers.length > 0 ? diagnostics.browsers.join(", ") : "(none)",
      auth_note: diagnostics.note ?? undefined,
      auth_error: diagnostics.error ?? undefined,
    });

    if (auth.state === "none") {
      if (!activation.activated) {
        return withStatusDetails(notAttemptedResult(), statusDetails);
      }
      return withStatusDetails(
        attemptedErrorResult(QWENCLOUD_LABEL, QWENCLOUD_SETUP_HINT),
        statusDetails,
      );
    }
    if (auth.state === "invalid") {
      return withStatusDetails(attemptedErrorResult(QWENCLOUD_LABEL, auth.error), statusDetails);
    }

    const result = await queryQwenCloudTokenPlan({
      session: auth.session,
      requestTimeoutMs: ctx.config?.requestTimeoutMsConfigured
        ? ctx.config.requestTimeoutMs
        : undefined,
      totalBudgetMs: QWENCLOUD_TOTAL_BUDGET_MS,
    });
    if (!result.success) {
      return withStatusDetails(
        attemptedErrorResult(QWENCLOUD_LABEL, result.error, {
          retryable: result.retryable === true,
        }),
        [
          ...statusDetails,
          ...statusDetailsFromRecord({
            live_fetch_error: result.error,
            sec_token_source: "(none)",
          }),
        ],
      );
    }

    const group = `${QWENCLOUD_LABEL} ${result.snapshot.planName}`.trim();
    const entries = buildWindowEntries(result.snapshot, group);
    const errors = [
      ...(result.snapshot.subscriptionActive === false
        ? [{ label: QWENCLOUD_LABEL, message: "QwenCloud subscription is not active." }]
        : []),
      ...(result.snapshot.partial?.subscription
        ? [{ label: QWENCLOUD_LABEL, message: "QwenCloud subscription metadata is unavailable." }]
        : []),
      ...(result.snapshot.partial?.quotaConfig
        ? [{ label: QWENCLOUD_LABEL, message: "QwenCloud quota configuration is unavailable." }]
        : []),
    ];
    return withStatusDetails(attemptedResult(entries, errors, { singleWindowDisplayName: group }), [
      ...statusDetails,
      ...statusDetailsFromRecord({
        sec_token_source: result.secTokenSource,
        plan: result.snapshot.planName,
        subscription_status: result.snapshot.subscriptionStatus ?? "(none)",
        subscription_active:
          result.snapshot.subscriptionActive === undefined
            ? "(unknown)"
            : result.snapshot.subscriptionActive
              ? "true"
              : "false",
        five_hour: formatWindowDetail(result.snapshot.fiveHour),
        weekly: formatWindowDetail(result.snapshot.weekly),
      }),
    ]);
  },
};

/**
 * Activation is either a Qwen/Alibaba Token Plan credential registered in
 * OpenCode, or a session that is currently using one of those provider ids.
 */
async function resolveQwenCloudActivation(ctx: QuotaProviderContext): Promise<QwenCloudActivation> {
  const fromSession = qwenCloudSessionActivation({
    currentProviderID: ctx.config?.currentProviderID,
    currentModel: ctx.config?.currentModel,
    runtimeIds: QWENCLOUD_RUNTIME_IDS,
  });
  if (fromSession) return fromSession;
  return isQwenCloudTokenPlanActivated();
}

function buildWindowEntries(snapshot: QwenCloudUsageSnapshot, group: string): QuotaToastEntry[] {
  const entries: QuotaToastEntry[] = [];
  if (snapshot.fiveHour) {
    entries.push(windowEntry(group, "5h", "five_hour", 0, snapshot.fiveHour));
  }
  if (snapshot.weekly) {
    entries.push(windowEntry(group, "Weekly", "week", 1, snapshot.weekly));
  }
  return entries;
}

function windowEntry(
  group: string,
  label: string,
  window: "five_hour" | "week",
  sortPriority: number,
  data: QwenCloudQuotaWindow,
): QuotaToastEntry {
  return {
    accounting: QUOTA_ACCOUNTING,
    name: `${group} ${label}`,
    group,
    label: `${label}:`,
    percentRemaining: data.percentRemaining,
    sortPriority,
    semantic: {
      metric: { kind: "window", window },
      prominence: "primary",
    },
    ...(data.limit !== undefined && data.used !== undefined && data.remaining !== undefined
      ? {
          basis: {
            used: {
              quantity: {
                decimal: accountingDecimalFromNumber(data.used),
                unit: CREDIT_UNIT,
              },
              authority: "locally_derived",
            },
            limit: {
              quantity: {
                decimal: accountingDecimalFromNumber(data.limit),
                unit: CREDIT_UNIT,
              },
              authority: "provider_reported",
            },
            remaining: {
              quantity: {
                decimal: accountingDecimalFromNumber(data.remaining),
                unit: CREDIT_UNIT,
              },
              authority: "locally_derived",
            },
          },
        }
      : {}),
    ...(data.resetTimeIso ? { resetTimeIso: data.resetTimeIso } : {}),
  };
}

function formatWindowDetail(window: QwenCloudQuotaWindow | undefined): string | undefined {
  if (!window) return "(none)";
  const limit =
    window.limit !== undefined
      ? ` used=${window.used}/${window.limit} remaining=${window.remaining}`
      : "";
  return `percent_remaining=${window.percentRemaining}${limit} reset_at=${window.resetTimeIso ?? "(none)"}`;
}
