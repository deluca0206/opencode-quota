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
  isQwenCloudBrowserReadingSupported,
  markQwenCloudSessionRejected,
  markQwenCloudSessionValidated,
  type QwenCloudAuthDiagnostics,
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

/**
 * Browser profiles one refresh may validate against the console.
 *
 * A rejected session fails fast (the console answers before any quota window is
 * fetched), so sweeping several expired profiles costs little and must not hide a
 * valid login behind them. The bound only stops a pathological machine full of
 * profiles from turning one refresh into an unbounded sweep; the wall-clock budget
 * below is what normally ends the chain.
 */
const MAX_SESSION_CANDIDATES_PER_REFRESH = 8;

/**
 * Wall-clock budget for validating browser profiles in one refresh.
 *
 * Every rejected profile costs a single fast console round trip and the accepted
 * one costs a full refresh (`QWENCLOUD_TOTAL_BUDGET_MS`), so this leaves room for
 * a handful of expired logins plus one successful query without letting a hung
 * keyring or console stall the refresh indefinitely.
 */
const SESSION_SWEEP_BUDGET_MS = 60_000;

export const qwenCloudTokenPlanProvider: QuotaProvider = {
  id: "qwencloud-token-plan",

  async isAvailable(ctx: QuotaProviderContext): Promise<boolean> {
    const auth = await resolveQwenCloudAuthCached({
      maxAgeMs: DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS,
    });
    if (auth.state === "configured" || auth.state === "invalid") return true;
    // Browser session reading is Linux-only: without a cookie override there is
    // no session to find elsewhere, so the provider stays silent.
    if (!isQwenCloudBrowserReadingSupported()) return false;
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
    const activation = await resolveQwenCloudActivation(ctx);
    let { auth, diagnostics } = await resolveQwenCloudAuthWithDiagnostics({
      maxAgeMs: DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS,
    });

    if (auth.state === "none") {
      if (!activation.activated || !isQwenCloudBrowserReadingSupported()) {
        return withStatusDetails(notAttemptedResult(), buildStatusDetails(diagnostics, activation));
      }
      return withStatusDetails(
        attemptedErrorResult(QWENCLOUD_LABEL, QWENCLOUD_SETUP_HINT),
        buildStatusDetails(diagnostics, activation),
      );
    }
    if (auth.state === "invalid") {
      return withStatusDetails(
        attemptedErrorResult(QWENCLOUD_LABEL, auth.error),
        buildStatusDetails(diagnostics, activation),
      );
    }

    const queryOptions = {
      requestTimeoutMs: ctx.config?.requestTimeoutMsConfigured
        ? ctx.config.requestTimeoutMs
        : undefined,
      totalBudgetMs: QWENCLOUD_TOTAL_BUDGET_MS,
    };
    const sweepStartedAt = Date.now();
    const sweepRemainingMs = (): number =>
      Math.max(0, SESSION_SWEEP_BUDGET_MS - (Date.now() - sweepStartedAt));

    // The quota call is also the session check: a profile whose login the console
    // rejects is dropped and the next browser or profile is tried.
    let result = await queryQwenCloudTokenPlan({ session: auth.session, ...queryOptions });
    // The rejection is recorded the moment the console answers — not when the
    // sweep continues — so a chain ended by the candidate cap or the wall-clock
    // budget still invalidates its last rejected session.
    const markRejectedIfLoginRequired = (): void => {
      if (!result.success && result.reason === "login_required" && auth.state === "configured") {
        markQwenCloudSessionRejected(auth.source);
      }
    };
    markRejectedIfLoginRequired();
    const triedStorePaths = new Set<string>(auth.storePath ? [auth.storePath] : []);
    for (
      let attempt = 1;
      !result.success &&
      result.reason === "login_required" &&
      attempt < MAX_SESSION_CANDIDATES_PER_REFRESH &&
      sweepRemainingMs() > 0;
      attempt += 1
    ) {
      const next = await resolveQwenCloudAuthWithDiagnostics({
        maxAgeMs: DEFAULT_QWENCLOUD_AUTH_CACHE_MAX_AGE_MS,
      });
      if (next.auth.state !== "configured") break;
      // Resolution is expected to skip rejected stores; a repeated one means the
      // sweep has nothing new to offer and must not be retried in a tight loop.
      if (!next.auth.storePath || triedStorePaths.has(next.auth.storePath)) break;
      triedStorePaths.add(next.auth.storePath);
      auth = next.auth;
      diagnostics = next.diagnostics;
      result = await queryQwenCloudTokenPlan({
        session: auth.session,
        ...queryOptions,
        totalBudgetMs: Math.min(QWENCLOUD_TOTAL_BUDGET_MS, sweepRemainingMs()),
      });
      markRejectedIfLoginRequired();
    }

    const statusDetails = buildStatusDetails(diagnostics, activation);
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
    markQwenCloudSessionValidated(auth.source);

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

function buildStatusDetails(
  diagnostics: QwenCloudAuthDiagnostics,
  activation: QwenCloudActivation,
) {
  return statusDetailsFromRecord({
    auth_state: diagnostics.state,
    auth_source: diagnostics.source ?? "(none)",
    activation: activation.source ?? "(none)",
    browsers_inspected:
      diagnostics.browsers.length > 0 ? diagnostics.browsers.join(", ") : "(none)",
    browser_session_report: formatInspections(diagnostics),
    auth_note: diagnostics.note ?? undefined,
    auth_error: diagnostics.error ?? undefined,
  });
}

/**
 * One line per inspected store, e.g. `google-chrome/Default: session (rows=102
 * v11=102 schema=24 keyring=available)`. Carries no cookie name, value, or path.
 */
function formatInspections(diagnostics: QwenCloudAuthDiagnostics): string {
  const inspections = diagnostics.inspections ?? [];
  if (inspections.length === 0) return "(none)";
  return inspections
    .map((inspection) =>
      [
        `${inspection.browser}/${inspection.profile}:`,
        inspection.outcome,
        inspection.detail ? `(${inspection.detail})` : "",
      ]
        .filter(Boolean)
        .join(" "),
    )
    .join("; ");
}

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
