import { readAuthFileCached } from "./opencode-auth.js";

import { getQuotaProviderRuntimeIds } from "./provider-metadata.js";

/**
 * Activation for the Qwen/Alibaba Token Plan provider.
 *
 * Quota itself only comes from the QwenCloud console session, never from an API
 * key. The key is used purely as an activation signal: once the user registers a
 * Qwen/Alibaba Token Plan credential in OpenCode, the provider becomes relevant
 * and either reports quota or explains how to sign in. Without any credential
 * and without a matching session model, the provider stays silent.
 */
export const QWENCLOUD_ACTIVATION_AUTH_KEYS: readonly string[] = [
  ...getQuotaProviderRuntimeIds("qwencloud-token-plan"),
  "qwencloud",
];

export const DEFAULT_QWENCLOUD_ACTIVATION_CACHE_MAX_AGE_MS = 30_000;

export type QwenCloudActivationSource = "auth.json" | "session" | null;

export interface QwenCloudActivation {
  activated: boolean;
  source: QwenCloudActivationSource;
}

interface ActivationCacheEntry {
  activated: boolean;
  at: number;
}

let cachedActivation: ActivationCacheEntry | null = null;

export function matchesQwenCloudRuntimeProvider(
  providerId: string | undefined,
  runtimeIds: ReadonlySet<string>,
): boolean {
  const normalized = providerId?.trim().toLowerCase();
  return normalized ? runtimeIds.has(normalized) : false;
}

export function qwenCloudSessionActivation(params: {
  currentProviderID?: string;
  currentModel?: string;
  runtimeIds: ReadonlySet<string>;
}): QwenCloudActivation | null {
  if (matchesQwenCloudRuntimeProvider(params.currentProviderID, params.runtimeIds)) {
    return { activated: true, source: "session" };
  }
  const model = params.currentModel?.trim().toLowerCase() ?? "";
  if (!model) return null;
  const [prefix] = model.split("/", 2);
  return matchesQwenCloudRuntimeProvider(prefix, params.runtimeIds)
    ? { activated: true, source: "session" }
    : null;
}

export async function isQwenCloudTokenPlanActivated(params?: {
  maxAgeMs?: number;
  nowMs?: number;
}): Promise<QwenCloudActivation> {
  const maxAgeMs = Math.max(0, params?.maxAgeMs ?? DEFAULT_QWENCLOUD_ACTIVATION_CACHE_MAX_AGE_MS);
  const now = params?.nowMs ?? Date.now();
  if (cachedActivation && now - cachedActivation.at < maxAgeMs) {
    return {
      activated: cachedActivation.activated,
      source: cachedActivation.activated ? "auth.json" : null,
    };
  }

  const activated = await detectRegisteredQwenCloudCredential();
  cachedActivation = { activated, at: now };
  return { activated, source: activated ? "auth.json" : null };
}

async function detectRegisteredQwenCloudCredential(): Promise<boolean> {
  const auth = await readAuthFileCached({
    maxAgeMs: DEFAULT_QWENCLOUD_ACTIVATION_CACHE_MAX_AGE_MS,
  });
  if (!auth || typeof auth !== "object") return false;
  const root = auth as Record<string, unknown>;
  return QWENCLOUD_ACTIVATION_AUTH_KEYS.some(
    (key) => Object.hasOwn(root, key) && hasUsableCredential(root[key]),
  );
}

function hasUsableCredential(entry: unknown): boolean {
  if (!entry || typeof entry !== "object") return false;
  const record = entry as Record<string, unknown>;
  for (const field of ["key", "access", "accessToken", "token"]) {
    const value = record[field];
    if (typeof value === "string" && value.trim()) return true;
  }
  return false;
}

export function clearQwenCloudActivationCacheForTests(): void {
  cachedActivation = null;
}
