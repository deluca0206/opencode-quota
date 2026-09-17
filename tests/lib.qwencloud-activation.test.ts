import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const authMocks = vi.hoisted(() => ({
  readAuthFileCached: vi.fn(),
}));

vi.mock("../src/lib/opencode-auth.js", () => ({
  readAuthFileCached: authMocks.readAuthFileCached,
}));

import {
  clearQwenCloudActivationCacheForTests,
  isQwenCloudTokenPlanActivated,
  qwenCloudSessionActivation,
} from "../src/lib/qwencloud-activation.js";

const RUNTIME_IDS = new Set(["qwencloud-token-plan", "alibaba-token-plan"]);

describe("Qwen/Alibaba Token Plan activation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearQwenCloudActivationCacheForTests();
    authMocks.readAuthFileCached.mockResolvedValue(null);
  });

  afterEach(() => {
    clearQwenCloudActivationCacheForTests();
  });

  it.each([
    ["qwencloud-token-plan", { type: "api", key: "sk-sp-secret" }],
    ["alibaba-token-plan", { type: "api", key: "sk-sp-secret" }],
    ["qwencloud", { type: "api", key: "sk-sp-secret" }],
    ["qwencloud-token-plan", { type: "oauth", access: "token-secret" }],
  ])("activates on a registered %s credential", async (key, entry) => {
    authMocks.readAuthFileCached.mockResolvedValue({ [key]: entry });
    await expect(isQwenCloudTokenPlanActivated({ nowMs: 1_000 })).resolves.toEqual({
      activated: true,
      source: "auth.json",
    });
  });

  it("stays inactive without a credential", async () => {
    authMocks.readAuthFileCached.mockResolvedValue({
      "qwen-code": { type: "oauth", access: "other" },
      anthropic: { type: "api", key: "sk-ant" },
    });
    await expect(isQwenCloudTokenPlanActivated({ nowMs: 1_000 })).resolves.toEqual({
      activated: false,
      source: null,
    });
  });

  it("ignores an empty credential entry", async () => {
    authMocks.readAuthFileCached.mockResolvedValue({
      "qwencloud-token-plan": { type: "api", key: "   " },
    });
    await expect(isQwenCloudTokenPlanActivated({ nowMs: 1_000 })).resolves.toMatchObject({
      activated: false,
    });
  });

  it("never exposes the credential value", async () => {
    authMocks.readAuthFileCached.mockResolvedValue({
      "qwencloud-token-plan": { type: "api", key: "sk-sp-secret-value" },
    });
    const activation = await isQwenCloudTokenPlanActivated({ nowMs: 1_000 });
    expect(JSON.stringify(activation)).not.toContain("sk-sp-secret-value");
  });

  it("caches the activation lookup", async () => {
    authMocks.readAuthFileCached.mockResolvedValue({
      "qwencloud-token-plan": { type: "api", key: "sk-sp-secret" },
    });
    await isQwenCloudTokenPlanActivated({ nowMs: 1_000 });
    await isQwenCloudTokenPlanActivated({ nowMs: 2_000 });
    await isQwenCloudTokenPlanActivated({ nowMs: 3_000 });
    expect(authMocks.readAuthFileCached).toHaveBeenCalledTimes(1);
  });

  it.each([
    [{ currentProviderID: "alibaba-token-plan" }, true],
    [{ currentProviderID: "QWENCLOUD-TOKEN-PLAN" }, true],
    [{ currentProviderID: "qwen-code" }, false],
    [{ currentModel: "alibaba-token-plan/qwen3.8-max" }, true],
    [{ currentModel: "anthropic/claude-x" }, false],
    [{}, false],
  ])("session relevance for %j -> %s", (session, expected) => {
    const result = qwenCloudSessionActivation({ ...session, runtimeIds: RUNTIME_IDS });
    expect(result?.activated ?? false).toBe(expected);
    if (result) expect(result.source).toBe("session");
  });
});
