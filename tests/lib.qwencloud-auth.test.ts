import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const browserMocks = vi.hoisted(() => ({
  discoverBrowserCookieStores: vi.fn(),
  fingerprintBrowserCookieStores: vi.fn(),
  importBrowserQwenCloudSession: vi.fn(),
  isBrowserImportDisabled: vi.fn(),
}));

vi.mock("../src/lib/qwencloud-browser.js", () => ({
  discoverBrowserCookieStores: browserMocks.discoverBrowserCookieStores,
  fingerprintBrowserCookieStores: browserMocks.fingerprintBrowserCookieStores,
  importBrowserQwenCloudSession: browserMocks.importBrowserQwenCloudSession,
  isBrowserImportDisabled: browserMocks.isBrowserImportDisabled,
  browserStoresSignature: (items: Array<{ path: string; mtimeMs: number; size: number }>) =>
    items.length === 0
      ? null
      : items.map((item) => `${item.path}:${Math.floor(item.mtimeMs)}:${item.size}`).join("|"),
}));

const originalEnv = process.env;

const STORE = {
  kind: "firefox" as const,
  browser: "firefox",
  profile: "default-release",
  dbPath: "/tmp/firefox/cookies.sqlite",
};

const CHROMIUM_STORE = {
  kind: "chromium" as const,
  browser: "google-chrome",
  profile: "Default",
  dbPath: "/tmp/chrome/Cookies",
  rootPath: "/tmp/chrome",
};

function fingerprint(mtimeMs = 1_000, size = 10, path = STORE.dbPath) {
  return [{ path, mtimeMs, size }];
}

describe("QwenCloud auth resolution", () => {
  beforeEach(async () => {
    vi.resetModules();
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    delete process.env.QWEN_CLOUD_COOKIE;
    delete process.env.QWEN_CLOUD_BROWSER;
    delete process.env.QWEN_CLOUD_BROWSER_PROFILE;
    delete process.env.QWEN_CLOUD_FIREFOX;
    delete process.env.QWEN_CLOUD_FIREFOX_PROFILE;
    browserMocks.isBrowserImportDisabled.mockImplementation(
      (env: NodeJS.ProcessEnv = process.env) =>
        env.QWEN_CLOUD_BROWSER?.trim().toLowerCase() === "none",
    );
    browserMocks.discoverBrowserCookieStores.mockResolvedValue([STORE]);
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint());
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  async function loadAuth() {
    return await import("../src/lib/qwencloud-auth.js");
  }

  it("keeps a console-rejected store out of the next sweep and prefers a validated one", async () => {
    const ticket = [{ name: "login_qwencloud_ticket", value: "ff-secret", host: ".qwencloud.com" }];
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: STORE,
      cookies: ticket,
      inspections: [{ browser: "firefox", profile: "default-release", outcome: "session" }],
    });
    const {
      resolveQwenCloudAuth,
      markQwenCloudSessionRejected,
      markQwenCloudSessionValidated,
      qwenCloudRejectedStorePaths,
    } = await loadAuth();

    await resolveQwenCloudAuth({ nowMs: 1_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenLastCalledWith(
      expect.objectContaining({ preferredStorePaths: [], excludeStorePaths: [] }),
    );

    // The console accepted this session, so its store is tried first next time.
    markQwenCloudSessionValidated("browser:firefox/default-release");
    // Past the re-import throttle, so a fingerprint change forces a new sweep.
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(10_000));
    await resolveQwenCloudAuth({ nowMs: 10_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenLastCalledWith(
      expect.objectContaining({ preferredStorePaths: [STORE.dbPath], excludeStorePaths: [] }),
    );

    // The console later rejects it: the store is skipped and never reused as the
    // last known good session.
    markQwenCloudSessionRejected("browser:firefox/default-release");
    expect(qwenCloudRejectedStorePaths()).toEqual([STORE.dbPath]);
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "no_session",
      stores: [STORE],
      keyringSeen: false,
      inspections: [{ browser: "firefox", profile: "default-release", outcome: "no_ticket" }],
    });
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(20_000));
    await expect(resolveQwenCloudAuth({ nowMs: 20_000 })).resolves.toMatchObject({ state: "none" });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenLastCalledWith(
      expect.objectContaining({ excludeStorePaths: [STORE.dbPath] }),
    );
  });

  it("ignores a rejection that does not match the resolved session", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret", host: ".qwencloud.com" }],
      inspections: [],
    });
    const { resolveQwenCloudAuth, markQwenCloudSessionRejected, qwenCloudRejectedStorePaths } =
      await loadAuth();
    await resolveQwenCloudAuth({ nowMs: 1_000 });
    markQwenCloudSessionRejected("browser:google-chrome/Default");
    expect(qwenCloudRejectedStorePaths()).toEqual([]);
  });

  it("reports value-free store inspections through diagnostics", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "no_session",
      stores: [STORE, CHROMIUM_STORE],
      keyringSeen: true,
      inspections: [
        { browser: "firefox", profile: "default-release", outcome: "no_rows", detail: "rows=0" },
        {
          browser: "google-chrome",
          profile: "Default",
          outcome: "keyring",
          detail: "rows=102 v11=102 schema=24 keyring=locked",
        },
      ],
    });
    const { getQwenCloudAuthDiagnostics } = await loadAuth();
    const diagnostics = await getQwenCloudAuthDiagnostics({ nowMs: 1_000 });
    expect(diagnostics.inspections).toEqual([
      { browser: "firefox", profile: "default-release", outcome: "no_rows", detail: "rows=0" },
      {
        browser: "google-chrome",
        profile: "Default",
        outcome: "keyring",
        detail: "rows=102 v11=102 schema=24 keyring=locked",
      },
    ]);
    expect(diagnostics.note).toContain("keyring");
    expect(diagnostics.note).not.toContain("QWEN_CLOUD_COOKIE");
    expect(JSON.stringify(diagnostics)).not.toContain("/tmp/chrome");
  });

  it("bounds the number of reported inspections", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "no_session",
      stores: [STORE],
      keyringSeen: false,
      inspections: Array.from({ length: 20 }, (_, index) => ({
        browser: "firefox",
        profile: `p${index}`,
        outcome: "no_rows" as const,
      })),
    });
    const { getQwenCloudAuthDiagnostics, QWENCLOUD_MAX_REPORTED_INSPECTIONS } = await loadAuth();
    const diagnostics = await getQwenCloudAuthDiagnostics({ nowMs: 1_000 });
    expect(diagnostics.inspections).toHaveLength(QWENCLOUD_MAX_REPORTED_INSPECTIONS);
  });

  it("prefers a valid environment cookie header without browser I/O", async () => {
    process.env.QWEN_CLOUD_COOKIE = "login_qwencloud_ticket=env-secret; cna=anon";
    const { resolveQwenCloudAuth } = await loadAuth();
    const resolved = await resolveQwenCloudAuth({ nowMs: 1_000 });
    expect(resolved).toMatchObject({ state: "configured", source: "env:QWEN_CLOUD_COOKIE" });
    expect(browserMocks.discoverBrowserCookieStores).not.toHaveBeenCalled();
    expect(browserMocks.importBrowserQwenCloudSession).not.toHaveBeenCalled();
  });

  it("treats an invalid environment cookie as blocking", async () => {
    process.env.QWEN_CLOUD_COOKIE = "cna=anon";
    const { resolveQwenCloudAuth } = await loadAuth();
    await expect(resolveQwenCloudAuth({ nowMs: 1_000 })).resolves.toEqual({
      state: "invalid",
      source: "env:QWEN_CLOUD_COOKIE",
      error: "QwenCloud cookie header is missing a login ticket",
    });
  });

  it("detects a browser session without any environment variable", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret", host: ".qwencloud.com" }],
    });
    const { resolveQwenCloudAuth } = await loadAuth();
    const resolved = await resolveQwenCloudAuth({ nowMs: 1_000 });
    expect(resolved).toMatchObject({
      state: "configured",
      source: "browser:firefox/default-release",
    });
    expect(process.env.QWEN_CLOUD_FIREFOX).toBeUndefined();
  });

  it("detects Chromium browsers as well as Firefox", async () => {
    browserMocks.discoverBrowserCookieStores.mockResolvedValue([CHROMIUM_STORE]);
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(
      fingerprint(2_000, 20, CHROMIUM_STORE.dbPath),
    );
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: CHROMIUM_STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "chrome-secret" }],
    });
    const { resolveQwenCloudAuth } = await loadAuth();
    await expect(resolveQwenCloudAuth({ nowMs: 1_000 })).resolves.toMatchObject({
      state: "configured",
      source: "browser:google-chrome/Default",
    });
  });

  it("reuses the cached session while the cookie fingerprint is unchanged", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret" }],
    });
    const { resolveQwenCloudAuthCached, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();
    await resolveQwenCloudAuthCached({ nowMs: 1_000 });
    await resolveQwenCloudAuthCached({ nowMs: 2_000 });
    await resolveQwenCloudAuthCached({ nowMs: 3_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(1);
  });

  it("re-reads the session when a browser cookie database changes", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret" }],
    });
    const { resolveQwenCloudAuthCached, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();
    await resolveQwenCloudAuthCached({ nowMs: 1_000 });
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(9_999));
    await resolveQwenCloudAuthCached({ nowMs: 10_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(2);
  });

  it("throttles re-imports while a browser rewrites its cookie database", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "no_session",
      stores: [STORE],
      keyringSeen: false,
    });
    const { resolveQwenCloudAuthCached, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();
    await resolveQwenCloudAuthCached({ nowMs: 1_000 });
    // Actively browsed: the fingerprint changes on every call inside the window.
    for (let i = 0; i < 10; i++) {
      browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(2_000 + i));
      await resolveQwenCloudAuthCached({ nowMs: 1_100 + i * 50 });
    }
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(1);

    // Past the minimum interval the change is picked up again.
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(9_000));
    await resolveQwenCloudAuthCached({ nowMs: 9_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(2);
  });

  it("deduplicates concurrent resolutions into one browser read", async () => {
    let release: (() => void) | undefined;
    browserMocks.importBrowserQwenCloudSession.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () =>
            resolve({
              state: "imported",
              store: STORE,
              cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret" }],
            });
        }),
    );
    const { resolveQwenCloudAuthCached, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();
    const pending = [
      resolveQwenCloudAuthCached({ nowMs: 1_000 }),
      resolveQwenCloudAuthCached({ nowMs: 1_000 }),
      resolveQwenCloudAuthCached({ nowMs: 1_000 }),
    ];
    await vi.waitFor(() => {
      expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(1);
    });
    release?.();
    const results = await Promise.all(pending);
    expect(results.every((result) => result.state === "configured")).toBe(true);
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(1);
  });

  it("shares one resolution between auth and diagnostics", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret" }],
    });
    const { resolveQwenCloudAuthWithDiagnostics, clearQwenCloudAuthCacheForTests } =
      await loadAuth();
    clearQwenCloudAuthCacheForTests();
    const { auth, diagnostics } = await resolveQwenCloudAuthWithDiagnostics({ nowMs: 1_000 });
    expect(auth.state).toBe("configured");
    expect(diagnostics.browsers).toEqual(["firefox/default-release"]);
    expect(JSON.stringify(diagnostics)).not.toContain("ff-secret");
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(1);
  });

  it("stays unavailable instead of erroring when no browser profile exists", async () => {
    browserMocks.discoverBrowserCookieStores.mockResolvedValue([]);
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue([]);
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({ state: "no_stores" });
    const { resolveQwenCloudAuth } = await loadAuth();
    await expect(resolveQwenCloudAuth({ nowMs: 1_000 })).resolves.toMatchObject({
      state: "none",
    });
  });

  it("reports keyring-protected cookies as a hint, not a blocking error", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "no_session",
      stores: [CHROMIUM_STORE],
      keyringSeen: true,
    });
    const { getQwenCloudAuthDiagnostics } = await loadAuth();
    const diagnostics = await getQwenCloudAuthDiagnostics({ nowMs: 1_000 });
    expect(diagnostics.state).toBe("none");
    expect(diagnostics.error).toBeNull();
    expect(diagnostics.note).toMatch(/keyring/u);
  });

  it("honours an explicit browser import opt-out", async () => {
    process.env.QWEN_CLOUD_BROWSER = "none";
    const { resolveQwenCloudAuth } = await loadAuth();
    await expect(resolveQwenCloudAuth({ nowMs: 1_000 })).resolves.toMatchObject({
      state: "none",
      note: "browser import disabled",
    });
    expect(browserMocks.discoverBrowserCookieStores).not.toHaveBeenCalled();
  });

  it("expires negative results quickly even when nothing changed", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "no_session",
      stores: [STORE],
      keyringSeen: false,
    });
    const { resolveQwenCloudAuthCached, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();

    await resolveQwenCloudAuthCached({ nowMs: 1_000 });
    // Same fingerprint, still inside the negative window: served from cache.
    await resolveQwenCloudAuthCached({ nowMs: 20_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(1);

    // Past the short negative TTL the store is read again without waiting for a
    // fingerprint change or the full positive TTL.
    await resolveQwenCloudAuthCached({ nowMs: 40_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(2);
  });

  it("retries an unreadable store once within the same resolution", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "unreadable",
      stores: [STORE],
    });
    const { resolveQwenCloudAuth, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();
    await resolveQwenCloudAuth({ nowMs: 1_000 });
    expect(browserMocks.importBrowserQwenCloudSession).toHaveBeenCalledTimes(2);
  });

  it("serves the last known session while the browser holds its database", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValueOnce({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret", host: ".qwencloud.com" }],
    });
    const { resolveQwenCloudAuthWithDiagnostics, clearQwenCloudAuthCacheForTests } =
      await loadAuth();
    clearQwenCloudAuthCacheForTests();

    const first = await resolveQwenCloudAuthWithDiagnostics({ nowMs: 1_000 });
    expect(first.auth.state).toBe("configured");

    // The browser got busy: every read now fails.
    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "unreadable",
      stores: [STORE],
    });
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(9_999));

    const second = await resolveQwenCloudAuthWithDiagnostics({ nowMs: 10_000 });
    expect(second.auth.state).toBe("configured");
    if (second.auth.state !== "configured") return;
    expect(second.auth.session.dashboardCookies[0]?.value).toBe("ff-secret");
    expect(second.diagnostics.note).toMatch(/last known/u);
    expect(JSON.stringify(second)).toContain("ff-secret"); // session, never diagnostics
  });

  it("drops the last known session after its bounded lifetime", async () => {
    browserMocks.importBrowserQwenCloudSession.mockResolvedValueOnce({
      state: "imported",
      store: STORE,
      cookies: [{ name: "login_qwencloud_ticket", value: "ff-secret", host: ".qwencloud.com" }],
    });
    const { resolveQwenCloudAuth, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();

    await expect(resolveQwenCloudAuth({ nowMs: 1_000 })).resolves.toMatchObject({
      state: "configured",
    });

    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "unreadable",
      stores: [STORE],
    });
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(9_999));

    // Ten minutes later the fallback is gone and the real state surfaces.
    await expect(resolveQwenCloudAuth({ nowMs: 700_000 })).resolves.toMatchObject({
      state: "none",
    });
  });

  it("never serves a last known session whose ticket has expired", async () => {
    const expiredAtMs = 5_000;
    browserMocks.importBrowserQwenCloudSession.mockResolvedValueOnce({
      state: "imported",
      store: STORE,
      cookies: [
        {
          name: "login_qwencloud_ticket",
          value: "ff-secret",
          host: ".qwencloud.com",
          expiry: Math.floor(expiredAtMs / 1000),
        },
      ],
    });
    const { resolveQwenCloudAuth, clearQwenCloudAuthCacheForTests } = await loadAuth();
    clearQwenCloudAuthCacheForTests();

    await expect(resolveQwenCloudAuth({ nowMs: 1_000 })).resolves.toMatchObject({
      state: "configured",
    });

    browserMocks.importBrowserQwenCloudSession.mockResolvedValue({
      state: "unreadable",
      stores: [STORE],
    });
    browserMocks.fingerprintBrowserCookieStores.mockResolvedValue(fingerprint(9_999));

    await expect(resolveQwenCloudAuth({ nowMs: 10_000 })).resolves.toMatchObject({
      state: "none",
    });
  });
});
