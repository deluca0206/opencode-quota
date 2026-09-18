import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SystemSecretRequest } from "../src/lib/browser-keystore.js";
import {
  classifySecretServiceError,
  createDbusSecretServiceTransport,
  createSecretServiceKeyStore,
  resetSecretServiceStateForTests,
  SECRET_SERVICE_CLEANUP_TIMEOUT_MS,
  SECRET_SERVICE_INTERFACE,
  SECRET_SERVICE_MAX_CANDIDATES,
  SECRET_SERVICE_MAX_SECRETS,
  SECRET_SERVICE_OBJECT_PATH,
  SECRET_SERVICE_PROMPT_INTERFACE,
  SECRET_SERVICE_PROMPT_TIMEOUT_MS,
  SECRET_SERVICE_TIMEOUT_MS,
  SecretServiceError,
  type SecretServiceTransport,
  type SecretServiceTransportFactory,
  secretAttributeCandidates,
} from "../src/lib/browser-secret-service.js";

const dbusMock = vi.hoisted(() => ({
  interfaces: new Map<string, Record<string, unknown>>(),
  ended: 0,
  busOptions: [] as Array<{ timeout?: number }>,
}));

/** The object path Secret Service returns when it did not open a session. */
const NO_SESSION_PATH = "/";

vi.mock("dbus-native", () => ({
  Variant: class {
    constructor(
      readonly signature: string,
      readonly value: unknown,
    ) {}
  },
  sessionBus: (options?: { timeout?: number }) => {
    dbusMock.busOptions.push(options ?? {});
    return {
      getService: () => ({
        getInterface: async (objectPath: string, interfaceName: string) => {
          const iface = dbusMock.interfaces.get(`${objectPath} ${interfaceName}`);
          if (!iface) throw new Error(`no interface for ${objectPath} ${interfaceName}`);
          return iface;
        },
      }),
      connection: {
        end: () => {
          dbusMock.ended += 1;
        },
      },
    };
  },
}));

const CHROME_REQUEST: SystemSecretRequest = {
  schemas: ["chrome_libsecret_os_crypt_password_v2", "chrome_libsecret_os_crypt_password_v1"],
  applications: ["chrome"],
};

interface FakeTransport extends SecretServiceTransport {
  readonly searched: Array<Record<string, string>>;
  disposed: number;
  closedSessions: string[];
  unlockCalls: number;
  promptCalls: number;
}

function createFakeTransport(behavior: {
  search?: (attributes: Record<string, string>) => { unlocked: string[]; locked: string[] };
  unlock?: () => { unlocked: string[]; promptPath: string };
  prompt?: () =>
    | { dismissed: boolean; unlocked: string[] }
    | Promise<{ dismissed: boolean; unlocked: string[] }>;
  secrets?: string[];
  /** Per-item secrets, so different attribute combinations can yield different keys. */
  secretsFor?: (objectPaths: readonly string[]) => string[];
  failOn?: "openSession" | "searchItems" | "getSecrets";
  hangOn?: "searchItems";
  /** Hang the nth `searchItems` call, to exercise a deadline mid-exchange. */
  hangOnSearchCall?: number;
  /** Never let teardown finish, to exercise the bounded cleanup. */
  hangOnDispose?: boolean;
  error?: unknown;
}): FakeTransport {
  const searched: Array<Record<string, string>> = [];
  let disposed = 0;
  let unlockCalls = 0;
  let promptCalls = 0;
  const closedSessions: string[] = [];

  const transport: FakeTransport = {
    searched,
    get disposed() {
      return disposed;
    },
    closedSessions,
    get unlockCalls() {
      return unlockCalls;
    },
    get promptCalls() {
      return promptCalls;
    },

    async openSession() {
      if (behavior.failOn === "openSession") throw behavior.error ?? new Error("open failed");
      return "/org/freedesktop/secrets/session/s1";
    },

    async searchItems(attributes) {
      searched.push({ ...attributes });
      if (behavior.hangOn === "searchItems" || behavior.hangOnSearchCall === searched.length) {
        return await new Promise<never>(() => {});
      }
      if (behavior.failOn === "searchItems") throw behavior.error ?? new Error("search failed");
      return behavior.search?.(attributes) ?? { unlocked: [], locked: [] };
    },

    async unlock(objectPaths) {
      unlockCalls += 1;
      return behavior.unlock?.() ?? { unlocked: [...objectPaths], promptPath: "/" };
    },

    async prompt() {
      promptCalls += 1;
      return (
        behavior.prompt?.() ?? {
          dismissed: false,
          unlocked: ["/org/freedesktop/secrets/collection/login/1"],
        }
      );
    },

    async getSecrets(objectPaths) {
      if (behavior.failOn === "getSecrets") throw behavior.error ?? new Error("read failed");
      return behavior.secretsFor?.(objectPaths) ?? behavior.secrets ?? ["safe-storage-password"];
    },

    async closeSession(sessionPath) {
      closedSessions.push(sessionPath);
    },

    async dispose() {
      disposed += 1;
      if (behavior.hangOnDispose) await new Promise<never>(() => {});
    },
  };
  return transport;
}

const unlockedItem = { unlocked: ["/org/freedesktop/secrets/collection/login/1"], locked: [] };

describe("Secret Service key store", () => {
  beforeEach(() => {
    // No global state is shared between cases: each store owns its failure cache.
  });

  it("does not touch D-Bus on unsupported platforms", async () => {
    let created = 0;
    const store = createSecretServiceKeyStore({
      platform: "darwin",
      transportFactory: async () => {
        created += 1;
        return createFakeTransport({});
      },
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "unavailable",
      detail: "unsupported_platform",
    });
    expect(created).toBe(0);
  });

  it("returns the Safe Storage password from an unlocked item", async () => {
    const transport = createFakeTransport({ search: () => unlockedItem });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "available",
      secrets: ["safe-storage-password"],
    });
    expect(transport.searched[0]).toEqual({
      "xdg:schema": "chrome_libsecret_os_crypt_password_v2",
      application: "chrome",
    });
    expect(transport.closedSessions).toEqual(["/org/freedesktop/secrets/session/s1"]);
    expect(transport.disposed).toBe(1);
  });

  it("unlocks a locked item without a prompt", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/org/freedesktop/secrets/collection/login/2"] }),
      unlock: () => ({
        unlocked: ["/org/freedesktop/secrets/collection/login/2"],
        promptPath: "/",
      }),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toMatchObject({ state: "available" });
    expect(transport.disposed).toBe(1);
  });

  it("reports a locked keyring when the user dismisses the unlock prompt", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/org/freedesktop/secrets/collection/login/3"] }),
      unlock: () => ({ unlocked: [], promptPath: "/org/freedesktop/secrets/prompt/p1" }),
      prompt: () => ({ dismissed: true, unlocked: [] }),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({ state: "locked" });
    expect(transport.disposed).toBe(1);
  });

  it("uses the prompt result when the desktop unlocks the keyring", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/org/freedesktop/secrets/collection/login/4"] }),
      unlock: () => ({ unlocked: [], promptPath: "/org/freedesktop/secrets/prompt/p2" }),
      prompt: () => ({
        dismissed: false,
        unlocked: ["/org/freedesktop/secrets/collection/login/4"],
      }),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toMatchObject({
      state: "available",
      secrets: ["safe-storage-password"],
    });
  });

  it("falls through to the next schema when the newest one has no entry", async () => {
    const transport = createFakeTransport({
      search: (attributes) =>
        attributes["xdg:schema"] === "chrome_libsecret_os_crypt_password_v1"
          ? unlockedItem
          : { unlocked: [], locked: [] },
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toMatchObject({ state: "available" });
    expect(transport.searched.map((entry) => entry["xdg:schema"])).toEqual([
      "chrome_libsecret_os_crypt_password_v2",
      "chrome_libsecret_os_crypt_password_v1",
    ]);
  });

  it("collects Safe Storage passwords from every attribute combination", async () => {
    const request: SystemSecretRequest = {
      schemas: ["schema_v2", "schema_v1"],
      applications: ["brave", "chromium"],
    };
    const itemFor: Record<string, string> = {
      "schema_v2|brave": "/item/1",
      "schema_v2|chromium": "/item/2",
      // The oldest schema points back at the same item: its password is a duplicate.
      "schema_v1|brave": "/item/1",
      "schema_v1|chromium": "/item/3",
    };
    const passwordFor: Record<string, string> = {
      "/item/1": "password-one",
      "/item/2": "password-two",
      "/item/3": "password-three",
    };
    const transport = createFakeTransport({
      search: (attributes) => {
        const path = itemFor[`${attributes["xdg:schema"]}|${attributes.application}`];
        return path ? { unlocked: [path], locked: [] } : { unlocked: [], locked: [] };
      },
      secretsFor: (objectPaths) =>
        objectPaths.flatMap((path) => (passwordFor[path] ? [passwordFor[path]] : [])),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(request)).resolves.toEqual({
      state: "available",
      secrets: ["password-one", "password-two", "password-three"],
    });
    expect(transport.searched).toHaveLength(4);
  });

  it("caps how many passwords one lookup returns", async () => {
    const passwords = Array.from(
      { length: SECRET_SERVICE_MAX_SECRETS + 4 },
      (_, index) => `password-${index}`,
    );
    const transport = createFakeTransport({
      search: () => unlockedItem,
      secretsFor: () => [...passwords],
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    const lookup = await store.getSecrets(CHROME_REQUEST);
    expect(lookup.state).toBe("available");
    if (lookup.state !== "available") return;
    expect(lookup.secrets).toHaveLength(SECRET_SERVICE_MAX_SECRETS);
    expect(lookup.secrets[0]).toBe("password-0");
  });

  it("does not prompt to unlock another keyring once a password is known", async () => {
    const transport = createFakeTransport({
      search: (attributes) =>
        attributes["xdg:schema"] === "schema_v2"
          ? { unlocked: ["/item/1"], locked: [] }
          : { unlocked: [], locked: ["/item/locked"] },
      secretsFor: () => ["password-one"],
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(
      store.getSecrets({ schemas: ["schema_v2", "schema_v1"], applications: ["chrome"] }),
    ).resolves.toEqual({ state: "available", secrets: ["password-one"] });
    expect(transport.unlockCalls).toBe(0);
    expect(transport.promptCalls).toBe(0);
  });

  it("bounds an exchange whose bus stops answering and tears it down", async () => {
    const transport = createFakeTransport({ hangOn: "searchItems" });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "error",
      detail: "timeout",
    });
    expect(transport.disposed).toBe(1);
    // The deadline is spent, so the exchange gives up on a polite Close.
    expect(transport.closedSessions).toEqual([]);
  });

  it("keeps the passwords already read when a later candidate hangs", async () => {
    const transport = createFakeTransport({
      search: () => unlockedItem,
      secretsFor: () => ["password-one"],
      hangOnSearchCall: 2,
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      transportFactory: async () => transport,
    });

    await expect(
      store.getSecrets({ schemas: ["schema_v2", "schema_v1"], applications: ["chrome"] }),
    ).resolves.toEqual({ state: "available", secrets: ["password-one"] });
    expect(transport.disposed).toBe(1);
  });

  it("lets an unlock prompt outlive the machine-to-machine budget", async () => {
    // The desktop dialog waits for a human, so it must not be cut down to the few
    // seconds the D-Bus calls share — and the read after it still has to run.
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/item/locked"] }),
      unlock: () => ({ unlocked: [], promptPath: "/prompt/p1" }),
      prompt: async () => {
        await new Promise((resolve) => setTimeout(resolve, 120));
        return { dismissed: false, unlocked: ["/item/locked"] };
      },
      secretsFor: () => ["password-after-unlock"],
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      promptTimeoutMs: 5_000,
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "available",
      secrets: ["password-after-unlock"],
    });
    expect(transport.promptCalls).toBe(1);
  });

  it("gives a default store's unlock prompt the documented budget", async () => {
    let received: Parameters<SecretServiceTransportFactory>[0] | undefined;
    const startedAt = Date.now();
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async (options) => {
        received = options;
        return createFakeTransport({});
      },
    });

    await store.getSecrets(CHROME_REQUEST);

    const machineBudgetMs = (received?.deadlineAt ?? startedAt) - startedAt;
    const promptBudgetMs = (received?.promptDeadlineAt ?? startedAt) - startedAt;
    expect(machineBudgetMs).toBeLessThanOrEqual(SECRET_SERVICE_TIMEOUT_MS + 50);
    // A locked keyring is a normal desktop state: the window to answer the dialog
    // is the prompt budget, not the machine one.
    expect(promptBudgetMs).toBeGreaterThan(SECRET_SERVICE_TIMEOUT_MS);
    expect(promptBudgetMs).toBeLessThanOrEqual(
      SECRET_SERVICE_TIMEOUT_MS + SECRET_SERVICE_PROMPT_TIMEOUT_MS + 50,
    );
  });

  it("asks the user to unlock the keyring at most once per latch window", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/item/locked"] }),
      unlock: () => ({ unlocked: [], promptPath: "/prompt/p1" }),
      prompt: () => ({ dismissed: true, unlocked: [] }),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    // Two browsers, two request keys, one dialog: unlocking is a property of the
    // collection, not of the item that asked for it.
    await expect(
      store.getSecrets({ schemas: ["schema_v2"], applications: ["chrome"] }),
    ).resolves.toEqual({ state: "locked" });
    await expect(
      store.getSecrets({ schemas: ["schema_v2"], applications: ["brave"] }),
    ).resolves.toEqual({ state: "locked" });
    expect(transport.promptCalls).toBe(1);
  });

  it("prompts again once the latch window has passed", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/item/locked"] }),
      unlock: () => ({ unlocked: [], promptPath: "/prompt/p1" }),
      prompt: () => ({ dismissed: true, unlocked: [] }),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      promptLatchMs: 10,
      transportFactory: async () => transport,
    });

    await store.getSecrets({ schemas: ["schema_v2"], applications: ["chrome"] });
    await new Promise((resolve) => setTimeout(resolve, 25));
    await store.getSecrets({ schemas: ["schema_v2"], applications: ["brave"] });
    expect(transport.promptCalls).toBe(2);
  });

  it("bounds the whole exchange when several locked candidates each need a prompt", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/item/locked"] }),
      unlock: () => ({ unlocked: [], promptPath: "/prompt/p1" }),
      prompt: async () => {
        await new Promise((resolve) => setTimeout(resolve, 350));
        return { dismissed: false, unlocked: ["/item/locked"] };
      },
      // Nothing usable comes back, so the sweep keeps reaching for another prompt.
      secretsFor: () => [],
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      promptTimeoutMs: 400,
      promptLatchMs: 0,
      transportFactory: async () => transport,
    });

    const startedAt = Date.now();
    await store.getSecrets({
      schemas: ["schema_v3", "schema_v2", "schema_v1"],
      applications: ["chrome", "brave", "edge"],
    });
    const elapsedMs = Date.now() - startedAt;

    // The ceiling is one machine budget plus one prompt budget, however many
    // candidates ask for a dialog. Without the per-prompt clamp the second
    // dialog would run its full sleep (~700ms) instead of being cut to the
    // remaining ceiling (~425ms).
    expect(transport.promptCalls).toBeGreaterThan(1);
    expect(elapsedMs).toBeLessThan(25 + 400 + 150);
    expect(transport.disposed).toBe(1);
  });

  it("does not raise a second dialog after a prompt nobody answered", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/item/locked"] }),
      unlock: () => ({ unlocked: [], promptPath: "/prompt/p1" }),
      // The dialog is never answered, so it ends only when its budget runs out —
      // exactly as long as the latch window that has to cover it.
      prompt: () => new Promise<never>(() => {}),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      promptTimeoutMs: 100,
      promptLatchMs: 100,
      transportFactory: async () => transport,
    });

    const startedAt = Date.now();
    await expect(
      store.getSecrets({ schemas: ["schema_v2"], applications: ["chrome"] }),
    ).resolves.toEqual({ state: "error", detail: "timeout" });
    // Another browser is another request key, but the same desktop keyring: it
    // must report the lock instead of raising a second dialog.
    await expect(
      store.getSecrets({ schemas: ["schema_v2"], applications: ["brave"] }),
    ).resolves.toEqual({ state: "locked" });
    expect(transport.promptCalls).toBe(1);
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it("shows a single dialog when two browsers ask for the keyring at once", async () => {
    const transport = createFakeTransport({
      search: () => ({ unlocked: [], locked: ["/item/locked"] }),
      unlock: () => ({ unlocked: [], promptPath: "/prompt/p1" }),
      prompt: () => new Promise<never>(() => {}),
    });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      promptTimeoutMs: 100,
      transportFactory: async () => transport,
    });

    const [first, second] = await Promise.all([
      store.getSecrets({ schemas: ["schema_v2"], applications: ["chrome"] }),
      store.getSecrets({ schemas: ["schema_v2"], applications: ["brave"] }),
    ]);
    expect(transport.promptCalls).toBe(1);
    expect(
      [first, second]
        .map((result) =>
          result.state === "error" ? `${result.state}/${result.detail}` : result.state,
        )
        .sort(),
    ).toEqual(["error/timeout", "locked"]);
  });

  it("does not leak a deadline timer when a transport call throws synchronously", async () => {
    const rejections: unknown[] = [];
    const onRejection = (reason: unknown): void => {
      rejections.push(reason);
    };
    process.on("unhandledRejection", onRejection);
    try {
      const transport = createFakeTransport({});
      transport.searchItems = () => {
        throw new Error("synchronous transport failure");
      };
      const store = createSecretServiceKeyStore({
        platform: "linux",
        timeoutMs: 25,
        transportFactory: async () => transport,
      });

      await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({
        state: "error",
        detail: "protocol",
      });
      // Past the guard timer: an orphaned one would reject with nothing handling it.
      await new Promise((resolve) => setTimeout(resolve, 80));
      expect(rejections).toEqual([]);
    } finally {
      process.off("unhandledRejection", onRejection);
    }
  });

  it("bounds teardown when the bus cannot be disposed", async () => {
    const transport = createFakeTransport({ hangOn: "searchItems", hangOnDispose: true });
    const store = createSecretServiceKeyStore({
      platform: "linux",
      timeoutMs: 25,
      transportFactory: async () => transport,
    });

    const startedAt = Date.now();
    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "error",
      detail: "timeout",
    });
    expect(Date.now() - startedAt).toBeLessThan(25 + SECRET_SERVICE_CLEANUP_TIMEOUT_MS + 2_000);
    expect(transport.disposed).toBe(1);
  });

  it("reports a missing secret when no candidate matches", async () => {
    const transport = createFakeTransport({});
    const store = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => transport,
    });

    await expect(store.getSecrets(CHROME_REQUEST)).resolves.toEqual({ state: "missing" });
    expect(transport.disposed).toBe(1);
  });

  it("classifies transport failures and still disposes the connection", async () => {
    const timeout = createFakeTransport({
      failOn: "searchItems",
      error: Object.assign(new Error("no reply"), { name: "TimeoutError" }),
    });
    const timeoutStore = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => timeout,
    });
    await expect(timeoutStore.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "error",
      detail: "timeout",
    });
    expect(timeout.disposed).toBe(1);
    expect(timeout.closedSessions).toEqual(["/org/freedesktop/secrets/session/s1"]);

    const denied = createFakeTransport({
      search: () => unlockedItem,
      failOn: "getSecrets",
      error: Object.assign(new Error("access refused"), {
        dbusName: "org.freedesktop.DBus.Error.AccessDenied",
      }),
    });
    const deniedStore = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => denied,
    });
    await expect(deniedStore.getSecrets(CHROME_REQUEST)).resolves.toEqual({
      state: "error",
      detail: "denied",
    });
    expect(denied.disposed).toBe(1);
  });

  it("caches failures briefly and never caches a successful lookup", async () => {
    let created = 0;
    const failing = () => createFakeTransport({ failOn: "openSession" });
    const failingStore = createSecretServiceKeyStore({
      platform: "linux",
      failureCacheMs: 60_000,
      transportFactory: async () => {
        created += 1;
        return failing();
      },
    });
    await failingStore.getSecrets(CHROME_REQUEST);
    await failingStore.getSecrets(CHROME_REQUEST);
    expect(created).toBe(1);

    let okCreated = 0;
    const okStore = createSecretServiceKeyStore({
      platform: "linux",
      transportFactory: async () => {
        okCreated += 1;
        return createFakeTransport({ search: () => unlockedItem });
      },
    });
    await okStore.getSecrets(CHROME_REQUEST);
    await okStore.getSecrets(CHROME_REQUEST);
    expect(okCreated).toBe(2);
  });

  it("retries after the failure cache expires", async () => {
    let created = 0;
    const store = createSecretServiceKeyStore({
      platform: "linux",
      failureCacheMs: 10,
      transportFactory: async () => {
        created += 1;
        return createFakeTransport({ failOn: "openSession" });
      },
    });
    await store.getSecrets(CHROME_REQUEST);
    await new Promise((resolve) => setTimeout(resolve, 20));
    await store.getSecrets(CHROME_REQUEST);
    expect(created).toBe(2);
  });

  it("bounds and orders the searched attribute candidates", () => {
    const candidates = secretAttributeCandidates({
      schemas: ["schema_v2", "schema_v1"],
      applications: ["chrome", "chromium", "brave"],
    });
    expect(candidates[0]).toEqual({ "xdg:schema": "schema_v2", application: "chrome" });
    expect(candidates).toHaveLength(Math.min(6, SECRET_SERVICE_MAX_CANDIDATES));

    const capped = secretAttributeCandidates({
      schemas: Array.from({ length: 20 }, (_, index) => `schema_${index}`),
      applications: ["app"],
    });
    expect(capped).toHaveLength(SECRET_SERVICE_MAX_CANDIDATES);

    expect(
      secretAttributeCandidates({ schemas: ["", "schema_v2"], applications: ["chrome", ""] }),
    ).toEqual([{ "xdg:schema": "schema_v2", application: "chrome" }]);
  });

  it("maps failures onto fixed categories without leaking raw error text", () => {
    expect(classifySecretServiceError(new SecretServiceError("timeout", "x"))).toBe("timeout");
    expect(
      classifySecretServiceError(Object.assign(new Error("late"), { code: "ETIMEDOUT" })),
    ).toBe("timeout");
    expect(classifySecretServiceError(new Error("org.freedesktop.DBus.Error.AccessDenied"))).toBe(
      "denied",
    );
    expect(
      classifySecretServiceError(
        new Error("The name org.freedesktop.secrets was not provided by any .service files"),
      ),
    ).toBe("no_session_bus");
    expect(classifySecretServiceError(new Error("ECONNREFUSED /run/user/1000/bus"))).toBe(
      "connect_failed",
    );
    expect(classifySecretServiceError("unexpected")).toBe("protocol");

    const details = new Set([
      classifySecretServiceError(new Error("password=hunter2 xdg:schema=chrome")),
      classifySecretServiceError(new Error("secret value leaked")),
    ]);
    for (const detail of details) {
      expect([
        "unsupported_platform",
        "no_session_bus",
        "connect_failed",
        "timeout",
        "denied",
        "protocol",
      ]).toContain(detail);
    }
  });
});

describe("Secret Service D-Bus transport", () => {
  beforeEach(() => {
    dbusMock.interfaces.clear();
    dbusMock.ended = 0;
    dbusMock.busOptions.length = 0;
    resetSecretServiceStateForTests();
  });

  function stubPrompt(promptPath: string): { prompts: number; dismissals: number } {
    const counters = { prompts: 0, dismissals: 0 };
    dbusMock.interfaces.set(`${promptPath} ${SECRET_SERVICE_PROMPT_INTERFACE}`, {
      Prompt: () => {
        counters.prompts += 1;
      },
      Dismiss: async () => {
        counters.dismissals += 1;
      },
      // The dialog never completes, so only the timeout path can settle it.
      once: () => {},
      off: () => {},
    });
    return counters;
  }

  it("dismisses the desktop dialog when the prompt budget runs out", async () => {
    const counters = stubPrompt("/prompt/p1");
    const transport = await createDbusSecretServiceTransport({
      timeoutMs: 5_000,
      promptTimeoutMs: 20,
    });

    await expect(transport.prompt("/prompt/p1")).rejects.toMatchObject({ detail: "timeout" });
    expect(counters.prompts).toBe(1);
    expect(counters.dismissals).toBe(1);

    await transport.dispose();
    expect(dbusMock.ended).toBe(1);
  });

  it("never waits for a prompt past the end of the exchange", async () => {
    const counters = stubPrompt("/prompt/p2");
    const transport = await createDbusSecretServiceTransport({
      timeoutMs: 60_000,
      promptTimeoutMs: 60_000,
      promptDeadlineAt: Date.now() + 25,
    });

    const startedAt = Date.now();
    await expect(transport.prompt("/prompt/p2")).rejects.toMatchObject({ detail: "timeout" });
    expect(Date.now() - startedAt).toBeLessThan(5_000);
    expect(counters.dismissals).toBe(1);

    await transport.dispose();
  });

  it("falls back to the exchange deadline when no prompt deadline is given", async () => {
    stubPrompt("/prompt/p3");
    const transport = await createDbusSecretServiceTransport({
      timeoutMs: 60_000,
      promptTimeoutMs: 60_000,
      deadlineAt: Date.now() + 25,
    });

    await expect(transport.prompt("/prompt/p3")).rejects.toMatchObject({ detail: "timeout" });
    await transport.dispose();
  });

  it("passes the exchange timeout to the bus and ends the connection on dispose", async () => {
    const transport = await createDbusSecretServiceTransport({
      timeoutMs: 1_500,
      promptTimeoutMs: 60_000,
    });
    expect(dbusMock.busOptions).toEqual([{ timeout: 1_500 }]);
    await transport.dispose();
    expect(dbusMock.ended).toBe(1);
  });

  it("reports a protocol violation as a fixed category", async () => {
    dbusMock.interfaces.set(`${SECRET_SERVICE_OBJECT_PATH} ${SECRET_SERVICE_INTERFACE}`, {
      // A reply without a usable session path must not be passed on as a session.
      OpenSession: () => ["v", NO_SESSION_PATH],
    });
    const transport = await createDbusSecretServiceTransport({
      timeoutMs: 1_000,
      promptTimeoutMs: 1_000,
    });

    await expect(transport.openSession()).rejects.toMatchObject({ detail: "protocol" });
    await transport.dispose();
  });
});
