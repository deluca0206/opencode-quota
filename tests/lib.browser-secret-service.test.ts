import { beforeEach, describe, expect, it } from "vitest";
import type { SystemSecretRequest } from "../src/lib/browser-keystore.js";
import {
  classifySecretServiceError,
  createSecretServiceKeyStore,
  SECRET_SERVICE_MAX_CANDIDATES,
  SecretServiceError,
  type SecretServiceTransport,
  secretAttributeCandidates,
} from "../src/lib/browser-secret-service.js";

const CHROME_REQUEST: SystemSecretRequest = {
  schemas: ["chrome_libsecret_os_crypt_password_v2", "chrome_libsecret_os_crypt_password_v1"],
  applications: ["chrome"],
};

interface FakeTransport extends SecretServiceTransport {
  readonly searched: Array<Record<string, string>>;
  disposed: number;
  closedSessions: string[];
}

function createFakeTransport(behavior: {
  search?: (attributes: Record<string, string>) => { unlocked: string[]; locked: string[] };
  unlock?: () => { unlocked: string[]; promptPath: string };
  prompt?: () => { dismissed: boolean; unlocked: string[] };
  secrets?: string[];
  failOn?: "openSession" | "searchItems" | "getSecrets";
  error?: unknown;
}): FakeTransport {
  const searched: Array<Record<string, string>> = [];
  let disposed = 0;
  const closedSessions: string[] = [];

  const transport: FakeTransport = {
    searched,
    get disposed() {
      return disposed;
    },
    closedSessions,

    async openSession() {
      if (behavior.failOn === "openSession") throw behavior.error ?? new Error("open failed");
      return "/org/freedesktop/secrets/session/s1";
    },

    async searchItems(attributes) {
      searched.push({ ...attributes });
      if (behavior.failOn === "searchItems") throw behavior.error ?? new Error("search failed");
      return behavior.search?.(attributes) ?? { unlocked: [], locked: [] };
    },

    async unlock(objectPaths) {
      return behavior.unlock?.() ?? { unlocked: [...objectPaths], promptPath: "/" };
    },

    async prompt() {
      return (
        behavior.prompt?.() ?? {
          dismissed: false,
          unlocked: ["/org/freedesktop/secrets/collection/login/1"],
        }
      );
    },

    async getSecrets() {
      if (behavior.failOn === "getSecrets") throw behavior.error ?? new Error("read failed");
      return behavior.secrets ?? ["safe-storage-password"];
    },

    async closeSession(sessionPath) {
      closedSessions.push(sessionPath);
    },

    async dispose() {
      disposed += 1;
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
