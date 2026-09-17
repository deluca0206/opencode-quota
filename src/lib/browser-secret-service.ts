import {
  type SystemKeyStore,
  type SystemSecretDetail,
  type SystemSecretLookup,
  type SystemSecretRequest,
  systemSecretRequestKey,
} from "./browser-keystore.js";

export const SECRET_SERVICE_BUS_NAME = "org.freedesktop.secrets";
export const SECRET_SERVICE_OBJECT_PATH = "/org/freedesktop/secrets";
export const SECRET_SERVICE_INTERFACE = "org.freedesktop.Secret.Service";
export const SECRET_SERVICE_ITEM_INTERFACE = "org.freedesktop.Secret.Item";
export const SECRET_SERVICE_SESSION_INTERFACE = "org.freedesktop.Secret.Session";
export const SECRET_SERVICE_PROMPT_INTERFACE = "org.freedesktop.Secret.Prompt";

/** Bound for the whole keyring exchange; a hung bus must never stall a quota refresh. */
export const SECRET_SERVICE_TIMEOUT_MS = 5_000;

/** Bound for a user-facing unlock prompt, which waits for a human. */
export const SECRET_SERVICE_PROMPT_TIMEOUT_MS = 60_000;

/** How long a failed lookup is remembered, so an absent bus is not retried per render. */
export const SECRET_SERVICE_FAILURE_CACHE_MS = 60_000;

/** Cap on schema/application combinations tried for one request. */
export const SECRET_SERVICE_MAX_CANDIDATES = 8;

/**
 * Minimal Secret Service surface used by the key store.
 *
 * Injectable so the D-Bus exchange is testable without a session bus, and so a
 * future KWallet backend can reuse the same key-store logic.
 */
export interface SecretServiceTransport {
  openSession(): Promise<string>;
  searchItems(
    attributes: Readonly<Record<string, string>>,
  ): Promise<{ unlocked: string[]; locked: string[] }>;
  unlock(objectPaths: readonly string[]): Promise<{ unlocked: string[]; promptPath: string }>;
  prompt(promptPath: string): Promise<{ dismissed: boolean; unlocked: string[] }>;
  getSecrets(objectPaths: readonly string[], sessionPath: string): Promise<string[]>;
  closeSession(sessionPath: string): Promise<void>;
  dispose(): Promise<void>;
}

export type SecretServiceTransportFactory = (options: {
  timeoutMs: number;
  promptTimeoutMs: number;
}) => Promise<SecretServiceTransport>;

export interface SecretServiceKeyStoreOptions {
  platform?: NodeJS.Platform;
  transportFactory?: SecretServiceTransportFactory;
  timeoutMs?: number;
  promptTimeoutMs?: number;
  failureCacheMs?: number;
}

export class SecretServiceError extends Error {
  readonly detail: SystemSecretDetail;

  constructor(detail: SystemSecretDetail, message: string) {
    super(message);
    this.name = "SecretServiceError";
    this.detail = detail;
  }
}

const NO_PROMPT_PATH = "/";

/**
 * Secret Service key store.
 *
 * Searches the schema/application candidates a Chromium browser may have used,
 * unlocks the keyring through the desktop's own prompt when needed, and returns
 * the Safe Storage passwords. Nothing is created, modified, logged, or
 * persisted: the connection is disposed as soon as the exchange finishes.
 */
export function createSecretServiceKeyStore(
  options: SecretServiceKeyStoreOptions = {},
): SystemKeyStore {
  const platform = options.platform ?? process.platform;
  const timeoutMs = options.timeoutMs ?? SECRET_SERVICE_TIMEOUT_MS;
  const promptTimeoutMs = options.promptTimeoutMs ?? SECRET_SERVICE_PROMPT_TIMEOUT_MS;
  const failureCacheMs = options.failureCacheMs ?? SECRET_SERVICE_FAILURE_CACHE_MS;
  const failures = new Map<string, { lookup: SystemSecretLookup; at: number }>();

  return {
    id: "secret-service",

    async getSecrets(request: SystemSecretRequest): Promise<SystemSecretLookup> {
      if (platform !== "linux") {
        return { state: "unavailable", detail: "unsupported_platform" };
      }

      const key = systemSecretRequestKey(request);
      const cached = failures.get(key);
      if (cached && Date.now() - cached.at < failureCacheMs) return cached.lookup;

      let lookup: SystemSecretLookup;
      try {
        lookup = await lookupSecrets(request, {
          timeoutMs,
          promptTimeoutMs,
          transportFactory: options.transportFactory ?? createDbusSecretServiceTransport,
        });
      } catch (error) {
        lookup = { state: "error", detail: classifySecretServiceError(error) };
      }

      if (lookup.state === "available") {
        failures.delete(key);
      } else {
        failures.set(key, { lookup, at: Date.now() });
      }
      return lookup;
    },
  };
}

async function lookupSecrets(
  request: SystemSecretRequest,
  options: {
    timeoutMs: number;
    promptTimeoutMs: number;
    transportFactory: SecretServiceTransportFactory;
  },
): Promise<SystemSecretLookup> {
  const transport = await options.transportFactory({
    timeoutMs: options.timeoutMs,
    promptTimeoutMs: options.promptTimeoutMs,
  });
  let sessionPath: string | null = null;
  try {
    sessionPath = await transport.openSession();
    let sawLocked = false;

    for (const attributes of secretAttributeCandidates(request)) {
      const found = await transport.searchItems(attributes);
      let itemPaths = found.unlocked;

      if (itemPaths.length === 0 && found.locked.length > 0) {
        sawLocked = true;
        const unlocked = await transport.unlock(found.locked);
        itemPaths = unlocked.unlocked;
        if (
          itemPaths.length === 0 &&
          unlocked.promptPath &&
          unlocked.promptPath !== NO_PROMPT_PATH
        ) {
          const prompted = await transport.prompt(unlocked.promptPath);
          if (prompted.dismissed) return { state: "locked" };
          itemPaths = prompted.unlocked;
        }
      }

      if (itemPaths.length === 0) continue;

      const secrets = await transport.getSecrets(itemPaths, sessionPath);
      const usable = secrets.filter((secret) => secret.length > 0);
      if (usable.length > 0) return { state: "available", secrets: usable };
    }

    return sawLocked ? { state: "locked" } : { state: "missing" };
  } finally {
    if (sessionPath) {
      try {
        await transport.closeSession(sessionPath);
      } catch {
        // A session the service already dropped needs no cleanup.
      }
    }
    await transport.dispose();
  }
}

/**
 * Attribute sets to search, most specific first.
 *
 * Chromium's libsecret schema is constant while the `application` attribute
 * varies by product and, for some builds, falls back to the generic Chromium
 * identity. Every combination is bounded so a malformed request cannot fan out.
 */
export function secretAttributeCandidates(
  request: SystemSecretRequest,
): Array<Record<string, string>> {
  const candidates: Array<Record<string, string>> = [];
  for (const schema of request.schemas) {
    for (const application of request.applications) {
      if (!schema || !application) continue;
      candidates.push({ "xdg:schema": schema, application });
      if (candidates.length >= SECRET_SERVICE_MAX_CANDIDATES) return candidates;
    }
  }
  return candidates;
}

export function classifySecretServiceError(error: unknown): SystemSecretDetail {
  if (error instanceof SecretServiceError) return error.detail;
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : String(error ?? "");
  const dbusName = readStringProperty(error, "dbusName");
  const code = readStringProperty(error, "code");

  if (name === "TimeoutError" || name === "AbortError" || code === "ETIMEDOUT") return "timeout";
  if (/timed out|timeout/iu.test(message)) return "timeout";
  if (/AccessDenied|NotAuthorized|permission|denied/iu.test(`${dbusName} ${message}`)) {
    return "denied";
  }
  if (
    /ServiceUnknown|NameHasNoOwner|not provided|No such|spawn|ENOENT/iu.test(
      `${dbusName} ${message}`,
    )
  ) {
    return "no_session_bus";
  }
  if (/ECONNREFUSED|ENOTFOUND|DBusError|connect/iu.test(`${dbusName} ${message}`)) {
    return "connect_failed";
  }
  return "protocol";
}

function readStringProperty(value: unknown, key: string): string {
  if (typeof value !== "object" || value === null) return "";
  const candidate = (value as Record<string, unknown>)[key];
  return typeof candidate === "string" ? candidate : "";
}

export function resetSecretServiceStateForTests(): void {
  dbusModulePromise = null;
}

// ---------------------------------------------------------------------------
// D-Bus transport
// ---------------------------------------------------------------------------

type DbusMember = (...args: never[]) => unknown;

interface DbusInterfaceLike {
  [member: string]: DbusMember | unknown;
}

interface DbusServiceLike {
  getInterface(objectPath: string, interfaceName: string): Promise<DbusInterfaceLike>;
}

interface DbusBusLike {
  getService(busName: string): DbusServiceLike;
  connection?: { end?: unknown };
}

interface DbusModuleLike {
  sessionBus?: (options?: { timeout?: number }) => DbusBusLike;
  Variant?: new (signature: string, value: unknown) => unknown;
  variantValue?: (value: unknown) => unknown;
  default?: DbusModuleLike;
}

let dbusModulePromise: Promise<DbusModuleLike> | null = null;

/**
 * Load the D-Bus client lazily.
 *
 * The dependency is only resolved when a Chromium cookie actually needs a
 * keyring password, so non-Linux hosts and Firefox-only setups never touch it.
 */
async function loadDbusModule(): Promise<DbusModuleLike> {
  if (!dbusModulePromise) {
    dbusModulePromise = import("dbus-native")
      .then((loaded) => {
        const candidate = loaded as unknown as DbusModuleLike;
        return typeof candidate.sessionBus === "function" ? candidate : (candidate.default ?? {});
      })
      .catch(() => {
        dbusModulePromise = null;
        return {} as DbusModuleLike;
      });
  }
  return dbusModulePromise;
}

export const createDbusSecretServiceTransport: SecretServiceTransportFactory = async ({
  timeoutMs,
  promptTimeoutMs,
}) => {
  const dbus = await loadDbusModule();
  if (typeof dbus.sessionBus !== "function") {
    throw new SecretServiceError("no_session_bus", "D-Bus client is unavailable");
  }

  let bus: DbusBusLike;
  try {
    bus = dbus.sessionBus({ timeout: timeoutMs });
  } catch {
    throw new SecretServiceError("no_session_bus", "session bus is unavailable");
  }

  const service = bus.getService(SECRET_SERVICE_BUS_NAME);
  const unwrap = (value: unknown): unknown =>
    typeof dbus.variantValue === "function" ? dbus.variantValue(value) : value;

  const call = async (
    objectPath: string,
    interfaceName: string,
    member: string,
    args: unknown[],
  ): Promise<unknown> => {
    const iface = await service.getInterface(objectPath, interfaceName);
    const fn = iface[member];
    if (typeof fn !== "function") {
      throw new SecretServiceError("protocol", `Secret Service member ${member} is unavailable`);
    }
    // The generated proxy methods call back into the interface instance, so the
    // receiver has to be preserved.
    return await Reflect.apply(fn as (...values: unknown[]) => unknown, iface, args);
  };

  const dispose = async (): Promise<void> => {
    const end = bus.connection?.end;
    if (typeof end === "function") {
      try {
        (end as () => void).call(bus.connection);
      } catch {
        // A connection that already went away needs no second teardown.
      }
    }
  };

  return {
    async openSession(): Promise<string> {
      const emptyInput = dbus.Variant ? new dbus.Variant("s", "") : ["s", ""];
      const reply = await call(
        SECRET_SERVICE_OBJECT_PATH,
        SECRET_SERVICE_INTERFACE,
        "OpenSession",
        ["plain", emptyInput],
      );
      const sessionPath = Array.isArray(reply) ? reply[1] : undefined;
      if (typeof sessionPath !== "string" || sessionPath === NO_PROMPT_PATH) {
        throw new SecretServiceError("protocol", "Secret Service returned no session");
      }
      return sessionPath;
    },

    async searchItems(attributes) {
      const reply = await call(
        SECRET_SERVICE_OBJECT_PATH,
        SECRET_SERVICE_INTERFACE,
        "SearchItems",
        [attributes],
      );
      const [unlocked, locked] = Array.isArray(reply) ? reply : [];
      return { unlocked: asObjectPaths(unlocked), locked: asObjectPaths(locked) };
    },

    async unlock(objectPaths) {
      const reply = await call(SECRET_SERVICE_OBJECT_PATH, SECRET_SERVICE_INTERFACE, "Unlock", [
        [...objectPaths],
      ]);
      const [unlocked, promptPath] = Array.isArray(reply) ? reply : [];
      return {
        unlocked: asObjectPaths(unlocked),
        promptPath: typeof promptPath === "string" ? promptPath : NO_PROMPT_PATH,
      };
    },

    prompt(promptPath) {
      return withPromptCompletion(service, promptPath, promptTimeoutMs, unwrap, async (iface) => {
        const start = iface.Prompt;
        if (typeof start !== "function") {
          throw new SecretServiceError("protocol", "Secret Service prompt is unavailable");
        }
        Reflect.apply(start as (...values: unknown[]) => unknown, iface, [""]);
      });
    },

    async getSecrets(objectPaths, sessionPath) {
      const reply = await call(SECRET_SERVICE_OBJECT_PATH, SECRET_SERVICE_INTERFACE, "GetSecrets", [
        [...objectPaths],
        sessionPath,
      ]);
      const entries = asRecord(reply);
      const secrets: string[] = [];
      for (const value of Object.values(entries)) {
        const decoded = decodeSecretValue(value);
        if (decoded !== null) secrets.push(decoded);
      }
      return secrets;
    },

    async closeSession(sessionPath) {
      await call(sessionPath, SECRET_SERVICE_SESSION_INTERFACE, "Close", []);
    },

    dispose,
  };
};

/**
 * Wait for a prompt to complete.
 *
 * The desktop shows its own unlock dialog; the caller only observes the
 * `Completed` signal so no secret travels through this process twice.
 */
async function withPromptCompletion(
  service: DbusServiceLike,
  promptPath: string,
  timeoutMs: number,
  unwrap: (value: unknown) => unknown,
  start: (iface: DbusInterfaceLike) => Promise<void> | void,
): Promise<{ dismissed: boolean; unlocked: string[] }> {
  const iface = await service.getInterface(promptPath, SECRET_SERVICE_PROMPT_INTERFACE);
  const emitter = iface as unknown as {
    once?: (event: string, listener: (...args: unknown[]) => void) => unknown;
    off?: (event: string, listener: (...args: unknown[]) => void) => unknown;
  };
  if (typeof emitter.once !== "function") {
    throw new SecretServiceError("protocol", "Secret Service prompt cannot be observed");
  }

  return await new Promise<{ dismissed: boolean; unlocked: string[] }>((resolve, reject) => {
    const listener = (dismissed: unknown, result: unknown): void => {
      clearTimeout(timer);
      resolve({
        dismissed: dismissed === true,
        unlocked: asObjectPaths(unwrap(result)),
      });
    };
    const timer = setTimeout(() => {
      emitter.off?.("Completed", listener);
      reject(new SecretServiceError("timeout", "keyring unlock prompt timed out"));
    }, timeoutMs);
    if (typeof timer.unref === "function") timer.unref();

    emitter.once?.("Completed", listener);
    try {
      const started = start(iface);
      if (started instanceof Promise) started.catch(reject);
    } catch (error) {
      clearTimeout(timer);
      reject(error);
    }
  });
}

function asObjectPaths(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string" && entry !== "");
}

function asRecord(value: unknown): Record<string, unknown> {
  if (Array.isArray(value)) {
    const record: Record<string, unknown> = {};
    for (const entry of value) {
      if (Array.isArray(entry) && typeof entry[0] === "string") record[entry[0]] = entry[1];
    }
    return record;
  }
  if (typeof value === "object" && value !== null) return value as Record<string, unknown>;
  return {};
}

/** A Secret struct is `(oayays)`; only the value member is interesting here. */
function decodeSecretValue(secret: unknown): string | null {
  if (!Array.isArray(secret)) return null;
  const value = secret[2];
  const bytes = asBytes(value);
  return bytes === null ? null : Buffer.from(bytes).toString("utf8");
}

function asBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === "number")) {
    return Uint8Array.from(value as number[]);
  }
  return null;
}
