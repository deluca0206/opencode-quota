import {
  type SystemKeyStore,
  type SystemSecretDetail,
  type SystemSecretLookup,
  type SystemSecretRequest,
  systemSecretRequestKey,
  unavailableSystemKeyStore,
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

/** Bound for closing the session and bus once the exchange is over or timed out. */
export const SECRET_SERVICE_CLEANUP_TIMEOUT_MS = 500;

/** How long a failed lookup is remembered, so an absent bus is not retried per render. */
export const SECRET_SERVICE_FAILURE_CACHE_MS = 60_000;

/**
 * How long one user-facing unlock prompt covers every other lookup.
 *
 * A Secret Service prompt unlocks the whole collection, not one item, so asking
 * again straight afterwards cannot succeed where the first attempt did not — it
 * would only stack a dialog per installed Chromium browser. `0` disables the
 * latch.
 */
export const SECRET_SERVICE_PROMPT_LATCH_MS = 60_000;

/** Cap on schema/application combinations tried for one request. */
export const SECRET_SERVICE_MAX_CANDIDATES = 8;

/**
 * Cap on Safe Storage passwords returned for one request.
 *
 * More than one Chromium product can share a keyring, and any of them may be the
 * one that encrypted a given cookie database, so several candidates are kept in
 * priority order for the decryptor to validate.
 */
export const SECRET_SERVICE_MAX_SECRETS = 8;

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
  /** Wall-clock end of the machine-to-machine calls. */
  deadlineAt?: number;
  /**
   * Wall-clock end of the whole exchange, one unlock prompt included.
   *
   * A prompt waits for a human and is bounded by this rather than `deadlineAt`;
   * it falls back to `deadlineAt` when a factory is only given that.
   */
  promptDeadlineAt?: number;
}) => Promise<SecretServiceTransport>;

export interface SecretServiceKeyStoreOptions {
  platform?: NodeJS.Platform;
  transportFactory?: SecretServiceTransportFactory;
  timeoutMs?: number;
  promptTimeoutMs?: number;
  failureCacheMs?: number;
  /** Window in which one unlock prompt covers every lookup; `0` always prompts. */
  promptLatchMs?: number;
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
  const promptLatchMs = options.promptLatchMs ?? SECRET_SERVICE_PROMPT_LATCH_MS;
  const failures = new Map<string, { lookup: SystemSecretLookup; at: number }>();
  /** When this store last showed an unlock dialog; shared by every browser. */
  const promptLatch = { at: 0 };

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
          promptLatchMs,
          promptLatch,
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

/**
 * Wall-clock bound for one phase of the keyring exchange.
 *
 * Every individual call is raced against the remaining budget, and the bus is
 * disposed when the budget runs out — closing the connection is what actually
 * cancels an in-flight D-Bus call, since the protocol offers no cancellation.
 */
interface SecretServiceDeadline {
  /** Absolute end of the current budget, for callers that clamp their own timers. */
  readonly at: number;
  expired(): boolean;
  /** Grant another `ms`, never past the ceiling this deadline was built with. */
  extend(ms: number): void;
  run<T>(task: () => Promise<T>, label: string): Promise<T>;
}

function createSecretServiceDeadline(timeoutMs: number, ceilingAt?: number): SecretServiceDeadline {
  let deadlineAt = Date.now() + Math.max(0, timeoutMs);
  const timeout = (label: string): SecretServiceError =>
    new SecretServiceError("timeout", `Secret Service ${label} timed out`);
  return {
    get at() {
      return deadlineAt;
    },
    expired: () => Date.now() >= deadlineAt,
    extend(ms: number) {
      const extended = Date.now() + Math.max(0, ms);
      deadlineAt =
        ceilingAt === undefined ? extended : Math.min(ceilingAt, Math.max(deadlineAt, extended));
    },
    run(task, label) {
      const remaining = deadlineAt - Date.now();
      if (remaining <= 0) return Promise.reject(timeout(label));
      let timer: ReturnType<typeof setTimeout> | undefined;
      const guard = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(timeout(label)), remaining);
        if (typeof timer.unref === "function") timer.unref();
      });
      // The task is invoked inside a promise: a synchronous throw must not skip the
      // race and leave the guard timer behind as an unhandled rejection.
      return Promise.race([Promise.resolve().then(task), guard]).finally(() => {
        if (timer !== undefined) clearTimeout(timer);
      });
    },
  };
}

/**
 * Whether the user may be asked to unlock the keyring.
 *
 * One prompt unlocks the whole collection, so a second one inside the latch
 * window cannot help; it would only stack a dialog per installed browser while
 * every Chromium store is being read.
 */
function mayPrompt(latch: { at: number }, latchMs: number): boolean {
  if (latchMs <= 0 || latch.at === 0) return true;
  return Date.now() - latch.at >= latchMs;
}

async function lookupSecrets(
  request: SystemSecretRequest,
  options: {
    timeoutMs: number;
    promptTimeoutMs: number;
    promptLatchMs: number;
    promptLatch: { at: number };
    transportFactory: SecretServiceTransportFactory;
  },
): Promise<SystemSecretLookup> {
  const startedAt = Date.now();
  // An unlock prompt waits for a human, so the exchange as a whole may outlive the
  // machine-to-machine budget by exactly one prompt — but never more than that.
  const ceilingAt =
    startedAt + Math.max(0, options.timeoutMs) + Math.max(0, options.promptTimeoutMs);
  const deadline = createSecretServiceDeadline(options.timeoutMs, ceilingAt);
  const connecting = options.transportFactory({
    timeoutMs: options.timeoutMs,
    promptTimeoutMs: options.promptTimeoutMs,
    deadlineAt: deadline.at,
    promptDeadlineAt: ceilingAt,
  });
  let transport: SecretServiceTransport;
  try {
    transport = await deadline.run(() => connecting, "connection");
  } catch (error) {
    // A bus that arrives after the deadline must still be torn down.
    void connecting.then((late) => late.dispose()).catch(() => {});
    throw error;
  }

  let sessionPath: string | null = null;
  let sawLocked = false;
  let dismissed = false;
  // Every schema/application combination contributes candidates: the password that
  // encrypted a cookie database is not necessarily the first one found, so the
  // decryptor validates them in priority order instead of guessing here.
  const secrets: string[] = [];
  const seen = new Set<string>();
  try {
    sessionPath = await deadline.run(() => transport.openSession(), "session");

    for (const attributes of secretAttributeCandidates(request)) {
      if (secrets.length >= SECRET_SERVICE_MAX_SECRETS || deadline.expired()) break;
      const found = await deadline.run(() => transport.searchItems(attributes), "search");
      let itemPaths = found.unlocked;

      if (itemPaths.length === 0 && found.locked.length > 0) {
        sawLocked = true;
        // Never ask the user to unlock a keyring once a usable password is known.
        if (secrets.length === 0) {
          const locked = found.locked;
          const unlocked = await deadline.run(() => transport.unlock(locked), "unlock");
          itemPaths = unlocked.unlocked;
          if (
            itemPaths.length === 0 &&
            unlocked.promptPath &&
            unlocked.promptPath !== NO_PROMPT_PATH &&
            mayPrompt(options.promptLatch, options.promptLatchMs)
          ) {
            // Claim the latch before waiting, so a concurrent lookup cannot stack
            // a second dialog, and reclaim it once the dialog is gone: a prompt
            // nobody answers would otherwise consume exactly its own window and
            // let the next browser raise another one.
            options.promptLatch.at = Date.now();
            const promptPath = unlocked.promptPath;
            // The prompt gets its own budget: bounding a human interaction to the
            // few seconds the machine calls share would dismiss the desktop dialog
            // before it can be answered.
            const promptDeadline = createSecretServiceDeadline(
              Math.max(0, Math.min(options.promptTimeoutMs, ceilingAt - Date.now())),
            );
            let prompted: { dismissed: boolean; unlocked: string[] };
            try {
              prompted = await promptDeadline.run(() => transport.prompt(promptPath), "prompt");
            } finally {
              options.promptLatch.at = Date.now();
            }
            if (prompted.dismissed) {
              dismissed = true;
              break;
            }
            itemPaths = prompted.unlocked;
            // Waiting for the user spent the machine budget; the read that follows
            // still needs one, and the ceiling keeps the exchange bounded.
            deadline.extend(options.timeoutMs);
          }
        }
      }

      if (itemPaths.length === 0) continue;

      const paths = itemPaths;
      const session = sessionPath;
      const foundSecrets = await deadline.run(() => transport.getSecrets(paths, session), "read");
      for (const secret of foundSecrets) {
        if (!secret || seen.has(secret)) continue;
        seen.add(secret);
        secrets.push(secret);
        if (secrets.length >= SECRET_SERVICE_MAX_SECRETS) break;
      }
    }
  } catch (error) {
    // A later candidate that hangs or is refused must not throw away the
    // passwords already read: the decryptor validates each one on its own.
    if (secrets.length === 0) throw error;
  } finally {
    // Teardown is bounded too: a bus that stopped answering must not outlive the
    // exchange it was opened for.
    const cleanupMs = Math.min(options.timeoutMs, SECRET_SERVICE_CLEANUP_TIMEOUT_MS);
    if (sessionPath && !deadline.expired()) {
      const closing = sessionPath;
      await settleWithin(() => transport.closeSession(closing), cleanupMs);
    }
    await settleWithin(() => transport.dispose(), cleanupMs);
  }

  if (secrets.length > 0) return { state: "available", secrets };
  if (dismissed || sawLocked) return { state: "locked" };
  return { state: "missing" };
}

/** Await cleanup, giving up after `ms` instead of hanging the caller. */
async function settleWithin(task: () => Promise<unknown>, ms: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      task().catch(() => {}),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, Math.max(0, ms));
        if (typeof timer.unref === "function") timer.unref();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
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
  deadlineAt,
  promptDeadlineAt,
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
      // A prompt waits for a human, but never past the end of the exchange that
      // asked for it.
      const ceiling = promptDeadlineAt ?? deadlineAt;
      const budgetMs =
        ceiling === undefined
          ? promptTimeoutMs
          : Math.max(0, Math.min(promptTimeoutMs, ceiling - Date.now()));
      return withPromptCompletion(service, promptPath, budgetMs, unwrap, async (iface) => {
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
      // Leaving the desktop dialog open after giving up would keep prompting the
      // user for a keyring this process no longer waits for.
      void dismissPrompt(iface);
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

/** Best-effort `Prompt.Dismiss`; a dialog the service already closed needs none. */
async function dismissPrompt(iface: DbusInterfaceLike): Promise<void> {
  const dismiss = iface.Dismiss;
  if (typeof dismiss !== "function") return;
  try {
    await Reflect.apply(dismiss as (...values: unknown[]) => unknown, iface, []);
  } catch {
    // The prompt is already gone; there is nothing left to cancel.
  }
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

/**
 * Default key store for the running platform.
 *
 * Resolved once per process. Linux uses the Secret Service; everywhere else the
 * store reports itself unavailable so readers fall back to plaintext and `v10`
 * values without touching D-Bus.
 */
let resolvedKeyStore: SystemKeyStore | null = null;

export function resolveSystemKeyStore(
  platform: NodeJS.Platform = process.platform,
): SystemKeyStore {
  if (!resolvedKeyStore) {
    resolvedKeyStore =
      platform === "linux" ? createSecretServiceKeyStore({ platform }) : unavailableSystemKeyStore;
  }
  return resolvedKeyStore;
}

export function resetSystemKeyStoreForTests(): void {
  resolvedKeyStore = null;
}
