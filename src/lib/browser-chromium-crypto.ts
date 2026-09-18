import { createDecipheriv, createHash, pbkdf2Sync } from "node:crypto";

/**
 * Chromium cookie value decryption for Linux.
 *
 * `v10` and `v11` are encryption-format tags, not browser versions: both use
 * PBKDF2-SHA1 over `saltysalt` with a single iteration and AES-128-CBC. They
 * differ only in where the password comes from — the well-known local fallback
 * for `v10`, and the desktop keyring's Safe Storage entry for `v11`.
 */
export const CHROMIUM_SALT = "saltysalt";
export const CHROMIUM_KEY_LENGTH = 16;
export const CHROMIUM_LOCAL_PREFIX = "v10";
export const CHROMIUM_KEYRING_PREFIX = "v11";
/** Password Chromium uses when no keyring is available. */
export const CHROMIUM_FALLBACK_PASSWORD = "peanuts";
/** Cookie schema that binds an encrypted value to a SHA-256 digest of its host. */
export const CHROMIUM_HOST_DIGEST_SCHEMA_VERSION = 24;
export const CHROMIUM_HOST_DIGEST_BYTES = 32;
export const CHROMIUM_IV_BYTE = 0x20;

export type ChromiumValueProtection = "plaintext" | "local" | "keyring" | "unsupported";

/** Version tags look like `v10`; anything else in an encrypted value is legacy data. */
const VERSION_PREFIX_PATTERN = /^v\d+$/u;

export type ChromiumDecryptionResult =
  | { state: "decrypted"; value: string }
  | { state: "keyring" }
  | { state: "unsupported"; prefix: string }
  | { state: "invalid" };

export interface ChromiumDecryptionContext {
  /** `encrypted_value` column. */
  encryptedValue: Uint8Array | null;
  /** `value` column, used when the row is not encrypted. */
  plaintextValue?: unknown;
  /** `host_key` column, needed to validate schema 24 payloads. */
  hostKey: string;
  /** `meta.version` of the cookie database; 0 when the store predates it. */
  schemaVersion: number;
  /** Safe Storage passwords for `v11`, most likely first. */
  keyringPasswords?: readonly string[];
}

export function chromiumValueProtection(bytes: Uint8Array | null): ChromiumValueProtection {
  const prefix = chromiumEncryptedPrefix(bytes);
  if (prefix === CHROMIUM_LOCAL_PREFIX) return "local";
  if (prefix === CHROMIUM_KEYRING_PREFIX) return "keyring";
  if (isChromiumVersionPrefix(prefix)) return "unsupported";
  // No version tag: either an empty value or legacy data stored unencrypted.
  return "plaintext";
}

export function isChromiumVersionPrefix(prefix: string): boolean {
  return VERSION_PREFIX_PATTERN.test(prefix);
}

/** First three bytes of an encrypted value, or an empty string when unencrypted. */
export function chromiumEncryptedPrefix(bytes: Uint8Array | null): string {
  if (!bytes || bytes.length === 0) return "";
  return Buffer.from(bytes.subarray(0, 3)).toString("latin1");
}

export function deriveChromiumKey(password: string): Buffer {
  return pbkdf2Sync(password, CHROMIUM_SALT, 1, CHROMIUM_KEY_LENGTH, "sha1");
}

/**
 * Decrypt one Chromium cookie value.
 *
 * Every candidate password is validated by the payload itself: schema 24 stores
 * a SHA-256 digest of the host key ahead of the value, so a wrong key fails the
 * digest instead of producing garbage that would be sent as a cookie.
 */
export function decryptChromiumCookieValue(
  context: ChromiumDecryptionContext,
): ChromiumDecryptionResult {
  if (typeof context.plaintextValue === "string" && context.plaintextValue.length > 0) {
    return { state: "decrypted", value: context.plaintextValue };
  }

  const bytes = context.encryptedValue;
  if (!bytes || bytes.length === 0) return { state: "invalid" };
  const prefix = chromiumEncryptedPrefix(bytes);

  if (prefix === CHROMIUM_LOCAL_PREFIX) {
    return decryptWithPassword(bytes, CHROMIUM_FALLBACK_PASSWORD, context);
  }

  if (prefix === CHROMIUM_KEYRING_PREFIX) {
    const passwords = context.keyringPasswords ?? [];
    if (passwords.length === 0) return { state: "keyring" };
    for (const password of passwords) {
      const result = decryptWithPassword(bytes, password, context);
      if (result.state === "decrypted") return result;
    }
    return { state: "invalid" };
  }

  if (isChromiumVersionPrefix(prefix)) {
    // A newer format (Windows app-bound `v20`, for example) must never be read
    // as text: reporting it keeps the value out of the cookie jar.
    return { state: "unsupported", prefix };
  }

  const legacy = printableOrNull(Buffer.from(bytes).toString("utf8"));
  return legacy === null ? { state: "invalid" } : { state: "decrypted", value: legacy };
}

function decryptWithPassword(
  bytes: Uint8Array,
  password: string,
  context: ChromiumDecryptionContext,
): ChromiumDecryptionResult {
  // The derived key and the decrypted bytes are only useful inside this call, so
  // both are cleared as soon as the value has been read out of them.
  const key = deriveChromiumKey(password);
  try {
    const decipher = createDecipheriv("aes-128-cbc", key, Buffer.alloc(16, CHROMIUM_IV_BYTE));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(bytes.subarray(3))),
      decipher.final(),
    ]);
    try {
      const value = stripHostDigest(plain, context);
      if (value === null) return { state: "invalid" };
      const text = printableOrNull(value.toString("utf8"));
      return text === null ? { state: "invalid" } : { state: "decrypted", value: text };
    } finally {
      plain.fill(0);
    }
  } catch {
    return { state: "invalid" };
  } finally {
    key.fill(0);
  }
}

/**
 * Remove the host binding Chromium adds from cookie schema 24 onwards.
 *
 * Returns `null` when the digest does not match the row's host, which is how a
 * wrong decryption key is detected.
 */
function stripHostDigest(plain: Buffer, context: ChromiumDecryptionContext): Buffer | null {
  if (context.schemaVersion < CHROMIUM_HOST_DIGEST_SCHEMA_VERSION) return plain;
  if (plain.length <= CHROMIUM_HOST_DIGEST_BYTES) return null;
  const digest = plain.subarray(0, CHROMIUM_HOST_DIGEST_BYTES);
  const expected = createHash("sha256").update(context.hostKey, "utf8").digest();
  return digest.equals(expected) ? plain.subarray(CHROMIUM_HOST_DIGEST_BYTES) : null;
}

function printableOrNull(value: string): string | null {
  if (value.length === 0) return null;
  // Reject padding garbage from a wrong key instead of sending it as a cookie.
  return /^[\u0020-\u007E]+$/u.test(value) ? value : null;
}
