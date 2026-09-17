import { describe, expect, it } from "vitest";

import {
  CHROMIUM_FALLBACK_PASSWORD,
  CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
  chromiumEncryptedPrefix,
  chromiumValueProtection,
  decryptChromiumCookieValue,
  deriveChromiumKey,
} from "../src/lib/browser-chromium-crypto.js";
import {
  encryptChromiumValue,
  FIXTURE_SAFE_STORAGE_PASSWORD,
} from "./helpers/browser-chromium-fixtures.js";

const HOST = ".qwencloud.com";
const TICKET = "ticket-value-1234567890";

describe("Chromium cookie decryption", () => {
  it("derives a 16-byte AES key from the Safe Storage password", () => {
    const key = deriveChromiumKey(FIXTURE_SAFE_STORAGE_PASSWORD);
    expect(key).toHaveLength(16);
    expect(deriveChromiumKey(FIXTURE_SAFE_STORAGE_PASSWORD).equals(key)).toBe(true);
    expect(deriveChromiumKey(CHROMIUM_FALLBACK_PASSWORD).equals(key)).toBe(false);
  });

  it("classifies the encryption format from the value prefix", () => {
    expect(chromiumEncryptedPrefix(null)).toBe("");
    expect(chromiumValueProtection(null)).toBe("plaintext");
    expect(chromiumValueProtection(Buffer.alloc(0))).toBe("plaintext");
    expect(chromiumValueProtection(Buffer.from("v10abc", "latin1"))).toBe("local");
    expect(chromiumValueProtection(Buffer.from("v11abc", "latin1"))).toBe("keyring");
    expect(chromiumValueProtection(Buffer.from("v20abc", "latin1"))).toBe("unsupported");
    // Legacy rows stored unencrypted in `encrypted_value` carry no version tag.
    expect(chromiumValueProtection(Buffer.from("plain", "utf8"))).toBe("plaintext");
  });

  it("decrypts a v10 value with the local fallback password", () => {
    const value = encryptChromiumValue({ value: TICKET, prefix: "v10" });
    expect(
      decryptChromiumCookieValue({
        encryptedValue: value,
        hostKey: HOST,
        schemaVersion: 10,
      }),
    ).toEqual({ state: "decrypted", value: TICKET });
  });

  it("decrypts a v11 value with the keyring password", () => {
    const value = encryptChromiumValue({ value: TICKET, prefix: "v11" });
    expect(
      decryptChromiumCookieValue({
        encryptedValue: value,
        hostKey: HOST,
        schemaVersion: 10,
        keyringPasswords: [FIXTURE_SAFE_STORAGE_PASSWORD],
      }),
    ).toEqual({ state: "decrypted", value: TICKET });
  });

  it("reports keyring protection when no password is supplied", () => {
    const value = encryptChromiumValue({ value: TICKET, prefix: "v11" });
    expect(
      decryptChromiumCookieValue({ encryptedValue: value, hostKey: HOST, schemaVersion: 10 }),
    ).toEqual({ state: "keyring" });
  });

  it("rejects a v11 value when every candidate password is wrong", () => {
    const value = encryptChromiumValue({ value: TICKET, prefix: "v11" });
    expect(
      decryptChromiumCookieValue({
        encryptedValue: value,
        hostKey: HOST,
        schemaVersion: 10,
        keyringPasswords: ["not-the-password", "also-wrong"],
      }),
    ).toEqual({ state: "invalid" });
  });

  it("tries every candidate password until one decrypts", () => {
    const value = encryptChromiumValue({ value: TICKET, prefix: "v11" });
    expect(
      decryptChromiumCookieValue({
        encryptedValue: value,
        hostKey: HOST,
        schemaVersion: 10,
        keyringPasswords: ["stale-password", FIXTURE_SAFE_STORAGE_PASSWORD],
      }),
    ).toEqual({ state: "decrypted", value: TICKET });
  });

  it("strips and validates the host digest from schema 24 onwards", () => {
    const value = encryptChromiumValue({
      value: TICKET,
      prefix: "v11",
      schemaVersion: CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
      hostKey: HOST,
    });
    expect(
      decryptChromiumCookieValue({
        encryptedValue: value,
        hostKey: HOST,
        schemaVersion: CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
        keyringPasswords: [FIXTURE_SAFE_STORAGE_PASSWORD],
      }),
    ).toEqual({ state: "decrypted", value: TICKET });
  });

  it("rejects a schema 24 payload bound to a different host", () => {
    const value = encryptChromiumValue({
      value: TICKET,
      prefix: "v11",
      schemaVersion: CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
      hostKey: ".evil.example",
    });
    expect(
      decryptChromiumCookieValue({
        encryptedValue: value,
        hostKey: HOST,
        schemaVersion: CHROMIUM_HOST_DIGEST_SCHEMA_VERSION,
        keyringPasswords: [FIXTURE_SAFE_STORAGE_PASSWORD],
      }),
    ).toEqual({ state: "invalid" });
  });

  it("reports an unsupported format instead of reading it as text", () => {
    const value = Buffer.concat([Buffer.from("v20", "latin1"), Buffer.from(TICKET, "utf8")]);
    expect(
      decryptChromiumCookieValue({ encryptedValue: value, hostKey: HOST, schemaVersion: 24 }),
    ).toEqual({ state: "unsupported", prefix: "v20" });
  });

  it("prefers the plaintext column and rejects unusable values", () => {
    expect(
      decryptChromiumCookieValue({
        encryptedValue: null,
        plaintextValue: "plain-ticket",
        hostKey: HOST,
        schemaVersion: 24,
      }),
    ).toEqual({ state: "decrypted", value: "plain-ticket" });

    expect(
      decryptChromiumCookieValue({ encryptedValue: null, hostKey: HOST, schemaVersion: 24 }),
    ).toEqual({ state: "invalid" });

    expect(
      decryptChromiumCookieValue({
        encryptedValue: Buffer.alloc(0),
        hostKey: HOST,
        schemaVersion: 24,
      }),
    ).toEqual({ state: "invalid" });

    expect(
      decryptChromiumCookieValue({
        encryptedValue: Buffer.from("v10\x00\x01\x02\x03\x04", "latin1"),
        hostKey: HOST,
        schemaVersion: 10,
      }),
    ).toEqual({ state: "invalid" });
  });

  it("reads a legacy unencrypted value stored in encrypted_value", () => {
    expect(
      decryptChromiumCookieValue({
        encryptedValue: Buffer.from("legacy-value", "utf8"),
        hostKey: HOST,
        schemaVersion: 0,
      }),
    ).toEqual({ state: "decrypted", value: "legacy-value" });
  });
});
