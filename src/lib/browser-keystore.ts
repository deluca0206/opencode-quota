/**
 * System key store abstraction.
 *
 * Chromium browsers on Linux keep the password that protects their cookie
 * encryption key (`v11` values) in the desktop keyring. Reading it must not
 * require an external command, a native binding, or any user configuration, so
 * the default backend speaks the freedesktop Secret Service API over the
 * session D-Bus. Backends are pluggable so KWallet-only desktops, the macOS
 * Keychain, or Windows DPAPI can be added without touching browser readers.
 */

/** Outcome of one keyring lookup. `detail` is a fixed category, never raw error text. */
export type SystemSecretDetail =
  | "unsupported_platform"
  | "no_session_bus"
  | "connect_failed"
  | "timeout"
  | "denied"
  | "protocol";

export type SystemSecretLookup =
  | { state: "available"; secrets: string[] }
  | { state: "missing" }
  | { state: "locked" }
  | { state: "unavailable"; detail?: SystemSecretDetail }
  | { state: "error"; detail?: SystemSecretDetail };

export interface SystemSecretRequest {
  /** libsecret schema names to search, most specific first. */
  schemas: readonly string[];
  /** `application` attribute candidates accepted by those schemas. */
  applications: readonly string[];
}

export interface SystemKeyStore {
  /** Stable backend identifier used in diagnostics, e.g. `secret-service`. */
  readonly id: string;
  getSecrets(request: SystemSecretRequest): Promise<SystemSecretLookup>;
}

/** Backend used where no keyring integration exists; every lookup is unavailable. */
export const unavailableSystemKeyStore: SystemKeyStore = {
  id: "none",
  async getSecrets(): Promise<SystemSecretLookup> {
    return { state: "unavailable", detail: "unsupported_platform" };
  },
};

export function systemSecretRequestKey(request: SystemSecretRequest): string {
  return `${request.schemas.join(",")}::${request.applications.join(",")}`;
}
