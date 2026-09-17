import { createCipheriv, createHash, pbkdf2Sync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

/** Microseconds between 1601-01-01 and the Unix epoch. */
export const CHROMIUM_EPOCH_OFFSET_MS = 11_644_473_600_000;

/** Password used by fixtures that simulate a keyring-protected browser. */
export const FIXTURE_SAFE_STORAGE_PASSWORD = "fixture-safe-storage-password";

export function toChromiumExpiry(unixMs: number): string {
  return String(BigInt(unixMs + CHROMIUM_EPOCH_OFFSET_MS) * 1000n);
}

export interface EncryptChromiumValueParams {
  value: string;
  /** `v10` uses the local fallback password; `v11` a keyring password. */
  prefix?: "v10" | "v11" | "v20";
  password?: string;
  /** Cookie database schema version; 24 and above bind the value to its host. */
  schemaVersion?: number;
  hostKey?: string;
}

export function encryptChromiumValue(params: EncryptChromiumValueParams): Buffer {
  const prefix = params.prefix ?? "v10";
  const password =
    params.password ?? (prefix === "v10" ? "peanuts" : FIXTURE_SAFE_STORAGE_PASSWORD);
  const key = pbkdf2Sync(password, "saltysalt", 1, 16, "sha1");
  const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(16, 0x20));

  // Chromium encrypts the host digest together with the value, so the digest is
  // part of the plaintext rather than a prefix of the ciphertext.
  const schemaVersion = params.schemaVersion ?? 0;
  const hostKey = params.hostKey;
  const plaintext =
    schemaVersion >= 24 && hostKey
      ? Buffer.concat([
          createHash("sha256").update(hostKey, "utf8").digest(),
          Buffer.from(params.value, "utf8"),
        ])
      : Buffer.from(params.value, "utf8");

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from(prefix, "latin1"), encrypted]);
}

export interface FixtureCookie {
  host: string;
  name: string;
  value: string;
  expiresUtc?: string;
  /** Store the value in the plaintext `value` column instead of encrypting it. */
  plaintext?: boolean;
  prefix?: "v10" | "v11" | "v20";
  password?: string;
  /** Encrypt with a payload whose host digest does not match the row host. */
  hostKeyOverride?: string;
}

export interface CreateChromiumProfileParams {
  rootPath: string;
  profile?: string;
  schemaVersion?: number;
  /** `null` skips the file entirely. */
  localState?: string | null;
  cookies?: FixtureCookie[];
  dbRel?: "Cookies" | "Network/Cookies";
  nowMs: number;
}

/** Create a Chromium profile directory with a cookie database; returns its path. */
export async function createChromiumProfile(params: CreateChromiumProfileParams): Promise<string> {
  const profile = params.profile ?? "Default";
  const profilePath = profile === "(root)" ? params.rootPath : join(params.rootPath, profile);
  await mkdir(profilePath, { recursive: true });

  if (params.localState !== null && profile !== "(root)") {
    await writeFile(join(params.rootPath, "Local State"), params.localState ?? "{}");
  }

  const rel = params.dbRel ?? "Cookies";
  const dbPath = join(profilePath, ...rel.split("/"));
  await mkdir(join(dbPath, ".."), { recursive: true });

  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL PRIMARY KEY,
    host_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    encrypted_value BLOB DEFAULT '',
    path TEXT NOT NULL DEFAULT '/',
    expires_utc INTEGER NOT NULL DEFAULT 0,
    is_secure INTEGER NOT NULL DEFAULT 0
  )`);
  if (params.schemaVersion !== undefined) {
    db.exec(
      "CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR NOT NULL)",
    );
    db.prepare("INSERT INTO meta (key, value) VALUES ('version', ?)").run(
      String(params.schemaVersion),
    );
  }

  const insert = db.prepare(
    `INSERT INTO cookies (creation_utc, host_key, name, value, encrypted_value, path, expires_utc, is_secure)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  let index = 0;
  for (const cookie of params.cookies ?? []) {
    const encrypted = cookie.plaintext
      ? Buffer.alloc(0)
      : encryptChromiumValue({
          value: cookie.value,
          prefix: cookie.prefix,
          password: cookie.password,
          schemaVersion: params.schemaVersion,
          hostKey: cookie.hostKeyOverride ?? cookie.host,
        });
    insert.run(
      index++,
      cookie.host,
      cookie.name,
      cookie.plaintext ? cookie.value : "",
      encrypted,
      "/",
      cookie.expiresUtc ?? toChromiumExpiry(params.nowMs + 3_600_000),
      1,
    );
  }
  db.close();
  return dbPath;
}
