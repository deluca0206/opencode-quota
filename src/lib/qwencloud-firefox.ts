import { access, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  cookieExpiryDeadlineMs,
  firefoxCookieHostSql,
  isQwenCloudCookieDomain,
  type QwenCloudCookie,
} from "./qwencloud-cookies.js";
import { type OpenBrowserStoreOptions, openBrowserCookieDatabase } from "./qwencloud-store-open.js";

export interface FirefoxProfile {
  name: string;
  path: string;
  isDefault: boolean;
}

type MozCookieRow = {
  name: unknown;
  value: unknown;
  host: unknown;
  path: unknown;
  expiry: unknown;
  isSecure: unknown;
  originAttributes: unknown;
};

export function firefoxProfileRoots(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): string[] {
  const home = params?.homeDir ?? homedir();
  const env = params?.env ?? process.env;
  const extra = env.QWEN_CLOUD_FIREFOX_HOME?.trim();
  return [
    ...(extra ? [extra] : []),
    join(home, ".mozilla", "firefox"),
    join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
  ];
}

export function parseFirefoxInstallDefaultPaths(content: string, root: string): string[] {
  const paths: string[] = [];
  let section: string | null = null;
  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(";")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1);
      continue;
    }
    if (!section || section.toLowerCase().startsWith("profile")) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key !== "default" || !value || value === "0" || value === "1") continue;
    paths.push(value.startsWith("/") ? value : join(root, value));
  }
  return paths;
}

export function parseFirefoxProfilesIni(content: string, root: string): FirefoxProfile[] {
  const profiles: FirefoxProfile[] = [];
  let current: { name?: string; path?: string; isRelative?: boolean; isDefault?: boolean } | null =
    null;

  const flush = (): void => {
    if (!current?.path) {
      current = null;
      return;
    }
    const profilePath = current.isRelative === false ? current.path : join(root, current.path);
    profiles.push({
      name: current.name?.trim() || current.path,
      path: profilePath,
      isDefault: current.isDefault === true,
    });
    current = null;
  };

  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(";")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      flush();
      const section = line.slice(1, -1);
      current = section.toLowerCase().startsWith("profile") ? {} : null;
      continue;
    }
    if (!current) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key === "name") current.name = value;
    if (key === "path") current.path = value;
    if (key === "isrelative") current.isRelative = value !== "0";
    if (key === "default") current.isDefault = value === "1";
  }
  flush();
  return profiles;
}

export async function listFirefoxProfiles(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<FirefoxProfile[]> {
  const roots = firefoxProfileRoots(params);
  const profiles: FirefoxProfile[] = [];
  const seen = new Set<string>();
  for (const root of roots) {
    let content: string;
    try {
      content = await readFile(join(root, "profiles.ini"), "utf8");
    } catch {
      continue;
    }
    for (const profile of parseFirefoxProfilesIni(content, root)) {
      if (seen.has(profile.path)) continue;
      seen.add(profile.path);
      profiles.push(profile);
    }
  }
  return profiles;
}

export async function listFirefoxInstallDefaultPaths(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<string[]> {
  const roots = firefoxProfileRoots(params);
  const paths: string[] = [];
  const seen = new Set<string>();
  for (const root of roots) {
    for (const fileName of ["profiles.ini", "installs.ini"]) {
      let content: string;
      try {
        content = await readFile(join(root, fileName), "utf8");
      } catch {
        continue;
      }
      for (const profilePath of parseFirefoxInstallDefaultPaths(content, root)) {
        if (seen.has(profilePath)) continue;
        seen.add(profilePath);
        paths.push(profilePath);
      }
    }
  }
  return paths;
}

/**
 * Firefox profiles that actually hold a cookie database.
 *
 * `isDefault` also reflects the install-level default from `installs.ini`, so a
 * stale `Default=1` profile that was never used does not win over the profile
 * the browser really runs.
 */
export async function listFirefoxCookieStores(params?: {
  homeDir?: string;
  env?: NodeJS.ProcessEnv;
}): Promise<FirefoxProfile[]> {
  const profiles = await listFirefoxProfiles(params);
  if (profiles.length === 0) return [];
  const installDefaultPaths = await listFirefoxInstallDefaultPaths(params);
  const withCookies = await profilesWithCookieDatabase(profiles);
  const candidates = withCookies.length > 0 ? withCookies : profiles;
  return candidates.map((profile) => ({
    ...profile,
    isDefault:
      profile.isDefault ||
      installDefaultPaths.some((installPath) => profileMatchesInstallPath(profile, installPath)),
  }));
}

export async function readFirefoxCookies(
  profilePath: string,
  nowMs: number,
): Promise<QwenCloudCookie[]> {
  return await readFirefoxCookieDatabase(join(profilePath, "cookies.sqlite"), nowMs);
}

export async function readFirefoxCookieDatabase(
  dbPath: string,
  nowMs: number,
  options?: OpenBrowserStoreOptions,
): Promise<QwenCloudCookie[]> {
  return await queryFirefoxCookies(dbPath, nowMs, options);
}

async function queryFirefoxCookies(
  dbPath: string,
  nowMs: number,
  options?: OpenBrowserStoreOptions,
): Promise<QwenCloudCookie[]> {
  const db = await openBrowserCookieDatabase(dbPath, options);
  if (!db) throw new Error("Firefox cookie database could not be opened");
  try {
    const expirySeconds = Math.floor(nowMs / 1000);
    const hostFilter = firefoxCookieHostSql();
    const rows = db.all<MozCookieRow>(
      `SELECT name, value, host, path, expiry, isSecure, originAttributes
       FROM moz_cookies
       WHERE name IS NOT NULL AND value IS NOT NULL AND host IS NOT NULL
         AND (expiry = 0 OR expiry > ?)
         AND (originAttributes IS NULL OR originAttributes = '')
         AND (${hostFilter.sql})`,
      [expirySeconds, ...hostFilter.params],
    );
    return rows.flatMap((row) => {
      if (typeof row.name !== "string" || typeof row.value !== "string") return [];
      if (typeof row.host !== "string" || !isQwenCloudCookieDomain(row.host)) return [];
      if (!row.name || !row.value) return [];
      const expiry = typeof row.expiry === "number" ? row.expiry : undefined;
      const expiryMs = cookieExpiryDeadlineMs(expiry);
      if (expiryMs !== undefined && expiryMs <= nowMs) return [];
      return [
        {
          name: row.name,
          value: row.value,
          host: row.host,
          path: typeof row.path === "string" && row.path ? row.path : "/",
          expiry,
          secure: row.isSecure === 1 || row.isSecure === true,
          originAttributes: typeof row.originAttributes === "string" ? row.originAttributes : "",
        },
      ];
    });
  } finally {
    db.close();
  }
}

async function profilesWithCookieDatabase(
  profiles: readonly FirefoxProfile[],
): Promise<FirefoxProfile[]> {
  const matched: FirefoxProfile[] = [];
  for (const profile of profiles) {
    try {
      await access(join(profile.path, "cookies.sqlite"));
      matched.push(profile);
    } catch {
      // Skip unused Firefox profiles that never created a cookie database.
    }
  }
  return matched;
}

function profileMatchesInstallPath(profile: FirefoxProfile, installPath: string): boolean {
  return (
    profile.path === installPath ||
    profile.path.endsWith(`/${installPath}`) ||
    profile.path.endsWith(`\\${installPath}`)
  );
}
