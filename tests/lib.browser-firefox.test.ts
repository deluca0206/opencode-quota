import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";

import {
  listFirefoxCookieStores,
  parseFirefoxInstallDefaultPaths,
  parseFirefoxProfilesIni,
  readFirefoxCookieDatabase,
} from "../src/lib/browser-firefox.js";

const tempRoots: string[] = [];
const NOW_MS = 1_700_000_000_000;

async function createHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "qwencloud-firefox-"));
  tempRoots.push(root);
  return root;
}

function writeCookies(profilePath: string, rows: Array<Record<string, unknown>>): void {
  const db = new DatabaseSync(join(profilePath, "cookies.sqlite"));
  db.exec(`CREATE TABLE moz_cookies (
    id INTEGER PRIMARY KEY,
    originAttributes TEXT NOT NULL DEFAULT '',
    name TEXT,
    value TEXT,
    host TEXT,
    path TEXT,
    expiry INTEGER,
    isSecure INTEGER
  )`);
  const insert = db.prepare(
    `INSERT INTO moz_cookies (originAttributes, name, value, host, path, expiry, isSecure)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const row of rows) {
    insert.run(
      row.originAttributes ?? "",
      row.name,
      row.value,
      row.host,
      row.path ?? "/",
      row.expiry ?? NOW_MS / 1000 + 3600,
      row.isSecure ?? 1,
    );
  }
  db.close();
}

async function writeProfilesIni(root: string, content: string): Promise<void> {
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "profiles.ini"), content);
}

describe("QwenCloud Firefox import", () => {
  afterEach(async () => {
    for (const root of tempRoots.splice(0)) {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("parses profiles.ini and install metadata separately", () => {
    const dual = `[Profile0]
Name=default
IsRelative=1
Path=pr0jz2kc.default
Default=1

[Profile1]
Name=default-release
IsRelative=1
Path=aamarink.default-release

[Install11457493C5A56847]
Default=aamarink.default-release
Locked=1
`;
    const profiles = parseFirefoxProfilesIni(dual, "/tmp/firefox");
    expect(profiles).toEqual([
      { name: "default", path: "/tmp/firefox/pr0jz2kc.default", isDefault: true },
      { name: "default-release", path: "/tmp/firefox/aamarink.default-release", isDefault: false },
    ]);
    // The stale `Default=1` profile is overridden by the install metadata, which
    // names the profile the browser actually runs.
    expect(parseFirefoxInstallDefaultPaths(dual, "/tmp/firefox")).toEqual([
      "/tmp/firefox/aamarink.default-release",
    ]);
  });

  it("lists only profiles that hold a cookie database", async () => {
    const home = await createHome();
    const root = join(home, ".mozilla", "firefox");
    await mkdir(join(root, "aaaa.unused"), { recursive: true });
    const profilePath = join(root, "bbbb.default-release");
    await mkdir(profilePath, { recursive: true });
    await writeProfilesIni(
      root,
      `[Profile0]
Name=unused
IsRelative=1
Path=aaaa.unused
Default=1

[Profile1]
Name=default-release
IsRelative=1
Path=bbbb.default-release

[Install11457493C5A56847]
Default=bbbb.default-release
Locked=1
`,
    );
    writeCookies(profilePath, [
      { name: "login_qwencloud_ticket", value: "ticket-secret", host: ".qwencloud.com" },
      { name: "cna", value: "anon", host: ".qwencloud.com" },
      { name: "unrelated", value: "nope", host: "example.com" },
      {
        name: "container",
        value: "other",
        host: ".qwencloud.com",
        originAttributes: "^userContextId=1",
      },
    ]);

    const stores = await listFirefoxCookieStores({ homeDir: home });
    expect(stores.map((store) => store.name)).toEqual(["default-release"]);
    expect(stores[0]?.isDefault).toBe(true);

    const cookies = await readFirefoxCookieDatabase(join(profilePath, "cookies.sqlite"), NOW_MS);
    expect(cookies.map((cookie) => cookie.name).sort()).toEqual(["cna", "login_qwencloud_ticket"]);
  });

  it("reads cookies while another connection holds an exclusive lock", async () => {
    const home = await createHome();
    const root = join(home, ".mozilla", "firefox");
    const profilePath = join(root, "abcd.default-release");
    await mkdir(profilePath, { recursive: true });
    await writeProfilesIni(
      root,
      `[Profile0]
Name=default-release
IsRelative=1
Path=abcd.default-release
Default=1
`,
    );
    writeCookies(profilePath, [
      { name: "login_qwencloud_ticket", value: "ticket-secret", host: ".qwencloud.com" },
    ]);

    const locker = new DatabaseSync(join(profilePath, "cookies.sqlite"));
    locker.exec("BEGIN EXCLUSIVE");
    try {
      const cookies = await readFirefoxCookieDatabase(join(profilePath, "cookies.sqlite"), NOW_MS);
      expect(cookies.map((cookie) => cookie.name)).toEqual(["login_qwencloud_ticket"]);
    } finally {
      locker.close();
    }
  });

  it("returns no cookies when the profile has no QwenCloud login ticket", async () => {
    const home = await createHome();
    const root = join(home, ".mozilla", "firefox");
    const profilePath = join(root, "abcd.default-release");
    await mkdir(profilePath, { recursive: true });
    await writeProfilesIni(
      root,
      `[Profile0]
Name=default-release
IsRelative=1
Path=abcd.default-release
Default=1
`,
    );
    writeCookies(profilePath, [{ name: "cna", value: "anon", host: ".qwencloud.com" }]);

    const cookies = await readFirefoxCookieDatabase(join(profilePath, "cookies.sqlite"), NOW_MS);
    expect(cookies.map((cookie) => cookie.name)).toEqual(["cna"]);
    expect(cookies.some((cookie) => /ticket/u.test(cookie.name))).toBe(false);
  });

  it("drops cookies whose millisecond expiry has already passed", async () => {
    const home = await createHome();
    const root = join(home, ".mozilla", "firefox");
    const profilePath = join(root, "abcd.default-release");
    await mkdir(profilePath, { recursive: true });
    await writeProfilesIni(
      root,
      `[Profile0]
Name=default-release
IsRelative=1
Path=abcd.default-release
Default=1
`,
    );
    writeCookies(profilePath, [
      {
        name: "login_qwencloud_ticket",
        value: "live",
        host: ".qwencloud.com",
        expiry: NOW_MS + 60_000,
      },
      { name: "stale", value: "old", host: ".qwencloud.com", expiry: NOW_MS - 60_000 },
    ]);

    const cookies = await readFirefoxCookieDatabase(join(profilePath, "cookies.sqlite"), NOW_MS);
    expect(cookies.map((cookie) => cookie.name)).toEqual(["login_qwencloud_ticket"]);
  });
});
