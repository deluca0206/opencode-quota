import { describe, expect, it } from "vitest";

import {
  cookieHeaderFromCookies,
  cookieMatchesHost,
  cookiesForUrl,
  hasAuthTicket,
  hasQwenCloudRequestTickets,
  parseCookieHeader,
  sanitizeQwenCloudError,
} from "../src/lib/qwencloud-cookies.js";

describe("QwenCloud cookies", () => {
  it("parses a Cookie header and keeps the login ticket", () => {
    const cookies = parseCookieHeader(
      "Cookie: login_qwencloud_ticket=ticket-secret; cna=anon; ignored=ok",
    );
    expect(cookies).toEqual([
      { name: "login_qwencloud_ticket", value: "ticket-secret" },
      { name: "cna", value: "anon" },
      { name: "ignored", value: "ok" },
    ]);
    expect(hasAuthTicket(cookies ?? [])).toBe(true);
    expect(cookieHeaderFromCookies(cookies ?? [])).toBe(
      "login_qwencloud_ticket=ticket-secret; cna=anon; ignored=ok",
    );
  });

  it.each([
    ["missing ticket", "cna=anon"],
    ["empty header", ""],
    ["CR injection", "login_qwencloud_ticket=ticket\rignored=value"],
    ["duplicate name", "login_qwencloud_ticket=a; login_qwencloud_ticket=b"],
    ["malformed pair", "login_qwencloud_ticket=ticket; no-equals"],
  ])("rejects %s", (_label, raw) => {
    const cookies = parseCookieHeader(raw);
    if (_label === "missing ticket") {
      expect(hasAuthTicket(cookies ?? [])).toBe(false);
      return;
    }
    expect(cookies).toBeNull();
  });

  it("matches domain cookies onto dashboard and data hosts", () => {
    expect(cookieMatchesHost(".qwencloud.com", "home.qwencloud.com")).toBe(true);
    expect(cookieMatchesHost(".qwencloud.com", "cs-data.qwencloud.com")).toBe(true);
    expect(cookieMatchesHost("home.qwencloud.com", "cs-data.qwencloud.com")).toBe(false);
  });

  it("filters expired, container, and host-mismatched cookies", () => {
    const nowMs = 1_700_000_000_000;
    const cookies = cookiesForUrl(
      [
        {
          name: "login_qwencloud_ticket",
          value: "live",
          host: ".qwencloud.com",
          path: "/",
          expiry: nowMs / 1000 + 60,
        },
        {
          name: "expired",
          value: "old",
          host: ".qwencloud.com",
          path: "/",
          expiry: nowMs / 1000 - 60,
        },
        {
          name: "container",
          value: "other",
          host: ".qwencloud.com",
          path: "/",
          originAttributes: "^userContextId=1",
        },
        {
          name: "other-host",
          value: "nope",
          host: "example.com",
          path: "/",
        },
      ],
      new URL("https://home.qwencloud.com/billing"),
      nowMs,
    );
    expect(cookies.map((cookie) => cookie.name)).toEqual(["login_qwencloud_ticket"]);
  });

  it("treats Firefox millisecond expiry as not expired", () => {
    const nowMs = 1_700_000_000_000;
    const cookies = cookiesForUrl(
      [
        {
          name: "login_qwencloud_ticket",
          value: "live",
          host: ".qwencloud.com",
          path: "/",
          expiry: nowMs + 60_000,
        },
        {
          name: "expired-ms",
          value: "old",
          host: ".qwencloud.com",
          path: "/",
          expiry: nowMs - 60_000,
        },
      ],
      new URL("https://home.qwencloud.com/billing"),
      nowMs,
    );
    expect(cookies.map((cookie) => cookie.name)).toEqual(["login_qwencloud_ticket"]);
  });

  it("does not attach cookies to unauthorized request URLs", () => {
    const cookies = cookiesForUrl(
      [
        {
          name: "login_qwencloud_ticket",
          value: "ticket-secret",
          host: ".qwencloud.com",
          path: "/",
        },
      ],
      new URL("https://evil.example/"),
      Date.now(),
    );
    expect(cookies).toEqual([]);
  });

  it("redacts cookie values from errors", () => {
    expect(sanitizeQwenCloudError(new Error("boom ticket-secret boom"), ["ticket-secret"])).toBe(
      "boom [redacted] boom",
    );
  });
});

describe("QwenCloud request ticket applicability", () => {
  const NOW_MS = 1_700_000_000_000;

  it("accepts a ticket scoped to the QwenCloud hosts", () => {
    expect(
      hasQwenCloudRequestTickets(
        [{ name: "login_qwencloud_ticket", value: "secret", host: ".qwencloud.com" }],
        NOW_MS,
      ),
    ).toBe(true);
  });

  it("accepts a ticket from a parsed header, which carries no host", () => {
    const cookies = parseCookieHeader("login_aliyunid_ticket=secret; cna=anon");
    expect(hasQwenCloudRequestTickets(cookies ?? [], NOW_MS)).toBe(true);
  });

  it("rejects a ticket that only applies to another Alibaba host", () => {
    expect(
      hasQwenCloudRequestTickets(
        [
          { name: "login_aliyunid_ticket", value: "secret", host: ".aliyun.com" },
          { name: "cna", value: "anon", host: ".qwencloud.com" },
        ],
        NOW_MS,
      ),
    ).toBe(false);
  });

  it("rejects an expired ticket and a non-default Firefox container", () => {
    expect(
      hasQwenCloudRequestTickets(
        [
          {
            name: "login_qwencloud_ticket",
            value: "secret",
            host: ".qwencloud.com",
            expiry: Math.floor(NOW_MS / 1000) - 60,
          },
        ],
        NOW_MS,
      ),
    ).toBe(false);
    expect(
      hasQwenCloudRequestTickets(
        [
          {
            name: "login_qwencloud_ticket",
            value: "secret",
            host: ".qwencloud.com",
            originAttributes: "^userContextId=2",
          },
        ],
        NOW_MS,
      ),
    ).toBe(false);
  });

  it("requires a ticket for every console host the API uses", () => {
    expect(
      hasQwenCloudRequestTickets(
        [{ name: "login_qwencloud_ticket", value: "secret", host: "home.qwencloud.com" }],
        NOW_MS,
      ),
    ).toBe(false);
    expect(
      hasQwenCloudRequestTickets(
        [
          { name: "login_qwencloud_ticket", value: "secret", host: "home.qwencloud.com" },
          { name: "login_aliyunid_ticket", value: "secret", host: ".qwencloud.com" },
        ],
        NOW_MS,
      ),
    ).toBe(true);
  });
});
