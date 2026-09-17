import { describe, expect, it } from "vitest";

import type { QuotaToastEntry } from "../src/lib/entries.js";
import { renderAccountingFourSurfaces } from "./helpers/accounting-four-surface.js";

const group = "Qwen/Alibaba Token Plan Pro";
const accounting = {
  resultType: "quota",
  acquisitionMethod: "remote_api",
  ownership: "maintained",
  authority: "provider_reported",
} as const;

const fiveHour: QuotaToastEntry = {
  accounting,
  name: `${group} 5h`,
  group,
  label: "5h:",
  percentRemaining: 79,
  semantic: { metric: { kind: "window", window: "five_hour" }, prominence: "primary" },
  basis: {
    used: {
      quantity: { decimal: "2520", unit: { kind: "count", unit: "credit" } },
      authority: "locally_derived",
    },
    limit: {
      quantity: { decimal: "12000", unit: { kind: "count", unit: "credit" } },
      authority: "provider_reported",
    },
    remaining: {
      quantity: { decimal: "9480", unit: { kind: "count", unit: "credit" } },
      authority: "locally_derived",
    },
  },
  resetTimeIso: "2026-07-21T12:07:00.000Z",
};

const weekly: QuotaToastEntry = {
  accounting,
  name: `${group} Weekly`,
  group,
  label: "Weekly:",
  percentRemaining: 63,
  semantic: { metric: { kind: "window", window: "week" }, prominence: "primary" },
  basis: {
    used: {
      quantity: { decimal: "14800", unit: { kind: "count", unit: "credit" } },
      authority: "locally_derived",
    },
    limit: {
      quantity: { decimal: "40000", unit: { kind: "count", unit: "credit" } },
      authority: "provider_reported",
    },
    remaining: {
      quantity: { decimal: "25200", unit: { kind: "count", unit: "credit" } },
      authority: "locally_derived",
    },
  },
  resetTimeIso: "2026-07-26T09:15:00.000Z",
};

describe("Qwen/Alibaba Token Plan four-surface formatting", () => {
  it("shows plan identity and both credit windows", () => {
    const outputs = renderAccountingFourSurfaces({
      data: { entries: [fiveHour, weekly], errors: [] },
      accountingDetail: "detailed",
      toastMaxWidth: 72,
      toastNarrowAt: 48,
      compactMaxWidth: 240,
    });

    for (const output of Object.values(outputs)) {
      expect(output).toContain("Qwen/Alibaba Token Plan");
      expect(output).toContain("Pro");
      expect(output).toContain("79%");
    }
    expect(outputs.command).toContain("Five-hour quota");
    expect(outputs.command).toContain("Weekly quota");
  });
});
