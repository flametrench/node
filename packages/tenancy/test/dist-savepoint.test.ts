// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

/**
 * Regression guard for the v0.2.0 publish bug. See
 * packages/identity/test/dist-savepoint.test.ts for context.
 */
describe("built dist preserves ADR 0013 savepoint cooperation", () => {
  const distDir = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");

  function bundledSource(): string {
    const files = readdirSync(distDir).filter((f) => f.endsWith(".js"));
    return files.map((f) => readFileSync(join(distDir, f), "utf8")).join("\n");
  }

  test("dist bundle contains the caller-owned-client detector", () => {
    expect(bundledSource()).toContain("clientIsCallerOwned");
  });

  test("dist bundle contains SAVEPOINT statements (nested-transaction path)", () => {
    expect(bundledSource()).toContain("SAVEPOINT");
  });
});
