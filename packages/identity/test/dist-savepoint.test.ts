// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

/**
 * Regression guard for the v0.2.0 publish bug: dist artifacts shipped to
 * npm without ADR 0013 savepoint cooperation, even though the source had
 * it. The `prepack` hook now rebuilds before pack, so any future publish
 * picks up current source. This test catches the failure mode at CI time:
 * if the bundled output stops including `clientIsCallerOwned` /
 * `SAVEPOINT`, the savepoint cooperation is gone and an outer-transaction
 * caller will get "Client has already been connected" again.
 *
 * Requires `pnpm build` to have run first. CI runs build before test.
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
