// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Run with: node --test scripts/assert-tarball-workspace-specifiers.test.mjs
//
// Builds two fixture tarballs on the fly — one with an unresolved
// `workspace:*` dependency (as a bare `npm pack` would produce) and one
// without (as `pnpm pack` correctly produces) — and asserts the guard
// rejects the former and accepts the latter.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "assert-tarball-workspace-specifiers.mjs");

function buildFixtureTarball(pkgJson) {
  const dir = mkdtempSync(join(tmpdir(), "workspace-specifier-fixture-"));
  const pkgDir = join(dir, "package");
  mkdirSync(pkgDir);
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify(pkgJson, null, 2));

  const tarballPath = join(dir, "fixture.tgz");
  const result = spawnSync("tar", ["-czf", tarballPath, "-C", dir, "package"]);
  assert.equal(result.status, 0, `tar failed: ${result.stderr}`);

  return { tarballPath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function runAssertion(tarballPath) {
  return spawnSync("node", [SCRIPT, tarballPath], { encoding: "utf8" });
}

test("fails on a tarball with an unresolved workspace: specifier", () => {
  const { tarballPath, cleanup } = buildFixtureTarball({
    name: "@flametrench/bad",
    version: "0.4.0",
    dependencies: { "@flametrench/ids": "workspace:*" },
  });

  try {
    const result = runAssertion(tarballPath);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /unresolved workspace: specifiers/);
    assert.match(result.stderr, /dependencies\.@flametrench\/ids = "workspace:\*"/);
  } finally {
    cleanup();
  }
});

test("passes on a tarball with resolved dependency versions", () => {
  const { tarballPath, cleanup } = buildFixtureTarball({
    name: "@flametrench/good",
    version: "0.4.0",
    dependencies: { "@flametrench/ids": "^0.4.0" },
  });

  try {
    const result = runAssertion(tarballPath);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /OK: .* has no workspace: specifiers/);
  } finally {
    cleanup();
  }
});
